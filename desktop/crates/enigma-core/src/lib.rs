#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use enigma_protocol::{
    CapabilitySet, DeviceId, DeviceState, HistoryTransferManifest, MessageId, ProtocolError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRelation {
    Contact,
    SameAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTarget {
    pub device_id: DeviceId,
    pub state: DeviceState,
    pub relation: DeviceRelation,
}

#[must_use]
pub fn plan_fanout(sender_device_id: DeviceId, targets: &[DeviceTarget]) -> Vec<DeviceTarget> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for target in targets {
        if target.device_id == sender_device_id || target.state == DeviceState::Revoked {
            continue;
        }
        if seen.insert(target.device_id) {
            output.push(*target);
        }
    }
    output
}

#[derive(Debug)]
pub struct MessageDeduplicator {
    capacity: usize,
    order: VecDeque<MessageId>,
    seen: HashSet<MessageId>,
}

impl MessageDeduplicator {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "deduplication capacity must be positive");
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        }
    }

    /// Returns `true` only for the first observation of a logical message id.
    #[must_use]
    pub fn observe(&mut self, message_id: MessageId) -> bool {
        if !self.seen.insert(message_id) {
            return false;
        }
        self.order.push_back(message_id);
        if self.order.len() > self.capacity {
            let evicted = self
                .order
                .pop_front()
                .expect("deduplication queue must be non-empty after insertion");
            self.seen.remove(&evicted);
        }
        true
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryTransferError {
    InvalidManifest(ProtocolError),
    MissingHistoryTransferCapability,
    SourceMismatch,
    DestinationMismatch,
    RevokedDevice,
    Expired,
    AlreadyConsumed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryTransferGuard {
    manifest: HistoryTransferManifest,
    consumed: bool,
}

impl HistoryTransferGuard {
    pub fn new(
        manifest: HistoryTransferManifest,
        now_unix_ms: u64,
    ) -> Result<Self, HistoryTransferError> {
        manifest
            .validate(now_unix_ms)
            .map_err(HistoryTransferError::InvalidManifest)?;
        if !manifest
            .header
            .capabilities
            .contains(CapabilitySet::HISTORY_TRANSFER)
        {
            return Err(HistoryTransferError::MissingHistoryTransferCapability);
        }
        Ok(Self {
            manifest,
            consumed: false,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &HistoryTransferManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    pub fn consume(
        &mut self,
        source_device_id: DeviceId,
        source_state: DeviceState,
        destination_device_id: DeviceId,
        destination_state: DeviceState,
        now_unix_ms: u64,
    ) -> Result<MessageId, HistoryTransferError> {
        if self.consumed {
            return Err(HistoryTransferError::AlreadyConsumed);
        }
        if now_unix_ms >= self.manifest.expires_at_unix_ms {
            return Err(HistoryTransferError::Expired);
        }
        if source_device_id != self.manifest.source_device_id {
            return Err(HistoryTransferError::SourceMismatch);
        }
        if destination_device_id != self.manifest.destination_device_id {
            return Err(HistoryTransferError::DestinationMismatch);
        }
        if source_state == DeviceState::Revoked || destination_state == DeviceState::Revoked {
            return Err(HistoryTransferError::RevokedDevice);
        }

        self.consumed = true;
        Ok(self.manifest.transfer_id)
    }
}

#[derive(Debug)]
pub struct CoreRuntime {
    deduplicator: MessageDeduplicator,
}

impl CoreRuntime {
    #[must_use]
    pub fn new(dedup_capacity: usize) -> Self {
        Self {
            deduplicator: MessageDeduplicator::new(dedup_capacity),
        }
    }

    #[must_use]
    pub fn observe_message(&mut self, message_id: MessageId) -> bool {
        self.deduplicator.observe(message_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enigma_protocol::WireHeader;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 16])
    }

    fn history_manifest() -> HistoryTransferManifest {
        HistoryTransferManifest {
            header: WireHeader::v1(CapabilitySet::HISTORY_TRANSFER),
            transfer_id: MessageId::from_bytes([8; 16]),
            source_device_id: device(1),
            destination_device_id: device(2),
            expires_at_unix_ms: 2_000,
            single_use: true,
            ciphertext_len: 128,
        }
    }

    #[test]
    fn alice_android_fans_out_to_bob_devices_and_alice_sibling() {
        let a1 = device(1);
        let a2 = device(2);
        let b1 = device(3);
        let b2 = device(4);
        let targets = [
            DeviceTarget {
                device_id: b1,
                state: DeviceState::Active,
                relation: DeviceRelation::Contact,
            },
            DeviceTarget {
                device_id: b2,
                state: DeviceState::Active,
                relation: DeviceRelation::Contact,
            },
            DeviceTarget {
                device_id: a2,
                state: DeviceState::Active,
                relation: DeviceRelation::SameAccount,
            },
            DeviceTarget {
                device_id: a1,
                state: DeviceState::Active,
                relation: DeviceRelation::SameAccount,
            },
        ];
        let planned = plan_fanout(a1, &targets);
        assert_eq!(planned.len(), 3);
        assert!(planned.iter().any(|target| target.device_id == a2));
        assert!(planned.iter().any(|target| target.device_id == b1));
        assert!(planned.iter().any(|target| target.device_id == b2));
    }

    #[test]
    fn revoked_device_never_enters_fanout() {
        let targets = [DeviceTarget {
            device_id: device(9),
            state: DeviceState::Revoked,
            relation: DeviceRelation::SameAccount,
        }];
        assert!(plan_fanout(device(1), &targets).is_empty());
    }

    #[test]
    fn p2p_then_relay_duplicate_is_rendered_once() {
        let mut dedup = MessageDeduplicator::new(16);
        let message_id = MessageId::from_bytes([7; 16]);
        assert!(dedup.observe(message_id));
        assert!(!dedup.observe(message_id));
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn history_transfer_is_single_use_and_bound_to_active_devices() {
        let mut guard =
            HistoryTransferGuard::new(history_manifest(), 1_000).expect("valid manifest");
        assert_eq!(
            guard.consume(
                device(1),
                DeviceState::Active,
                device(2),
                DeviceState::Active,
                1_500,
            ),
            Ok(MessageId::from_bytes([8; 16]))
        );
        assert!(guard.is_consumed());
        assert_eq!(
            guard.consume(
                device(1),
                DeviceState::Active,
                device(2),
                DeviceState::Active,
                1_600,
            ),
            Err(HistoryTransferError::AlreadyConsumed)
        );
    }

    #[test]
    fn history_transfer_rejects_wrong_revoked_or_expired_endpoints() {
        let mut wrong_destination =
            HistoryTransferGuard::new(history_manifest(), 1_000).expect("valid manifest");
        assert_eq!(
            wrong_destination.consume(
                device(1),
                DeviceState::Active,
                device(3),
                DeviceState::Active,
                1_500,
            ),
            Err(HistoryTransferError::DestinationMismatch)
        );
        assert!(!wrong_destination.is_consumed());

        let mut revoked =
            HistoryTransferGuard::new(history_manifest(), 1_000).expect("valid manifest");
        assert_eq!(
            revoked.consume(
                device(1),
                DeviceState::Revoked,
                device(2),
                DeviceState::Active,
                1_500,
            ),
            Err(HistoryTransferError::RevokedDevice)
        );
        assert!(!revoked.is_consumed());

        let mut expired =
            HistoryTransferGuard::new(history_manifest(), 1_000).expect("valid manifest");
        assert_eq!(
            expired.consume(
                device(1),
                DeviceState::Active,
                device(2),
                DeviceState::Active,
                2_000,
            ),
            Err(HistoryTransferError::Expired)
        );
        assert!(!expired.is_consumed());
    }

    #[test]
    fn history_transfer_requires_explicit_wire_capability() {
        let mut manifest = history_manifest();
        manifest.header = WireHeader::v1(CapabilitySet::MULTI_DEVICE);
        assert_eq!(
            HistoryTransferGuard::new(manifest, 1_000),
            Err(HistoryTransferError::MissingHistoryTransferCapability)
        );
    }
}
