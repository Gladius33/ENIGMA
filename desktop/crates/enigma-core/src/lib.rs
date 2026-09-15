#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use enigma_protocol::{
    CapabilitySet, DeviceId, DeviceState, HistoryTransferManifest, MessageId, PairingQrPayload,
    PairingSessionId, ProtocolError, WireHeader,
};
use enigma_sodium::{random_public_bytes, Ed25519SigningKeyPair, SodiumError};
use qrcode::{render::svg, QrCode};

pub const DEFAULT_PAIRING_TTL_MS: u64 = 120_000;
pub const MIN_PAIRING_TTL_MS: u64 = 30_000;
pub const MAX_PAIRING_TTL_MS: u64 = 300_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingBootstrapError {
    InvalidTtl,
    ExpiryOverflow,
    Randomness(SodiumError),
    InvalidPayload(ProtocolError),
    QrEncoding,
}

pub struct PairingBootstrap {
    payload: PairingQrPayload,
    signing_key: Ed25519SigningKeyPair,
    payload_json: String,
    uri: String,
    svg: String,
}

impl PairingBootstrap {
    pub fn generate(now_unix_ms: u64, ttl_ms: u64) -> Result<Self, PairingBootstrapError> {
        if !(MIN_PAIRING_TTL_MS..=MAX_PAIRING_TTL_MS).contains(&ttl_ms) {
            return Err(PairingBootstrapError::InvalidTtl);
        }

        let expires_at_unix_ms = now_unix_ms
            .checked_add(ttl_ms)
            .ok_or(PairingBootstrapError::ExpiryOverflow)?;

        let mut session_bytes =
            random_public_bytes::<16>().map_err(PairingBootstrapError::Randomness)?;
        session_bytes[6] = (session_bytes[6] & 0x0f) | 0x40;
        session_bytes[8] = (session_bytes[8] & 0x3f) | 0x80;
        let session_id = PairingSessionId::from_bytes(session_bytes);

        let signing_key =
            Ed25519SigningKeyPair::generate().map_err(PairingBootstrapError::Randomness)?;
        let capabilities = CapabilitySet::MULTI_DEVICE;
        let payload = PairingQrPayload {
            header: WireHeader::v1(capabilities),
            session_id,
            expires_at_unix_ms,
            pairing_public_key: signing_key.public_key().to_vec(),
        };
        payload
            .validate(now_unix_ms)
            .map_err(PairingBootstrapError::InvalidPayload)?;

        let public_key = STANDARD_NO_PAD.encode(signing_key.public_key());
        let payload_json = format!(
            concat!(
                "{{\"type\":\"enigma.pair_device\",",
                "\"version\":1,",
                "\"protocol_version\":{},",
                "\"min_supported_version\":{},",
                "\"capabilities\":{},",
                "\"pairing_session_id\":\"{}\",",
                "\"expires_at_unix_ms\":{},",
                "\"pairing_public_key\":\"{}\"}}"
            ),
            payload.header.protocol_version,
            payload.header.min_supported_version,
            payload.header.capabilities.bits(),
            payload.session_id.to_canonical_uuid(),
            payload.expires_at_unix_ms,
            public_key,
        );
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let uri = format!("enigma://pair-device?payload={encoded_payload}");
        let qr = QrCode::new(uri.as_bytes()).map_err(|_| PairingBootstrapError::QrEncoding)?;
        let svg = qr
            .render::<svg::Color>()
            .min_dimensions(320, 320)
            .quiet_zone(true)
            .build();

        Ok(Self {
            payload,
            signing_key,
            payload_json,
            uri,
            svg,
        })
    }

    #[must_use]
    pub const fn payload(&self) -> &PairingQrPayload {
        &self.payload
    }

    #[must_use]
    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }

    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    #[must_use]
    pub fn svg(&self) -> &str {
        &self.svg
    }

    pub fn sign_pairing_message(
        &self,
        message: &[u8],
    ) -> Result<[u8; 64], PairingBootstrapError> {
        self.signing_key
            .sign(message)
            .map_err(PairingBootstrapError::Randomness)
    }
}

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
    CiphertextLengthMismatch,
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
        observed_ciphertext_len: u64,
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
        if observed_ciphertext_len != self.manifest.ciphertext_len {
            return Err(HistoryTransferError::CiphertextLengthMismatch);
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

    #[test]
    fn pairing_bootstrap_matches_android_qr_contract() {
        let bootstrap =
            PairingBootstrap::generate(1_700_000_000_000, DEFAULT_PAIRING_TTL_MS)
                .expect("pairing bootstrap");

        assert_eq!(
            bootstrap.payload().header.capabilities,
            CapabilitySet::MULTI_DEVICE
        );
        assert_eq!(
            bootstrap.payload().expires_at_unix_ms,
            1_700_000_120_000
        );
        assert_eq!(bootstrap.payload().pairing_public_key.len(), 32);
        assert!(bootstrap.uri().starts_with("enigma://pair-device?payload="));
        assert!(bootstrap
            .payload_json()
            .contains("\"type\":\"enigma.pair_device\""));
        assert!(bootstrap
            .payload_json()
            .contains("\"protocol_version\":1"));
        assert!(bootstrap
            .payload_json()
            .contains("\"min_supported_version\":1"));
        assert!(bootstrap.payload_json().contains("\"capabilities\":4"));
        assert!(bootstrap.svg().contains("<svg"));
    }

    #[test]
    fn pairing_bootstrap_enforces_short_lived_ttl_and_signs() {
        assert!(matches!(
            PairingBootstrap::generate(1_000, MIN_PAIRING_TTL_MS - 1),
            Err(PairingBootstrapError::InvalidTtl)
        ));
        assert!(matches!(
            PairingBootstrap::generate(1_000, MAX_PAIRING_TTL_MS + 1),
            Err(PairingBootstrapError::InvalidTtl)
        ));

        let bootstrap = PairingBootstrap::generate(1_000, DEFAULT_PAIRING_TTL_MS)
            .expect("pairing bootstrap");
        let signature = bootstrap
            .sign_pairing_message(b"ENIGMA_PAIRING_CHANNEL_V1")
            .expect("pairing signature");
        assert!(signature.iter().any(|byte| *byte != 0));
    }

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
                128,
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
                128,
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
                128,
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
                128,
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
                128,
                2_000,
            ),
            Err(HistoryTransferError::Expired)
        );
        assert!(!expired.is_consumed());
    }

    #[test]
    fn history_transfer_rejects_ciphertext_length_mismatch_without_consuming_ticket() {
        let mut guard =
            HistoryTransferGuard::new(history_manifest(), 1_000).expect("valid manifest");

        assert_eq!(
            guard.consume(
                device(1),
                DeviceState::Active,
                device(2),
                DeviceState::Active,
                127,
                1_500,
            ),
            Err(HistoryTransferError::CiphertextLengthMismatch)
        );
        assert!(!guard.is_consumed());

        assert_eq!(
            guard.consume(
                device(1),
                DeviceState::Active,
                device(2),
                DeviceState::Active,
                128,
                1_500,
            ),
            Ok(MessageId::from_bytes([8; 16]))
        );
        assert!(guard.is_consumed());
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
