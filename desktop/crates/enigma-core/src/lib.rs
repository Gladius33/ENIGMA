#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use enigma_protocol::{DeviceId, DeviceState, MessageId};

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

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 16])
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
}
