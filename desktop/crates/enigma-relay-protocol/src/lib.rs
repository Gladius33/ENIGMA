#![forbid(unsafe_code)]

use core::fmt;
use enigma_protocol::{MailboxId, MessageId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayDeliveryState {
    Pending,
    Acknowledged,
    Expired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueRelayEnvelope {
    pub mailbox_id: MailboxId,
    pub message_id: MessageId,
    pub expires_at_unix_ms: u64,
    pub ciphertext: Vec<u8>,
    state: RelayDeliveryState,
}

impl fmt::Debug for OpaqueRelayEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueRelayEnvelope")
            .field("mailbox_id", &self.mailbox_id)
            .field("message_id", &self.message_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("state", &self.state)
            .finish()
    }
}

impl OpaqueRelayEnvelope {
    pub fn new(
        mailbox_id: MailboxId,
        message_id: MessageId,
        now_unix_ms: u64,
        expires_at_unix_ms: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Self, RelayError> {
        if expires_at_unix_ms <= now_unix_ms {
            return Err(RelayError::MissingOrExpiredTtl);
        }
        if ciphertext.is_empty() {
            return Err(RelayError::EmptyCiphertext);
        }
        Ok(Self {
            mailbox_id,
            message_id,
            expires_at_unix_ms,
            ciphertext,
            state: RelayDeliveryState::Pending,
        })
    }

    #[must_use]
    pub const fn state(&self) -> RelayDeliveryState {
        self.state
    }

    pub fn acknowledge(&mut self) {
        self.state = RelayDeliveryState::Acknowledged;
    }

    pub fn refresh_expiry_state(&mut self, now_unix_ms: u64) {
        if self.state == RelayDeliveryState::Pending && now_unix_ms >= self.expires_at_unix_ms {
            self.state = RelayDeliveryState::Expired;
        }
    }

    #[must_use]
    pub const fn must_delete(&self) -> bool {
        matches!(
            self.state,
            RelayDeliveryState::Acknowledged | RelayDeliveryState::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    MissingOrExpiredTtl,
    EmptyCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_requires_delete() {
        let mut envelope = OpaqueRelayEnvelope::new(
            MailboxId::from_bytes([1; 32]),
            MessageId::from_bytes([2; 16]),
            1_000,
            2_000,
            vec![0xAA],
        )
        .expect("valid relay envelope");
        assert!(!envelope.must_delete());
        envelope.acknowledge();
        assert!(envelope.must_delete());
    }

    #[test]
    fn expiry_requires_delete() {
        let mut envelope = OpaqueRelayEnvelope::new(
            MailboxId::from_bytes([1; 32]),
            MessageId::from_bytes([2; 16]),
            1_000,
            2_000,
            vec![0xAA],
        )
        .expect("valid relay envelope");
        envelope.refresh_expiry_state(2_000);
        assert_eq!(envelope.state(), RelayDeliveryState::Expired);
        assert!(envelope.must_delete());
    }

    #[test]
    fn debug_output_never_contains_ciphertext_bytes() {
        let secret_marker = b"plaintext-must-never-hit-logs".to_vec();
        let envelope = OpaqueRelayEnvelope::new(
            MailboxId::from_bytes([1; 32]),
            MessageId::from_bytes([2; 16]),
            1_000,
            2_000,
            secret_marker.clone(),
        )
        .expect("valid relay envelope");

        let rendered = format!("{envelope:?}");
        assert!(!rendered.contains("plaintext-must-never-hit-logs"));
        assert!(!rendered.contains(&format!("{secret_marker:?}")));
        assert!(rendered.contains("ciphertext_len"));
    }
}
