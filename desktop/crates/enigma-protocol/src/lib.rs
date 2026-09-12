#![forbid(unsafe_code)]

use std::fmt;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MIN_SUPPORTED_VERSION: u16 = 1;
pub const MAX_PAIRING_PUBLIC_KEY_BYTES: usize = 4096;
pub const MAX_DEVICE_IDENTITY_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountId([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageId([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairingSessionId([u8; 16]);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MailboxId([u8; 32]);

macro_rules! impl_id16 {
    ($name:ident) => {
        impl $name {
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

impl_id16!(AccountId);
impl_id16!(DeviceId);
impl_id16!(MessageId);
impl_id16!(PairingSessionId);

impl MailboxId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailboxId(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    pub const TEXT: Self = Self(1 << 0);
    pub const ATTACHMENTS: Self = Self(1 << 1);
    pub const MULTI_DEVICE: Self = Self(1 << 2);
    pub const P2P_DIRECT: Self = Self(1 << 3);
    pub const TURN_TRANSIT: Self = Self(1 << 4);
    pub const TEMPORARY_RELAY: Self = Self(1 << 5);
    pub const HISTORY_TRANSFER: Self = Self(1 << 6);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireHeader {
    pub protocol_version: u16,
    pub min_supported_version: u16,
    pub capabilities: CapabilitySet,
}

impl WireHeader {
    #[must_use]
    pub const fn v1(capabilities: CapabilitySet) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            min_supported_version: MIN_SUPPORTED_VERSION,
            capabilities,
        }
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.min_supported_version > self.protocol_version {
            return Err(ProtocolError::InvalidVersionRange);
        }
        if self.protocol_version < MIN_SUPPORTED_VERSION
            || self.min_supported_version > PROTOCOL_VERSION
        {
            return Err(ProtocolError::UnsupportedVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingQrPayload {
    pub header: WireHeader,
    pub session_id: PairingSessionId,
    pub expires_at_unix_ms: u64,
    pub pairing_public_key: Vec<u8>,
}

impl PairingQrPayload {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        self.header.validate()?;
        if self.expires_at_unix_ms <= now_unix_ms {
            return Err(ProtocolError::Expired);
        }
        if self.pairing_public_key.is_empty()
            || self.pairing_public_key.len() > MAX_PAIRING_PUBLIC_KEY_BYTES
        {
            return Err(ProtocolError::InvalidPairingPublicKey);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAuthorizationPayload {
    pub header: WireHeader,
    pub account_id: AccountId,
    pub new_device_id: DeviceId,
    pub authorizing_device_id: DeviceId,
    pub new_signal_identity_public: Vec<u8>,
    pub issued_at_unix_ms: u64,
    pub pairing_session_id: PairingSessionId,
}

impl DeviceAuthorizationPayload {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.header.validate()?;
        if self.new_device_id == self.authorizing_device_id {
            return Err(ProtocolError::SelfAuthorization);
        }
        if self.new_signal_identity_public.is_empty()
            || self.new_signal_identity_public.len() > MAX_DEVICE_IDENTITY_BYTES
        {
            return Err(ProtocolError::InvalidDeviceIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAuthorizationCertificate {
    pub payload: DeviceAuthorizationPayload,
    pub authorizer_signature: Vec<u8>,
}

impl DeviceAuthorizationCertificate {
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.payload.validate()?;
        if self.authorizer_signature.is_empty() || self.authorizer_signature.len() > 4096 {
            return Err(ProtocolError::InvalidSignatureShape);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEnvelope {
    pub header: WireHeader,
    pub message_id: MessageId,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub ciphertext: Vec<u8>,
}

impl RecipientEnvelope {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        self.header.validate()?;
        if self.sender_device_id == self.recipient_device_id {
            return Err(ProtocolError::SameSenderAndRecipient);
        }
        if self.expires_at_unix_ms <= self.created_at_unix_ms
            || self.expires_at_unix_ms <= now_unix_ms
        {
            return Err(ProtocolError::Expired);
        }
        if self.ciphertext.is_empty() {
            return Err(ProtocolError::EmptyCiphertext);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryTransferManifest {
    pub header: WireHeader,
    pub transfer_id: MessageId,
    pub source_device_id: DeviceId,
    pub destination_device_id: DeviceId,
    pub expires_at_unix_ms: u64,
    pub single_use: bool,
    pub ciphertext_len: u64,
}

impl HistoryTransferManifest {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        self.header.validate()?;
        if self.source_device_id == self.destination_device_id {
            return Err(ProtocolError::SameSenderAndRecipient);
        }
        if self.expires_at_unix_ms <= now_unix_ms {
            return Err(ProtocolError::Expired);
        }
        if !self.single_use {
            return Err(ProtocolError::HistoryTransferMustBeSingleUse);
        }
        if self.ciphertext_len == 0 {
            return Err(ProtocolError::EmptyCiphertext);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    UnsupportedVersion,
    InvalidVersionRange,
    Expired,
    InvalidPairingPublicKey,
    InvalidDeviceIdentity,
    InvalidSignatureShape,
    SelfAuthorization,
    SameSenderAndRecipient,
    EmptyCiphertext,
    HistoryTransferMustBeSingleUse,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 16])
    }

    #[test]
    fn version_negotiation_fails_closed() {
        let header = WireHeader {
            protocol_version: 0,
            min_supported_version: 0,
            capabilities: CapabilitySet::empty(),
        };
        assert_eq!(header.validate(), Err(ProtocolError::UnsupportedVersion));
    }

    #[test]
    fn pairing_payload_requires_live_bounded_public_material() {
        let payload = PairingQrPayload {
            header: WireHeader::v1(CapabilitySet::MULTI_DEVICE),
            session_id: PairingSessionId::from_bytes([7; 16]),
            expires_at_unix_ms: 2_000,
            pairing_public_key: vec![1; 32],
        };
        assert_eq!(payload.validate(1_000), Ok(()));
        assert_eq!(payload.validate(2_000), Err(ProtocolError::Expired));
    }

    #[test]
    fn device_authorization_cannot_self_authorize() {
        let payload = DeviceAuthorizationPayload {
            header: WireHeader::v1(CapabilitySet::MULTI_DEVICE),
            account_id: AccountId::from_bytes([1; 16]),
            new_device_id: device(2),
            authorizing_device_id: device(2),
            new_signal_identity_public: vec![9; 33],
            issued_at_unix_ms: 1_000,
            pairing_session_id: PairingSessionId::from_bytes([3; 16]),
        };
        assert_eq!(payload.validate(), Err(ProtocolError::SelfAuthorization));
    }

    #[test]
    fn recipient_envelope_requires_ciphertext_and_ttl() {
        let envelope = RecipientEnvelope {
            header: WireHeader::v1(CapabilitySet::TEXT),
            message_id: MessageId::from_bytes([4; 16]),
            sender_device_id: device(1),
            recipient_device_id: device(2),
            created_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            ciphertext: vec![8, 9],
        };
        assert_eq!(envelope.validate(1_500), Ok(()));
        assert_eq!(envelope.validate(2_000), Err(ProtocolError::Expired));
    }
}
