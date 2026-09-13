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

pub const DEVICE_AUTHORIZATION_DOMAIN: &str = "ENIGMA_DEVICE_LINK_V1";
pub const MULTI_DEVICE_CAPABILITY_BIT: u64 = 1 << 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalDeviceAuthorization {
    pub account_id: String,
    pub new_device_id: String,
    pub authorizing_device_id: String,
    pub pairing_session_id: String,
    pub platform: String,
    pub protocol_version: u16,
    pub min_supported_version: u16,
    pub capabilities: u64,
    pub issued_at_unix_ms: u64,
    pub target_identity_key: String,
    pub authorizer_identity_key: String,
}

impl CanonicalDeviceAuthorization {
    pub fn parse(input: &str) -> Result<Self, ProtocolError> {
        if input.len() > 32 * 1024 {
            return Err(ProtocolError::InvalidDeviceAuthorizationTranscript);
        }
        let lines: Vec<&str> = input.split('\n').collect();
        if lines.len() != 13 || lines[0] != DEVICE_AUTHORIZATION_DOMAIN || !lines[12].is_empty() {
            return Err(ProtocolError::InvalidDeviceAuthorizationTranscript);
        }

        let value = |index: usize, key: &str| -> Result<&str, ProtocolError> {
            lines[index]
                .strip_prefix(key)
                .filter(|candidate| !candidate.is_empty())
                .ok_or(ProtocolError::InvalidDeviceAuthorizationTranscript)
        };

        let account_id = value(1, "account_id=")?;
        let new_device_id = value(2, "new_device_id=")?;
        let authorizing_device_id = value(3, "authorizing_device_id=")?;
        let pairing_session_id = value(4, "pairing_session_id=")?;
        let platform = value(5, "platform=")?;
        let protocol_version = value(6, "protocol_version=")?
            .parse::<u16>()
            .map_err(|_| ProtocolError::InvalidDeviceAuthorizationTranscript)?;
        let min_supported_version = value(7, "min_supported_version=")?
            .parse::<u16>()
            .map_err(|_| ProtocolError::InvalidDeviceAuthorizationTranscript)?;
        let capabilities = value(8, "capabilities=")?
            .parse::<u64>()
            .map_err(|_| ProtocolError::InvalidDeviceAuthorizationTranscript)?;
        let issued_at_unix_ms = value(9, "issued_at_unix_ms=")?
            .parse::<u64>()
            .map_err(|_| ProtocolError::InvalidDeviceAuthorizationTranscript)?;
        let target_identity_key = value(10, "target_identity_key=")?;
        let authorizer_identity_key = value(11, "authorizer_identity_key=")?;

        if !is_canonical_uuid(account_id)
            || !is_canonical_uuid(new_device_id)
            || !is_canonical_uuid(authorizing_device_id)
            || !is_canonical_uuid(pairing_session_id)
            || new_device_id == authorizing_device_id
            || !matches!(platform, "windows" | "linux")
            || protocol_version != PROTOCOL_VERSION
            || min_supported_version != MIN_SUPPORTED_VERSION
            || capabilities & MULTI_DEVICE_CAPABILITY_BIT == 0
            || issued_at_unix_ms == 0
            || !is_bounded_base64_public_material(target_identity_key)
            || !is_bounded_base64_public_material(authorizer_identity_key)
        {
            return Err(ProtocolError::InvalidDeviceAuthorizationTranscript);
        }

        Ok(Self {
            account_id: account_id.to_owned(),
            new_device_id: new_device_id.to_owned(),
            authorizing_device_id: authorizing_device_id.to_owned(),
            pairing_session_id: pairing_session_id.to_owned(),
            platform: platform.to_owned(),
            protocol_version,
            min_supported_version,
            capabilities,
            issued_at_unix_ms,
            target_identity_key: target_identity_key.to_owned(),
            authorizer_identity_key: authorizer_identity_key.to_owned(),
        })
    }
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
    })
}

fn is_bounded_base64_public_material(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 8192
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
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
    InvalidDeviceAuthorizationTranscript,
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
    fn canonical_device_authorization_parser_is_strict_and_fail_closed() {
        let transcript = concat!(
            "ENIGMA_DEVICE_LINK_V1\n",
            "account_id=33333333-3333-4333-8333-333333333333\n",
            "new_device_id=11111111-1111-4111-8111-111111111111\n",
            "authorizing_device_id=44444444-4444-4444-8444-444444444444\n",
            "pairing_session_id=22222222-2222-4222-8222-222222222222\n",
            "platform=windows\n",
            "protocol_version=1\n",
            "min_supported_version=1\n",
            "capabilities=127\n",
            "issued_at_unix_ms=1700000000000\n",
            "target_identity_key=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
            "authorizer_identity_key=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC\n",
        );
        let parsed = CanonicalDeviceAuthorization::parse(transcript).expect("valid transcript");
        assert_eq!(parsed.platform, "windows");
        assert_eq!(parsed.capabilities, 127);

        let extra = format!("{transcript}unexpected=value\n");
        assert_eq!(
            CanonicalDeviceAuthorization::parse(&extra),
            Err(ProtocolError::InvalidDeviceAuthorizationTranscript)
        );

        let downgraded = transcript.replace("protocol_version=1", "protocol_version=0");
        assert_eq!(
            CanonicalDeviceAuthorization::parse(&downgraded),
            Err(ProtocolError::InvalidDeviceAuthorizationTranscript)
        );
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
