#![forbid(unsafe_code)]

use enigma_protocol::CanonicalDeviceAuthorization;

pub const ANDROID_LIBSIGNAL_VERSION: &str = "0.86.5";
pub const DESKTOP_LIBSIGNAL_TAG: &str = "v0.86.5";
pub const DESKTOP_LIBSIGNAL_SOURCE_PIN: &str = "b39e93f1a5e6531044dfcdf5876585cbcf08f884";
pub const DESKTOP_LIBSIGNAL_INTEROP_VERIFIED: bool = false;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalPublicBundle {
    pub identity_public: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub kyber_prekey: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SignalAdapterError {
    BackendNotPinned,
    InvalidBundle,
    SessionUnavailable,
    CryptoFailure,
    InvalidDeviceAuthorizationProof,
}

pub trait SignalAdapter {
    fn public_bundle(&self) -> Result<SignalPublicBundle, SignalAdapterError>;
    fn encrypt_for_device(
        &mut self,
        remote_device_id: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SignalAdapterError>;
    fn decrypt_from_device(
        &mut self,
        remote_device_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SignalAdapterError>;
    fn sign_identity_proof(&self, transcript: &[u8]) -> Result<Vec<u8>, SignalAdapterError>;
    fn verify_identity_proof(
        &self,
        remote_identity_public: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<bool, SignalAdapterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAuthorizationExpectation<'a> {
    pub account_id: &'a str,
    pub new_device_id: &'a str,
    pub authorizing_device_id: &'a str,
    pub pairing_session_id: &'a str,
    pub platform: &'a str,
    pub target_identity_key: &'a str,
    pub authorizer_identity_key: &'a str,
}

pub fn verify_device_authorization_proof<A: SignalAdapter>(
    adapter: &A,
    known_authorizer_identity_public: &[u8],
    canonical_payload: &str,
    authorizer_signature: &[u8],
    expected: DeviceAuthorizationExpectation<'_>,
) -> Result<(), SignalAdapterError> {
    if known_authorizer_identity_public.is_empty()
        || authorizer_signature.is_empty()
        || authorizer_signature.len() > 4096
    {
        return Err(SignalAdapterError::InvalidDeviceAuthorizationProof);
    }

    let parsed = CanonicalDeviceAuthorization::parse(canonical_payload)
        .map_err(|_| SignalAdapterError::InvalidDeviceAuthorizationProof)?;
    if parsed.account_id != expected.account_id
        || parsed.new_device_id != expected.new_device_id
        || parsed.authorizing_device_id != expected.authorizing_device_id
        || parsed.pairing_session_id != expected.pairing_session_id
        || parsed.platform != expected.platform
        || parsed.target_identity_key != expected.target_identity_key
        || parsed.authorizer_identity_key != expected.authorizer_identity_key
    {
        return Err(SignalAdapterError::InvalidDeviceAuthorizationProof);
    }

    match adapter.verify_identity_proof(
        known_authorizer_identity_public,
        canonical_payload.as_bytes(),
        authorizer_signature,
    )? {
        true => Ok(()),
        false => Err(SignalAdapterError::InvalidDeviceAuthorizationProof),
    }
}

#[must_use]
pub fn desktop_backend_release_ready() -> bool {
    is_full_lower_hex_sha(DESKTOP_LIBSIGNAL_SOURCE_PIN) && DESKTOP_LIBSIGNAL_INTEROP_VERIFIED
}

fn is_full_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ProofVerifier {
        accepts_signature: bool,
    }

    impl SignalAdapter for ProofVerifier {
        fn public_bundle(&self) -> Result<SignalPublicBundle, SignalAdapterError> {
            Err(SignalAdapterError::SessionUnavailable)
        }

        fn encrypt_for_device(
            &mut self,
            _remote_device_id: &[u8],
            _plaintext: &[u8],
        ) -> Result<Vec<u8>, SignalAdapterError> {
            Err(SignalAdapterError::SessionUnavailable)
        }

        fn decrypt_from_device(
            &mut self,
            _remote_device_id: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, SignalAdapterError> {
            Err(SignalAdapterError::SessionUnavailable)
        }

        fn sign_identity_proof(&self, _transcript: &[u8]) -> Result<Vec<u8>, SignalAdapterError> {
            Err(SignalAdapterError::SessionUnavailable)
        }

        fn verify_identity_proof(
            &self,
            remote_identity_public: &[u8],
            transcript: &[u8],
            signature: &[u8],
        ) -> Result<bool, SignalAdapterError> {
            Ok(self.accepts_signature
                && remote_identity_public == [9, 9, 9]
                && transcript.starts_with(b"ENIGMA_DEVICE_LINK_V1\n")
                && signature == [7, 7])
        }
    }

    fn certified_transcript() -> &'static str {
        concat!(
            "ENIGMA_DEVICE_LINK_V1\n",
            "account_id=33333333-3333-4333-8333-333333333333\n",
            "new_device_id=11111111-1111-4111-8111-111111111111\n",
            "authorizing_device_id=44444444-4444-4444-8444-444444444444\n",
            "pairing_session_id=22222222-2222-4222-8222-222222222222\n",
            "platform=linux\n",
            "protocol_version=1\n",
            "min_supported_version=1\n",
            "capabilities=127\n",
            "issued_at_unix_ms=1700000000000\n",
            "target_identity_key=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB\n",
            "authorizer_identity_key=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC\n",
        )
    }

    fn expectation() -> DeviceAuthorizationExpectation<'static> {
        DeviceAuthorizationExpectation {
            account_id: "33333333-3333-4333-8333-333333333333",
            new_device_id: "11111111-1111-4111-8111-111111111111",
            authorizing_device_id: "44444444-4444-4444-8444-444444444444",
            pairing_session_id: "22222222-2222-4222-8222-222222222222",
            platform: "linux",
            target_identity_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            authorizer_identity_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
        }
    }

    #[test]
    fn device_authorization_requires_matching_metadata_and_signal_signature() {
        let verifier = ProofVerifier {
            accepts_signature: true,
        };
        assert_eq!(
            verify_device_authorization_proof(
                &verifier,
                &[9, 9, 9],
                certified_transcript(),
                &[7, 7],
                expectation(),
            ),
            Ok(())
        );

        let mut wrong_device = expectation();
        wrong_device.new_device_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(
            verify_device_authorization_proof(
                &verifier,
                &[9, 9, 9],
                certified_transcript(),
                &[7, 7],
                wrong_device,
            ),
            Err(SignalAdapterError::InvalidDeviceAuthorizationProof)
        );

        let rejecting = ProofVerifier {
            accepts_signature: false,
        };
        assert_eq!(
            verify_device_authorization_proof(
                &rejecting,
                &[9, 9, 9],
                certified_transcript(),
                &[7, 7],
                expectation(),
            ),
            Err(SignalAdapterError::InvalidDeviceAuthorizationProof)
        );
    }

    #[test]
    fn desktop_libsignal_source_is_pinned_to_full_immutable_sha() {
        assert_eq!(DESKTOP_LIBSIGNAL_TAG, "v0.86.5");
        assert!(is_full_lower_hex_sha(DESKTOP_LIBSIGNAL_SOURCE_PIN));
        assert_eq!(
            DESKTOP_LIBSIGNAL_SOURCE_PIN,
            "b39e93f1a5e6531044dfcdf5876585cbcf08f884"
        );
    }

    #[test]
    fn release_remains_blocked_until_cross_platform_interop_is_verified() {
        assert!(!DESKTOP_LIBSIGNAL_INTEROP_VERIFIED);
        assert!(!desktop_backend_release_ready());
    }
}
