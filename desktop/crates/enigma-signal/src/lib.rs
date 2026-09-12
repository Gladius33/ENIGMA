#![forbid(unsafe_code)]

pub const ANDROID_LIBSIGNAL_VERSION: &str = "0.86.5";
pub const DESKTOP_LIBSIGNAL_SOURCE_PIN: Option<&str> = None;

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

#[must_use]
pub const fn desktop_backend_release_ready() -> bool {
    DESKTOP_LIBSIGNAL_SOURCE_PIN.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_is_blocked_until_desktop_libsignal_is_exactly_pinned() {
        assert!(!desktop_backend_release_ready());
    }
}
