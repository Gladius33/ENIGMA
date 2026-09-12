#![forbid(unsafe_code)]

use std::fmt;

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct StorageMasterKey([u8; 32]);

impl StorageMasterKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StorageMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageMasterKey(REDACTED)")
    }
}

impl Drop for StorageMasterKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub trait RecordVault {
    type Error;

    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn open(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<SecretBytes, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_secret_value() {
        let secret = SecretBytes::new(b"ENIGMA_PLAINTEXT_CANARY_7CE2".to_vec());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes(REDACTED)");
        assert!(!rendered.contains("7CE2"));
    }

    #[test]
    fn master_key_debug_is_redacted() {
        let key = StorageMasterKey::new([0x42; 32]);
        assert_eq!(format!("{key:?}"), "StorageMasterKey(REDACTED)");
    }
}
