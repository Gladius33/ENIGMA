#![forbid(unsafe_code)]

use std::fmt;

use enigma_sodium::{SecureBytes, SodiumError, XChaCha20Poly1305Vault};

pub struct SecretBytes(SecureBytes);

impl SecretBytes {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn with_read<R>(&mut self, operation: impl FnOnce(&[u8]) -> R) -> Result<R, SodiumError> {
        self.0.with_read(operation)
    }
}

impl From<SecureBytes> for SecretBytes {
    fn from(value: SecureBytes) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.len())
            .field("contents", &"REDACTED")
            .finish()
    }
}

pub struct StorageMasterKey(SecureBytes);

impl StorageMasterKey {
    pub fn generate() -> Result<Self, SodiumError> {
        Ok(Self(SecureBytes::random(32)?))
    }

    pub fn import_and_wipe(key: &mut [u8; 32]) -> Result<Self, SodiumError> {
        Ok(Self(SecureBytes::copy_and_wipe(key)?))
    }

    fn into_secure_bytes(self) -> SecureBytes {
        self.0
    }
}

impl fmt::Debug for StorageMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageMasterKey(REDACTED)")
    }
}

pub trait RecordVault {
    type Error;

    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn open(&self, ciphertext: &[u8], associated_data: &[u8]) -> Result<SecretBytes, Self::Error>;
}

pub struct SodiumRecordVault {
    inner: XChaCha20Poly1305Vault,
}

impl SodiumRecordVault {
    pub fn generate() -> Result<Self, SodiumError> {
        Ok(Self {
            inner: XChaCha20Poly1305Vault::generate()?,
        })
    }

    pub fn from_master_key(key: StorageMasterKey) -> Result<Self, SodiumError> {
        Ok(Self {
            inner: XChaCha20Poly1305Vault::from_secure_key(key.into_secure_bytes())?,
        })
    }

    pub fn import_key_and_wipe(key: &mut [u8; 32]) -> Result<Self, SodiumError> {
        Self::from_master_key(StorageMasterKey::import_and_wipe(key)?)
    }
}

impl RecordVault for SodiumRecordVault {
    type Error = SodiumError;

    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.seal(plaintext, associated_data)
    }

    fn open(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<SecretBytes, Self::Error> {
        self.inner
            .open(ciphertext, associated_data)
            .map(SecretBytes::from)
    }
}

impl fmt::Debug for SodiumRecordVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SodiumRecordVault(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imported_master_key_is_wiped_and_debug_is_redacted() {
        let mut raw = [0x42_u8; 32];
        let key = StorageMasterKey::import_and_wipe(&mut raw).expect("master key");
        assert!(raw.iter().all(|byte| *byte == 0));
        assert_eq!(format!("{key:?}"), "StorageMasterKey(REDACTED)");
    }

    #[test]
    fn record_vault_round_trip_returns_guarded_plaintext() {
        let vault = SodiumRecordVault::generate().expect("vault");
        let plaintext = b"ENIGMA_PLAINTEXT_CANARY_7CE2";
        let aad = b"record:v1";
        let sealed = vault.seal(plaintext, aad).expect("seal");

        assert!(!sealed.windows(plaintext.len()).any(|window| window == plaintext));

        let mut opened = vault.open(&sealed, aad).expect("open");
        assert!(!format!("{opened:?}").contains("7CE2"));
        opened
            .with_read(|bytes| assert_eq!(bytes, plaintext))
            .expect("guarded read");
    }

    #[test]
    fn wrong_associated_data_fails_authentication() {
        let vault = SodiumRecordVault::generate().expect("vault");
        let sealed = vault.seal(b"secret", b"record:a").expect("seal");
        assert_eq!(
            vault.open(&sealed, b"record:b").expect_err("must reject"),
            SodiumError::AuthenticationFailed
        );
    }
}
