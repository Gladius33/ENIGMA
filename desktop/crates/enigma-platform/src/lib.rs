#![forbid(unsafe_code)]

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProtectionBackend {
    WindowsDpapi,
    LinuxSecretService,
    PasswordFallback,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PlatformKeyError {
    BackendUnavailable,
    AccessDenied,
    CorruptProtectedValue,
}

impl fmt::Display for PlatformKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable => f.write_str("platform key backend unavailable"),
            Self::AccessDenied => f.write_str("platform key backend access denied"),
            Self::CorruptProtectedValue => f.write_str("protected key value is invalid"),
        }
    }
}

impl std::error::Error for PlatformKeyError {}

pub trait PlatformKeyProtector {
    fn backend(&self) -> KeyProtectionBackend;
    fn protect(&self, secret: &[u8]) -> Result<Vec<u8>, PlatformKeyError>;
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError>;
}

pub const WINDOWS_PRIMARY_BACKEND: KeyProtectionBackend = KeyProtectionBackend::WindowsDpapi;
pub const LINUX_PRIMARY_BACKEND: KeyProtectionBackend = KeyProtectionBackend::LinuxSecretService;

#[cfg(windows)]
const DPAPI_PREFIX: &[u8] = b"ENIGMA-DPAPI\0v1\0";
#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"ENIGMA/desktop/storage-master-key/v1";

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsDpapiProtector;

#[cfg(windows)]
impl PlatformKeyProtector for WindowsDpapiProtector {
    fn backend(&self) -> KeyProtectionBackend {
        KeyProtectionBackend::WindowsDpapi
    }

    fn protect(&self, secret: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        use windows_dpapi::{Scope, encrypt_data};

        if secret.is_empty() {
            return Err(PlatformKeyError::CorruptProtectedValue);
        }

        let encrypted = encrypt_data(secret, Scope::User, Some(DPAPI_ENTROPY))
            .map_err(|_| PlatformKeyError::BackendUnavailable)?;

        let mut protected = Vec::with_capacity(DPAPI_PREFIX.len() + encrypted.len());
        protected.extend_from_slice(DPAPI_PREFIX);
        protected.extend_from_slice(&encrypted);
        Ok(protected)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        use windows_dpapi::{Scope, decrypt_data};

        let encrypted = protected
            .strip_prefix(DPAPI_PREFIX)
            .filter(|value| !value.is_empty())
            .ok_or(PlatformKeyError::CorruptProtectedValue)?;

        decrypt_data(encrypted, Scope::User, Some(DPAPI_ENTROPY))
            .map_err(|_| PlatformKeyError::CorruptProtectedValue)
    }
}

#[cfg(target_os = "linux")]
const SECRET_SERVICE_LOCATOR_PREFIX: &[u8] = b"ENIGMA-SECRET-SERVICE\0v1\0";
#[cfg(target_os = "linux")]
const SECRET_SERVICE_APPLICATION: &str = "ENIGMA";
#[cfg(target_os = "linux")]
const SECRET_SERVICE_PURPOSE: &str = "storage-master-key";

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSecretServiceProtector {
    slot: String,
}

#[cfg(target_os = "linux")]
impl LinuxSecretServiceProtector {
    pub fn new(slot: impl Into<String>) -> Result<Self, PlatformKeyError> {
        let slot = slot.into();
        let valid = !slot.is_empty()
            && slot.len() <= 128
            && slot
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));

        if !valid {
            return Err(PlatformKeyError::CorruptProtectedValue);
        }

        Ok(Self { slot })
    }

    fn locator(&self) -> Vec<u8> {
        let mut locator = Vec::with_capacity(SECRET_SERVICE_LOCATOR_PREFIX.len() + self.slot.len());
        locator.extend_from_slice(SECRET_SERVICE_LOCATOR_PREFIX);
        locator.extend_from_slice(self.slot.as_bytes());
        locator
    }

    fn validate_locator(&self, protected: &[u8]) -> Result<(), PlatformKeyError> {
        if protected == self.locator() {
            Ok(())
        } else {
            Err(PlatformKeyError::CorruptProtectedValue)
        }
    }

    fn attributes(&self) -> std::collections::HashMap<&str, &str> {
        std::collections::HashMap::from([
            ("application", SECRET_SERVICE_APPLICATION),
            ("purpose", SECRET_SERVICE_PURPOSE),
            ("slot", self.slot.as_str()),
        ])
    }
}

#[cfg(target_os = "linux")]
impl PlatformKeyProtector for LinuxSecretServiceProtector {
    fn backend(&self) -> KeyProtectionBackend {
        KeyProtectionBackend::LinuxSecretService
    }

    fn protect(&self, secret: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        use secret_service::{EncryptionType, blocking::SecretService};

        if secret.is_empty() {
            return Err(PlatformKeyError::CorruptProtectedValue);
        }

        let service = SecretService::connect(EncryptionType::Dh).map_err(map_secret_service_error)?;
        let collection = service
            .get_default_collection()
            .map_err(map_secret_service_error)?;

        if collection.is_locked().map_err(map_secret_service_error)? {
            collection.unlock().map_err(map_secret_service_error)?;
        }

        collection
            .create_item(
                &format!("ENIGMA secure storage ({})", self.slot),
                self.attributes(),
                secret,
                true,
                "application/octet-stream",
            )
            .map_err(map_secret_service_error)?;

        Ok(self.locator())
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
        use secret_service::{EncryptionType, blocking::SecretService};

        self.validate_locator(protected)?;

        let service = SecretService::connect(EncryptionType::Dh).map_err(map_secret_service_error)?;
        let mut found = service
            .search_items(self.attributes())
            .map_err(map_secret_service_error)?;

        if found.unlocked.len() + found.locked.len() != 1 {
            return Err(PlatformKeyError::CorruptProtectedValue);
        }

        let secret = if let Some(item) = found.unlocked.pop() {
            item.get_secret().map_err(map_secret_service_error)?
        } else {
            let item = found
                .locked
                .pop()
                .ok_or(PlatformKeyError::CorruptProtectedValue)?;
            item.unlock().map_err(map_secret_service_error)?;
            item.get_secret().map_err(map_secret_service_error)?
        };

        if secret.is_empty() {
            Err(PlatformKeyError::CorruptProtectedValue)
        } else {
            Ok(secret)
        }
    }
}

#[cfg(target_os = "linux")]
fn map_secret_service_error(error: secret_service::Error) -> PlatformKeyError {
    use secret_service::Error;

    match error {
        Error::Locked | Error::Prompt => PlatformKeyError::AccessDenied,
        Error::NoResult | Error::Crypto(_) | Error::Zvariant(_) => {
            PlatformKeyError::CorruptProtectedValue
        }
        Error::Unavailable | Error::Zbus(_) | Error::ZbusFdo(_) => {
            PlatformKeyError::BackendUnavailable
        }
        _ => PlatformKeyError::BackendUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_backends_remain_platform_native() {
        assert_eq!(
            WINDOWS_PRIMARY_BACKEND,
            KeyProtectionBackend::WindowsDpapi
        );
        assert_eq!(
            LINUX_PRIMARY_BACKEND,
            KeyProtectionBackend::LinuxSecretService
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_locator_is_opaque_and_validated_before_backend_access() {
        let protector = LinuxSecretServiceProtector::new("primary").expect("valid slot");
        let locator = protector.locator();

        assert!(locator.starts_with(SECRET_SERVICE_LOCATOR_PREFIX));
        assert!(!locator.windows(12).any(|window| window == b"master-secret"));
        assert_eq!(
            protector.unprotect(b"not-an-enigma-locator"),
            Err(PlatformKeyError::CorruptProtectedValue)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_slot_names_are_bounded_and_canonical() {
        assert!(LinuxSecretServiceProtector::new("primary-1").is_ok());
        assert!(LinuxSecretServiceProtector::new("").is_err());
        assert!(LinuxSecretServiceProtector::new("contains space").is_err());
        assert!(LinuxSecretServiceProtector::new("x".repeat(129)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_user_scope_round_trip_is_not_plaintext() {
        let protector = WindowsDpapiProtector;
        let secret = b"ENIGMA_PLATFORM_KEY_CANARY";
        let protected = protector.protect(secret).expect("DPAPI protect");

        assert!(protected.starts_with(DPAPI_PREFIX));
        assert!(!protected.windows(secret.len()).any(|window| window == secret));
        assert_eq!(protector.unprotect(&protected).expect("DPAPI unprotect"), secret);
    }
}
