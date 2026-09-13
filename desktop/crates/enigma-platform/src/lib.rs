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
