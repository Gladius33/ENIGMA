#![deny(unsafe_op_in_unsafe_fn)]

use enigma_platform::{PlatformKeyError, PlatformKeyProtector};
use enigma_runtime_core::CoreRuntime;
use enigma_signal::session::LibsignalSessionBackend;

pub const ENIGMA_CORE_ABI_VERSION: u32 = 1;
const DEFAULT_DEDUP_CAPACITY: usize = 16_384;
const MAX_PROTECTED_SIGNAL_IDENTITY_BYTES: usize = 64 * 1024;

pub struct EnigmaCoreHandle {
    _runtime: CoreRuntime,
    signal_backend: Option<LibsignalSessionBackend>,
}

#[no_mangle]
pub extern "C" fn enigma_core_abi_version() -> u32 {
    ENIGMA_CORE_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn enigma_core_create() -> *mut EnigmaCoreHandle {
    Box::into_raw(Box::new(EnigmaCoreHandle {
        _runtime: CoreRuntime::new(DEFAULT_DEDUP_CAPACITY),
        signal_backend: None,
    }))
}

/// Destroys an opaque core handle allocated by enigma_core_create.
///
/// # Safety
///
/// handle must either be null or a live pointer returned exactly once by
/// enigma_core_create. It must not be used again after this function returns.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_destroy(handle: *mut EnigmaCoreHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller contract requires a unique live pointer returned by
    // enigma_core_create. Null was handled above, Box restores the original
    // allocation ownership, alignment and provenance, and dropping it occurs
    // exactly once here.
    unsafe {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub extern "C" fn enigma_core_is_ready(handle: *mut EnigmaCoreHandle) -> bool {
    !handle.is_null()
}

/// Returns whether a real libsignal session backend has been restored from protected storage.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create.
/// Callers must not destroy or mutably access the same handle concurrently.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_signal_is_ready(handle: *const EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: caller contract requires a live handle for the duration of this
    // immutable read and forbids concurrent destruction/mutation.
    unsafe { (*handle).signal_backend.is_some() }
}

/// Restores a canonical serialized libsignal identity from platform-protected storage.
///
/// Windows accepts an ENIGMA DPAPI user-scope blob. Linux accepts only an ENIGMA
/// Secret Service locator; the identity itself remains inside the Secret Service
/// provider. The recovered plaintext is handled only inside Rust, parsed by the
/// pinned libsignal backend and then wiped on a best-effort basis.
///
/// # Safety
///
/// - handle must be a live pointer returned by enigma_core_create.
/// - protected_identity must point to protected_identity_len readable bytes.
/// - both pointers must remain valid and unaliased for mutation for this call.
/// - the same handle must not be accessed concurrently.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_signal_initialize_protected(
    handle: *mut EnigmaCoreHandle,
    protected_identity: *const u8,
    protected_identity_len: usize,
    registration_id: u32,
) -> bool {
    if handle.is_null()
        || protected_identity.is_null()
        || protected_identity_len == 0
        || protected_identity_len > MAX_PROTECTED_SIGNAL_IDENTITY_BYTES
    {
        return false;
    }

    // SAFETY: caller guarantees a readable region of exactly
    // protected_identity_len bytes for this call; bounds were capped above.
    let protected =
        unsafe { std::slice::from_raw_parts(protected_identity, protected_identity_len) };

    let mut serialized_identity = match unprotect_signal_identity(protected) {
        Ok(identity) if !identity.is_empty() => identity,
        Ok(_) | Err(_) => return false,
    };

    let backend =
        LibsignalSessionBackend::from_serialized_identity(&serialized_identity, registration_id);
    serialized_identity.fill(0);

    let backend = match backend {
        Ok(backend) => backend,
        Err(_) => return false,
    };

    // SAFETY: caller guarantees exclusive live access to handle for this call.
    unsafe {
        (*handle).signal_backend = Some(backend);
    }
    true
}

#[cfg(windows)]
fn unprotect_signal_identity(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.unprotect(protected)
}

#[cfg(target_os = "linux")]
fn unprotect_signal_identity(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    let protector = LinuxSecretServiceProtector::from_locator(protected)?;
    protector.unprotect(protected)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unprotect_signal_identity(_protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable_and_handle_lifecycle_is_explicit() {
        assert_eq!(enigma_core_abi_version(), 1);
        let handle = enigma_core_create();
        assert!(!handle.is_null());
        assert!(enigma_core_is_ready(handle));
        // SAFETY: handle is live and exclusively owned by this test.
        assert!(!unsafe { enigma_core_signal_is_ready(handle) });
        // SAFETY: handle was returned by enigma_core_create above and has not
        // been freed or aliased for destruction elsewhere.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn protected_signal_initialization_fails_closed_on_invalid_value() {
        let handle = enigma_core_create();
        assert!(!handle.is_null());

        let invalid = b"not-an-enigma-protected-identity";
        // SAFETY: handle is live and invalid points to a readable immutable
        // region for the duration of this call.
        assert!(!unsafe {
            enigma_core_signal_initialize_protected(
                handle,
                invalid.as_ptr(),
                invalid.len(),
                7,
            )
        });
        // SAFETY: handle is still live and exclusively owned by this test.
        assert!(!unsafe { enigma_core_signal_is_ready(handle) });

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn protected_signal_initialization_rejects_null_and_oversized_inputs() {
        let handle = enigma_core_create();

        // SAFETY: null identity pointer is explicitly permitted and rejected.
        assert!(!unsafe {
            enigma_core_signal_initialize_protected(handle, std::ptr::null(), 1, 7)
        });
        // SAFETY: this pointer is never dereferenced because the length fails
        // the bounded-input check before slice construction.
        assert!(!unsafe {
            enigma_core_signal_initialize_protected(
                handle,
                std::ptr::NonNull::<u8>::dangling().as_ptr(),
                MAX_PROTECTED_SIGNAL_IDENTITY_BYTES + 1,
                7,
            )
        });

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[cfg(windows)]
    #[test]
    fn protected_signal_identity_restores_through_dpapi_without_ui_plaintext() {
        use enigma_platform::WindowsDpapiProtector;
        use libsignal_protocol::{IdentityKeyPair, PrivateKey};

        let private = PrivateKey::deserialize(&[0x42; 32]).expect("fixed private key");
        let identity = IdentityKeyPair::try_from(private).expect("identity key pair");
        let mut serialized = identity.serialize().to_vec();
        let protector = WindowsDpapiProtector;
        let protected = protector.protect(&serialized).expect("DPAPI protect");
        serialized.fill(0);

        let handle = enigma_core_create();
        // SAFETY: handle is live and protected points to a readable immutable
        // region for the duration of this call.
        assert!(unsafe {
            enigma_core_signal_initialize_protected(
                handle,
                protected.as_ptr(),
                protected.len(),
                7,
            )
        });
        // SAFETY: handle remains live and exclusively owned.
        assert!(unsafe { enigma_core_signal_is_ready(handle) });

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn null_destroy_is_allowed() {
        // SAFETY: the ABI explicitly permits a null handle.
        unsafe { enigma_core_destroy(std::ptr::null_mut()) };
    }
}
