#![deny(unsafe_op_in_unsafe_fn)]

use enigma_core::CoreRuntime;
use enigma_signal::session::LibsignalSessionBackend;

pub const ENIGMA_CORE_ABI_VERSION: u32 = 1;
const DEFAULT_DEDUP_CAPACITY: usize = 16_384;
const MAX_SERIALIZED_SIGNAL_IDENTITY_BYTES: usize = 4_096;

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

/// Returns whether a real libsignal session backend has been loaded into this core.
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

/// Loads a canonical serialized libsignal identity into the native session backend.
///
/// The private identity bytes must have been restored from ENIGMA's protected
/// local storage. ENIGMA does not parse or reinterpret this representation:
/// the pinned libsignal backend validates it directly.
///
/// # Safety
///
/// - handle must be a live pointer returned by enigma_core_create.
/// - serialized_identity must point to serialized_identity_len readable bytes.
/// - both pointers must remain valid and unaliased for mutation for this call.
/// - the same handle must not be accessed concurrently.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_signal_initialize(
    handle: *mut EnigmaCoreHandle,
    serialized_identity: *const u8,
    serialized_identity_len: usize,
    registration_id: u32,
) -> bool {
    if handle.is_null()
        || serialized_identity.is_null()
        || serialized_identity_len == 0
        || serialized_identity_len > MAX_SERIALIZED_SIGNAL_IDENTITY_BYTES
    {
        return false;
    }

    // SAFETY: caller guarantees a readable region of exactly
    // serialized_identity_len bytes for this call; bounds were capped above.
    let serialized =
        unsafe { std::slice::from_raw_parts(serialized_identity, serialized_identity_len) };

    let backend =
        match LibsignalSessionBackend::from_serialized_identity(serialized, registration_id) {
            Ok(backend) => backend,
            Err(_) => return false,
        };

    // SAFETY: caller guarantees exclusive live access to handle for this call.
    unsafe {
        (*handle).signal_backend = Some(backend);
    }
    true
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::{IdentityKeyPair, PrivateKey};

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
    fn signal_backend_initializes_only_from_valid_libsignal_identity() {
        let handle = enigma_core_create();
        assert!(!handle.is_null());

        let malformed = [1_u8, 2, 3];
        // SAFETY: handle is live and malformed is readable for this call.
        assert!(!unsafe {
            enigma_core_signal_initialize(handle, malformed.as_ptr(), malformed.len(), 7)
        });
        // SAFETY: handle is still live and exclusively owned by this test.
        assert!(!unsafe { enigma_core_signal_is_ready(handle) });

        let private = PrivateKey::deserialize(&[0x42; 32]).expect("fixed private key");
        let identity = IdentityKeyPair::try_from(private).expect("identity key pair");
        let serialized = identity.serialize();

        // SAFETY: serialized points to a live immutable buffer for the duration
        // of this call and handle is live/exclusively owned.
        assert!(unsafe {
            enigma_core_signal_initialize(handle, serialized.as_ptr(), serialized.len(), 7)
        });
        // SAFETY: handle remains live and exclusively owned.
        assert!(unsafe { enigma_core_signal_is_ready(handle) });

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn signal_initialization_rejects_null_and_oversized_inputs() {
        let handle = enigma_core_create();

        // SAFETY: null identity pointer is explicitly permitted and rejected.
        assert!(!unsafe {
            enigma_core_signal_initialize(handle, std::ptr::null(), 1, 7)
        });
        // SAFETY: this pointer is never dereferenced because the length fails
        // the bounded-input check before slice construction.
        assert!(!unsafe {
            enigma_core_signal_initialize(
                handle,
                std::ptr::NonNull::<u8>::dangling().as_ptr(),
                MAX_SERIALIZED_SIGNAL_IDENTITY_BYTES + 1,
                7,
            )
        });

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn null_destroy_is_allowed() {
        // SAFETY: the ABI explicitly permits a null handle.
        unsafe { enigma_core_destroy(std::ptr::null_mut()) };
    }
}
