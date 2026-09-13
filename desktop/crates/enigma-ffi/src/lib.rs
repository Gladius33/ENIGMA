#![deny(unsafe_op_in_unsafe_fn)]

use enigma_core::CoreRuntime;

pub const ENIGMA_CORE_ABI_VERSION: u32 = 1;
const DEFAULT_DEDUP_CAPACITY: usize = 16_384;

pub struct EnigmaCoreHandle {
    _runtime: CoreRuntime,
}

#[no_mangle]
pub extern "C" fn enigma_core_abi_version() -> u32 {
    ENIGMA_CORE_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn enigma_core_create() -> *mut EnigmaCoreHandle {
    Box::into_raw(Box::new(EnigmaCoreHandle {
        _runtime: CoreRuntime::new(DEFAULT_DEDUP_CAPACITY),
    }))
}

/// Destroys an opaque core handle allocated by [`enigma_core_create`].
///
/// # Safety
///
/// `handle` must either be null or a live pointer returned exactly once by
/// `enigma_core_create`. It must not be used again after this function returns.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable_and_handle_lifecycle_is_explicit() {
        assert_eq!(enigma_core_abi_version(), 1);
        let handle = enigma_core_create();
        assert!(!handle.is_null());
        assert!(enigma_core_is_ready(handle));
        // SAFETY: handle was returned by enigma_core_create above and has not
        // been freed or aliased for destruction elsewhere.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn null_destroy_is_allowed() {
        // SAFETY: the ABI explicitly permits a null handle.
        unsafe { enigma_core_destroy(std::ptr::null_mut()) };
    }
}
