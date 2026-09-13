#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};

use libsodium_sys as sodium;

const VAULT_MAGIC: &[u8; 4] = b"EGV1";
const KEY_BYTES: usize = sodium::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize;
const NONCE_BYTES: usize = sodium::crypto_aead_xchacha20poly1305_IETF_NPUBBYTES as usize;
const TAG_BYTES: usize = sodium::crypto_aead_xchacha20poly1305_IETF_ABYTES as usize;

static SODIUM_READY: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SodiumError {
    InitializationFailed,
    AllocationFailed,
    MemoryProtectionFailed,
    InvalidKeyLength,
    CiphertextTooShort,
    InvalidCiphertextHeader,
    MessageTooLarge,
    EncryptionFailed,
    AuthenticationFailed,
    LockPoisoned,
}

impl fmt::Display for SodiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed => f.write_str("libsodium initialization failed"),
            Self::AllocationFailed => f.write_str("libsodium secure allocation failed"),
            Self::MemoryProtectionFailed => f.write_str("libsodium memory protection failed"),
            Self::InvalidKeyLength => f.write_str("invalid XChaCha20-Poly1305 key length"),
            Self::CiphertextTooShort => f.write_str("ciphertext is too short"),
            Self::InvalidCiphertextHeader => f.write_str("ciphertext header is invalid"),
            Self::MessageTooLarge => f.write_str("message is too large"),
            Self::EncryptionFailed => f.write_str("XChaCha20-Poly1305 encryption failed"),
            Self::AuthenticationFailed => f.write_str("XChaCha20-Poly1305 authentication failed"),
            Self::LockPoisoned => f.write_str("secure-memory lock is poisoned"),
        }
    }
}

impl std::error::Error for SodiumError {}

fn ensure_sodium() -> Result<(), SodiumError> {
    let ready = *SODIUM_READY.get_or_init(|| {
        // SAFETY: sodium_init has no pointer arguments, is explicitly safe to
        // call repeatedly, and internally serializes first-time initialization.
        unsafe { sodium::sodium_init() >= 0 }
    });
    if ready {
        Ok(())
    } else {
        Err(SodiumError::InitializationFailed)
    }
}

#[derive(Debug)]
struct NoAccessGuard {
    ptr: NonNull<u8>,
}

impl Drop for NoAccessGuard {
    fn drop(&mut self) {
        // SAFETY: ptr originates from sodium_malloc, remains allocated for this
        // guard lifetime, and sodium_mprotect_noaccess accepts that allocation.
        let status = unsafe { sodium::sodium_mprotect_noaccess(self.ptr.as_ptr().cast()) };
        if status != 0 {
            std::process::abort();
        }
    }
}

pub struct SecureBytes {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: SecureBytes exclusively owns the sodium_malloc allocation. Access to
// the bytes requires &mut self, and cross-thread shared use in this crate is
// serialized by Mutex before changing page protections.
unsafe impl Send for SecureBytes {}

impl SecureBytes {
    pub fn allocate(len: usize) -> Result<Self, SodiumError> {
        ensure_sodium()?;
        // SAFETY: sodium_init completed and sodium_malloc accepts any usize,
        // including zero. Ownership of a non-null returned allocation is unique.
        let raw = unsafe { sodium::sodium_malloc(len) }.cast::<u8>();
        let ptr = NonNull::new(raw).ok_or(SodiumError::AllocationFailed)?;
        // SAFETY: ptr is a live sodium_malloc allocation and has not been freed.
        if unsafe { sodium::sodium_mprotect_noaccess(ptr.as_ptr().cast()) } != 0 {
            // SAFETY: ptr is still the unique live sodium allocation.
            unsafe { sodium::sodium_free(ptr.as_ptr().cast()) };
            return Err(SodiumError::MemoryProtectionFailed);
        }
        Ok(Self { ptr, len })
    }

    pub fn random(len: usize) -> Result<Self, SodiumError> {
        let mut output = Self::allocate(len)?;
        output.with_write(|bytes| {
            if !bytes.is_empty() {
                // SAFETY: bytes points to a live writable slice of exactly
                // bytes.len() bytes and libsodium is initialized.
                unsafe { sodium::randombytes_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
            }
        })?;
        Ok(output)
    }

    pub fn copy_and_wipe(input: &mut [u8]) -> Result<Self, SodiumError> {
        ensure_sodium()?;
        let result = (|| {
            let mut output = Self::allocate(input.len())?;
            output.with_write(|bytes| bytes.copy_from_slice(input))?;
            Ok(output)
        })();
        // SAFETY: input is a valid mutable slice for input.len() bytes. Wiping
        // happens regardless of whether allocation/protection succeeded.
        unsafe { sodium::sodium_memzero(input.as_mut_ptr().cast(), input.len()) };
        result
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn with_read<R>(&mut self, operation: impl FnOnce(&[u8]) -> R) -> Result<R, SodiumError> {
        // SAFETY: ptr is a live sodium_malloc allocation owned by self and
        // &mut self guarantees no concurrent protection transition through it.
        if unsafe { sodium::sodium_mprotect_readonly(self.ptr.as_ptr().cast()) } != 0 {
            return Err(SodiumError::MemoryProtectionFailed);
        }
        let _guard = NoAccessGuard { ptr: self.ptr };
        // SAFETY: page protection was switched to readonly, ptr is valid for
        // self.len bytes, and the returned slice cannot outlive this call.
        let bytes = unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
        Ok(operation(bytes))
    }

    pub fn with_write<R>(
        &mut self,
        operation: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, SodiumError> {
        // SAFETY: ptr is a live sodium_malloc allocation owned by self and
        // &mut self guarantees exclusive access during the protection change.
        if unsafe { sodium::sodium_mprotect_readwrite(self.ptr.as_ptr().cast()) } != 0 {
            return Err(SodiumError::MemoryProtectionFailed);
        }
        let _guard = NoAccessGuard { ptr: self.ptr };
        // SAFETY: page protection was switched to readwrite, ptr is valid for
        // self.len bytes, and &mut self guarantees exclusive slice access.
        let bytes = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
        Ok(operation(bytes))
    }
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &self.len)
            .field("contents", &"REDACTED")
            .finish()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // SAFETY: ptr is the unique allocation returned by sodium_malloc.
        // sodium_free accepts allocations protected with sodium_mprotect_* and
        // zeroes the region before deallocation.
        unsafe { sodium::sodium_free(self.ptr.as_ptr().cast()) };
    }
}

pub struct XChaCha20Poly1305Vault {
    key: Mutex<SecureBytes>,
}

impl XChaCha20Poly1305Vault {
    pub fn generate() -> Result<Self, SodiumError> {
        Ok(Self {
            key: Mutex::new(SecureBytes::random(KEY_BYTES)?),
        })
    }

    pub fn from_secure_key(key: SecureBytes) -> Result<Self, SodiumError> {
        if key.len() != KEY_BYTES {
            return Err(SodiumError::InvalidKeyLength);
        }
        Ok(Self {
            key: Mutex::new(key),
        })
    }

    pub fn import_and_wipe(key: &mut [u8]) -> Result<Self, SodiumError> {
        if key.len() != KEY_BYTES {
            // SAFETY: key is a valid mutable slice for key.len() bytes.
            unsafe { sodium::sodium_memzero(key.as_mut_ptr().cast(), key.len()) };
            return Err(SodiumError::InvalidKeyLength);
        }
        Ok(Self {
            key: Mutex::new(SecureBytes::copy_and_wipe(key)?),
        })
    }

    pub fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, SodiumError> {
        ensure_sodium()?;
        let ciphertext_len = plaintext
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(SodiumError::MessageTooLarge)?;
        let total_len = VAULT_MAGIC
            .len()
            .checked_add(NONCE_BYTES)
            .and_then(|prefix| prefix.checked_add(ciphertext_len))
            .ok_or(SodiumError::MessageTooLarge)?;

        let mut nonce = [0_u8; NONCE_BYTES];
        // SAFETY: nonce is a valid writable array and libsodium is initialized.
        unsafe { sodium::randombytes_buf(nonce.as_mut_ptr().cast(), nonce.len()) };

        let mut output = vec![0_u8; total_len];
        output[..VAULT_MAGIC.len()].copy_from_slice(VAULT_MAGIC);
        let nonce_start = VAULT_MAGIC.len();
        let ciphertext_start = nonce_start + NONCE_BYTES;
        output[nonce_start..ciphertext_start].copy_from_slice(&nonce);

        let mut key = self.lock_key()?;
        let mut produced = 0_u64;
        let status = key.with_read(|key_bytes| {
            // SAFETY: output has ciphertext_len writable bytes at the supplied
            // pointer; plaintext/ad/nonce/key pointers are valid for their
            // declared lengths; key_bytes is exactly KEY_BYTES by construction.
            unsafe {
                sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
                    output[ciphertext_start..].as_mut_ptr(),
                    &mut produced,
                    plaintext.as_ptr(),
                    plaintext.len() as u64,
                    associated_data.as_ptr(),
                    associated_data.len() as u64,
                    std::ptr::null(),
                    nonce.as_ptr(),
                    key_bytes.as_ptr(),
                )
            }
        })?;

        if status != 0 || produced as usize != ciphertext_len {
            output.fill(0);
            return Err(SodiumError::EncryptionFailed);
        }
        Ok(output)
    }

    pub fn open(
        &self,
        envelope: &[u8],
        associated_data: &[u8],
    ) -> Result<SecureBytes, SodiumError> {
        ensure_sodium()?;
        let minimum = VAULT_MAGIC.len() + NONCE_BYTES + TAG_BYTES;
        if envelope.len() < minimum {
            return Err(SodiumError::CiphertextTooShort);
        }
        if &envelope[..VAULT_MAGIC.len()] != VAULT_MAGIC {
            return Err(SodiumError::InvalidCiphertextHeader);
        }

        let nonce_start = VAULT_MAGIC.len();
        let ciphertext_start = nonce_start + NONCE_BYTES;
        let nonce = &envelope[nonce_start..ciphertext_start];
        let ciphertext = &envelope[ciphertext_start..];
        let plaintext_len = ciphertext
            .len()
            .checked_sub(TAG_BYTES)
            .ok_or(SodiumError::CiphertextTooShort)?;
        let mut plaintext = SecureBytes::allocate(plaintext_len)?;
        let mut key = self.lock_key()?;
        let mut produced = 0_u64;

        let status = plaintext.with_write(|plaintext_bytes| {
            key.with_read(|key_bytes| {
                // SAFETY: plaintext_bytes is a writable sodium allocation of
                // plaintext_len bytes; all input pointers are valid for the
                // provided lengths; nonce/key sizes are fixed by this type.
                unsafe {
                    sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
                        plaintext_bytes.as_mut_ptr(),
                        &mut produced,
                        std::ptr::null_mut(),
                        ciphertext.as_ptr(),
                        ciphertext.len() as u64,
                        associated_data.as_ptr(),
                        associated_data.len() as u64,
                        nonce.as_ptr(),
                        key_bytes.as_ptr(),
                    )
                }
            })
        })??;

        if status != 0 || produced as usize != plaintext_len {
            return Err(SodiumError::AuthenticationFailed);
        }
        Ok(plaintext)
    }

    fn lock_key(&self) -> Result<MutexGuard<'_, SecureBytes>, SodiumError> {
        self.key.lock().map_err(|_| SodiumError::LockPoisoned)
    }
}

impl fmt::Debug for XChaCha20Poly1305Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20Poly1305Vault(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bytes_debug_is_redacted_and_access_is_scoped() {
        let mut source = *b"ENIGMA_PLAINTEXT_CANARY_7CE2!";
        let mut secret = SecureBytes::copy_and_wipe(&mut source).expect("secure allocation");
        assert!(source.iter().all(|byte| *byte == 0));
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("7CE2"));
        let observed = secret
            .with_read(|bytes| bytes.to_vec())
            .expect("read protected memory");
        assert_eq!(observed, b"ENIGMA_PLAINTEXT_CANARY_7CE2!");
    }

    #[test]
    fn vault_round_trip_authenticates_ciphertext_and_associated_data() {
        let vault = XChaCha20Poly1305Vault::generate().expect("vault");
        let plaintext = b"never store this plaintext";
        let aad = b"conversation:42";
        let sealed = vault.seal(plaintext, aad).expect("seal");
        assert!(!sealed
            .windows(plaintext.len())
            .any(|window| window == plaintext));

        let mut opened = vault.open(&sealed, aad).expect("open");
        opened
            .with_read(|bytes| assert_eq!(bytes, plaintext))
            .expect("read plaintext");

        let mut tampered = sealed;
        let last = tampered.last_mut().expect("ciphertext byte");
        *last ^= 1;
        assert_eq!(
            vault.open(&tampered, aad).expect_err("tamper must fail"),
            SodiumError::AuthenticationFailed
        );
        assert_eq!(
            vault
                .open(&vault.seal(plaintext, aad).expect("seal"), b"wrong aad")
                .expect_err("wrong aad must fail"),
            SodiumError::AuthenticationFailed
        );
    }
}
