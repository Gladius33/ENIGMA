#![deny(unsafe_op_in_unsafe_fn)]

mod inbox;
mod outbox;

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use enigma_platform::{PlatformKeyError, PlatformKeyProtector};
use enigma_runtime_core::{CoreRuntime, PairingBootstrap, DEFAULT_PAIRING_TTL_MS};
use enigma_signal::session::LibsignalSessionBackend;
use enigma_sodium::{random_public_bytes, SecureBytes};
use enigma_storage::SodiumRecordVault;
use enigma_transport::{
    PairingCandidatePublish, PairingClaimState, PairingRendezvousClient, PublicKeyUpload,
    PublicOneTimePreKey, PublicSignedPreKey,
};
use futures_executor::block_on;
use inbox::{DurableInboxEntry, EncryptedDesktopInbox};
use outbox::{DurableOutboundDelivery, EncryptedDesktopOutbox};
use rand::Rng as _;

pub const ENIGMA_CORE_ABI_VERSION: u32 = 1;
const DEFAULT_DEDUP_CAPACITY: usize = 16_384;
const MAX_PROTECTED_SIGNAL_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_PROTECTED_SIGNAL_STORE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROTECTED_DEVICE_SESSION_BYTES: usize = 64 * 1024;
const SIGNAL_IDENTITY_RECORD_MAGIC: &[u8] = b"ENIGMA-SIGNAL-IDENTITY\0v1\0";
const SIGNAL_STORE_RECORD_MAGIC: &[u8] = b"ENIGMA-SIGNAL-STORE\0v2\0";
const INBOX_MASTER_KEY_RECORD_MAGIC: &[u8] = b"ENIGMA-INBOX-MASTER-KEY\0v1\0";
const DEVICE_SESSION_RECORD_MAGIC: &[u8] = b"ENIGMA-DEVICE-SESSION\0v1\0";
const V1_PROTOCOL_DEVICE_ID: u32 = 1;
const DESKTOP_PREKEY_UPLOAD_COUNT: u32 = 50;
const INBOX_MASTER_KEY_BYTES: usize = 32;
const PAIRING_CLAIM_ERROR: u32 = 0;
const PAIRING_CLAIM_PENDING: u32 = 1;
const PAIRING_CLAIMED: u32 = 2;
const PAIRING_CLAIM_ALREADY_USED: u32 = 3;
const PAIRING_CLAIM_EXPIRED: u32 = 4;
const PAIRING_CLAIM_MISSING: u32 = 5;
#[cfg(target_os = "linux")]
const LINUX_SIGNAL_IDENTITY_SLOT: &str = "signal-identity-primary";
#[cfg(target_os = "linux")]
const LINUX_SIGNAL_STORE_SLOT: &str = "signal-store-primary-v2";
#[cfg(target_os = "linux")]
const LINUX_INBOX_MASTER_KEY_SLOT: &str = "desktop-inbox-master-key-v1";
#[cfg(target_os = "linux")]
const LINUX_DEVICE_SESSION_SLOT: &str = "device-session-primary";

pub struct EnigmaCoreHandle {
    _runtime: CoreRuntime,
    signal_backend: Option<LibsignalSessionBackend>,
    pairing_bootstrap: Option<PairingBootstrap>,
    device_id: Option<String>,
    device_access_token: Option<SecureBytes>,
    desktop_inbox: Option<EncryptedDesktopInbox>,
    desktop_outbox: Option<EncryptedDesktopOutbox>,
}

#[no_mangle]
pub extern "C" fn enigma_core_abi_version() -> u32 {
    ENIGMA_CORE_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn enigma_core_create() -> *mut EnigmaCoreHandle {
    let restored_session = load_default_device_session().ok();
    let (device_id, device_access_token) = restored_session
        .map(|(device_id, token)| (Some(device_id), Some(token)))
        .unwrap_or((None, None));

    Box::into_raw(Box::new(EnigmaCoreHandle {
        _runtime: CoreRuntime::new(DEFAULT_DEDUP_CAPACITY),
        signal_backend: None,
        pairing_bootstrap: None,
        device_id,
        device_access_token,
        desktop_inbox: None,
        desktop_outbox: None,
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

/// Loads the default protected desktop Signal identity, or creates and persists one on first run.
///
/// The libsignal private identity is generated inside Rust and immediately protected with the
/// native OS backend (DPAPI user scope on Windows, Secret Service on Linux). Only the protected
/// record is persisted; plaintext private-key material never crosses the FFI boundary.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create. The same handle must not
/// be destroyed or mutably accessed concurrently for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_signal_load_or_create_default(
    handle: *mut EnigmaCoreHandle,
) -> bool {
    if handle.is_null() {
        return false;
    }

    // SAFETY: caller guarantees a live, exclusively accessed handle for this call.
    if unsafe { (*handle).signal_backend.is_some() } {
        return true;
    }

    let backend = match load_or_create_default_signal_backend() {
        Ok(backend) => backend,
        Err(()) => return false,
    };

    // SAFETY: caller guarantees exclusive live access to handle for this call.
    unsafe {
        (*handle).signal_backend = Some(backend);
    }
    true
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

fn current_unix_ms() -> Option<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    u64::try_from(millis).ok()
}

/// Starts a fresh short-lived desktop pairing bootstrap.
///
/// The ephemeral pairing secret remains inside Rust/libsodium. Only the public QR payload can be
/// retrieved through the read-only copy functions below.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create. The same handle must not
/// be destroyed or accessed concurrently for mutation during this call.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_start(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: caller guarantees a live, exclusively accessed handle for this call.
    let Some(signal_backend) = (unsafe { (*handle).signal_backend.as_ref() }) else {
        return false;
    };
    let Some(now_unix_ms) = current_unix_ms() else {
        return false;
    };
    let pairing = match PairingBootstrap::generate(
        now_unix_ms,
        DEFAULT_PAIRING_TTL_MS,
        signal_backend.identity_public_key(),
    ) {
        Ok(pairing) => pairing,
        Err(_) => return false,
    };
    // SAFETY: caller guarantees exclusive live access to handle for this call.
    unsafe {
        (*handle).pairing_bootstrap = Some(pairing);
    }
    true
}

fn pairing_server_config() -> Option<(String, bool)> {
    let base_url = std::env::var("ENIGMA_SERVER_BASE_URL").ok()?;
    let allow_insecure_http = std::env::var("ENIGMA_ALLOW_INSECURE_HTTP")
        .ok()
        .is_some_and(|value| value == "1");
    Some((base_url, allow_insecure_http))
}

fn pairing_client() -> Option<PairingRendezvousClient> {
    let (base_url, allow_insecure_http) = pairing_server_config()?;
    PairingRendezvousClient::new(&base_url, allow_insecure_http).ok()
}

/// Publishes the public pairing candidate to the configured rendezvous server.
///
/// No claim secret or private key crosses this ABI boundary.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_publish(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    let Some(client) = pairing_client() else {
        return false;
    };
    // SAFETY: caller guarantees exclusive live access to handle for this call.
    let Some(pairing) = (unsafe { (*handle).pairing_bootstrap.as_ref() }) else {
        return false;
    };

    let payload = pairing.payload();
    let candidate = pairing.candidate();
    let pairing_session_id = payload.session_id.to_canonical_uuid();
    let device_id = candidate.device_id.to_canonical_uuid();
    let pairing_public_key = STANDARD_NO_PAD.encode(&payload.pairing_public_key);
    let publish = PairingCandidatePublish {
        pairing_session_id: &pairing_session_id,
        device_id: &device_id,
        display_name: &candidate.display_name,
        platform: &candidate.platform,
        protocol_version: payload.header.protocol_version,
        min_supported_version: payload.header.min_supported_version,
        capabilities: payload.header.capabilities.bits(),
        expires_at_unix_ms: payload.expires_at_unix_ms,
        pairing_public_key: &pairing_public_key,
        target_identity_key: &candidate.target_identity_key,
        claim_secret_hash: &candidate.claim_secret_hash,
        candidate_commitment: &candidate.candidate_commitment,
    };
    client.publish_candidate(&publish).is_ok()
}

/// Attempts the single-use desktop claim against the configured rendezvous server.
///
/// The claim secret is materialized only inside Rust, wiped immediately after the HTTP request,
/// and the returned device token is moved into libsodium-protected memory.
///
/// Return values: 0 error, 1 pending authorization, 2 claimed, 3 already used, 4 expired, 5 missing.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_claim(handle: *mut EnigmaCoreHandle) -> u32 {
    if handle.is_null() {
        return PAIRING_CLAIM_ERROR;
    }
    let Some(client) = pairing_client() else {
        return PAIRING_CLAIM_ERROR;
    };

    // SAFETY: caller guarantees exclusive live access to handle for this call.
    let Some(pairing) = (unsafe { (*handle).pairing_bootstrap.as_mut() }) else {
        return PAIRING_CLAIM_ERROR;
    };
    let pairing_session_id = pairing.payload().session_id.to_canonical_uuid();
    let device_id = pairing.candidate().device_id.to_canonical_uuid();
    let claim_secret = match pairing.claim_secret_base64() {
        Ok(secret) => secret,
        Err(_) => return PAIRING_CLAIM_ERROR,
    };

    let result = client.claim(&pairing_session_id, &claim_secret);
    let mut secret_bytes = claim_secret.into_bytes();
    secret_bytes.fill(0);

    match result {
        Ok((PairingClaimState::PendingAuthorization, None)) => PAIRING_CLAIM_PENDING,
        Ok((PairingClaimState::Claimed, Some(token))) => {
            let mut token_bytes = token.into_bytes();
            let persisted = persist_default_device_session(&device_id, &token_bytes).is_ok();
            let secure_token = match SecureBytes::copy_and_wipe(&mut token_bytes) {
                Ok(token) => token,
                Err(_) => return PAIRING_CLAIM_ERROR,
            };
            // SAFETY: caller guarantees exclusive live access to handle for this call.
            unsafe {
                (*handle).device_id = Some(device_id);
                (*handle).device_access_token = Some(secure_token);
                (*handle).pairing_bootstrap = None;
            }
            if persisted {
                PAIRING_CLAIMED
            } else {
                PAIRING_CLAIM_ERROR
            }
        }
        Ok((PairingClaimState::AlreadyClaimed, None)) => PAIRING_CLAIM_ALREADY_USED,
        Ok((PairingClaimState::Expired, None)) => {
            // SAFETY: caller guarantees exclusive live access to handle for this call.
            unsafe {
                (*handle).pairing_bootstrap = None;
            }
            PAIRING_CLAIM_EXPIRED
        }
        Ok((PairingClaimState::Missing, None)) => PAIRING_CLAIM_MISSING,
        Ok(_) | Err(_) => PAIRING_CLAIM_ERROR,
    }
}

/// Returns whether a device-bound session token has been claimed and retained in secure memory.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_device_session_ready(handle: *const EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: caller guarantees immutable live access.
    unsafe { (*handle).device_id.is_some() && (*handle).device_access_token.is_some() }
}

/// Persists the claimed device session with the native platform secret backend and uploads a
/// fresh public libsignal pre-key bundle. The token and private pre-key material remain inside Rust.
///
/// This operation is retry-safe: server key publication is transactional and one-time pre-key IDs
/// are regenerated when a retry is required.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_device_initialize(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    let Some(client) = pairing_client() else {
        return false;
    };
    let Some(now_unix_ms) = current_unix_ms() else {
        return false;
    };

    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    let Some(device_id) = core.device_id.clone() else {
        return false;
    };
    let Some(token) = core.device_access_token.as_mut() else {
        return false;
    };
    let Some(signal_backend) = core.signal_backend.as_mut() else {
        return false;
    };

    let persisted = token
        .with_read(|bytes| persist_default_device_session(&device_id, bytes))
        .is_ok_and(|result| result.is_ok());
    if !persisted {
        return false;
    }

    let mut rng = rand::rng();
    let max_first_one_time = (i32::MAX as u32)
        .saturating_sub(DESKTOP_PREKEY_UPLOAD_COUNT)
        .max(1);
    let first_one_time_pre_key_id = rng.random_range(1..=max_first_one_time);
    let signed_pre_key_id = rng.random_range(1..=i32::MAX as u32);
    let kyber_pre_key_id = rng.random_range(1..=i32::MAX as u32);

    let published = match block_on(signal_backend.generate_and_store_prekey_bundle(
        first_one_time_pre_key_id,
        DESKTOP_PREKEY_UPLOAD_COUNT,
        signed_pre_key_id,
        kyber_pre_key_id,
        now_unix_ms,
        &mut rng,
    )) {
        Ok(bundle) => bundle,
        Err(_) => return false,
    };

    let identity_key = STANDARD_NO_PAD.encode(&published.identity_key);
    let signed_public_key = STANDARD_NO_PAD.encode(&published.signed_pre_key.public_key);
    let signed_signature = STANDARD_NO_PAD.encode(&published.signed_pre_key.signature);
    let kyber_public_key = STANDARD_NO_PAD.encode(&published.kyber_pre_key.public_key);
    let kyber_signature = STANDARD_NO_PAD.encode(&published.kyber_pre_key.signature);
    let encoded_one_time: Vec<(u32, String)> = published
        .one_time_pre_keys
        .iter()
        .map(|prekey| (prekey.key_id, STANDARD_NO_PAD.encode(&prekey.public_key)))
        .collect();
    let one_time_prekeys = encoded_one_time
        .iter()
        .map(|(key_id, public_key)| PublicOneTimePreKey {
            key_id: *key_id,
            public_key,
        })
        .collect();

    if persist_default_signal_store(signal_backend).is_err() {
        return false;
    }

    let upload = PublicKeyUpload {
        device_id: &device_id,
        identity_key: &identity_key,
        registration_id: published.registration_id,
        protocol_device_id: V1_PROTOCOL_DEVICE_ID,
        signed_prekey: PublicSignedPreKey {
            key_id: published.signed_pre_key.key_id,
            public_key: &signed_public_key,
            signature: &signed_signature,
        },
        kyber_prekey: PublicSignedPreKey {
            key_id: published.kyber_pre_key.key_id,
            public_key: &kyber_public_key,
            signature: &kyber_signature,
        },
        one_time_prekeys,
    };

    token
        .with_read(|bytes| client.upload_keys(bytes, &upload))
        .is_ok_and(|result| result.is_ok())
}

/// Pulls encrypted pending messages, decrypts them entirely inside Rust, persists the
/// updated libsignal ratchet and encrypted local inbox durably, then acknowledges the relay.
///
/// A crash-safe encrypted journal makes the ratchet/inbox commit replayable. The server is never
/// ACKed before both the updated Signal state and plaintext message are durable at rest.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_sync_pending(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    let Some(client) = pairing_client() else {
        return false;
    };

    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    let Some(device_id) = core.device_id.clone() else {
        return false;
    };
    if core.device_access_token.is_none() || core.signal_backend.is_none() {
        return false;
    }
    if core.desktop_inbox.is_none() {
        core.desktop_inbox = load_or_create_desktop_inbox().ok();
    }
    if core.desktop_inbox.is_none() || recover_inbox_journal(core).is_err() {
        return false;
    }

    let pending = {
        let Some(token) = core.device_access_token.as_mut() else {
            return false;
        };
        match token.with_read(|bytes| client.pending_messages(bytes, &device_id)) {
            Ok(Ok(messages)) => messages,
            Ok(Err(_)) | Err(_) => return false,
        }
    };

    for message in pending {
        let already_durable = core
            .desktop_inbox
            .as_ref()
            .and_then(|inbox| inbox.contains_remote_message(&message.id).ok())
            .unwrap_or(false);

        if !already_durable {
            let (sender_device_id, mut plaintext_bytes) = {
                let Some(signal_backend) = core.signal_backend.as_mut() else {
                    return false;
                };
                let mut rng = rand::rng();
                match block_on(signal_backend.decrypt_wire(
                    &message.ciphertext,
                    &device_id,
                    V1_PROTOCOL_DEVICE_ID,
                    &mut rng,
                )) {
                    Ok(value) => value,
                    Err(_) => return false,
                }
            };
            if sender_device_id != message.sender_device_id {
                plaintext_bytes.fill(0);
                return false;
            }
            let plaintext = match std::str::from_utf8(&plaintext_bytes) {
                Ok(value) if !value.is_empty() => value.to_owned(),
                Ok(_) | Err(_) => {
                    plaintext_bytes.fill(0);
                    return false;
                }
            };
            plaintext_bytes.fill(0);

            let entry = DurableInboxEntry {
                remote_message_id: message.id.clone(),
                bubble_id: message.bubble_id,
                sender_device_id: message.sender_device_id,
                sender_user_id: message.sender_user_id,
                sender_public_id: message.sender_public_id,
                recipient_device_id: message.recipient_device_id,
                client_message_id: message.client_message_id,
                message_type: message.message_type,
                plaintext,
                created_at: message.created_at,
                expires_at: message.expires_at,
            };

            let mut snapshot = match core
                .signal_backend
                .as_ref()
                .and_then(|backend| backend.export_serialized_store().ok())
            {
                Some(snapshot) => snapshot,
                None => return false,
            };
            let journal_written = core
                .desktop_inbox
                .as_ref()
                .is_some_and(|inbox| inbox.write_journal(&entry, &snapshot).is_ok());
            snapshot.fill(0);
            if !journal_written {
                return false;
            }

            let signal_persisted = core
                .signal_backend
                .as_ref()
                .is_some_and(|backend| persist_default_signal_store(backend).is_ok());
            if !signal_persisted {
                return false;
            }
            let inbox_persisted = core
                .desktop_inbox
                .as_ref()
                .is_some_and(|inbox| inbox.append(entry).is_ok());
            if !inbox_persisted {
                return false;
            }
            if let Some(inbox) = core.desktop_inbox.as_ref() {
                let _ = inbox.clear_journal();
            }
        }

        let acknowledged = {
            let Some(token) = core.device_access_token.as_mut() else {
                return false;
            };
            token
                .with_read(|bytes| client.acknowledge_message(bytes, &message.id, &device_id))
                .is_ok_and(|result| result.is_ok())
        };
        if !acknowledged {
            return false;
        }
    }

    true
}

/// Returns the number of durably encrypted local inbox entries.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and immutably accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_inbox_count(handle: *const EnigmaCoreHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    let core = unsafe { &*handle };
    core.desktop_inbox
        .as_ref()
        .and_then(|inbox| inbox.entries().ok())
        .map_or(0, |entries| entries.len())
}

/// Returns the UTF-8 JSON byte length of an inbox entry, or zero for an invalid index.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and immutably accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_inbox_entry_json_len(
    handle: *const EnigmaCoreHandle,
    index: usize,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    let core = unsafe { &*handle };
    core.desktop_inbox
        .as_ref()
        .and_then(|inbox| inbox.entries().ok())
        .and_then(|entries| entries.get(index).cloned())
        .and_then(|entry| serde_json::to_vec(&entry).ok())
        .map_or(0, |encoded| encoded.len())
}

/// Copies one decrypted inbox entry as UTF-8 JSON into caller-owned memory.
///
/// # Safety
///
/// handle must be live or null. output must reference at least output_len writable bytes and must
/// not overlap Rust-owned storage. The same handle must not be concurrently mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_inbox_entry_json_copy(
    handle: *const EnigmaCoreHandle,
    index: usize,
    output: *mut u8,
    output_len: usize,
) -> bool {
    if handle.is_null() || output.is_null() {
        return false;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    let core = unsafe { &*handle };
    let Some(encoded) = core
        .desktop_inbox
        .as_ref()
        .and_then(|inbox| inbox.entries().ok())
        .and_then(|entries| entries.get(index).cloned())
        .and_then(|entry| serde_json::to_vec(&entry).ok())
    else {
        return false;
    };
    copy_pairing_bytes(&encoded, output, output_len)
}

/// Cancels and destroys the current ephemeral pairing bootstrap.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_cancel(handle: *mut EnigmaCoreHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: caller guarantees exclusive live access; dropping the bootstrap wipes its guarded
    // libsodium secret-key allocation through SecureBytes.
    unsafe {
        (*handle).pairing_bootstrap = None;
    }
}

/// Returns the UTF-8 byte length of the current pairing URI.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and not concurrently
/// mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_uri_len(handle: *const EnigmaCoreHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    unsafe {
        (*handle)
            .pairing_bootstrap
            .as_ref()
            .map_or(0, |pairing| pairing.uri().len())
    }
}

/// Copies the exact UTF-8 pairing URI bytes to a caller-owned buffer.
///
/// # Safety
///
/// handle must be live or null. output must reference at least output_len writable bytes and must
/// not overlap Rust-owned storage. The same handle must not be concurrently mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_uri_copy(
    handle: *const EnigmaCoreHandle,
    output: *mut u8,
    output_len: usize,
) -> bool {
    if handle.is_null() || output.is_null() {
        return false;
    }
    // SAFETY: caller guarantees immutable live handle access.
    let Some(pairing) = (unsafe { (*handle).pairing_bootstrap.as_ref() }) else {
        return false;
    };
    copy_pairing_bytes(pairing.uri().as_bytes(), output, output_len)
}

/// Returns the UTF-8 byte length of the current SVG QR image.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and not concurrently
/// mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_svg_len(handle: *const EnigmaCoreHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    unsafe {
        (*handle)
            .pairing_bootstrap
            .as_ref()
            .map_or(0, |pairing| pairing.svg().len())
    }
}

/// Copies the exact UTF-8 SVG QR image to a caller-owned buffer.
///
/// # Safety
///
/// handle must be live or null. output must reference at least output_len writable bytes and must
/// not overlap Rust-owned storage. The same handle must not be concurrently mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_svg_copy(
    handle: *const EnigmaCoreHandle,
    output: *mut u8,
    output_len: usize,
) -> bool {
    if handle.is_null() || output.is_null() {
        return false;
    }
    // SAFETY: caller guarantees immutable live handle access.
    let Some(pairing) = (unsafe { (*handle).pairing_bootstrap.as_ref() }) else {
        return false;
    };
    copy_pairing_bytes(pairing.svg().as_bytes(), output, output_len)
}

/// Returns the current pairing expiration timestamp in Unix milliseconds, or zero when absent.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and not concurrently
/// mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_pairing_expires_at_unix_ms(
    handle: *const EnigmaCoreHandle,
) -> u64 {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    unsafe {
        (*handle)
            .pairing_bootstrap
            .as_ref()
            .map_or(0, |pairing| pairing.payload().expires_at_unix_ms)
    }
}

fn copy_pairing_bytes(source: &[u8], output: *mut u8, output_len: usize) -> bool {
    if source.is_empty() || output.is_null() || output_len < source.len() {
        return false;
    }
    // SAFETY: callers of the exported copy functions guarantee output references a writable,
    // non-overlapping region of at least output_len bytes. The bound above proves source.len()
    // bytes fit in that region.
    unsafe {
        std::ptr::copy_nonoverlapping(source.as_ptr(), output, source.len());
    }
    true
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

fn is_canonical_device_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn encode_device_session_record(device_id: &str, protected: &[u8]) -> Option<Vec<u8>> {
    if !is_canonical_device_uuid(device_id)
        || protected.is_empty()
        || protected.len() > MAX_PROTECTED_DEVICE_SESSION_BYTES
    {
        return None;
    }
    let mut record =
        Vec::with_capacity(DEVICE_SESSION_RECORD_MAGIC.len() + device_id.len() + protected.len());
    record.extend_from_slice(DEVICE_SESSION_RECORD_MAGIC);
    record.extend_from_slice(device_id.as_bytes());
    record.extend_from_slice(protected);
    Some(record)
}

fn decode_device_session_record(record: &[u8]) -> Option<(String, &[u8])> {
    let body = record.strip_prefix(DEVICE_SESSION_RECORD_MAGIC)?;
    if body.len() <= 36 {
        return None;
    }
    let (device_id_bytes, protected) = body.split_at(36);
    let device_id = std::str::from_utf8(device_id_bytes).ok()?;
    if !is_canonical_device_uuid(device_id)
        || protected.is_empty()
        || protected.len() > MAX_PROTECTED_DEVICE_SESSION_BYTES
    {
        return None;
    }
    Some((device_id.to_owned(), protected))
}

#[cfg(windows)]
fn default_device_session_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"))?;
    Some(
        PathBuf::from(base)
            .join("ENIGMA")
            .join("device-session-v1.bin"),
    )
}

#[cfg(target_os = "linux")]
fn default_device_session_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("ENIGMA").join("device-session-v1.bin"))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn default_device_session_path() -> Option<PathBuf> {
    None
}

fn persist_protected_record(path: &Path, record: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected record path has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;

    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(record)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)
}

fn persist_default_device_session(device_id: &str, token: &[u8]) -> Result<(), ()> {
    if token.is_empty() || token.len() > 16 * 1024 {
        return Err(());
    }
    let protected = protect_device_session_token(token).map_err(|_| ())?;
    let record = encode_device_session_record(device_id, &protected).ok_or(())?;
    let path = default_device_session_path().ok_or(())?;
    persist_protected_record(&path, &record).map_err(|_| ())
}

fn load_default_device_session() -> Result<(String, SecureBytes), ()> {
    let path = default_device_session_path().ok_or(())?;
    let record = fs::read(path).map_err(|_| ())?;
    let (device_id, protected) = decode_device_session_record(&record).ok_or(())?;
    let mut token = unprotect_device_session_token(protected).map_err(|_| ())?;
    if token.is_empty() || token.len() > 16 * 1024 {
        token.fill(0);
        return Err(());
    }
    let secure = SecureBytes::copy_and_wipe(&mut token).map_err(|_| ())?;
    Ok((device_id, secure))
}

#[cfg(windows)]
fn protect_device_session_token(token: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.protect(token)
}

#[cfg(target_os = "linux")]
fn protect_device_session_token(token: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    LinuxSecretServiceProtector::new(LINUX_DEVICE_SESSION_SLOT)?.protect(token)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn protect_device_session_token(_token: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

#[cfg(windows)]
fn unprotect_device_session_token(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.unprotect(protected)
}

#[cfg(target_os = "linux")]
fn unprotect_device_session_token(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    let protector = LinuxSecretServiceProtector::from_locator(protected)?;
    protector.unprotect(protected)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unprotect_device_session_token(_protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

fn encode_signal_identity_record(registration_id: u32, protected: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(SIGNAL_IDENTITY_RECORD_MAGIC.len() + 4 + protected.len());
    record.extend_from_slice(SIGNAL_IDENTITY_RECORD_MAGIC);
    record.extend_from_slice(&registration_id.to_le_bytes());
    record.extend_from_slice(protected);
    record
}

fn decode_signal_identity_record(record: &[u8]) -> Option<(u32, &[u8])> {
    let body = record.strip_prefix(SIGNAL_IDENTITY_RECORD_MAGIC)?;
    if body.len() < 5 {
        return None;
    }
    let (registration_bytes, protected) = body.split_at(4);
    let registration_id = u32::from_le_bytes(registration_bytes.try_into().ok()?);
    if registration_id == 0
        || protected.is_empty()
        || protected.len() > MAX_PROTECTED_SIGNAL_IDENTITY_BYTES
    {
        return None;
    }
    Some((registration_id, protected))
}

fn encode_inbox_master_key_record(protected: &[u8]) -> Option<Vec<u8>> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED_DEVICE_SESSION_BYTES {
        return None;
    }
    let mut record = Vec::with_capacity(INBOX_MASTER_KEY_RECORD_MAGIC.len() + protected.len());
    record.extend_from_slice(INBOX_MASTER_KEY_RECORD_MAGIC);
    record.extend_from_slice(protected);
    Some(record)
}

fn decode_inbox_master_key_record(record: &[u8]) -> Option<&[u8]> {
    let protected = record.strip_prefix(INBOX_MASTER_KEY_RECORD_MAGIC)?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_DEVICE_SESSION_BYTES {
        return None;
    }
    Some(protected)
}

fn default_desktop_state_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"))?;
        return Some(PathBuf::from(base).join("ENIGMA"));
    }
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        return Some(base.join("ENIGMA"));
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

fn default_inbox_master_key_path() -> Option<PathBuf> {
    Some(default_desktop_state_dir()?.join("desktop-inbox-master-key-v1.bin"))
}

fn default_inbox_path() -> Option<PathBuf> {
    Some(default_desktop_state_dir()?.join("desktop-inbox-v1.enc"))
}

fn default_inbox_journal_path() -> Option<PathBuf> {
    Some(default_desktop_state_dir()?.join("desktop-inbox-journal-v1.enc"))
}

fn default_outbox_path() -> Option<PathBuf> {
    Some(default_desktop_state_dir()?.join("desktop-outbox-v1.enc"))
}

fn default_outbox_journal_path() -> Option<PathBuf> {
    Some(default_desktop_state_dir()?.join("desktop-outbox-journal-v1.enc"))
}

fn load_or_create_desktop_vault() -> Result<SodiumRecordVault, ()> {
    let key_path = default_inbox_master_key_path().ok_or(())?;
    match fs::read(&key_path) {
        Ok(record) => {
            let protected = decode_inbox_master_key_record(&record).ok_or(())?;
            let mut raw = unprotect_inbox_master_key(protected).map_err(|_| ())?;
            if raw.len() != INBOX_MASTER_KEY_BYTES {
                raw.fill(0);
                return Err(());
            }
            let mut key = [0_u8; INBOX_MASTER_KEY_BYTES];
            key.copy_from_slice(&raw);
            raw.fill(0);
            SodiumRecordVault::import_key_and_wipe(&mut key).map_err(|_| ())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut key = random_public_bytes::<INBOX_MASTER_KEY_BYTES>().map_err(|_| ())?;
            let protected_result = protect_inbox_master_key(&key);
            let protected = match protected_result {
                Ok(value) => value,
                Err(_) => {
                    key.fill(0);
                    return Err(());
                }
            };
            let Some(record) = encode_inbox_master_key_record(&protected) else {
                key.fill(0);
                return Err(());
            };
            if persist_protected_record(&key_path, &record).is_err() {
                key.fill(0);
                return Err(());
            }
            SodiumRecordVault::import_key_and_wipe(&mut key).map_err(|_| ())
        }
        Err(_) => Err(()),
    }
}

fn load_or_create_desktop_inbox() -> Result<EncryptedDesktopInbox, ()> {
    Ok(EncryptedDesktopInbox::new(
        default_inbox_path().ok_or(())?,
        default_inbox_journal_path().ok_or(())?,
        load_or_create_desktop_vault()?,
    ))
}

fn load_or_create_desktop_outbox() -> Result<EncryptedDesktopOutbox, ()> {
    Ok(EncryptedDesktopOutbox::new(
        default_outbox_path().ok_or(())?,
        default_outbox_journal_path().ok_or(())?,
        load_or_create_desktop_vault()?,
    ))
}

fn recover_outbox_journal(core: &mut EnigmaCoreHandle) -> Result<(), ()> {
    let journal = core.desktop_outbox.as_ref().ok_or(())?.read_journal()?;
    let Some((deliveries, mut snapshot)) = journal else {
        return Ok(());
    };

    let backend = LibsignalSessionBackend::from_serialized_store(&snapshot).map_err(|_| ())?;
    snapshot.fill(0);
    persist_default_signal_store(&backend)?;
    core.signal_backend = Some(backend);
    core.desktop_outbox
        .as_ref()
        .ok_or(())?
        .enqueue_batch(&deliveries)?;
    let _ = core.desktop_outbox.as_ref().ok_or(())?.clear_journal();
    Ok(())
}

fn recover_inbox_journal(core: &mut EnigmaCoreHandle) -> Result<(), ()> {
    let journal = core.desktop_inbox.as_ref().ok_or(())?.read_journal()?;
    let Some((entry, mut snapshot)) = journal else {
        return Ok(());
    };

    let backend = LibsignalSessionBackend::from_serialized_store(&snapshot).map_err(|_| ())?;
    snapshot.fill(0);
    persist_default_signal_store(&backend)?;
    core.signal_backend = Some(backend);
    core.desktop_inbox.as_ref().ok_or(())?.append(entry)?;
    let _ = core.desktop_inbox.as_ref().ok_or(())?.clear_journal();
    Ok(())
}

#[cfg(windows)]
fn protect_inbox_master_key(key: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.protect(key)
}

#[cfg(target_os = "linux")]
fn protect_inbox_master_key(key: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    LinuxSecretServiceProtector::new(LINUX_INBOX_MASTER_KEY_SLOT)?.protect(key)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn protect_inbox_master_key(_key: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

#[cfg(windows)]
fn unprotect_inbox_master_key(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.unprotect(protected)
}

#[cfg(target_os = "linux")]
fn unprotect_inbox_master_key(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    let protector = LinuxSecretServiceProtector::from_locator(protected)?;
    protector.unprotect(protected)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unprotect_inbox_master_key(_protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

fn encode_signal_store_record(protected: &[u8]) -> Option<Vec<u8>> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED_SIGNAL_STORE_BYTES {
        return None;
    }
    let mut record = Vec::with_capacity(SIGNAL_STORE_RECORD_MAGIC.len() + protected.len());
    record.extend_from_slice(SIGNAL_STORE_RECORD_MAGIC);
    record.extend_from_slice(protected);
    Some(record)
}

fn decode_signal_store_record(record: &[u8]) -> Option<&[u8]> {
    let protected = record.strip_prefix(SIGNAL_STORE_RECORD_MAGIC)?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_SIGNAL_STORE_BYTES {
        return None;
    }
    Some(protected)
}

#[cfg(windows)]
fn default_signal_store_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"))?;
    Some(
        PathBuf::from(base)
            .join("ENIGMA")
            .join("signal-store-v2.bin"),
    )
}

#[cfg(target_os = "linux")]
fn default_signal_store_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("ENIGMA").join("signal-store-v2.bin"))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn default_signal_store_path() -> Option<PathBuf> {
    None
}

fn persist_default_signal_store(backend: &LibsignalSessionBackend) -> Result<(), ()> {
    let mut snapshot = backend.export_serialized_store().map_err(|_| ())?;
    let protected_result = protect_signal_store(&snapshot);
    snapshot.fill(0);
    let protected = protected_result.map_err(|_| ())?;
    let record = encode_signal_store_record(&protected).ok_or(())?;
    let path = default_signal_store_path().ok_or(())?;
    persist_protected_record(&path, &record).map_err(|_| ())
}

fn restore_signal_backend_from_store_record(record: &[u8]) -> Result<LibsignalSessionBackend, ()> {
    let protected = decode_signal_store_record(record).ok_or(())?;
    let mut snapshot = unprotect_signal_store(protected).map_err(|_| ())?;
    if snapshot.is_empty() || snapshot.len() > 16 * 1024 * 1024 {
        snapshot.fill(0);
        return Err(());
    }
    let backend = LibsignalSessionBackend::from_serialized_store(&snapshot).map_err(|_| ());
    snapshot.fill(0);
    backend
}

#[cfg(windows)]
fn protect_signal_store(snapshot: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.protect(snapshot)
}

#[cfg(target_os = "linux")]
fn protect_signal_store(snapshot: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    LinuxSecretServiceProtector::new(LINUX_SIGNAL_STORE_SLOT)?.protect(snapshot)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn protect_signal_store(_snapshot: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

#[cfg(windows)]
fn unprotect_signal_store(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.unprotect(protected)
}

#[cfg(target_os = "linux")]
fn unprotect_signal_store(protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    let protector = LinuxSecretServiceProtector::from_locator(protected)?;
    protector.unprotect(protected)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unprotect_signal_store(_protected: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
}

#[cfg(windows)]
fn default_signal_identity_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA"))?;
    Some(
        PathBuf::from(base)
            .join("ENIGMA")
            .join("signal-identity-v1.bin"),
    )
}

#[cfg(target_os = "linux")]
fn default_signal_identity_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("ENIGMA").join("signal-identity-v1.bin"))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn default_signal_identity_path() -> Option<PathBuf> {
    None
}

fn persist_signal_identity_record(path: &Path, record: &[u8]) -> io::Result<()> {
    persist_protected_record(path, record)
}

fn restore_signal_backend_from_record(record: &[u8]) -> Result<LibsignalSessionBackend, ()> {
    let (registration_id, protected) = decode_signal_identity_record(record).ok_or(())?;
    let mut serialized_identity = unprotect_signal_identity(protected).map_err(|_| ())?;
    if serialized_identity.is_empty() {
        return Err(());
    }

    let backend =
        LibsignalSessionBackend::from_serialized_identity(&serialized_identity, registration_id)
            .map_err(|_| ());
    serialized_identity.fill(0);
    backend
}

fn load_or_create_default_signal_backend() -> Result<LibsignalSessionBackend, ()> {
    let store_path = default_signal_store_path().ok_or(())?;
    match fs::read(&store_path) {
        Ok(record) => return restore_signal_backend_from_store_record(&record),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(()),
    }

    let identity_path = default_signal_identity_path().ok_or(())?;
    let backend = match fs::read(&identity_path) {
        Ok(record) => restore_signal_backend_from_record(&record)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (backend, mut serialized_identity, registration_id) =
                LibsignalSessionBackend::generate_for_new_device().map_err(|_| ())?;
            let protected_result = protect_signal_identity(&serialized_identity);
            serialized_identity.fill(0);
            let protected = protected_result.map_err(|_| ())?;
            if protected.is_empty() || protected.len() > MAX_PROTECTED_SIGNAL_IDENTITY_BYTES {
                return Err(());
            }

            let record = encode_signal_identity_record(registration_id, &protected);
            persist_signal_identity_record(&identity_path, &record).map_err(|_| ())?;
            backend
        }
        Err(_) => return Err(()),
    };

    persist_default_signal_store(&backend)?;
    Ok(backend)
}

#[cfg(windows)]
fn protect_signal_identity(serialized_identity: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::WindowsDpapiProtector;

    WindowsDpapiProtector.protect(serialized_identity)
}

#[cfg(target_os = "linux")]
fn protect_signal_identity(serialized_identity: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    use enigma_platform::LinuxSecretServiceProtector;

    LinuxSecretServiceProtector::new(LINUX_SIGNAL_IDENTITY_SLOT)?.protect(serialized_identity)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn protect_signal_identity(_serialized_identity: &[u8]) -> Result<Vec<u8>, PlatformKeyError> {
    Err(PlatformKeyError::BackendUnavailable)
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
    fn signal_store_record_is_versioned_and_bounded() {
        let protected = vec![0x51_u8; 128];
        let record = encode_signal_store_record(&protected).expect("store record");
        assert!(record.starts_with(SIGNAL_STORE_RECORD_MAGIC));
        assert_eq!(
            decode_signal_store_record(&record).expect("decode"),
            protected.as_slice()
        );
        assert!(encode_signal_store_record(&[]).is_none());
    }

    #[test]
    fn pairing_exports_only_public_uri_and_svg_bytes() {
        let handle = enigma_core_create();
        assert!(!handle.is_null());

        let pairing =
            PairingBootstrap::generate(1_700_000_000_000, DEFAULT_PAIRING_TTL_MS, &[0x51; 33])
                .expect("pairing bootstrap");
        // SAFETY: handle is live and exclusively owned by this test.
        unsafe {
            (*handle).pairing_bootstrap = Some(pairing);
        }

        // SAFETY: handle remains live and exclusively owned.
        let uri_len = unsafe { enigma_core_pairing_uri_len(handle) };
        assert!(uri_len > 0);
        let mut uri = vec![0_u8; uri_len];
        // SAFETY: uri owns uri_len writable bytes and handle is live.
        assert!(unsafe { enigma_core_pairing_uri_copy(handle, uri.as_mut_ptr(), uri.len()) });
        let uri = String::from_utf8(uri).expect("UTF-8 URI");
        assert!(uri.starts_with("enigma://pair-device?payload="));

        // SAFETY: handle remains live and exclusively owned.
        let svg_len = unsafe { enigma_core_pairing_svg_len(handle) };
        assert!(svg_len > 0);
        let mut svg = vec![0_u8; svg_len];
        // SAFETY: svg owns svg_len writable bytes and handle is live.
        assert!(unsafe { enigma_core_pairing_svg_copy(handle, svg.as_mut_ptr(), svg.len()) });
        let svg = String::from_utf8(svg).expect("UTF-8 SVG");
        assert!(svg.contains("<svg"));

        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn pairing_start_requires_initialized_signal_identity() {
        let handle = enigma_core_create();
        // SAFETY: handle is live and exclusively owned.
        assert!(!unsafe { enigma_core_pairing_start(handle) });
        // SAFETY: handle is live and destroyed exactly once here.
        unsafe { enigma_core_destroy(handle) };
    }

    #[test]
    fn protected_identity_record_round_trips_and_rejects_corruption() {
        let protected = b"opaque-protected-identity";
        let record = encode_signal_identity_record(7, protected);
        assert_eq!(
            decode_signal_identity_record(&record),
            Some((7, protected.as_slice()))
        );

        assert_eq!(decode_signal_identity_record(b"not-an-enigma-record"), None);
        assert_eq!(
            decode_signal_identity_record(&encode_signal_identity_record(0, protected)),
            None
        );
    }

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
            enigma_core_signal_initialize_protected(handle, invalid.as_ptr(), invalid.len(), 7)
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
            enigma_core_signal_initialize_protected(handle, protected.as_ptr(), protected.len(), 7)
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
