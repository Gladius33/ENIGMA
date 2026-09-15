#![deny(unsafe_op_in_unsafe_fn)]

mod inbox;
mod outbox;
mod p2p;

use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use enigma_platform::{PlatformKeyError, PlatformKeyProtector};
use enigma_runtime_core::{CoreRuntime, PairingBootstrap, DEFAULT_PAIRING_TTL_MS};
use enigma_signal::{
    session::{
        LibsignalSessionBackend, RemotePreKeyBundleMaterial, RemotePublicPreKey,
        RemoteSignedPreKey as SignalRemoteSignedPreKey,
    },
    verify_linked_device_authorization_binding, LibsignalIdentityProofVerifier,
};
use enigma_sodium::{random_public_bytes, SecureBytes};
use enigma_storage::SodiumRecordVault;
use enigma_transport::{
    ClaimedRemoteDeviceKeyBundle, PairingCandidatePublish, PairingClaimState,
    PairingRendezvousClient, PublicKeyUpload, PublicOneTimePreKey, PublicSignedPreKey,
    RelayMessageSend, RemoteDeviceKeyBundle,
};
use futures_executor::block_on;
use inbox::{DurableInboxEntry, EncryptedDesktopInbox};
use outbox::{DurableOutboundDelivery, EncryptedDesktopOutbox};
use p2p::{delivery_timestamp, turn_ice_servers, DesktopP2pManager};
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
const MAX_OUTBOUND_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONTACT_PUBLIC_ID_BYTES: usize = 128;
const MAX_CONTACT_DISPLAY_NAME_BYTES: usize = 160;
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
    desktop_p2p: Option<DesktopP2pManager>,
    contacts_json_cache: Option<Vec<u8>>,
}

#[repr(C)]
pub struct EnigmaSendTextRequest {
    pub recipient_user_id: *const u8,
    pub recipient_user_id_len: usize,
    pub recipient_public_id: *const u8,
    pub recipient_public_id_len: usize,
    pub recipient_display_name: *const u8,
    pub recipient_display_name_len: usize,
    pub bubble_id: *const u8,
    pub bubble_id_len: usize,
    pub plaintext: *const u8,
    pub plaintext_len: usize,
}

#[derive(serde::Serialize)]
struct TextPayloadDto<'a> {
    version: u16,
    body: &'a str,
    attachments: Vec<()>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SenderSyncDto<'a> {
    version: u16,
    contact_user_id: &'a str,
    contact_public_id: &'a str,
    contact_display_name: &'a str,
    bubble_id: &'a str,
    client_message_id: &'a str,
    original_created_at: i64,
    encoded_message_payload: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SenderSyncInboundDto {
    version: u16,
    contact_user_id: String,
    contact_public_id: String,
    contact_display_name: String,
    bubble_id: String,
    client_message_id: String,
    original_created_at: i64,
    encoded_message_payload: String,
}

#[derive(serde::Deserialize)]
struct MessagePayloadInboundDto {
    version: u16,
    body: String,
    #[serde(default)]
    attachments: Vec<MessageAttachmentInboundDto>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageAttachmentInboundDto {
    bubble_id: String,
}

struct NormalizedInboundPayload {
    plaintext: String,
    message_type: String,
    direction: &'static str,
    contact_user_id: String,
    contact_public_id: String,
    contact_display_name: String,
    original_created_at_unix_ms: Option<i64>,
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
        desktop_p2p: None,
        contacts_json_cache: None,
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

fn random_uuid_v4() -> Result<String, ()> {
    let mut bytes = random_public_bytes::<16>().map_err(|_| ())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

unsafe fn read_utf8_input(
    pointer: *const u8,
    length: usize,
    maximum: usize,
) -> Option<String> {
    if pointer.is_null() || length == 0 || length > maximum {
        return None;
    }
    // SAFETY: the caller of the enclosing FFI function guarantees that pointer
    // references at least length readable bytes for the duration of the call.
    let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
    let value = std::str::from_utf8(bytes).ok()?;
    Some(value.to_owned())
}

fn encode_text_payload(body: &str) -> Result<String, ()> {
    if body.trim().is_empty() || body.len() > MAX_OUTBOUND_TEXT_BYTES {
        return Err(());
    }
    let json = serde_json::to_string(&TextPayloadDto {
        version: 1,
        body,
        attachments: Vec::new(),
    })
    .map_err(|_| ())?;
    Ok(format!("ENIGMA_PAYLOAD_V1:{json}"))
}

fn encode_sender_sync_payload(
    contact_user_id: &str,
    contact_public_id: &str,
    contact_display_name: &str,
    bubble_id: &str,
    client_message_id: &str,
    original_created_at: i64,
    encoded_message_payload: &str,
) -> Result<String, ()> {
    if !is_canonical_device_uuid(contact_user_id)
        || !is_canonical_device_uuid(bubble_id)
        || !is_canonical_device_uuid(client_message_id)
        || contact_public_id.trim().is_empty()
        || contact_public_id.len() > MAX_CONTACT_PUBLIC_ID_BYTES
        || contact_display_name.trim().is_empty()
        || contact_display_name.len() > MAX_CONTACT_DISPLAY_NAME_BYTES
        || original_created_at <= 0
        || encoded_message_payload.is_empty()
        || encoded_message_payload.len() > MAX_OUTBOUND_TEXT_BYTES
    {
        return Err(());
    }
    let json = serde_json::to_string(&SenderSyncDto {
        version: 1,
        contact_user_id,
        contact_public_id,
        contact_display_name,
        bubble_id,
        client_message_id,
        original_created_at,
        encoded_message_payload,
    })
    .map_err(|_| ())?;
    Ok(format!("ENIGMA_SENDER_SYNC_V1:{json}"))
}

fn decode_message_payload(value: &str, expected_bubble_id: &str) -> Result<String, ()> {
    const PREFIX: &str = "ENIGMA_PAYLOAD_V1:";
    let encoded = value.strip_prefix(PREFIX).ok_or(())?;
    if encoded.is_empty() || encoded.len() > MAX_OUTBOUND_TEXT_BYTES {
        return Err(());
    }
    let payload: MessagePayloadInboundDto = serde_json::from_str(encoded).map_err(|_| ())?;
    if payload.version != 1
        || payload.attachments.len() > 16
        || (payload.body.trim().is_empty() && payload.attachments.is_empty())
        || payload
            .attachments
            .iter()
            .any(|attachment| attachment.bubble_id != expected_bubble_id)
    {
        return Err(());
    }
    Ok(if payload.attachments.is_empty() {
        "text".to_owned()
    } else {
        "file".to_owned()
    })
}

fn normalize_inbound_payload(
    plaintext: String,
    message_type: &str,
    message_bubble_id: &str,
    message_client_message_id: &str,
    sender_user_id: &str,
    sender_public_id: &str,
    own_user_id: &str,
    from_verified_sibling: bool,
) -> Result<NormalizedInboundPayload, ()> {
    if from_verified_sibling {
        if sender_user_id != own_user_id
            || message_type != "opaque"
            || !plaintext.starts_with("ENIGMA_SENDER_SYNC_V1:")
        {
            return Err(());
        }
        let encoded = plaintext
            .strip_prefix("ENIGMA_SENDER_SYNC_V1:")
            .ok_or(())?;
        let sync: SenderSyncInboundDto = serde_json::from_str(encoded).map_err(|_| ())?;
        if sync.version != 1
            || !is_canonical_device_uuid(&sync.contact_user_id)
            || sync.contact_user_id == own_user_id
            || sync.contact_public_id.trim().is_empty()
            || sync.contact_public_id.len() > MAX_CONTACT_PUBLIC_ID_BYTES
            || sync.contact_display_name.trim().is_empty()
            || sync.contact_display_name.len() > MAX_CONTACT_DISPLAY_NAME_BYTES
            || !is_canonical_device_uuid(&sync.bubble_id)
            || !is_canonical_device_uuid(&sync.client_message_id)
            || sync.bubble_id != message_bubble_id
            || sync.client_message_id != message_client_message_id
            || sync.original_created_at <= 0
        {
            return Err(());
        }
        let normalized_type =
            decode_message_payload(&sync.encoded_message_payload, &sync.bubble_id)?;
        return Ok(NormalizedInboundPayload {
            plaintext: sync.encoded_message_payload,
            message_type: normalized_type,
            direction: "outbound",
            contact_user_id: sync.contact_user_id,
            contact_public_id: sync.contact_public_id,
            contact_display_name: sync.contact_display_name,
            original_created_at_unix_ms: Some(sync.original_created_at),
        });
    }

    if sender_user_id == own_user_id {
        return Err(());
    }
    let normalized_type = decode_message_payload(&plaintext, message_bubble_id)?;
    if !matches!(message_type, "text" | "file") || message_type != normalized_type.as_str() {
        return Err(());
    }
    Ok(NormalizedInboundPayload {
        plaintext,
        message_type: normalized_type,
        direction: "inbound",
        contact_user_id: sender_user_id.to_owned(),
        contact_public_id: sender_public_id.to_owned(),
        contact_display_name: sender_public_id.to_owned(),
        original_created_at_unix_ms: None,
    })
}

struct InboundEncryptedDelivery<'a> {
    remote_message_id: &'a str,
    bubble_id: &'a str,
    sender_device_id: &'a str,
    sender_user_id: &'a str,
    sender_public_id: &'a str,
    recipient_device_id: &'a str,
    client_message_id: &'a str,
    message_type: &'a str,
    ciphertext: &'a str,
    created_at: &'a str,
    expires_at: &'a str,
}

fn commit_inbound_encrypted_delivery(
    core: &mut EnigmaCoreHandle,
    own_user_id: &str,
    verified_sibling_ids: &HashSet<String>,
    delivery: &InboundEncryptedDelivery<'_>,
) -> Result<bool, ()> {
    let already_durable = core.desktop_inbox.as_ref().ok_or(())?.contains_remote_message(
        delivery.remote_message_id,
    )? || core
        .desktop_inbox
        .as_ref()
        .ok_or(())?
        .contains_client_delivery(delivery.sender_device_id, delivery.client_message_id)?;
    if already_durable {
        return Ok(false);
    }

    let mut working_backend = core.signal_backend.clone().ok_or(())?;
    let (sender_device_id, mut plaintext_bytes) = {
        let mut rng = rand::rng();
        block_on(working_backend.decrypt_wire(
            delivery.ciphertext,
            delivery.recipient_device_id,
            V1_PROTOCOL_DEVICE_ID,
            &mut rng,
        ))
        .map_err(|_| ())?
    };
    if sender_device_id != delivery.sender_device_id {
        plaintext_bytes.fill(0);
        return Err(());
    }
    let plaintext = match std::str::from_utf8(&plaintext_bytes) {
        Ok(value) if !value.is_empty() => value.to_owned(),
        Ok(_) | Err(_) => {
            plaintext_bytes.fill(0);
            return Err(());
        }
    };
    plaintext_bytes.fill(0);

    let from_verified_sibling = delivery.sender_user_id == own_user_id
        && verified_sibling_ids.contains(delivery.sender_device_id);
    if delivery.sender_user_id == own_user_id && !from_verified_sibling {
        return Err(());
    }
    let normalized = normalize_inbound_payload(
        plaintext,
        delivery.message_type,
        delivery.bubble_id,
        delivery.client_message_id,
        delivery.sender_user_id,
        delivery.sender_public_id,
        own_user_id,
        from_verified_sibling,
    )?;

    let entry = DurableInboxEntry {
        remote_message_id: delivery.remote_message_id.to_owned(),
        bubble_id: delivery.bubble_id.to_owned(),
        sender_device_id: delivery.sender_device_id.to_owned(),
        sender_user_id: delivery.sender_user_id.to_owned(),
        sender_public_id: delivery.sender_public_id.to_owned(),
        recipient_device_id: delivery.recipient_device_id.to_owned(),
        client_message_id: delivery.client_message_id.to_owned(),
        message_type: normalized.message_type,
        plaintext: normalized.plaintext,
        created_at: delivery.created_at.to_owned(),
        expires_at: delivery.expires_at.to_owned(),
        direction: normalized.direction.to_owned(),
        contact_user_id: Some(normalized.contact_user_id),
        contact_public_id: Some(normalized.contact_public_id),
        contact_display_name: Some(normalized.contact_display_name),
        original_created_at_unix_ms: normalized.original_created_at_unix_ms,
        delivery_status: if normalized.direction == "inbound" {
            Some("delivered".to_owned())
        } else {
            None
        },
        delivery_updated_at: None,
        delivery_recipient_device_ids: Vec::new(),
    };

    let mut snapshot = working_backend.export_serialized_store().map_err(|_| ())?;
    let journal_written = core
        .desktop_inbox
        .as_ref()
        .ok_or(())?
        .write_journal(&entry, &snapshot)
        .is_ok();
    snapshot.fill(0);
    if !journal_written {
        return Err(());
    }
    if persist_default_signal_store(&working_backend).is_err() {
        return Err(());
    }
    if core.desktop_inbox.as_ref().ok_or(())?.append(entry).is_err() {
        return Err(());
    }

    core.signal_backend = Some(working_backend);
    if let Some(inbox) = core.desktop_inbox.as_ref() {
        let _ = inbox.clear_journal();
    }
    Ok(true)
}

fn decode_signal_key(value: &str) -> Result<Vec<u8>, ()> {
    if value.is_empty() || value.len() > 16 * 1024 {
        return Err(());
    }
    STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| ())
}

fn claimed_prekey_material(
    claimed: &ClaimedRemoteDeviceKeyBundle,
) -> Result<RemotePreKeyBundleMaterial, ()> {
    let registration_id = u32::try_from(claimed.registration_id.ok_or(())?).map_err(|_| ())?;
    let protocol_device_id =
        u32::try_from(claimed.protocol_device_id.ok_or(())?).map_err(|_| ())?;
    let signed_key_id = u32::try_from(claimed.signed_prekey.key_id).map_err(|_| ())?;
    let kyber = claimed.kyber_prekey.as_ref().ok_or(())?;
    let kyber_key_id = u32::try_from(kyber.key_id).map_err(|_| ())?;
    let one_time_pre_key = claimed
        .one_time_prekey
        .as_ref()
        .map(|prekey| {
            Ok(RemotePublicPreKey {
                key_id: u32::try_from(prekey.key_id).map_err(|_| ())?,
                public_key: decode_signal_key(&prekey.public_key)?,
            })
        })
        .transpose()?;

    Ok(RemotePreKeyBundleMaterial {
        registration_id,
        protocol_device_id,
        identity_key: decode_signal_key(&claimed.identity_key)?,
        signed_pre_key: SignalRemoteSignedPreKey {
            key_id: signed_key_id,
            public_key: decode_signal_key(&claimed.signed_prekey.public_key)?,
            signature: decode_signal_key(&claimed.signed_prekey.signature)?,
        },
        kyber_pre_key: SignalRemoteSignedPreKey {
            key_id: kyber_key_id,
            public_key: decode_signal_key(&kyber.public_key)?,
            signature: decode_signal_key(&kyber.signature)?,
        },
        one_time_pre_key,
    })
}

fn prepare_remote_session(
    backend: &mut LibsignalSessionBackend,
    client: &PairingRendezvousClient,
    token: &mut SecureBytes,
    user_id: &str,
    discovered: &RemoteDeviceKeyBundle,
    now: SystemTime,
) -> Result<u32, ()> {
    let registration_id = u32::try_from(discovered.registration_id.ok_or(())?).map_err(|_| ())?;
    let protocol_device_id =
        u32::try_from(discovered.protocol_device_id.ok_or(())?).map_err(|_| ())?;
    if !(1..=16_380).contains(&registration_id)
        || !(1..=127).contains(&protocol_device_id)
        || !is_canonical_device_uuid(&discovered.device_id)
    {
        return Err(());
    }

    let discovered_identity = decode_signal_key(&discovered.identity_key)?;
    if block_on(backend.has_session_for(&discovered.device_id, protocol_device_id))
        .map_err(|_| ())?
    {
        let matches = block_on(backend.remote_identity_matches(
            &discovered.device_id,
            protocol_device_id,
            &discovered_identity,
        ))
        .map_err(|_| ())?;
        return matches.then_some(protocol_device_id).ok_or(());
    }

    let claimed = token
        .with_read(|bytes| client.claim_prekey(bytes, user_id, &discovered.device_id))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if claimed.identity_key != discovered.identity_key
        || claimed.registration_id != discovered.registration_id
        || claimed.protocol_device_id != discovered.protocol_device_id
    {
        return Err(());
    }

    let material = claimed_prekey_material(&claimed)?;
    let mut rng = rand::rng();
    let remote = block_on(backend.process_remote_prekey_material(
        &discovered.device_id,
        &material,
        now,
        &mut rng,
    ))
    .map_err(|_| ())?;
    if u32::from(remote.device_id()) != protocol_device_id {
        return Err(());
    }
    Ok(protocol_device_id)
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

fn ensure_desktop_p2p_manager(core: &mut EnigmaCoreHandle) -> Result<(), ()> {
    if core.desktop_p2p.is_some() {
        return Ok(());
    }
    let (base_url, _) = pairing_server_config().ok_or(())?;
    let device_id = core.device_id.clone().ok_or(())?;
    let manager = {
        let token = core.device_access_token.as_mut().ok_or(())?;
        token
            .with_read(|bytes| DesktopP2pManager::connect(&base_url, &device_id, bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?
    };
    core.desktop_p2p = Some(manager);
    Ok(())
}

fn recover_crypto_transactions(core: &mut EnigmaCoreHandle) -> Result<(), ()> {
    if core.desktop_outbox.is_none() {
        core.desktop_outbox = Some(load_or_create_desktop_outbox()?);
    }
    if core.desktop_inbox.is_none() {
        core.desktop_inbox = Some(load_or_create_desktop_inbox()?);
    }

    recover_outbox_journal(core)?;
    recover_inbox_journal(core)
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
                (*handle).desktop_p2p = None;
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
    if recover_crypto_transactions(core).is_err() {
        return false;
    }
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

fn flush_desktop_outbox(
    core: &mut EnigmaCoreHandle,
    client: &PairingRendezvousClient,
) -> Result<bool, ()> {
    if core.desktop_outbox.is_none() {
        core.desktop_outbox = Some(load_or_create_desktop_outbox()?);
    }
    recover_outbox_journal(core)?;
    let pending = core.desktop_outbox.as_ref().ok_or(())?.pending()?;
    if pending.is_empty() {
        return Ok(true);
    }

    let sender_device_id = core.device_id.clone().ok_or(())?;
    let _ = ensure_desktop_p2p_manager(core);
    let p2p_auth_backend = core.signal_backend.clone();

    let ice_servers = {
        let token = core.device_access_token.as_mut().ok_or(())?;
        token
            .with_read(|bytes| client.turn_credentials(bytes))
            .ok()
            .and_then(Result::ok)
            .and_then(|credentials| {
                turn_ice_servers(
                    &credentials.uris,
                    &credentials.username,
                    &credentials.credential,
                )
                .ok()
            })
            .unwrap_or_default()
    };

    let mut all_sent = true;
    for delivery in pending {
        let mut delivered_p2p = false;
        if let (Some(manager), Some(identity_key), Some(backend)) = (
            core.desktop_p2p.as_mut(),
            delivery.recipient_identity_key.as_deref(),
            p2p_auth_backend.as_ref(),
        ) {
            if let Ok(remote_identity_key) = decode_signal_key(identity_key) {
                if let Ok(session_id) = random_uuid_v4() {
                    delivered_p2p = manager
                        .try_send(
                            backend,
                            &session_id,
                            &delivery.bubble_id,
                            &delivery.sender_device_id,
                            &delivery.recipient_device_id,
                            &delivery.client_message_id,
                            &delivery.message_type,
                            &delivery.ciphertext,
                            &remote_identity_key,
                            &ice_servers,
                        )
                        .ok()
                        .flatten()
                        .is_some();
                }
            }
        }

        if delivered_p2p {
            core.desktop_outbox.as_ref().ok_or(())?.remove(
                &delivery.sender_device_id,
                &delivery.recipient_device_id,
                &delivery.client_message_id,
            )?;
            if let Some(inbox) = core.desktop_inbox.as_ref() {
                let delivered_at = delivery_timestamp();
                let _ = inbox.apply_outbound_receipts(&[(
                    delivery.bubble_id.clone(),
                    delivery.client_message_id.clone(),
                    delivery.recipient_device_id.clone(),
                    "delivered".to_owned(),
                    delivered_at,
                )]);
            }
            continue;
        }

        let request = RelayMessageSend {
            bubble_id: &delivery.bubble_id,
            sender_device_id: &delivery.sender_device_id,
            recipient_device_id: &delivery.recipient_device_id,
            client_message_id: &delivery.client_message_id,
            message_type: &delivery.message_type,
            ciphertext: &delivery.ciphertext,
            attachment_blob_ids: Vec::new(),
        };
        let sent = {
            let token = core.device_access_token.as_mut().ok_or(())?;
            token
                .with_read(|bytes| client.send_message(bytes, &request))
                .map_err(|_| ())?
                .is_ok()
        };
        if sent {
            core.desktop_outbox.as_ref().ok_or(())?.remove(
                &delivery.sender_device_id,
                &delivery.recipient_device_id,
                &delivery.client_message_id,
            )?;
            if let Some(inbox) = core.desktop_inbox.as_ref() {
                let _ = inbox.mark_outbound_relay_sent(
                    &delivery.bubble_id,
                    &delivery.client_message_id,
                    &delivery.recipient_device_id,
                );
            }
        } else {
            all_sent = false;
        }
    }

    Ok(all_sent)
}

fn discover_devices_for(
    core: &mut EnigmaCoreHandle,
    client: &PairingRendezvousClient,
    user_id: &str,
) -> Result<Vec<RemoteDeviceKeyBundle>, ()> {
    let token = core.device_access_token.as_mut().ok_or(())?;
    token
        .with_read(|bytes| client.discover_devices(bytes, user_id))
        .map_err(|_| ())?
        .map_err(|_| ())
}

fn verified_sender_sync_targets(
    backend: &LibsignalSessionBackend,
    own_user_id: &str,
    sender_device_id: &str,
    devices: &[RemoteDeviceKeyBundle],
) -> Result<Vec<RemoteDeviceKeyBundle>, ()> {
    let current = devices
        .iter()
        .find(|device| device.device_id == sender_device_id)
        .ok_or(())?;
    let current_authorization = current.authorization.as_ref().ok_or(())?;
    let local_identity = STANDARD_NO_PAD.encode(backend.identity_public_key());
    if current.identity_key != local_identity {
        return Err(());
    }

    let authorizer = devices
        .iter()
        .find(|device| device.device_id == current_authorization.authorizing_device_id)
        .ok_or(())?;
    let authorizer_identity = decode_signal_key(&authorizer.identity_key)?;
    let current_signature = decode_signal_key(&current_authorization.authorizer_signature)?;
    let verifier = LibsignalIdentityProofVerifier;
    verify_linked_device_authorization_binding(
        &verifier,
        &authorizer_identity,
        &current_authorization.canonical_payload,
        &current_signature,
        own_user_id,
        sender_device_id,
        &authorizer.device_id,
        &current.identity_key,
    )
    .map_err(|_| ())?;

    let mut targets = Vec::new();
    for device in devices {
        if device.device_id == sender_device_id {
            continue;
        }
        if device.device_id == authorizer.device_id {
            targets.push(device.clone());
            continue;
        }

        let Some(authorization) = device.authorization.as_ref() else {
            continue;
        };
        if authorization.authorizing_device_id != authorizer.device_id {
            return Err(());
        }
        let signature = decode_signal_key(&authorization.authorizer_signature)?;
        verify_linked_device_authorization_binding(
            &verifier,
            &authorizer_identity,
            &authorization.canonical_payload,
            &signature,
            own_user_id,
            &device.device_id,
            &authorizer.device_id,
            &device.identity_key,
        )
        .map_err(|_| ())?;
        targets.push(device.clone());
    }
    Ok(targets)
}

struct OutboundDeliveryContext<'a> {
    sender_device_id: &'a str,
    recipient_user_id: &'a str,
    bubble_id: &'a str,
    client_message_id: &'a str,
    message_type: &'a str,
    plaintext: &'a str,
    sender_sync: bool,
    now: SystemTime,
}

fn prepare_outbound_delivery(
    backend: &mut LibsignalSessionBackend,
    client: &PairingRendezvousClient,
    token: &mut SecureBytes,
    recipient: &RemoteDeviceKeyBundle,
    context: &OutboundDeliveryContext<'_>,
) -> Result<DurableOutboundDelivery, ()> {
    if recipient.device_id == context.sender_device_id {
        return Err(());
    }
    let protocol_device_id = prepare_remote_session(
        backend,
        client,
        token,
        context.recipient_user_id,
        recipient,
        context.now,
    )?;
    let mut rng = rand::rng();
    let ciphertext = block_on(backend.encrypt_wire_for_device(
        context.sender_device_id,
        V1_PROTOCOL_DEVICE_ID,
        &recipient.device_id,
        protocol_device_id,
        context.plaintext.as_bytes(),
        context.now,
        &mut rng,
    ))
    .map_err(|_| ())?;

    Ok(DurableOutboundDelivery {
        bubble_id: context.bubble_id.to_owned(),
        sender_device_id: context.sender_device_id.to_owned(),
        recipient_device_id: recipient.device_id.clone(),
        client_message_id: context.client_message_id.to_owned(),
        message_type: context.message_type.to_owned(),
        ciphertext,
        sender_sync: context.sender_sync,
        recipient_identity_key: Some(recipient.identity_key.clone()),
    })
}

fn contacts_json(
    core: &mut EnigmaCoreHandle,
    client: &PairingRendezvousClient,
) -> Result<Vec<u8>, ()> {
    let token = core.device_access_token.as_mut().ok_or(())?;
    let contacts = token
        .with_read(|bytes| client.contacts(bytes))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    serde_json::to_vec(&contacts).map_err(|_| ())
}

fn main_bubble_id(
    core: &mut EnigmaCoreHandle,
    client: &PairingRendezvousClient,
) -> Result<String, ()> {
    let token = core.device_access_token.as_mut().ok_or(())?;
    let bubbles = token
        .with_read(|bytes| client.bubbles(bytes))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    bubbles
        .into_iter()
        .find(|bubble| bubble.mode == "MAIN_GLOBAL")
        .map(|bubble| bubble.id)
        .ok_or(())
}

/// Returns the UTF-8 JSON length for the authenticated account contact list.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_contacts_json_len(handle: *mut EnigmaCoreHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    let Some(client) = pairing_client() else {
        return 0;
    };
    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    let Ok(encoded) = contacts_json(core, &client) else {
        core.contacts_json_cache = None;
        return 0;
    };
    let length = encoded.len();
    core.contacts_json_cache = Some(encoded);
    length
}

/// Copies the authenticated account contact list as UTF-8 JSON.
///
/// # Safety
///
/// handle must be live or null. output must reference at least output_len writable bytes and must
/// not overlap Rust-owned storage. The same handle must not be concurrently mutated or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_contacts_json_copy(
    handle: *mut EnigmaCoreHandle,
    output: *mut u8,
    output_len: usize,
) -> bool {
    if handle.is_null() || output.is_null() {
        return false;
    }
    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    let Some(encoded) = core.contacts_json_cache.as_ref() else {
        return false;
    };
    if encoded.len() != output_len {
        return false;
    }
    let copied = copy_pairing_bytes(encoded, output, output_len);
    if copied {
        core.contacts_json_cache = None;
    }
    copied
}

/// Sends text to one saved contact using the account MAIN_GLOBAL bubble.
///
/// # Safety
///
/// handle and all input buffers must be live for this call. The handle must not be concurrently
/// accessed or destroyed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_send_text_to_contact(
    handle: *mut EnigmaCoreHandle,
    recipient_user_id: *const u8,
    recipient_user_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> bool {
    if handle.is_null() {
        return false;
    }
    // SAFETY: caller guarantees readable input buffers for the declared lengths.
    let Some(recipient_user_id) =
        (unsafe { read_utf8_input(recipient_user_id, recipient_user_id_len, 36) })
    else {
        return false;
    };
    // SAFETY: caller guarantees readable input buffers for the declared lengths.
    let Some(plaintext) =
        (unsafe { read_utf8_input(plaintext, plaintext_len, MAX_OUTBOUND_TEXT_BYTES) })
    else {
        return false;
    };
    if !is_canonical_device_uuid(&recipient_user_id) || plaintext.trim().is_empty() {
        return false;
    }

    let Some(client) = pairing_client() else {
        return false;
    };
    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    let contact = {
        let Some(token) = core.device_access_token.as_mut() else {
            return false;
        };
        let contacts = match token.with_read(|bytes| client.contacts(bytes)) {
            Ok(Ok(contacts)) => contacts,
            Ok(Err(_)) | Err(_) => return false,
        };
        match contacts.into_iter().find(|contact| contact.user_id == recipient_user_id) {
            Some(contact) => contact,
            None => return false,
        }
    };
    let bubble_id = match main_bubble_id(core, &client) {
        Ok(value) => value,
        Err(()) => return false,
    };

    let public_id = contact.public_id;
    let request = EnigmaSendTextRequest {
        recipient_user_id: recipient_user_id.as_ptr(),
        recipient_user_id_len: recipient_user_id.len(),
        recipient_public_id: public_id.as_ptr(),
        recipient_public_id_len: public_id.len(),
        recipient_display_name: public_id.as_ptr(),
        recipient_display_name_len: public_id.len(),
        bubble_id: bubble_id.as_ptr(),
        bubble_id_len: bubble_id.len(),
        plaintext: plaintext.as_ptr(),
        plaintext_len: plaintext.len(),
    };
    // SAFETY: every pointer in request refers to Rust-owned strings that remain alive for this call,
    // and handle is exclusively borrowed by the current FFI invocation.
    unsafe { enigma_core_send_text(handle, &request) }
}

/// Encrypts and durably queues one text message for every active recipient device and every
/// sibling device required for sender-sync. The function returns true once the exact ciphertext
/// fanout and the advanced libsignal state are durably committed locally. Relay delivery is
/// attempted immediately but may complete later through enigma_core_retry_outbox.
///
/// # Safety
///
/// handle and request must be live, non-null and exclusively accessed for this call. Every request
/// pointer must reference the declared number of readable bytes and remain valid until return.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_send_text(
    handle: *mut EnigmaCoreHandle,
    request: *const EnigmaSendTextRequest,
) -> bool {
    if handle.is_null() || request.is_null() {
        return false;
    }

    // SAFETY: the caller contract guarantees a live request structure for this call.
    let request = unsafe { &*request };
    // SAFETY: request fields are caller-owned readable buffers covered by the FFI contract.
    let Some(recipient_user_id) = (unsafe {
        read_utf8_input(request.recipient_user_id, request.recipient_user_id_len, 36)
    }) else {
        return false;
    };
    // SAFETY: request fields are caller-owned readable buffers covered by the FFI contract.
    let Some(recipient_public_id) = (unsafe {
        read_utf8_input(
            request.recipient_public_id,
            request.recipient_public_id_len,
            MAX_CONTACT_PUBLIC_ID_BYTES,
        )
    }) else {
        return false;
    };
    // SAFETY: request fields are caller-owned readable buffers covered by the FFI contract.
    let Some(recipient_display_name) = (unsafe {
        read_utf8_input(
            request.recipient_display_name,
            request.recipient_display_name_len,
            MAX_CONTACT_DISPLAY_NAME_BYTES,
        )
    }) else {
        return false;
    };
    // SAFETY: request fields are caller-owned readable buffers covered by the FFI contract.
    let Some(bubble_id) =
        (unsafe { read_utf8_input(request.bubble_id, request.bubble_id_len, 36) })
    else {
        return false;
    };
    // SAFETY: request fields are caller-owned readable buffers covered by the FFI contract.
    let Some(plaintext) = (unsafe {
        read_utf8_input(
            request.plaintext,
            request.plaintext_len,
            MAX_OUTBOUND_TEXT_BYTES,
        )
    }) else {
        return false;
    };

    if !is_canonical_device_uuid(&recipient_user_id)
        || !is_canonical_device_uuid(&bubble_id)
        || recipient_public_id.trim().is_empty()
        || recipient_display_name.trim().is_empty()
    {
        return false;
    }

    let Some(client) = pairing_client() else {
        return false;
    };
    // SAFETY: caller guarantees exclusive live access to the core handle.
    let core = unsafe { &mut *handle };
    let Some(sender_device_id) = core.device_id.clone() else {
        return false;
    };
    if core.device_access_token.is_none() || core.signal_backend.is_none() {
        return false;
    }
    if recover_crypto_transactions(core).is_err() {
        return false;
    }

    let own_user_id = {
        let Some(token) = core.device_access_token.as_mut() else {
            return false;
        };
        match token.with_read(|bytes| client.account_user_id(bytes)) {
            Ok(Ok(user_id)) => user_id,
            Ok(Err(_)) | Err(_) => return false,
        }
    };
    if recipient_user_id == own_user_id {
        return false;
    }

    let recipient_devices = match discover_devices_for(core, &client, &recipient_user_id) {
        Ok(devices) if !devices.is_empty() => devices,
        Ok(_) | Err(_) => return false,
    };
    let own_devices = match discover_devices_for(core, &client, &own_user_id) {
        Ok(devices) => devices,
        Err(()) => return false,
    };
    let sibling_devices = match core.signal_backend.as_ref().and_then(|backend| {
        verified_sender_sync_targets(
            backend,
            &own_user_id,
            &sender_device_id,
            &own_devices,
        )
        .ok()
    }) {
        Some(devices) => devices,
        None => return false,
    };
    let encoded_payload = match encode_text_payload(&plaintext) {
        Ok(payload) => payload,
        Err(()) => return false,
    };
    let client_message_id = match random_uuid_v4() {
        Ok(value) => value,
        Err(()) => return false,
    };
    let created_at = match current_unix_ms().and_then(|value| i64::try_from(value).ok()) {
        Some(value) => value,
        None => return false,
    };
    let sender_sync_payload = match encode_sender_sync_payload(
        &recipient_user_id,
        &recipient_public_id,
        &recipient_display_name,
        &bubble_id,
        &client_message_id,
        created_at,
        &encoded_payload,
    ) {
        Ok(payload) => payload,
        Err(()) => return false,
    };

    let Some(mut working_backend) = core.signal_backend.clone() else {
        return false;
    };
    let now = SystemTime::now();
    let mut deliveries = Vec::with_capacity(recipient_devices.len() + sibling_devices.len());

    for recipient in &recipient_devices {
        let delivery = {
            let Some(token) = core.device_access_token.as_mut() else {
                return false;
            };
            let context = OutboundDeliveryContext {
                sender_device_id: &sender_device_id,
                recipient_user_id: &recipient_user_id,
                bubble_id: &bubble_id,
                client_message_id: &client_message_id,
                message_type: "text",
                plaintext: &encoded_payload,
                sender_sync: false,
                now,
            };
            prepare_outbound_delivery(
                &mut working_backend,
                &client,
                token,
                recipient,
                &context,
            )
        };
        match delivery {
            Ok(delivery) => deliveries.push(delivery),
            Err(()) => return false,
        }
    }

    for sibling in sibling_devices
        .iter()
        .filter(|device| device.device_id != sender_device_id)
    {
        let delivery = {
            let Some(token) = core.device_access_token.as_mut() else {
                return false;
            };
            let context = OutboundDeliveryContext {
                sender_device_id: &sender_device_id,
                recipient_user_id: &own_user_id,
                bubble_id: &bubble_id,
                client_message_id: &client_message_id,
                message_type: "opaque",
                plaintext: &sender_sync_payload,
                sender_sync: true,
                now,
            };
            prepare_outbound_delivery(
                &mut working_backend,
                &client,
                token,
                sibling,
                &context,
            )
        };
        match delivery {
            Ok(delivery) => deliveries.push(delivery),
            Err(()) => return false,
        }
    }
    if deliveries.is_empty() {
        return false;
    }

    let Some(primary_recipient_device_id) = deliveries
        .iter()
        .find(|delivery| !delivery.sender_sync)
        .map(|delivery| delivery.recipient_device_id.clone())
    else {
        return false;
    };
    let delivery_recipient_device_ids: Vec<String> = deliveries
        .iter()
        .filter(|delivery| !delivery.sender_sync)
        .map(|delivery| delivery.recipient_device_id.clone())
        .collect();
    let local_entry = DurableInboxEntry {
        remote_message_id: client_message_id.clone(),
        bubble_id: bubble_id.clone(),
        sender_device_id: sender_device_id.clone(),
        sender_user_id: own_user_id.clone(),
        sender_public_id: own_user_id.clone(),
        recipient_device_id: primary_recipient_device_id,
        client_message_id: client_message_id.clone(),
        message_type: "text".to_owned(),
        plaintext: encoded_payload.clone(),
        created_at: created_at.to_string(),
        expires_at: "local".to_owned(),
        direction: "outbound".to_owned(),
        contact_user_id: Some(recipient_user_id.clone()),
        contact_public_id: Some(recipient_public_id.clone()),
        contact_display_name: Some(recipient_display_name.clone()),
        original_created_at_unix_ms: Some(created_at),
        delivery_status: Some("queued".to_owned()),
        delivery_updated_at: None,
        delivery_recipient_device_ids,
    };

    let mut snapshot = match working_backend.export_serialized_store() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let journal_written = core.desktop_outbox.as_ref().is_some_and(|outbox| {
        outbox
            .write_journal(&deliveries, &snapshot, Some(&local_entry))
            .is_ok()
    });
    snapshot.fill(0);
    if !journal_written {
        return false;
    }
    if persist_default_signal_store(&working_backend).is_err() {
        return false;
    }
    if core
        .desktop_outbox
        .as_ref()
        .is_none_or(|outbox| outbox.enqueue_batch(&deliveries).is_err())
    {
        return false;
    }
    if core
        .desktop_inbox
        .as_ref()
        .is_none_or(|inbox| inbox.append(local_entry).is_err())
    {
        return false;
    }

    core.signal_backend = Some(working_backend);
    if let Some(outbox) = core.desktop_outbox.as_ref() {
        let _ = outbox.clear_journal();
    }
    let _ = flush_desktop_outbox(core, &client);
    true
}

fn poll_one_incoming_p2p(
    core: &mut EnigmaCoreHandle,
    client: &PairingRendezvousClient,
) -> Result<bool, ()> {
    ensure_desktop_p2p_manager(core)?;
    let offer = match core
        .desktop_p2p
        .as_mut()
        .and_then(DesktopP2pManager::take_incoming_offer)
    {
        Some(offer) => offer,
        None => return Ok(false),
    };

    let local_device_id = core.device_id.clone().ok_or(())?;
    if offer.sender_device_id == local_device_id {
        return Err(());
    }

    let own_user_id = {
        let token = core.device_access_token.as_mut().ok_or(())?;
        token
            .with_read(|bytes| client.account_user_id(bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?
    };
    let own_devices = discover_devices_for(core, client, &own_user_id)?;
    let verified_sibling_ids: HashSet<String> = {
        let backend = core.signal_backend.as_ref().ok_or(())?;
        verified_sender_sync_targets(
            backend,
            &own_user_id,
            &local_device_id,
            &own_devices,
        )?
        .into_iter()
        .map(|device| device.device_id)
        .collect()
    };

    let remote_devices = if offer.sender_user_id == own_user_id {
        if !verified_sibling_ids.contains(&offer.sender_device_id) {
            return Err(());
        }
        own_devices
    } else {
        discover_devices_for(core, client, &offer.sender_user_id)?
    };
    let remote_device = remote_devices
        .iter()
        .find(|device| device.device_id == offer.sender_device_id)
        .ok_or(())?;
    let remote_identity = decode_signal_key(&remote_device.identity_key)?;

    let sender_public_id = if offer.sender_user_id == own_user_id {
        own_user_id.clone()
    } else {
        let contacts = {
            let token = core.device_access_token.as_mut().ok_or(())?;
            token
                .with_read(|bytes| client.contacts(bytes))
                .map_err(|_| ())?
                .map_err(|_| ())?
        };
        contacts
            .into_iter()
            .find(|contact| contact.user_id == offer.sender_user_id)
            .map(|contact| contact.public_id)
            .ok_or(())?
    };

    let ice_servers = {
        let token = core.device_access_token.as_mut().ok_or(())?;
        token
            .with_read(|bytes| client.turn_credentials(bytes))
            .ok()
            .and_then(Result::ok)
            .and_then(|credentials| {
                turn_ice_servers(
                    &credentials.uris,
                    &credentials.username,
                    &credentials.credential,
                )
                .ok()
            })
            .unwrap_or_default()
    };

    let auth_backend = core.signal_backend.clone().ok_or(())?;
    let inbound = core
        .desktop_p2p
        .as_mut()
        .ok_or(())?
        .accept_incoming_until_message(
            &auth_backend,
            &local_device_id,
            &offer,
            &remote_identity,
            &ice_servers,
        )?;
    let Some(inbound) = inbound else {
        return Ok(true);
    };

    if inbound.sender_user_id != offer.sender_user_id
        || inbound.sender_device_id != offer.sender_device_id
        || inbound.recipient_device_id != local_device_id
    {
        return Err(());
    }

    let created_at = delivery_timestamp();
    let delivery = InboundEncryptedDelivery {
        remote_message_id: &inbound.client_message_id,
        bubble_id: &inbound.bubble_id,
        sender_device_id: &inbound.sender_device_id,
        sender_user_id: &inbound.sender_user_id,
        sender_public_id: &sender_public_id,
        recipient_device_id: &inbound.recipient_device_id,
        client_message_id: &inbound.client_message_id,
        message_type: &inbound.message_type,
        ciphertext: &inbound.ciphertext,
        created_at: &created_at,
        expires_at: "p2p",
    };
    commit_inbound_encrypted_delivery(
        core,
        &own_user_id,
        &verified_sibling_ids,
        &delivery,
    )?;

    core.desktop_p2p
        .as_mut()
        .ok_or(())?
        .acknowledge_incoming_delivery(
            &inbound.session_id,
            &inbound.client_message_id,
        )?;
    Ok(true)
}

/// Polls one authenticated incoming P2P offer, if present.
///
/// The function returns true when the P2P listener is healthy, including when no offer is queued.
/// Any received ciphertext is committed with the same crash-safe Signal/inbox transaction used by
/// relay delivery before a DELIVERED receipt is emitted.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_poll_p2p(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    let Some(client) = pairing_client() else {
        return false;
    };
    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    if core.device_access_token.is_none()
        || core.signal_backend.is_none()
        || recover_crypto_transactions(core).is_err()
    {
        return false;
    }
    poll_one_incoming_p2p(core, &client).is_ok()
}

/// Retries all durably encrypted outbound deliveries without re-encrypting or advancing ratchets.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and exclusively accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_retry_outbox(handle: *mut EnigmaCoreHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    let Some(client) = pairing_client() else {
        return false;
    };
    // SAFETY: caller guarantees exclusive live access for this call.
    let core = unsafe { &mut *handle };
    if core.device_access_token.is_none()
        || core.signal_backend.is_none()
        || recover_crypto_transactions(core).is_err()
    {
        return false;
    }
    flush_desktop_outbox(core, &client).unwrap_or(false)
}

/// Returns the number of durably queued outbound device deliveries.
///
/// # Safety
///
/// handle must be null or a live pointer returned by enigma_core_create and immutably accessed.
#[no_mangle]
pub unsafe extern "C" fn enigma_core_outbox_count(handle: *const EnigmaCoreHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees immutable live access for this read.
    let core = unsafe { &*handle };
    core.desktop_outbox
        .as_ref()
        .and_then(|outbox| outbox.pending().ok())
        .map_or(0, |pending| pending.len())
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
    if recover_crypto_transactions(core).is_err() {
        return false;
    }

    let own_user_id = {
        let Some(token) = core.device_access_token.as_mut() else {
            return false;
        };
        match token.with_read(|bytes| client.account_user_id(bytes)) {
            Ok(Ok(user_id)) => user_id,
            Ok(Err(_)) | Err(_) => return false,
        }
    };
    let own_devices = match discover_devices_for(core, &client, &own_user_id) {
        Ok(devices) => devices,
        Err(()) => return false,
    };
    let verified_sibling_ids: HashSet<String> = match core
        .signal_backend
        .as_ref()
        .and_then(|backend| {
            verified_sender_sync_targets(backend, &own_user_id, &device_id, &own_devices).ok()
        })
    {
        Some(devices) => devices.into_iter().map(|device| device.device_id).collect(),
        None => return false,
    };

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
        let already_durable = core.desktop_inbox.as_ref().is_some_and(|inbox| {
            inbox
                .contains_remote_message(&message.id)
                .unwrap_or(false)
                || inbox
                    .contains_client_delivery(
                        &message.sender_device_id,
                        &message.client_message_id,
                    )
                    .unwrap_or(false)
        });

        if !already_durable {
            let delivery = InboundEncryptedDelivery {
                remote_message_id: &message.id,
                bubble_id: &message.bubble_id,
                sender_device_id: &message.sender_device_id,
                sender_user_id: &message.sender_user_id,
                sender_public_id: &message.sender_public_id,
                recipient_device_id: &message.recipient_device_id,
                client_message_id: &message.client_message_id,
                message_type: &message.message_type,
                ciphertext: &message.ciphertext,
                created_at: &message.created_at,
                expires_at: &message.expires_at,
            };
            if commit_inbound_encrypted_delivery(
                core,
                &own_user_id,
                &verified_sibling_ids,
                &delivery,
            )
            .is_err()
            {
                return false;
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

    let receipts = {
        let Some(token) = core.device_access_token.as_mut() else {
            return false;
        };
        token
            .with_read(|bytes| client.sent_receipts(bytes, &device_id))
            .ok()
            .and_then(Result::ok)
    };
    if let Some(receipts) = receipts {
        let statuses: Vec<(String, String, String, String, String)> = receipts
            .into_iter()
            .map(|receipt| {
                (
                    receipt.bubble_id,
                    receipt.client_message_id,
                    receipt.recipient_device_id,
                    receipt.status,
                    receipt.delivered_at,
                )
            })
            .collect();
        if let Some(inbox) = core.desktop_inbox.as_ref() {
            let _ = inbox.apply_outbound_receipts(&statuses);
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
    let Some((deliveries, mut snapshot, local_inbox_entry)) = journal else {
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
    if let Some(entry) = local_inbox_entry {
        core.desktop_inbox.as_ref().ok_or(())?.append(entry)?;
    }
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
    fn desktop_text_payload_matches_android_contract() {
        let encoded = encode_text_payload("Bonjour ENIGMA").expect("text payload");
        assert!(encoded.starts_with("ENIGMA_PAYLOAD_V1:"));
        let body = encoded
            .strip_prefix("ENIGMA_PAYLOAD_V1:")
            .expect("payload prefix");
        let json: serde_json::Value = serde_json::from_str(body).expect("payload json");
        assert_eq!(json["version"], 1);
        assert_eq!(json["body"], "Bonjour ENIGMA");
        assert_eq!(json["attachments"], serde_json::json!([]));
        assert!(encode_text_payload("   ").is_err());
    }

    #[test]
    fn desktop_sender_sync_matches_android_contract() {
        let encoded_payload = encode_text_payload("Bonjour").expect("payload");
        let encoded = encode_sender_sync_payload(
            "11111111-1111-4111-8111-111111111111",
            "alice",
            "Alice",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            1_700_000_000_000,
            &encoded_payload,
        )
        .expect("sender sync");
        assert!(encoded.starts_with("ENIGMA_SENDER_SYNC_V1:"));
        let body = encoded
            .strip_prefix("ENIGMA_SENDER_SYNC_V1:")
            .expect("sender sync prefix");
        let json: serde_json::Value = serde_json::from_str(body).expect("sender sync json");
        assert_eq!(json["version"], 1);
        assert_eq!(
            json["contactUserId"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(json["contactPublicId"], "alice");
        assert_eq!(json["contactDisplayName"], "Alice");
        assert_eq!(
            json["bubbleId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            json["clientMessageId"],
            "33333333-3333-4333-8333-333333333333"
        );
        assert_eq!(json["originalCreatedAt"], 1_700_000_000_000_i64);
        assert_eq!(json["encodedMessagePayload"], encoded_payload);
    }

    #[test]
    fn inbound_payload_requires_android_message_contract() {
        let bubble_id = "22222222-2222-4222-8222-222222222222";
        let payload = encode_text_payload("Bonjour").expect("payload");
        let normalized = normalize_inbound_payload(
            payload.clone(),
            "text",
            bubble_id,
            "33333333-3333-4333-8333-333333333333",
            "11111111-1111-4111-8111-111111111111",
            "alice",
            "44444444-4444-4444-8444-444444444444",
            false,
        )
        .expect("valid inbound payload");
        assert_eq!(normalized.direction, "inbound");
        assert_eq!(normalized.contact_public_id, "alice");
        assert_eq!(normalized.message_type, "text");
        assert_eq!(normalized.plaintext, payload);

        assert!(normalize_inbound_payload(
            "plaintext libre".to_owned(),
            "text",
            bubble_id,
            "33333333-3333-4333-8333-333333333333",
            "11111111-1111-4111-8111-111111111111",
            "alice",
            "44444444-4444-4444-8444-444444444444",
            false,
        )
        .is_err());
    }

    #[test]
    fn verified_sender_sync_normalizes_to_outbound_contact_message() {
        let own_user_id = "44444444-4444-4444-8444-444444444444";
        let contact_user_id = "11111111-1111-4111-8111-111111111111";
        let bubble_id = "22222222-2222-4222-8222-222222222222";
        let client_message_id = "33333333-3333-4333-8333-333333333333";
        let payload = encode_text_payload("Synchronisé").expect("payload");
        let sender_sync = encode_sender_sync_payload(
            contact_user_id,
            "alice",
            "Alice",
            bubble_id,
            client_message_id,
            1_700_000_000_000,
            &payload,
        )
        .expect("sender sync");

        let normalized = normalize_inbound_payload(
            sender_sync.clone(),
            "opaque",
            bubble_id,
            client_message_id,
            own_user_id,
            "me",
            own_user_id,
            true,
        )
        .expect("verified sender sync");
        assert_eq!(normalized.direction, "outbound");
        assert_eq!(normalized.contact_user_id, contact_user_id);
        assert_eq!(normalized.contact_public_id, "alice");
        assert_eq!(normalized.contact_display_name, "Alice");
        assert_eq!(normalized.message_type, "text");
        assert_eq!(normalized.plaintext, payload);
        assert_eq!(
            normalized.original_created_at_unix_ms,
            Some(1_700_000_000_000)
        );

        assert!(normalize_inbound_payload(
            sender_sync,
            "opaque",
            bubble_id,
            client_message_id,
            own_user_id,
            "me",
            own_user_id,
            false,
        )
        .is_err());
    }

    #[test]
    fn generated_message_id_is_canonical_uuid_v4() {
        let id = random_uuid_v4().expect("uuid");
        assert!(is_canonical_device_uuid(&id));
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

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
