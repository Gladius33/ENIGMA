#![forbid(unsafe_code)]

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use enigma_storage::{RecordVault, SodiumRecordVault};
use serde::{Deserialize, Serialize};

const INBOX_AAD: &[u8] = b"ENIGMA_DESKTOP_INBOX_V1";
const JOURNAL_AAD: &[u8] = b"ENIGMA_DESKTOP_INBOX_JOURNAL_V1";
const MAX_INBOX_ENTRIES: usize = 16_384;
const MAX_INBOX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct DurableInboxEntry {
    pub remote_message_id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub sender_user_id: String,
    pub sender_public_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub message_type: String,
    pub plaintext: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default)]
    pub contact_user_id: Option<String>,
    #[serde(default)]
    pub contact_public_id: Option<String>,
    #[serde(default)]
    pub contact_display_name: Option<String>,
    #[serde(default)]
    pub original_created_at_unix_ms: Option<i64>,
    #[serde(default)]
    pub delivery_status: Option<String>,
    #[serde(default)]
    pub delivery_updated_at: Option<String>,
    #[serde(default)]
    pub delivery_recipient_device_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InboxFile {
    version: u16,
    entries: Vec<DurableInboxEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InboxJournal {
    version: u16,
    entry: DurableInboxEntry,
    signal_snapshot: String,
}

pub(crate) struct EncryptedDesktopInbox {
    inbox_path: PathBuf,
    journal_path: PathBuf,
    vault: SodiumRecordVault,
}

impl EncryptedDesktopInbox {
    pub(crate) fn new(
        inbox_path: PathBuf,
        journal_path: PathBuf,
        vault: SodiumRecordVault,
    ) -> Self {
        Self {
            inbox_path,
            journal_path,
            vault,
        }
    }

    pub(crate) fn entries(&self) -> Result<Vec<DurableInboxEntry>, ()> {
        self.read_entries()
    }

    pub(crate) fn contains_remote_message(&self, remote_message_id: &str) -> Result<bool, ()> {
        validate_uuid(remote_message_id)?;
        Ok(self
            .read_entries()?
            .iter()
            .any(|entry| entry.remote_message_id == remote_message_id))
    }

    pub(crate) fn contains_client_delivery(
        &self,
        sender_device_id: &str,
        client_message_id: &str,
    ) -> Result<bool, ()> {
        validate_uuid(sender_device_id)?;
        validate_uuid(client_message_id)?;
        Ok(self.read_entries()?.iter().any(|entry| {
            entry.sender_device_id == sender_device_id
                && entry.client_message_id == client_message_id
        }))
    }

    pub(crate) fn apply_outbound_receipts(
        &self,
        receipts: &[(String, String, String, String, String)],
    ) -> Result<bool, ()> {
        if receipts.len() > 500 {
            return Err(());
        }

        for (bubble_id, client_message_id, recipient_device_id, status, delivered_at) in receipts {
            validate_uuid(bubble_id)?;
            validate_uuid(client_message_id)?;
            validate_uuid(recipient_device_id)?;
            if !matches!(status.as_str(), "delivered" | "read")
                || delivered_at.is_empty()
                || delivered_at.len() > 128
            {
                return Err(());
            }
        }

        let mut entries = self.read_entries()?;
        let mut changed = false;
        for (bubble_id, client_message_id, recipient_device_id, status, delivered_at) in receipts {
            for entry in entries.iter_mut().filter(|entry| {
                entry.direction == "outbound"
                    && entry.bubble_id == bubble_id.as_str()
                    && entry.client_message_id == client_message_id.as_str()
                    && entry
                        .delivery_recipient_device_ids
                        .iter()
                        .any(|device_id| device_id == recipient_device_id)
            }) {
                let current_rank = delivery_status_rank(entry.delivery_status.as_deref());
                let next_rank = delivery_status_rank(Some(status.as_str()));
                if next_rank > current_rank {
                    entry.delivery_status = Some(status.clone());
                    entry.delivery_updated_at = Some(delivered_at.clone());
                    changed = true;
                }
            }
        }

        if changed {
            self.write_entries(&entries)?;
        }
        Ok(changed)
    }

    pub(crate) fn mark_outbound_relay_sent(
        &self,
        bubble_id: &str,
        client_message_id: &str,
        recipient_device_id: &str,
    ) -> Result<bool, ()> {
        validate_uuid(bubble_id)?;
        validate_uuid(client_message_id)?;
        validate_uuid(recipient_device_id)?;

        let mut entries = self.read_entries()?;
        let mut changed = false;
        for entry in entries.iter_mut().filter(|entry| {
            entry.direction == "outbound"
                && entry.bubble_id == bubble_id
                && entry.client_message_id == client_message_id
                && entry
                    .delivery_recipient_device_ids
                    .iter()
                    .any(|device_id| device_id == recipient_device_id)
        }) {
            if delivery_status_rank(entry.delivery_status.as_deref())
                < delivery_status_rank(Some("sent"))
            {
                entry.delivery_status = Some("sent".to_owned());
                changed = true;
            }
        }

        if changed {
            self.write_entries(&entries)?;
        }
        Ok(changed)
    }

    pub(crate) fn append(&self, entry: DurableInboxEntry) -> Result<(), ()> {
        validate_entry(&entry)?;
        let mut entries = self.read_entries()?;
        if let Some(existing) = entries
            .iter()
            .find(|existing| existing.remote_message_id == entry.remote_message_id)
        {
            if existing == &entry {
                return Ok(());
            }
            return Err(());
        }
        if entries.len() >= MAX_INBOX_ENTRIES {
            return Err(());
        }
        entries.push(entry);
        self.write_entries(&entries)
    }

    pub(crate) fn write_journal(
        &self,
        entry: &DurableInboxEntry,
        signal_snapshot: &[u8],
    ) -> Result<(), ()> {
        validate_entry(entry)?;
        if signal_snapshot.is_empty() || signal_snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(());
        }
        let journal = InboxJournal {
            version: 1,
            entry: entry.clone(),
            signal_snapshot: STANDARD_NO_PAD.encode(signal_snapshot),
        };
        let plaintext = serde_json::to_vec(&journal).map_err(|_| ())?;
        let sealed = self.vault.seal(&plaintext, JOURNAL_AAD).map_err(|_| ())?;
        persist_atomic(&self.journal_path, &sealed).map_err(|_| ())
    }

    pub(crate) fn read_journal(&self) -> Result<Option<(DurableInboxEntry, Vec<u8>)>, ()> {
        let sealed = match fs::read(&self.journal_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if sealed.is_empty() || sealed.len() > MAX_INBOX_FILE_BYTES {
            return Err(());
        }
        let mut plaintext = self.vault.open(&sealed, JOURNAL_AAD).map_err(|_| ())?;
        let parsed = plaintext
            .with_read(|bytes| serde_json::from_slice::<InboxJournal>(bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if parsed.version != 1 {
            return Err(());
        }
        validate_entry(&parsed.entry)?;
        let snapshot = STANDARD_NO_PAD
            .decode(parsed.signal_snapshot)
            .map_err(|_| ())?;
        if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(());
        }
        Ok(Some((parsed.entry, snapshot)))
    }

    pub(crate) fn clear_journal(&self) -> Result<(), ()> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn read_entries(&self) -> Result<Vec<DurableInboxEntry>, ()> {
        let sealed = match fs::read(&self.inbox_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
        };
        if sealed.is_empty() || sealed.len() > MAX_INBOX_FILE_BYTES {
            return Err(());
        }

        let mut plaintext = self.vault.open(&sealed, INBOX_AAD).map_err(|_| ())?;
        let decoded = plaintext
            .with_read(|bytes| serde_json::from_slice::<InboxFile>(bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if decoded.version != 1 || decoded.entries.len() > MAX_INBOX_ENTRIES {
            return Err(());
        }
        decoded.entries.iter().try_for_each(validate_entry)?;
        Ok(decoded.entries)
    }

    fn write_entries(&self, entries: &[DurableInboxEntry]) -> Result<(), ()> {
        if entries.len() > MAX_INBOX_ENTRIES {
            return Err(());
        }
        entries.iter().try_for_each(validate_entry)?;
        let plaintext = serde_json::to_vec(&InboxFile {
            version: 1,
            entries: entries.to_vec(),
        })
        .map_err(|_| ())?;
        if plaintext.len() > MAX_INBOX_FILE_BYTES {
            return Err(());
        }
        let sealed = self.vault.seal(&plaintext, INBOX_AAD).map_err(|_| ())?;
        persist_atomic(&self.inbox_path, &sealed).map_err(|_| ())
    }
}

fn default_direction() -> String {
    "inbound".to_owned()
}

pub(crate) fn validate_entry(entry: &DurableInboxEntry) -> Result<(), ()> {
    validate_uuid(&entry.remote_message_id)?;
    validate_uuid(&entry.bubble_id)?;
    validate_uuid(&entry.sender_device_id)?;
    validate_uuid(&entry.sender_user_id)?;
    validate_uuid(&entry.recipient_device_id)?;
    validate_uuid(&entry.client_message_id)?;
    if entry.sender_public_id.is_empty()
        || entry.sender_public_id.len() > 256
        || !matches!(entry.direction.as_str(), "inbound" | "outbound")
        || entry.message_type.is_empty()
        || entry.message_type.len() > 64
        || entry.plaintext.is_empty()
        || entry.plaintext.len() > MAX_PLAINTEXT_BYTES
        || entry.created_at.is_empty()
        || entry.created_at.len() > 128
        || entry.expires_at.is_empty()
        || entry.expires_at.len() > 128
    {
        return Err(());
    }

    match (
        entry.contact_user_id.as_deref(),
        entry.contact_public_id.as_deref(),
        entry.contact_display_name.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(user_id), Some(public_id), Some(display_name)) => {
            validate_uuid(user_id)?;
            if public_id.trim().is_empty()
                || public_id.len() > 128
                || display_name.trim().is_empty()
                || display_name.len() > 160
            {
                return Err(());
            }
        }
        _ => return Err(()),
    }
    if entry
        .original_created_at_unix_ms
        .is_some_and(|timestamp| timestamp <= 0)
    {
        return Err(());
    }
    if entry.delivery_recipient_device_ids.len() > 256 {
        return Err(());
    }
    let mut delivery_devices = entry.delivery_recipient_device_ids.clone();
    delivery_devices.sort_unstable();
    if delivery_devices.windows(2).any(|pair| pair[0] == pair[1])
        || delivery_devices
            .iter()
            .any(|device_id| validate_uuid(device_id).is_err())
    {
        return Err(());
    }

    if entry
        .delivery_status
        .as_deref()
        .is_some_and(|status| !matches!(status, "queued" | "sent" | "delivered" | "read"))
        || entry
            .delivery_updated_at
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 128)
    {
        return Err(());
    }
    Ok(())
}

fn delivery_status_rank(status: Option<&str>) -> u8 {
    match status {
        Some("read") => 4,
        Some("delivered") => 3,
        Some("sent") => 2,
        Some("queued") => 1,
        _ => 0,
    }
}

fn validate_uuid(value: &str) -> Result<(), ()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(());
    }
    Ok(())
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "inbox path has no parent"))?;
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
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_status_is_monotonic() {
        assert_eq!(delivery_status_rank(None), 0);
        assert_eq!(delivery_status_rank(Some("queued")), 1);
        assert_eq!(delivery_status_rank(Some("sent")), 2);
        assert_eq!(delivery_status_rank(Some("delivered")), 3);
        assert_eq!(delivery_status_rank(Some("read")), 4);
        assert!(
            delivery_status_rank(Some("sent")) > delivery_status_rank(Some("queued"))
        );
        assert!(
            delivery_status_rank(Some("delivered")) > delivery_status_rank(Some("sent"))
        );
        assert!(delivery_status_rank(Some("read")) > delivery_status_rank(Some("delivered")));
    }

    #[test]
    fn validates_canonical_message_identity() {
        let entry = DurableInboxEntry {
            remote_message_id: "11111111-1111-4111-8111-111111111111".into(),
            bubble_id: "22222222-2222-4222-8222-222222222222".into(),
            sender_device_id: "33333333-3333-4333-8333-333333333333".into(),
            sender_user_id: "44444444-4444-4444-8444-444444444444".into(),
            sender_public_id: "alice".into(),
            recipient_device_id: "55555555-5555-4555-8555-555555555555".into(),
            client_message_id: "66666666-6666-4666-8666-666666666666".into(),
            message_type: "opaque".into(),
            plaintext: "ENIGMA_PAYLOAD_V1:{}".into(),
            created_at: "2026-09-15T12:00:00Z".into(),
            expires_at: "2026-09-22T12:00:00Z".into(),
            direction: "inbound".into(),
            contact_user_id: Some("44444444-4444-4444-8444-444444444444".into()),
            contact_public_id: Some("alice".into()),
            contact_display_name: Some("alice".into()),
            original_created_at_unix_ms: None,
            delivery_status: Some("delivered".into()),
            delivery_updated_at: Some("2026-09-15T12:00:00Z".into()),
            delivery_recipient_device_ids: Vec::new(),
        };
        assert_eq!(validate_entry(&entry), Ok(()));
        assert!(validate_entry(&DurableInboxEntry {
            remote_message_id: "not-a-uuid".into(),
            ..entry
        })
        .is_err());
    }
}
