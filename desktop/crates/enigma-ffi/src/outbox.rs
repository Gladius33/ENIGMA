#![forbid(unsafe_code)]

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use enigma_storage::{RecordVault, SodiumRecordVault};
use serde::{Deserialize, Serialize};

use crate::inbox::{validate_entry as validate_inbox_entry, DurableInboxEntry};

const OUTBOX_AAD: &[u8] = b"ENIGMA_DESKTOP_OUTBOX_V1";
const OUTBOX_JOURNAL_AAD: &[u8] = b"ENIGMA_DESKTOP_OUTBOX_JOURNAL_V1";
const MAX_OUTBOX_ENTRIES: usize = 16_384;
const MAX_OUTBOX_FILE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct DurableOutboundDelivery {
    pub bubble_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub message_type: String,
    pub ciphertext: String,
    pub sender_sync: bool,
    #[serde(default)]
    pub recipient_identity_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OutboxFile {
    version: u16,
    entries: Vec<DurableOutboundDelivery>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OutboxJournal {
    version: u16,
    deliveries: Vec<DurableOutboundDelivery>,
    signal_snapshot: String,
    #[serde(default)]
    local_inbox_entry: Option<DurableInboxEntry>,
}

pub(crate) struct EncryptedDesktopOutbox {
    path: PathBuf,
    journal_path: PathBuf,
    vault: SodiumRecordVault,
}

impl EncryptedDesktopOutbox {
    pub(crate) fn new(path: PathBuf, journal_path: PathBuf, vault: SodiumRecordVault) -> Self {
        Self {
            path,
            journal_path,
            vault,
        }
    }

    pub(crate) fn pending(&self) -> Result<Vec<DurableOutboundDelivery>, ()> {
        self.read_entries()
    }

    pub(crate) fn write_journal(
        &self,
        deliveries: &[DurableOutboundDelivery],
        signal_snapshot: &[u8],
        local_inbox_entry: Option<&DurableInboxEntry>,
    ) -> Result<(), ()> {
        if deliveries.is_empty()
            || deliveries.len() > 256
            || signal_snapshot.is_empty()
            || signal_snapshot.len() > 16 * 1024 * 1024
        {
            return Err(());
        }
        deliveries.iter().try_for_each(validate_delivery)?;
        if let Some(entry) = local_inbox_entry {
            validate_inbox_entry(entry)?;
        }
        let journal = OutboxJournal {
            version: 1,
            deliveries: deliveries.to_vec(),
            signal_snapshot: STANDARD_NO_PAD.encode(signal_snapshot),
            local_inbox_entry: local_inbox_entry.cloned(),
        };
        let plaintext = serde_json::to_vec(&journal).map_err(|_| ())?;
        if plaintext.len() > MAX_OUTBOX_FILE_BYTES {
            return Err(());
        }
        let sealed = self
            .vault
            .seal(&plaintext, OUTBOX_JOURNAL_AAD)
            .map_err(|_| ())?;
        persist_atomic(&self.journal_path, &sealed).map_err(|_| ())
    }

    pub(crate) fn read_journal(
        &self,
    ) -> Result<Option<(Vec<DurableOutboundDelivery>, Vec<u8>, Option<DurableInboxEntry>)>, ()> {
        let sealed = match fs::read(&self.journal_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if sealed.is_empty() || sealed.len() > MAX_OUTBOX_FILE_BYTES {
            return Err(());
        }
        let mut plaintext = self
            .vault
            .open(&sealed, OUTBOX_JOURNAL_AAD)
            .map_err(|_| ())?;
        let journal = plaintext
            .with_read(|bytes| serde_json::from_slice::<OutboxJournal>(bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if journal.version != 1
            || journal.deliveries.is_empty()
            || journal.deliveries.len() > 256
        {
            return Err(());
        }
        journal.deliveries.iter().try_for_each(validate_delivery)?;
        if let Some(entry) = journal.local_inbox_entry.as_ref() {
            validate_inbox_entry(entry)?;
        }
        let snapshot = STANDARD_NO_PAD
            .decode(journal.signal_snapshot)
            .map_err(|_| ())?;
        if snapshot.is_empty() || snapshot.len() > 16 * 1024 * 1024 {
            return Err(());
        }
        Ok(Some((
            journal.deliveries,
            snapshot,
            journal.local_inbox_entry,
        )))
    }

    pub(crate) fn clear_journal(&self) -> Result<(), ()> {
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub(crate) fn enqueue_batch(
        &self,
        deliveries: &[DurableOutboundDelivery],
    ) -> Result<(), ()> {
        if deliveries.is_empty() || deliveries.len() > 256 {
            return Err(());
        }
        deliveries.iter().try_for_each(validate_delivery)?;
        let mut entries = self.read_entries()?;

        for delivery in deliveries {
            if let Some(existing) = entries.iter().find(|existing| {
                existing.sender_device_id == delivery.sender_device_id
                    && existing.recipient_device_id == delivery.recipient_device_id
                    && existing.client_message_id == delivery.client_message_id
            }) {
                if existing != delivery {
                    return Err(());
                }
                continue;
            }
            if entries.len() >= MAX_OUTBOX_ENTRIES {
                return Err(());
            }
            entries.push(delivery.clone());
        }

        self.write_entries(&entries)
    }

    pub(crate) fn remove(
        &self,
        sender_device_id: &str,
        recipient_device_id: &str,
        client_message_id: &str,
    ) -> Result<(), ()> {
        validate_uuid(sender_device_id)?;
        validate_uuid(recipient_device_id)?;
        validate_uuid(client_message_id)?;

        let mut entries = self.read_entries()?;
        let original_len = entries.len();
        entries.retain(|entry| {
            !(entry.sender_device_id == sender_device_id
                && entry.recipient_device_id == recipient_device_id
                && entry.client_message_id == client_message_id)
        });
        if entries.len() == original_len {
            return Ok(());
        }
        self.write_entries(&entries)
    }

    fn read_entries(&self) -> Result<Vec<DurableOutboundDelivery>, ()> {
        let sealed = match fs::read(&self.path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
        };
        if sealed.is_empty() || sealed.len() > MAX_OUTBOX_FILE_BYTES {
            return Err(());
        }

        let mut plaintext = self.vault.open(&sealed, OUTBOX_AAD).map_err(|_| ())?;
        let decoded = plaintext
            .with_read(|bytes| serde_json::from_slice::<OutboxFile>(bytes))
            .map_err(|_| ())?
            .map_err(|_| ())?;
        if decoded.version != 1 || decoded.entries.len() > MAX_OUTBOX_ENTRIES {
            return Err(());
        }
        decoded.entries.iter().try_for_each(validate_delivery)?;
        Ok(decoded.entries)
    }

    fn write_entries(&self, entries: &[DurableOutboundDelivery]) -> Result<(), ()> {
        if entries.len() > MAX_OUTBOX_ENTRIES {
            return Err(());
        }
        entries.iter().try_for_each(validate_delivery)?;
        let plaintext = serde_json::to_vec(&OutboxFile {
            version: 1,
            entries: entries.to_vec(),
        })
        .map_err(|_| ())?;
        if plaintext.len() > MAX_OUTBOX_FILE_BYTES {
            return Err(());
        }
        let sealed = self.vault.seal(&plaintext, OUTBOX_AAD).map_err(|_| ())?;
        persist_atomic(&self.path, &sealed).map_err(|_| ())
    }
}

fn validate_delivery(delivery: &DurableOutboundDelivery) -> Result<(), ()> {
    validate_uuid(&delivery.bubble_id)?;
    validate_uuid(&delivery.sender_device_id)?;
    validate_uuid(&delivery.recipient_device_id)?;
    validate_uuid(&delivery.client_message_id)?;
    if delivery.sender_device_id == delivery.recipient_device_id
        || delivery.message_type.is_empty()
        || delivery.message_type.len() > 64
        || delivery.ciphertext.is_empty()
        || delivery.ciphertext.len() > 4 * 1024 * 1024
        || delivery
            .recipient_identity_key
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 16 * 1024)
    {
        return Err(());
    }
    Ok(())
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
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "outbox path has no parent"))?;
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

    fn sample() -> DurableOutboundDelivery {
        DurableOutboundDelivery {
            bubble_id: "11111111-1111-4111-8111-111111111111".into(),
            sender_device_id: "22222222-2222-4222-8222-222222222222".into(),
            recipient_device_id: "33333333-3333-4333-8333-333333333333".into(),
            client_message_id: "44444444-4444-4444-8444-444444444444".into(),
            message_type: "text".into(),
            ciphertext: "opaque-ciphertext".into(),
            sender_sync: false,
            recipient_identity_key: Some("AQID".into()),
        }
    }

    #[test]
    fn validates_delivery_identity_and_ciphertext() {
        assert_eq!(validate_delivery(&sample()), Ok(()));
        assert!(validate_delivery(&DurableOutboundDelivery {
            recipient_device_id: "bad".into(),
            ..sample()
        })
        .is_err());
    }
}
