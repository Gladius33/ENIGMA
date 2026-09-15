use std::collections::HashMap;

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use serde::{Deserialize, Serialize};

use crate::SignalAdapterError;

const SNAPSHOT_VERSION: u16 = 1;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS_PER_KIND: usize = 16_384;
const MAX_ADDRESS_NAME_BYTES: usize = 512;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
struct AddressKey {
    name: String,
    device_id: u8,
}

impl AddressKey {
    fn from_address(address: &ProtocolAddress) -> Self {
        Self {
            name: address.name().to_owned(),
            device_id: u8::from(address.device_id()),
        }
    }

    fn validate(&self) -> Result<(), SignalAdapterError> {
        if self.name.is_empty()
            || self.name.len() > MAX_ADDRESS_NAME_BYTES
            || self.device_id == 0
            || self.device_id > 127
        {
            return Err(SignalAdapterError::InvalidBundle);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PersistentIdentityKeyStore {
    key_pair: IdentityKeyPair,
    registration_id: u32,
    known_keys: HashMap<AddressKey, IdentityKey>,
}

#[derive(Clone, Default)]
pub struct PersistentPreKeyStore {
    records: HashMap<PreKeyId, PreKeyRecord>,
}

#[derive(Clone, Default)]
pub struct PersistentSignedPreKeyStore {
    records: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

#[derive(Clone, Default)]
pub struct PersistentKyberPreKeyStore {
    records: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
    base_keys_seen: HashMap<(KyberPreKeyId, SignedPreKeyId), Vec<PublicKey>>,
}

#[derive(Clone, Default)]
pub struct PersistentSessionStore {
    records: HashMap<AddressKey, SessionRecord>,
}

#[derive(Clone)]
pub struct PersistentSignalProtocolStore {
    pub(crate) session_store: PersistentSessionStore,
    pub(crate) pre_key_store: PersistentPreKeyStore,
    pub(crate) signed_pre_key_store: PersistentSignedPreKeyStore,
    pub(crate) kyber_pre_key_store: PersistentKyberPreKeyStore,
    pub(crate) identity_store: PersistentIdentityKeyStore,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreSnapshot {
    version: u16,
    identity_key_pair: String,
    registration_id: u32,
    known_identities: Vec<AddressBlob>,
    pre_keys: Vec<IdBlob>,
    signed_pre_keys: Vec<IdBlob>,
    kyber_pre_keys: Vec<IdBlob>,
    kyber_base_keys_seen: Vec<KyberSeenBlob>,
    sessions: Vec<AddressBlob>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddressBlob {
    address: AddressKey,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdBlob {
    id: u32,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KyberSeenBlob {
    kyber_pre_key_id: u32,
    signed_pre_key_id: u32,
    base_keys: Vec<String>,
}

impl PersistentSignalProtocolStore {
    pub fn new(
        identity_key_pair: IdentityKeyPair,
        registration_id: u32,
    ) -> Result<Self, SignalAdapterError> {
        if registration_id == 0 || registration_id > 16_380 {
            return Err(SignalAdapterError::InvalidBundle);
        }
        Ok(Self {
            session_store: PersistentSessionStore::default(),
            pre_key_store: PersistentPreKeyStore::default(),
            signed_pre_key_store: PersistentSignedPreKeyStore::default(),
            kyber_pre_key_store: PersistentKyberPreKeyStore::default(),
            identity_store: PersistentIdentityKeyStore {
                key_pair: identity_key_pair,
                registration_id,
                known_keys: HashMap::new(),
            },
        })
    }

    #[must_use]
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.identity_store
            .key_pair
            .identity_key()
            .serialize()
            .to_vec()
    }

    #[must_use]
    pub const fn registration_id(&self) -> u32 {
        self.identity_store.registration_id
    }

    pub fn export_snapshot(&self) -> Result<Vec<u8>, SignalAdapterError> {
        let snapshot = StoreSnapshot {
            version: SNAPSHOT_VERSION,
            identity_key_pair: encode(&self.identity_store.key_pair.serialize()),
            registration_id: self.identity_store.registration_id,
            known_identities: self
                .identity_store
                .known_keys
                .iter()
                .map(|(address, identity)| AddressBlob {
                    address: address.clone(),
                    value: encode(&identity.serialize()),
                })
                .collect(),
            pre_keys: serialize_id_records(&self.pre_key_store.records, |record| {
                record.serialize()
            })?,
            signed_pre_keys: serialize_id_records(&self.signed_pre_key_store.records, |record| {
                record.serialize()
            })?,
            kyber_pre_keys: serialize_id_records(&self.kyber_pre_key_store.records, |record| {
                record.serialize()
            })?,
            kyber_base_keys_seen: self
                .kyber_pre_key_store
                .base_keys_seen
                .iter()
                .map(|((kyber_id, signed_id), keys)| KyberSeenBlob {
                    kyber_pre_key_id: (*kyber_id).into(),
                    signed_pre_key_id: (*signed_id).into(),
                    base_keys: keys.iter().map(|key| encode(&key.serialize())).collect(),
                })
                .collect(),
            sessions: self
                .session_store
                .records
                .iter()
                .map(|(address, record)| {
                    Ok(AddressBlob {
                        address: address.clone(),
                        value: encode(
                            &record
                                .serialize()
                                .map_err(|_| SignalAdapterError::CryptoFailure)?,
                        ),
                    })
                })
                .collect::<Result<Vec<_>, SignalAdapterError>>()?,
        };

        let encoded =
            serde_json::to_vec(&snapshot).map_err(|_| SignalAdapterError::CryptoFailure)?;
        if encoded.is_empty() || encoded.len() > MAX_SNAPSHOT_BYTES {
            return Err(SignalAdapterError::CryptoFailure);
        }
        Ok(encoded)
    }

    pub fn import_snapshot(snapshot: &[u8]) -> Result<Self, SignalAdapterError> {
        if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(SignalAdapterError::InvalidBundle);
        }
        let decoded = serde_json::from_slice::<StoreSnapshot>(snapshot)
            .map_err(|_| SignalAdapterError::InvalidBundle)?;
        if decoded.version != SNAPSHOT_VERSION
            || decoded.registration_id == 0
            || decoded.registration_id > 16_380
            || decoded.known_identities.len() > MAX_RECORDS_PER_KIND
            || decoded.pre_keys.len() > MAX_RECORDS_PER_KIND
            || decoded.signed_pre_keys.len() > MAX_RECORDS_PER_KIND
            || decoded.kyber_pre_keys.len() > MAX_RECORDS_PER_KIND
            || decoded.kyber_base_keys_seen.len() > MAX_RECORDS_PER_KIND
            || decoded.sessions.len() > MAX_RECORDS_PER_KIND
        {
            return Err(SignalAdapterError::InvalidBundle);
        }

        let identity_bytes = decode(&decoded.identity_key_pair)?;
        let identity_key_pair = IdentityKeyPair::try_from(identity_bytes.as_slice())
            .map_err(|_| SignalAdapterError::InvalidBundle)?;
        let mut store = Self::new(identity_key_pair, decoded.registration_id)?;

        for entry in decoded.known_identities {
            entry.address.validate()?;
            let bytes = decode(&entry.value)?;
            let identity =
                IdentityKey::decode(&bytes).map_err(|_| SignalAdapterError::InvalidBundle)?;
            if store
                .identity_store
                .known_keys
                .insert(entry.address, identity)
                .is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }

        store.pre_key_store.records =
            deserialize_id_records(decoded.pre_keys, PreKeyRecord::deserialize, |record| {
                record.id().map(Into::into)
            })?;
        store.signed_pre_key_store.records = deserialize_id_records(
            decoded.signed_pre_keys,
            SignedPreKeyRecord::deserialize,
            |record| record.id().map(Into::into),
        )?;
        store.kyber_pre_key_store.records = deserialize_id_records(
            decoded.kyber_pre_keys,
            KyberPreKeyRecord::deserialize,
            |record| record.id().map(Into::into),
        )?;

        for entry in decoded.kyber_base_keys_seen {
            if entry.base_keys.len() > MAX_RECORDS_PER_KIND {
                return Err(SignalAdapterError::InvalidBundle);
            }
            let key = (
                KyberPreKeyId::from(entry.kyber_pre_key_id),
                SignedPreKeyId::from(entry.signed_pre_key_id),
            );
            let mut values = Vec::with_capacity(entry.base_keys.len());
            for encoded in entry.base_keys {
                let bytes = decode(&encoded)?;
                let public = PublicKey::deserialize(&bytes)
                    .map_err(|_| SignalAdapterError::InvalidBundle)?;
                if values.contains(&public) {
                    return Err(SignalAdapterError::InvalidBundle);
                }
                values.push(public);
            }
            if store
                .kyber_pre_key_store
                .base_keys_seen
                .insert(key, values)
                .is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }

        for entry in decoded.sessions {
            entry.address.validate()?;
            let bytes = decode(&entry.value)?;
            let record = SessionRecord::deserialize(&bytes)
                .map_err(|_| SignalAdapterError::InvalidBundle)?;
            if store
                .session_store
                .records
                .insert(entry.address, record)
                .is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        Ok(store)
    }
}

fn serialize_id_records<I, R>(
    records: &HashMap<I, R>,
    serialize: impl Fn(&R) -> libsignal_protocol::Result<Vec<u8>>,
) -> Result<Vec<IdBlob>, SignalAdapterError>
where
    I: Copy + Into<u32> + Eq + std::hash::Hash,
{
    records
        .iter()
        .map(|(id, record)| {
            Ok(IdBlob {
                id: (*id).into(),
                value: encode(&serialize(record).map_err(|_| SignalAdapterError::CryptoFailure)?),
            })
        })
        .collect()
}

fn deserialize_id_records<I, R>(
    entries: Vec<IdBlob>,
    deserialize: impl Fn(&[u8]) -> libsignal_protocol::Result<R>,
    record_id: impl Fn(&R) -> libsignal_protocol::Result<u32>,
) -> Result<HashMap<I, R>, SignalAdapterError>
where
    I: From<u32> + Eq + std::hash::Hash,
{
    let mut records = HashMap::with_capacity(entries.len());
    for entry in entries {
        let bytes = decode(&entry.value)?;
        let record = deserialize(&bytes).map_err(|_| SignalAdapterError::InvalidBundle)?;
        if record_id(&record).map_err(|_| SignalAdapterError::InvalidBundle)? != entry.id {
            return Err(SignalAdapterError::InvalidBundle);
        }
        if records.insert(I::from(entry.id), record).is_some() {
            return Err(SignalAdapterError::InvalidBundle);
        }
    }
    Ok(records)
}

fn encode(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode(value: &str) -> Result<Vec<u8>, SignalAdapterError> {
    if value.is_empty() || value.len() > MAX_SNAPSHOT_BYTES * 2 {
        return Err(SignalAdapterError::InvalidBundle);
    }
    STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| SignalAdapterError::InvalidBundle)
}

#[async_trait(?Send)]
impl IdentityKeyStore for PersistentIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> libsignal_protocol::Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> libsignal_protocol::Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> libsignal_protocol::Result<IdentityChange> {
        let key = AddressKey::from_address(address);
        let change = match self.known_keys.get(&key) {
            None => IdentityChange::NewOrUnchanged,
            Some(existing) if existing == identity => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
        };
        self.known_keys.insert(key, *identity);
        Ok(change)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> libsignal_protocol::Result<bool> {
        Ok(self
            .known_keys
            .get(&AddressKey::from_address(address))
            .is_none_or(|existing| existing == identity))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<IdentityKey>> {
        Ok(self
            .known_keys
            .get(&AddressKey::from_address(address))
            .copied())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PersistentPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId) -> libsignal_protocol::Result<PreKeyRecord> {
        self.records
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.records.insert(id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> libsignal_protocol::Result<()> {
        self.records.remove(&id);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for PersistentSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> libsignal_protocol::Result<SignedPreKeyRecord> {
        self.records
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.records.insert(id, record.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for PersistentKyberPreKeyStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> libsignal_protocol::Result<KyberPreKeyRecord> {
        self.records
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.records.insert(id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_id: KyberPreKeyId,
        signed_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> libsignal_protocol::Result<()> {
        let seen = self
            .base_keys_seen
            .entry((kyber_id, signed_id))
            .or_default();
        if seen.contains(base_key) {
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key",
            ));
        }
        seen.push(*base_key);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for PersistentSessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<SessionRecord>> {
        Ok(self
            .records
            .get(&AddressKey::from_address(address))
            .cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> libsignal_protocol::Result<()> {
        self.records
            .insert(AddressKey::from_address(address), record.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt as _;
    use libsignal_protocol::{IdentityKeyPair, KeyPair, Timestamp};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn snapshot_round_trip_preserves_direct_message_state() {
        let mut rng = StdRng::from_seed([0x71; 32]);
        let identity = IdentityKeyPair::generate(&mut rng);
        let mut store = PersistentSignalProtocolStore::new(identity, 7).expect("persistent store");

        let pre_pair = KeyPair::generate(&mut rng);
        let pre = PreKeyRecord::new(11_u32.into(), &pre_pair);
        store
            .pre_key_store
            .save_pre_key(11_u32.into(), &pre)
            .now_or_never()
            .expect("in-memory future")
            .expect("prekey");

        let signed_pair = KeyPair::generate(&mut rng);
        let signature = identity
            .private_key()
            .calculate_signature(&signed_pair.public_key.serialize(), &mut rng)
            .expect("signature");
        let signed = SignedPreKeyRecord::new(
            12_u32.into(),
            Timestamp::from_epoch_millis(1_700_000_000_000),
            &signed_pair,
            &signature,
        );
        store
            .signed_pre_key_store
            .save_signed_pre_key(12_u32.into(), &signed)
            .now_or_never()
            .expect("in-memory future")
            .expect("signed prekey");

        let snapshot = store.export_snapshot().expect("export");
        let restored = PersistentSignalProtocolStore::import_snapshot(&snapshot).expect("import");
        assert_eq!(restored.registration_id(), 7);
        assert_eq!(restored.identity_public_key(), store.identity_public_key());
        assert_eq!(restored.pre_key_store.records.len(), 1);
        assert_eq!(restored.signed_pre_key_store.records.len(), 1);
    }
}
