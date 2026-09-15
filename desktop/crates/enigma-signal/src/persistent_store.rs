use std::collections::HashMap;

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStore, PublicKey, SessionRecord,
    SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
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
pub struct PersistentSignalProtocolStore {
    identity_key_pair: IdentityKeyPair,
    registration_id: u32,
    known_identities: HashMap<AddressKey, IdentityKey>,
    pre_keys: HashMap<PreKeyId, PreKeyRecord>,
    signed_pre_keys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
    kyber_pre_keys: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
    kyber_base_keys_seen: HashMap<(KyberPreKeyId, SignedPreKeyId), Vec<PublicKey>>,
    sessions: HashMap<AddressKey, SessionRecord>,
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
    pub fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self, SignalAdapterError> {
        if registration_id == 0 || registration_id > 16_380 {
            return Err(SignalAdapterError::InvalidBundle);
        }
        Ok(Self {
            identity_key_pair,
            registration_id,
            known_identities: HashMap::new(),
            pre_keys: HashMap::new(),
            signed_pre_keys: HashMap::new(),
            kyber_pre_keys: HashMap::new(),
            kyber_base_keys_seen: HashMap::new(),
            sessions: HashMap::new(),
        })
    }

    pub fn export_snapshot(&self) -> Result<Vec<u8>, SignalAdapterError> {
        let snapshot = StoreSnapshot {
            version: SNAPSHOT_VERSION,
            identity_key_pair: encode(&self.identity_key_pair.serialize()),
            registration_id: self.registration_id,
            known_identities: self
                .known_identities
                .iter()
                .map(|(address, identity)| AddressBlob {
                    address: address.clone(),
                    value: encode(&identity.serialize()),
                })
                .collect(),
            pre_keys: self
                .pre_keys
                .iter()
                .map(|(id, record)| {
                    Ok(IdBlob {
                        id: (*id).into(),
                        value: encode(&record.serialize().map_err(|_| SignalAdapterError::CryptoFailure)?),
                    })
                })
                .collect::<Result<Vec<_>, SignalAdapterError>>()?,
            signed_pre_keys: self
                .signed_pre_keys
                .iter()
                .map(|(id, record)| {
                    Ok(IdBlob {
                        id: (*id).into(),
                        value: encode(&record.serialize().map_err(|_| SignalAdapterError::CryptoFailure)?),
                    })
                })
                .collect::<Result<Vec<_>, SignalAdapterError>>()?,
            kyber_pre_keys: self
                .kyber_pre_keys
                .iter()
                .map(|(id, record)| {
                    Ok(IdBlob {
                        id: (*id).into(),
                        value: encode(&record.serialize().map_err(|_| SignalAdapterError::CryptoFailure)?),
                    })
                })
                .collect::<Result<Vec<_>, SignalAdapterError>>()?,
            kyber_base_keys_seen: self
                .kyber_base_keys_seen
                .iter()
                .map(|((kyber_id, signed_id), keys)| KyberSeenBlob {
                    kyber_pre_key_id: (*kyber_id).into(),
                    signed_pre_key_id: (*signed_id).into(),
                    base_keys: keys.iter().map(|key| encode(&key.serialize())).collect(),
                })
                .collect(),
            sessions: self
                .sessions
                .iter()
                .map(|(address, record)| {
                    Ok(AddressBlob {
                        address: address.clone(),
                        value: encode(&record.serialize().map_err(|_| SignalAdapterError::CryptoFailure)?),
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
            if store.known_identities.insert(entry.address, identity).is_some() {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        for entry in decoded.pre_keys {
            let bytes = decode(&entry.value)?;
            let record =
                PreKeyRecord::deserialize(&bytes).map_err(|_| SignalAdapterError::InvalidBundle)?;
            let id = PreKeyId::from(entry.id);
            if record.id().map_err(|_| SignalAdapterError::InvalidBundle)? != id
                || store.pre_keys.insert(id, record).is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        for entry in decoded.signed_pre_keys {
            let bytes = decode(&entry.value)?;
            let record = SignedPreKeyRecord::deserialize(&bytes)
                .map_err(|_| SignalAdapterError::InvalidBundle)?;
            let id = SignedPreKeyId::from(entry.id);
            if record.id().map_err(|_| SignalAdapterError::InvalidBundle)? != id
                || store.signed_pre_keys.insert(id, record).is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        for entry in decoded.kyber_pre_keys {
            let bytes = decode(&entry.value)?;
            let record = KyberPreKeyRecord::deserialize(&bytes)
                .map_err(|_| SignalAdapterError::InvalidBundle)?;
            let id = KyberPreKeyId::from(entry.id);
            if record.id().map_err(|_| SignalAdapterError::InvalidBundle)? != id
                || store.kyber_pre_keys.insert(id, record).is_some()
            {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
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
                let public =
                    PublicKey::deserialize(&bytes).map_err(|_| SignalAdapterError::InvalidBundle)?;
                if values.contains(&public) {
                    return Err(SignalAdapterError::InvalidBundle);
                }
                values.push(public);
            }
            if store.kyber_base_keys_seen.insert(key, values).is_some() {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        for entry in decoded.sessions {
            entry.address.validate()?;
            let bytes = decode(&entry.value)?;
            let record =
                SessionRecord::deserialize(&bytes).map_err(|_| SignalAdapterError::InvalidBundle)?;
            if store.sessions.insert(entry.address, record).is_some() {
                return Err(SignalAdapterError::InvalidBundle);
            }
        }
        Ok(store)
    }
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
impl IdentityKeyStore for PersistentSignalProtocolStore {
    async fn get_identity_key_pair(&self) -> libsignal_protocol::Result<IdentityKeyPair> {
        Ok(self.identity_key_pair)
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
        let change = match self.known_identities.get(&key) {
            None => IdentityChange::NewOrUnchanged,
            Some(existing) if existing == identity => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
        };
        self.known_identities.insert(key, *identity);
        Ok(change)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> libsignal_protocol::Result<bool> {
        Ok(self
            .known_identities
            .get(&AddressKey::from_address(address))
            .is_none_or(|existing| existing == identity))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<IdentityKey>> {
        Ok(self
            .known_identities
            .get(&AddressKey::from_address(address))
            .copied())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PersistentSignalProtocolStore {
    async fn get_pre_key(&self, id: PreKeyId) -> libsignal_protocol::Result<PreKeyRecord> {
        self.pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.pre_keys.insert(id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> libsignal_protocol::Result<()> {
        self.pre_keys.remove(&id);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for PersistentSignalProtocolStore {
    async fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> libsignal_protocol::Result<SignedPreKeyRecord> {
        self.signed_pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.signed_pre_keys.insert(id, record.clone());
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for PersistentSignalProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> libsignal_protocol::Result<KyberPreKeyRecord> {
        self.kyber_pre_keys
            .get(&id)
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> libsignal_protocol::Result<()> {
        self.kyber_pre_keys.insert(id, record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_id: KyberPreKeyId,
        signed_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> libsignal_protocol::Result<()> {
        let seen = self
            .kyber_base_keys_seen
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
impl SessionStore for PersistentSignalProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> libsignal_protocol::Result<Option<SessionRecord>> {
        Ok(self.sessions.get(&AddressKey::from_address(address)).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> libsignal_protocol::Result<()> {
        self.sessions
            .insert(AddressKey::from_address(address), record.clone());
        Ok(())
    }
}

impl ProtocolStore for PersistentSignalProtocolStore {}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::{IdentityKeyPair, KeyPair, Timestamp};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn snapshot_round_trip_preserves_all_direct_message_state() {
        let mut rng = StdRng::from_seed([0x71; 32]);
        let identity = IdentityKeyPair::generate(&mut rng);
        let mut store =
            PersistentSignalProtocolStore::new(identity, 7).expect("persistent store");

        let pre_pair = KeyPair::generate(&mut rng);
        let pre = PreKeyRecord::new(11_u32.into(), &pre_pair);
        futures_executor::block_on(store.save_pre_key(11_u32.into(), &pre)).expect("prekey");

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
        futures_executor::block_on(store.save_signed_pre_key(12_u32.into(), &signed))
            .expect("signed prekey");

        let snapshot = store.export_snapshot().expect("export");
        let restored =
            PersistentSignalProtocolStore::import_snapshot(&snapshot).expect("import");
        let reexported = restored.export_snapshot().expect("re-export");
        let a: StoreSnapshot = serde_json::from_slice(&snapshot).expect("snapshot json");
        let b: StoreSnapshot = serde_json::from_slice(&reexported).expect("snapshot json");
        assert_eq!(a.version, b.version);
        assert_eq!(a.registration_id, b.registration_id);
        assert_eq!(a.identity_key_pair, b.identity_key_pair);
        assert_eq!(a.pre_keys.len(), 1);
        assert_eq!(b.pre_keys.len(), 1);
        assert_eq!(a.signed_pre_keys.len(), 1);
        assert_eq!(b.signed_pre_keys.len(), 1);
    }
}
