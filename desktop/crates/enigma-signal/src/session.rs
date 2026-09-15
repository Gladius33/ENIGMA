use std::time::SystemTime;

use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair,
    IdentityKeyStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyBundle, PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::{CryptoRng, Rng};

use crate::{
    persistent_store::PersistentSignalProtocolStore,
    SignalAdapterError,
};

/// Real desktop session backend backed exclusively by the pinned libsignal implementation.
///
/// ENIGMA deliberately does not reproduce Signal session, ratchet, pre-key or PQ cryptography
/// here. This type owns libsignal's stores and delegates session establishment, encryption and
/// decryption to libsignal-protocol.
pub struct LibsignalSessionBackend {
    store: PersistentSignalProtocolStore,
    identity_public_key: Vec<u8>,
    registration_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedOneTimePreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedSignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedPreKeyBundle {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: PublishedSignedPreKey,
    pub kyber_pre_key: PublishedSignedPreKey,
    pub one_time_pre_keys: Vec<PublishedOneTimePreKey>,
}

impl LibsignalSessionBackend {
    pub fn new(
        identity: IdentityKeyPair,
        registration_id: u32,
    ) -> Result<Self, SignalAdapterError> {
        let identity_public_key = identity.identity_key().serialize().to_vec();
        let store = PersistentSignalProtocolStore::new(identity, registration_id)?;
        Ok(Self {
            store,
            identity_public_key,
            registration_id,
        })
    }

    /// Generates a fresh desktop Signal identity and registration id entirely inside Rust.
    ///
    /// The serialized identity is returned only so the FFI layer can immediately wrap it with
    /// the operating system's protected-storage backend. Frontends never receive this plaintext.
    pub fn generate_for_new_device() -> Result<(Self, Vec<u8>, u32), SignalAdapterError> {
        const MAX_SIGNAL_REGISTRATION_ID: u32 = 16_380;

        let mut rng = rand::rng();
        let registration_id = rng.random_range(1..=MAX_SIGNAL_REGISTRATION_ID);
        let identity = IdentityKeyPair::generate(&mut rng);
        let serialized_identity = identity.serialize().to_vec();
        let backend = Self::new(identity, registration_id)?;
        Ok((backend, serialized_identity, registration_id))
    }

    /// Restore a backend from libsignal's canonical serialized identity-key-pair representation.
    ///
    /// The serialized private identity is expected to come from ENIGMA's protected local storage.
    /// It is parsed by the pinned libsignal implementation rather than by ENIGMA.
    pub fn from_serialized_identity(
        serialized_identity: &[u8],
        registration_id: u32,
    ) -> Result<Self, SignalAdapterError> {
        let identity = IdentityKeyPair::try_from(serialized_identity)
            .map_err(|_| SignalAdapterError::InvalidBundle)?;
        Self::new(identity, registration_id)
    }

    pub fn from_serialized_store(snapshot: &[u8]) -> Result<Self, SignalAdapterError> {
        let store = PersistentSignalProtocolStore::import_snapshot(snapshot)?;
        let identity_public_key = store.identity_public_key();
        let registration_id = store.registration_id();
        Ok(Self {
            store,
            identity_public_key,
            registration_id,
        })
    }

    pub fn export_serialized_store(&self) -> Result<Vec<u8>, SignalAdapterError> {
        self.store.export_snapshot()
    }

    /// Generates, signs and stores the public pre-key material a desktop device publishes.
    ///
    /// All private material remains owned by libsignal inside the Rust backend. The returned
    /// structure contains only public keys, signatures and identifiers suitable for the existing
    /// ENIGMA server upload contract used by Android.
    pub async fn generate_and_store_prekey_bundle<R>(
        &mut self,
        first_one_time_pre_key_id: u32,
        one_time_pre_key_count: u32,
        signed_pre_key_id: u32,
        kyber_pre_key_id: u32,
        timestamp_unix_ms: u64,
        rng: &mut R,
    ) -> Result<PublishedPreKeyBundle, SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        const MAX_SIGNAL_KEY_ID: u32 = i32::MAX as u32;
        let one_time_range_end = first_one_time_pre_key_id
            .checked_add(one_time_pre_key_count)
            .filter(|end| *end <= MAX_SIGNAL_KEY_ID);
        if one_time_pre_key_count == 0
            || one_time_pre_key_count > 100
            || first_one_time_pre_key_id == 0
            || one_time_range_end.is_none()
            || signed_pre_key_id == 0
            || signed_pre_key_id > MAX_SIGNAL_KEY_ID
            || kyber_pre_key_id == 0
            || kyber_pre_key_id > MAX_SIGNAL_KEY_ID
        {
            return Err(SignalAdapterError::InvalidBundle);
        }

        let identity = self
            .store
            .identity_store
            .get_identity_key_pair()
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        let registration_id = self
            .store
            .identity_store
            .get_local_registration_id()
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;

        let signed_pair = KeyPair::generate(rng);
        let signed_public = signed_pair.public_key.serialize().to_vec();
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed_public, rng)
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        let signed_record = SignedPreKeyRecord::new(
            signed_pre_key_id.into(),
            Timestamp::from_epoch_millis(timestamp_unix_ms),
            &signed_pair,
            &signed_signature,
        );
        self.store
            .signed_pre_key_store
            .save_signed_pre_key(signed_pre_key_id.into(), &signed_record)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;

        let kyber_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let kyber_public = kyber_pair.public_key.serialize().to_vec();
        let kyber_signature = identity
            .private_key()
            .calculate_signature(&kyber_public, rng)
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        let kyber_record = KyberPreKeyRecord::new(
            kyber_pre_key_id.into(),
            Timestamp::from_epoch_millis(timestamp_unix_ms),
            &kyber_pair,
            &kyber_signature,
        );
        self.store
            .kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_id.into(), &kyber_record)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;

        let mut one_time_pre_keys = Vec::with_capacity(one_time_pre_key_count as usize);
        for offset in 0..one_time_pre_key_count {
            let key_id = first_one_time_pre_key_id
                .checked_add(offset)
                .ok_or(SignalAdapterError::InvalidBundle)?;
            let pair = KeyPair::generate(rng);
            let public_key = pair.public_key.serialize().to_vec();
            let record = PreKeyRecord::new(key_id.into(), &pair);
            self.store
                .pre_key_store
                .save_pre_key(key_id.into(), &record)
                .await
                .map_err(|_| SignalAdapterError::CryptoFailure)?;
            one_time_pre_keys.push(PublishedOneTimePreKey { key_id, public_key });
        }

        Ok(PublishedPreKeyBundle {
            registration_id,
            identity_key: identity.identity_key().serialize().to_vec(),
            signed_pre_key: PublishedSignedPreKey {
                key_id: signed_pre_key_id,
                public_key: signed_public,
                signature: signed_signature.to_vec(),
            },
            kyber_pre_key: PublishedSignedPreKey {
                key_id: kyber_pre_key_id,
                public_key: kyber_public,
                signature: kyber_signature.to_vec(),
            },
            one_time_pre_keys,
        })
    }

    /// Install the local classical, signed and post-quantum pre-key records required to receive
    /// a first Signal message. Frontends should not manipulate libsignal stores directly.
    pub async fn install_local_prekeys(
        &mut self,
        pre_key_id: u32,
        pre_key: &PreKeyRecord,
        signed_pre_key_id: u32,
        signed_pre_key: &SignedPreKeyRecord,
        kyber_pre_key_id: u32,
        kyber_pre_key: &KyberPreKeyRecord,
    ) -> Result<(), SignalAdapterError> {
        self.store
            .pre_key_store
            .save_pre_key(pre_key_id.into(), pre_key)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        self.store
            .signed_pre_key_store
            .save_signed_pre_key(signed_pre_key_id.into(), signed_pre_key)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        self.store
            .kyber_pre_key_store
            .save_kyber_pre_key(kyber_pre_key_id.into(), kyber_pre_key)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    pub async fn process_remote_prekey_bundle<R>(
        &mut self,
        remote: &ProtocolAddress,
        bundle: &PreKeyBundle,
        now: SystemTime,
        rng: &mut R,
    ) -> Result<(), SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        process_prekey_bundle(
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            bundle,
            now,
            rng,
        )
        .await
        .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    pub async fn encrypt<R>(
        &mut self,
        remote: &ProtocolAddress,
        plaintext: &[u8],
        now: SystemTime,
        rng: &mut R,
    ) -> Result<SessionCiphertext, SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        let encrypted = message_encrypt(
            plaintext,
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            now,
            rng,
        )
        .await
        .map_err(|_| SignalAdapterError::CryptoFailure)?;

        SessionCiphertext::from_libsignal(encrypted)
    }

    /// Decrypt a ciphertext produced by [`Self::encrypt`] without delegating protocol-message
    /// dispatch to a frontend. Windows/Linux callers must not infer or reinterpret libsignal wire
    /// formats; the typed message kind is kept inside this Rust boundary and dispatched directly
    /// to the corresponding pinned libsignal primitive.
    pub async fn decrypt_wire<R>(
        &mut self,
        encoded_envelope: &str,
        expected_recipient_device_id: &str,
        expected_recipient_protocol_device_id: u32,
        rng: &mut R,
    ) -> Result<(String, Vec<u8>), SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        let envelope =
            crate::parse_signal_wire_envelope(encoded_envelope, expected_recipient_device_id)?;
        if envelope.recipient_protocol_device_id != expected_recipient_protocol_device_id {
            return Err(SignalAdapterError::InvalidWireEnvelope);
        }
        let protocol_device_id = DeviceId::new(envelope.sender_protocol_device_id)
            .map_err(|_| SignalAdapterError::InvalidWireEnvelope)?;
        let remote = ProtocolAddress::new(envelope.sender_device_id.clone().into(), protocol_device_id);
        let ciphertext = SessionCiphertext {
            message_type: envelope.message_type,
            serialized: envelope.ciphertext,
        };
        let plaintext = self.decrypt(&remote, &ciphertext, rng).await?;
        Ok((envelope.sender_device_id, plaintext))
    }

    pub async fn decrypt<R>(
        &mut self,
        remote: &ProtocolAddress,
        ciphertext: &SessionCiphertext,
        rng: &mut R,
    ) -> Result<Vec<u8>, SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        match ciphertext.message_type {
            SessionMessageType::PreKey => {
                self.decrypt_prekey(remote, &ciphertext.serialized, rng)
                    .await
            }
            SessionMessageType::Signal => {
                self.decrypt_signal(remote, &ciphertext.serialized, rng)
                    .await
            }
        }
    }

    pub async fn decrypt_prekey<R>(
        &mut self,
        remote: &ProtocolAddress,
        serialized: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        let message = PreKeySignalMessage::try_from(serialized)
            .map_err(|_| SignalAdapterError::InvalidBundle)?;
        message_decrypt_prekey(
            &message,
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            rng,
        )
        .await
        .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    pub async fn decrypt_signal<R>(
        &mut self,
        remote: &ProtocolAddress,
        serialized: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, SignalAdapterError>
    where
        R: Rng + CryptoRng,
    {
        let message =
            SignalMessage::try_from(serialized).map_err(|_| SignalAdapterError::InvalidBundle)?;
        message_decrypt_signal(
            &message,
            remote,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            rng,
        )
        .await
        .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    pub async fn serialized_session(
        &self,
        remote: &ProtocolAddress,
    ) -> Result<Option<Vec<u8>>, SignalAdapterError> {
        self.store
            .session_store
            .load_session(remote)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)?
            .map(|record| {
                record
                    .serialize()
                    .map_err(|_| SignalAdapterError::CryptoFailure)
            })
            .transpose()
    }

    pub async fn restore_serialized_session(
        &mut self,
        remote: &ProtocolAddress,
        serialized: &[u8],
    ) -> Result<(), SignalAdapterError> {
        let record =
            libsignal_protocol::SessionRecord::deserialize(serialized)
                .map_err(|_| SignalAdapterError::InvalidBundle)?;
        self.store
            .session_store
            .store_session(remote, &record)
            .await
            .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    pub async fn save_remote_identity(
        &mut self,
        remote: &ProtocolAddress,
        identity: &libsignal_protocol::IdentityKey,
    ) -> Result<(), SignalAdapterError> {
        self.store
            .identity_store
            .save_identity(remote, identity)
            .await
            .map(|_| ())
            .map_err(|_| SignalAdapterError::CryptoFailure)
    }

    #[must_use]
    pub fn identity_public_key(&self) -> &[u8] {
        &self.identity_public_key
    }

    #[must_use]
    pub const fn registration_id(&self) -> u32 {
        self.registration_id
    }

}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCiphertext {
    pub message_type: SessionMessageType,
    pub serialized: Vec<u8>,
}

impl SessionCiphertext {
    fn from_libsignal(message: CiphertextMessage) -> Result<Self, SignalAdapterError> {
        let message_type = match message.message_type() {
            CiphertextMessageType::PreKey => SessionMessageType::PreKey,
            CiphertextMessageType::Whisper => SessionMessageType::Signal,
            _ => return Err(SignalAdapterError::CryptoFailure),
        };
        Ok(Self {
            message_type,
            serialized: message.serialize().to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMessageType {
    PreKey,
    Signal,
}
