use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, CiphertextMessageType, IdentityKeyPair, InMemSignalProtocolStore,
    PreKeyBundle, PreKeySignalMessage, ProtocolAddress, SignalMessage,
};
use rand::{CryptoRng, Rng};

use crate::SignalAdapterError;

/// Real desktop session backend backed exclusively by the pinned libsignal implementation.
///
/// ENIGMA deliberately does not reproduce Signal session, ratchet, pre-key or PQ cryptography
/// here. This type owns libsignal's stores and delegates session establishment, encryption and
/// decryption to libsignal-protocol.
pub struct LibsignalSessionBackend {
    store: InMemSignalProtocolStore,
}

impl LibsignalSessionBackend {
    pub fn new(
        identity: IdentityKeyPair,
        registration_id: u32,
    ) -> Result<Self, SignalAdapterError> {
        let store = InMemSignalProtocolStore::new(identity, registration_id)
            .map_err(|_| SignalAdapterError::CryptoFailure)?;
        Ok(Self { store })
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

    #[must_use]
    pub fn store(&self) -> &InMemSignalProtocolStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut InMemSignalProtocolStore {
        &mut self.store
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
