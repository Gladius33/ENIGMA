use std::time::SystemTime;

use futures_util::FutureExt;
use libsignal_protocol::{
    kem, message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rand::{rngs::StdRng, SeedableRng};

fn address(name: &str) -> ProtocolAddress {
    ProtocolAddress::new(name.into(), DeviceId::new(1).expect("valid device id"))
}

#[test]
fn pinned_libsignal_establishes_and_decrypts_prekey_session() {
    let mut alice_rng = StdRng::from_seed([0x11; 32]);
    let mut bob_rng = StdRng::from_seed([0x22; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);

    let mut alice =
        InMemSignalProtocolStore::new(alice_identity, 0x1234).expect("initialize alice store");
    let mut bob =
        InMemSignalProtocolStore::new(bob_identity, 0x2345).expect("initialize bob store");

    let pre_key_id = 1u32;
    let signed_pre_key_id = 2u32;
    let kyber_pre_key_id = 3u32;

    let pre_key_pair = KeyPair::generate(&mut bob_rng);
    let signed_pre_key_pair = KeyPair::generate(&mut bob_rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut bob_rng);

    let bob_identity = bob
        .get_identity_key_pair()
        .now_or_never()
        .expect("in-memory identity lookup is synchronous")
        .expect("load bob identity");

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = bob_identity
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut bob_rng)
        .expect("sign signed pre-key");

    let kyber_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_signature = bob_identity
        .private_key()
        .calculate_signature(&kyber_public, &mut bob_rng)
        .expect("sign kyber pre-key");

    let bundle = PreKeyBundle::new(
        0x2345,
        DeviceId::new(1).expect("valid device id"),
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        kyber_pre_key_id.into(),
        kyber_pre_key_pair.public_key.clone(),
        kyber_signature.to_vec(),
        *bob_identity.identity_key(),
    )
    .expect("construct bob pre-key bundle");

    bob.save_pre_key(
        pre_key_id.into(),
        &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
    )
    .now_or_never()
    .expect("in-memory pre-key save is synchronous")
    .expect("save bob pre-key");

    bob.save_signed_pre_key(
        signed_pre_key_id.into(),
        &SignedPreKeyRecord::new(
            signed_pre_key_id.into(),
            1_700_000_000_000,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        ),
    )
    .now_or_never()
    .expect("in-memory signed pre-key save is synchronous")
    .expect("save bob signed pre-key");

    bob.save_kyber_pre_key(
        kyber_pre_key_id.into(),
        &KyberPreKeyRecord::new(
            kyber_pre_key_id.into(),
            1_700_000_000_000,
            &kyber_pre_key_pair,
            &kyber_signature,
        ),
    )
    .now_or_never()
    .expect("in-memory kyber pre-key save is synchronous")
    .expect("save bob kyber pre-key");

    process_prekey_bundle(
        &address("bob"),
        &mut alice.session_store,
        &mut alice.identity_store,
        &bundle,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        &mut alice_rng,
    )
    .now_or_never()
    .expect("in-memory session setup is synchronous")
    .expect("alice processes bob bundle");

    let plaintext = b"ENIGMA pinned libsignal pre-key roundtrip";
    let encrypted = message_encrypt(
        plaintext,
        &address("bob"),
        &mut alice.session_store,
        &mut alice.identity_store,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
        &mut alice_rng,
    )
    .now_or_never()
    .expect("in-memory encrypt is synchronous")
    .expect("alice encrypts first message");

    assert_eq!(encrypted.message_type(), CiphertextMessageType::PreKey);
    let serialized = encrypted.serialize();
    assert!(!serialized
        .windows(plaintext.len())
        .any(|window| window == plaintext));

    let prekey_message = PreKeySignalMessage::try_from(serialized.as_ref())
        .expect("first session message is a valid pre-key message");
    let decrypted = message_decrypt_prekey(
        &prekey_message,
        &address("alice"),
        &mut bob.session_store,
        &mut bob.identity_store,
        &mut bob.pre_key_store,
        &bob.signed_pre_key_store,
        &mut bob.kyber_pre_key_store,
        &mut bob_rng,
    )
    .now_or_never()
    .expect("in-memory decrypt is synchronous")
    .expect("bob decrypts first message");

    assert_eq!(decrypted, plaintext);

    let reply_plaintext = b"ENIGMA ratcheted reply after pre-key establishment";
    let reply = message_encrypt(
        reply_plaintext,
        &address("alice"),
        &mut bob.session_store,
        &mut bob.identity_store,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_002),
        &mut bob_rng,
    )
    .now_or_never()
    .expect("in-memory reply encryption is synchronous")
    .expect("bob encrypts established-session reply");

    assert_eq!(reply.message_type(), CiphertextMessageType::Whisper);
    let reply_serialized = reply.serialize();
    assert!(!reply_serialized
        .windows(reply_plaintext.len())
        .any(|window| window == reply_plaintext));

    let signal_message = SignalMessage::try_from(reply_serialized.as_ref())
        .expect("reply is a valid established-session signal message");
    let reply_decrypted = message_decrypt_signal(
        &signal_message,
        &address("bob"),
        &mut alice.session_store,
        &mut alice.identity_store,
        &mut alice_rng,
    )
    .now_or_never()
    .expect("in-memory reply decrypt is synchronous")
    .expect("alice decrypts established-session reply");

    assert_eq!(reply_decrypted, reply_plaintext);
}
