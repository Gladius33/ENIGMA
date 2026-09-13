use std::time::{Duration, SystemTime};

use enigma_signal::session::{LibsignalSessionBackend, SessionMessageType};
use futures_util::FutureExt;
use libsignal_protocol::{
    kem, DeviceId, GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeyStore, ProtocolAddress,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::{rngs::StdRng, SeedableRng};

fn address(name: &str) -> ProtocolAddress {
    ProtocolAddress::new(name.into(), DeviceId::new(1).expect("valid device id"))
}

#[test]
fn public_backend_establishes_prekey_session_and_ratchets_reply() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut alice_rng = StdRng::from_seed([0x51; 32]);
    let mut bob_rng = StdRng::from_seed([0x52; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);

    let pre_key_id = 11u32;
    let signed_pre_key_id = 12u32;
    let kyber_pre_key_id = 13u32;

    let pre_key_pair = KeyPair::generate(&mut bob_rng);
    let signed_pre_key_pair = KeyPair::generate(&mut bob_rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut bob_rng);

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
        0x6202,
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

    let mut alice =
        LibsignalSessionBackend::new(alice_identity, 0x6101).expect("initialize alice backend");
    let mut bob =
        LibsignalSessionBackend::new(bob_identity, 0x6202).expect("initialize bob backend");

    bob.store_mut()
        .save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
        )
        .now_or_never()
        .expect("in-memory pre-key save is synchronous")
        .expect("save bob pre-key");

    bob.store_mut()
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                Timestamp::from_epoch_millis(1_700_000_000_000),
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .now_or_never()
        .expect("in-memory signed pre-key save is synchronous")
        .expect("save bob signed pre-key");

    bob.store_mut()
        .save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                kyber_pre_key_id.into(),
                Timestamp::from_epoch_millis(1_700_000_000_000),
                &kyber_pre_key_pair,
                &kyber_signature,
            ),
        )
        .now_or_never()
        .expect("in-memory kyber pre-key save is synchronous")
        .expect("save bob kyber pre-key");

    alice
        .process_remote_prekey_bundle(&address("bob"), &bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory session setup is synchronous")
        .expect("alice processes bob bundle");

    let plaintext = b"ENIGMA backend pre-key message";
    let first = alice
        .encrypt(
            &address("bob"),
            plaintext,
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory backend encryption is synchronous")
        .expect("alice encrypts first message");

    assert_eq!(first.message_type, SessionMessageType::PreKey);
    assert!(!first
        .serialized
        .windows(plaintext.len())
        .any(|window| window == plaintext));

    let decrypted = bob
        .decrypt_prekey(&address("alice"), &first.serialized, &mut bob_rng)
        .now_or_never()
        .expect("in-memory backend pre-key decrypt is synchronous")
        .expect("bob decrypts first message");
    assert_eq!(decrypted, plaintext);

    let reply_plaintext = b"ENIGMA backend ratcheted reply";
    let reply = bob
        .encrypt(
            &address("alice"),
            reply_plaintext,
            now + Duration::from_secs(2),
            &mut bob_rng,
        )
        .now_or_never()
        .expect("in-memory backend reply encryption is synchronous")
        .expect("bob encrypts ratcheted reply");

    assert_eq!(reply.message_type, SessionMessageType::Signal);
    assert!(!reply
        .serialized
        .windows(reply_plaintext.len())
        .any(|window| window == reply_plaintext));

    let reply_decrypted = alice
        .decrypt_signal(&address("bob"), &reply.serialized, &mut alice_rng)
        .now_or_never()
        .expect("in-memory backend signal decrypt is synchronous")
        .expect("alice decrypts ratcheted reply");
    assert_eq!(reply_decrypted, reply_plaintext);
}
