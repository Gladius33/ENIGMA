use std::time::{Duration, SystemTime};

use enigma_signal::session::{LibsignalSessionBackend, SessionMessageType};
use futures_util::FutureExt;
use libsignal_protocol::{
    kem, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord,
    PreKeyBundle, PreKeyRecord, ProtocolAddress, PublicKey, SignedPreKeyRecord, Timestamp,
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

    let pre_key_record = PreKeyRecord::new(pre_key_id.into(), &pre_key_pair);
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id.into(),
        Timestamp::from_epoch_millis(1_700_000_000_000),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );
    let kyber_pre_key_record = KyberPreKeyRecord::new(
        kyber_pre_key_id.into(),
        Timestamp::from_epoch_millis(1_700_000_000_000),
        &kyber_pre_key_pair,
        &kyber_signature,
    );

    bob.install_local_prekeys(
        pre_key_id,
        &pre_key_record,
        signed_pre_key_id,
        &signed_pre_key_record,
        kyber_pre_key_id,
        &kyber_pre_key_record,
    )
    .now_or_never()
    .expect("in-memory pre-key installation is synchronous")
    .expect("install bob pre-keys");

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
        .decrypt(&address("alice"), &first, &mut bob_rng)
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

    // Authentication must fail closed on an altered ratchet ciphertext. This check intentionally
    // happens before the valid decrypt: a rejected packet must not poison the receiver session.
    let mut tampered_reply = reply.clone();
    let last = tampered_reply
        .serialized
        .last_mut()
        .expect("libsignal ciphertext is non-empty");
    *last ^= 0x01;
    assert!(alice
        .decrypt(&address("bob"), &tampered_reply, &mut alice_rng)
        .now_or_never()
        .expect("in-memory tampered decrypt is synchronous")
        .is_err());

    let reply_decrypted = alice
        .decrypt(&address("bob"), &reply, &mut alice_rng)
        .now_or_never()
        .expect("in-memory backend signal decrypt is synchronous")
        .expect("alice decrypts ratcheted reply after rejecting tampered ciphertext");
    assert_eq!(reply_decrypted, reply_plaintext);
}

#[test]
fn public_backend_rejects_tampered_signed_prekey_bundle_without_creating_session() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut alice_rng = StdRng::from_seed([0x61; 32]);
    let mut bob_rng = StdRng::from_seed([0x62; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);
    let pre_key_pair = KeyPair::generate(&mut bob_rng);
    let signed_pre_key_pair = KeyPair::generate(&mut bob_rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut bob_rng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let mut tampered_signed_pre_key_signature = bob_identity
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut bob_rng)
        .expect("sign signed pre-key")
        .to_vec();
    tampered_signed_pre_key_signature[0] ^= 0x01;

    let kyber_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_signature = bob_identity
        .private_key()
        .calculate_signature(&kyber_public, &mut bob_rng)
        .expect("sign kyber pre-key");

    let tampered_bundle = PreKeyBundle::new(
        0x7202,
        DeviceId::new(1).expect("valid device id"),
        Some((21u32.into(), pre_key_pair.public_key)),
        22u32.into(),
        signed_pre_key_pair.public_key,
        tampered_signed_pre_key_signature,
        23u32.into(),
        kyber_pre_key_pair.public_key,
        kyber_signature.to_vec(),
        *bob_identity.identity_key(),
    )
    .expect("construct syntactically valid tampered bundle");

    let mut alice =
        LibsignalSessionBackend::new(alice_identity, 0x7101).expect("initialize alice backend");

    let rejected = alice
        .process_remote_prekey_bundle(&address("bob"), &tampered_bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory session setup is synchronous");
    assert!(rejected.is_err());

    // A rejected authentication transcript must not leave behind a usable outbound session.
    let encrypt_after_rejection = alice
        .encrypt(
            &address("bob"),
            b"must not encrypt after invalid pre-key signature",
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory post-rejection encryption is synchronous");
    assert!(encrypt_after_rejection.is_err());
}

#[test]
fn public_backend_rejects_tampered_kyber_prekey_bundle_without_creating_session() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut alice_rng = StdRng::from_seed([0x71; 32]);
    let mut bob_rng = StdRng::from_seed([0x72; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);
    let pre_key_pair = KeyPair::generate(&mut bob_rng);
    let signed_pre_key_pair = KeyPair::generate(&mut bob_rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut bob_rng);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = bob_identity
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut bob_rng)
        .expect("sign signed pre-key");

    let kyber_public = kyber_pre_key_pair.public_key.serialize();
    let mut tampered_kyber_signature = bob_identity
        .private_key()
        .calculate_signature(&kyber_public, &mut bob_rng)
        .expect("sign kyber pre-key")
        .to_vec();
    tampered_kyber_signature[0] ^= 0x01;

    let tampered_bundle = PreKeyBundle::new(
        0x8202,
        DeviceId::new(1).expect("valid device id"),
        Some((31u32.into(), pre_key_pair.public_key)),
        32u32.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        33u32.into(),
        kyber_pre_key_pair.public_key,
        tampered_kyber_signature,
        *bob_identity.identity_key(),
    )
    .expect("construct syntactically valid tampered Kyber bundle");

    let mut alice =
        LibsignalSessionBackend::new(alice_identity, 0x8101).expect("initialize alice backend");

    let rejected = alice
        .process_remote_prekey_bundle(&address("bob"), &tampered_bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory Kyber session setup is synchronous");
    assert!(rejected.is_err());

    // Kyber authentication failure must be atomic as well: no partial session may remain usable.
    let encrypt_after_rejection = alice
        .encrypt(
            &address("bob"),
            b"must not encrypt after invalid Kyber pre-key signature",
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory post-Kyber-rejection encryption is synchronous");
    assert!(encrypt_after_rejection.is_err());
}


#[test]
fn generated_desktop_prekeys_are_publishable_and_receive_first_message() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut alice_rng = StdRng::from_seed([0x31; 32]);
    let mut bob_rng = StdRng::from_seed([0x32; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);
    let mut alice =
        LibsignalSessionBackend::new(alice_identity, 0xA001).expect("initialize alice backend");
    let mut bob =
        LibsignalSessionBackend::new(bob_identity, 0xB002).expect("initialize bob backend");

    let published = bob
        .generate_and_store_prekey_bundle(
            1001,
            2,
            2001,
            3001,
            1_700_000_000_000,
            &mut bob_rng,
        )
        .now_or_never()
        .expect("in-memory pre-key generation is synchronous")
        .expect("generate bob publishable pre-keys");

    assert_eq!(published.registration_id, 0xB002);
    assert_eq!(published.one_time_pre_keys.len(), 2);
    assert_eq!(published.signed_pre_key.key_id, 2001);
    assert_eq!(published.kyber_pre_key.key_id, 3001);

    let first_pre_key = &published.one_time_pre_keys[0];
    let bundle = PreKeyBundle::new(
        published.registration_id,
        DeviceId::new(1).expect("valid device id"),
        Some((
            first_pre_key.key_id.into(),
            PublicKey::deserialize(&first_pre_key.public_key).expect("decode public pre-key"),
        )),
        published.signed_pre_key.key_id.into(),
        PublicKey::deserialize(&published.signed_pre_key.public_key)
            .expect("decode signed pre-key"),
        published.signed_pre_key.signature.clone(),
        published.kyber_pre_key.key_id.into(),
        kem::PublicKey::deserialize(&published.kyber_pre_key.public_key)
            .expect("decode Kyber pre-key"),
        published.kyber_pre_key.signature.clone(),
        IdentityKey::decode(&published.identity_key).expect("decode identity key"),
    )
    .expect("published material forms a libsignal pre-key bundle");

    alice
        .process_remote_prekey_bundle(&address("bob"), &bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory session setup is synchronous")
        .expect("alice processes generated bob bundle");

    let plaintext = b"ENIGMA desktop generated-prekey interop";
    let first = alice
        .encrypt(
            &address("bob"),
            plaintext,
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory encryption is synchronous")
        .expect("alice encrypts first message");

    assert_eq!(first.message_type, SessionMessageType::PreKey);
    let decrypted = bob
        .decrypt(&address("alice"), &first, &mut bob_rng)
        .now_or_never()
        .expect("in-memory decrypt is synchronous")
        .expect("bob decrypts using generated/stored pre-keys");

    assert_eq!(decrypted, plaintext);
}
