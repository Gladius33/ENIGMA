use std::{
    collections::BTreeMap,
    env,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use enigma_signal::session::{
    LibsignalSessionBackend, SessionCiphertext, SessionMessageType,
};
use futures_util::FutureExt;
use libsignal_protocol::{
    kem, DeviceId, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, KeyPair,
    KyberPreKeyRecord, PreKeyBundle, PreKeyRecord, ProtocolAddress, SessionRecord, SessionStore,
    SignedPreKeyRecord, Timestamp,
};
use rand::{rngs::StdRng, SeedableRng};

const FIXTURE_ENV: &str = "ENIGMA_ANDROID_INTEROP_FIXTURE";
const REPLY_ENV: &str = "ENIGMA_ANDROID_INTEROP_REPLY";
const FIXTURE_VERSION: &str = "1";

fn address(name: &str) -> ProtocolAddress {
    ProtocolAddress::new(name.into(), DeviceId::new(1).expect("valid device id"))
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the dedicated cross-runtime fixture"))
}

fn encode(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

fn decode(value: &str) -> Vec<u8> {
    BASE64
        .decode(value)
        .unwrap_or_else(|error| panic!("invalid fixture base64: {error}"))
}

fn write_properties(path: &Path, entries: impl IntoIterator<Item = (&'static str, String)>) {
    let body = entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    fs::write(path, body).expect("write cross-runtime fixture");
}

fn read_properties(path: &Path) -> BTreeMap<String, String> {
    fs::read_to_string(path)
        .expect("read cross-runtime fixture")
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .unwrap_or_else(|| panic!("invalid fixture property: {line}"))
        })
        .collect()
}

fn required<'a>(properties: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    properties
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("missing fixture property {key}"))
}

#[test]
#[ignore = "run only from the Android/Rust libsignal interoperability CI gate"]
fn rust_emits_android_prekey_fixture() {
    let fixture_path = required_path(FIXTURE_ENV);
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let mut alice_rng = StdRng::from_seed([0x91; 32]);
    let mut bob_rng = StdRng::from_seed([0x92; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);
    let alice_identity_serialized = alice_identity.serialize().to_vec();
    let bob_identity_serialized = bob_identity.serialize().to_vec();

    let alice_registration_id = 0x5101u32;
    let bob_registration_id = 0x5202u32;
    let pre_key_id = 5101u32;
    let signed_pre_key_id = 5201u32;
    let kyber_pre_key_id = 5301u32;

    let pre_key_pair = KeyPair::generate(&mut bob_rng);
    let signed_pre_key_pair = KeyPair::generate(&mut bob_rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut bob_rng);

    let signed_public = signed_pre_key_pair.public_key.serialize();
    let signed_signature = bob_identity
        .private_key()
        .calculate_signature(&signed_public, &mut bob_rng)
        .expect("sign deterministic signed pre-key");

    let kyber_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_signature = bob_identity
        .private_key()
        .calculate_signature(&kyber_public, &mut bob_rng)
        .expect("sign deterministic Kyber pre-key");

    let pre_key_record = PreKeyRecord::new(pre_key_id.into(), &pre_key_pair);
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id.into(),
        Timestamp::from_epoch_millis(1_700_000_000_000),
        &signed_pre_key_pair,
        &signed_signature,
    );
    let kyber_pre_key_record = KyberPreKeyRecord::new(
        kyber_pre_key_id.into(),
        Timestamp::from_epoch_millis(1_700_000_000_000),
        &kyber_pre_key_pair,
        &kyber_signature,
    );

    let bundle = PreKeyBundle::new(
        bob_registration_id,
        DeviceId::new(1).expect("valid device id"),
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_signature.to_vec(),
        kyber_pre_key_id.into(),
        kyber_pre_key_pair.public_key,
        kyber_signature.to_vec(),
        *bob_identity.identity_key(),
    )
    .expect("construct deterministic Bob pre-key bundle");

    let mut alice =
        LibsignalSessionBackend::new(alice_identity, alice_registration_id)
            .expect("initialize Alice backend");
    alice
        .process_remote_prekey_bundle(&address("bob"), &bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory session setup is synchronous")
        .expect("Alice processes Bob bundle");

    let first_plaintext = b"ENIGMA Rust libsignal to Android interoperability";
    let first = alice
        .encrypt(
            &address("bob"),
            first_plaintext,
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory encryption is synchronous")
        .expect("Rust encrypts first Android-bound message");

    assert_eq!(first.message_type, SessionMessageType::PreKey);
    assert!(!first
        .serialized
        .windows(first_plaintext.len())
        .any(|window| window == first_plaintext));

    let alice_session = alice
        .store()
        .session_store
        .load_session(&address("bob"))
        .now_or_never()
        .expect("in-memory session lookup is synchronous")
        .expect("load Alice session")
        .expect("Alice session must exist after encryption")
        .serialize()
        .expect("serialize canonical Alice libsignal session");

    write_properties(
        &fixture_path,
        [
            ("version", FIXTURE_VERSION.to_owned()),
            ("alice_identity", encode(&alice_identity_serialized)),
            ("alice_registration_id", alice_registration_id.to_string()),
            ("alice_session", encode(&alice_session)),
            ("bob_identity", encode(&bob_identity_serialized)),
            ("bob_registration_id", bob_registration_id.to_string()),
            ("bob_pre_key_id", pre_key_id.to_string()),
            (
                "bob_pre_key_record",
                encode(&pre_key_record.serialize().expect("serialize pre-key record")),
            ),
            ("bob_signed_pre_key_id", signed_pre_key_id.to_string()),
            (
                "bob_signed_pre_key_record",
                encode(
                    &signed_pre_key_record
                        .serialize()
                        .expect("serialize signed pre-key record"),
                ),
            ),
            ("bob_kyber_pre_key_id", kyber_pre_key_id.to_string()),
            (
                "bob_kyber_pre_key_record",
                encode(
                    &kyber_pre_key_record
                        .serialize()
                        .expect("serialize Kyber pre-key record"),
                ),
            ),
            ("first_ciphertext", encode(&first.serialized)),
            ("first_plaintext", encode(first_plaintext)),
            (
                "reply_plaintext",
                encode(b"ENIGMA Android libsignal reply to Rust"),
            ),
        ],
    );
}

#[test]
#[ignore = "run only after the Android half of the interoperability CI gate"]
fn rust_decrypts_android_signal_reply() {
    let fixture_path = required_path(FIXTURE_ENV);
    let reply_path = required_path(REPLY_ENV);
    let fixture = read_properties(&fixture_path);
    let reply = read_properties(&reply_path);

    assert_eq!(required(&fixture, "version"), FIXTURE_VERSION);
    assert_eq!(required(&reply, "version"), FIXTURE_VERSION);

    let alice_identity = decode(required(&fixture, "alice_identity"));
    let alice_registration_id = required(&fixture, "alice_registration_id")
        .parse::<u32>()
        .expect("valid Alice registration id");
    let mut alice =
        LibsignalSessionBackend::from_serialized_identity(&alice_identity, alice_registration_id)
            .expect("restore Alice identity through canonical libsignal serialization");

    let alice_session =
        SessionRecord::deserialize(&decode(required(&fixture, "alice_session")))
            .expect("restore canonical Alice libsignal session");
    alice
        .store_mut()
        .session_store
        .store_session(&address("bob"), &alice_session)
        .now_or_never()
        .expect("in-memory session restore is synchronous")
        .expect("store restored Alice session");

    let bob_identity =
        IdentityKeyPair::try_from(decode(required(&fixture, "bob_identity")).as_slice())
            .expect("restore Bob identity through canonical libsignal serialization");
    alice
        .store_mut()
        .identity_store
        .save_identity(&address("bob"), bob_identity.identity_key())
        .now_or_never()
        .expect("in-memory identity restore is synchronous")
        .expect("trust the Bob identity certified by the fixture transcript");

    let ciphertext = SessionCiphertext {
        message_type: SessionMessageType::Signal,
        serialized: decode(required(&reply, "reply_ciphertext")),
    };
    let expected_plaintext = decode(required(&fixture, "reply_plaintext"));
    let mut alice_rng = StdRng::from_seed([0x93; 32]);
    let decrypted = alice
        .decrypt(&address("bob"), &ciphertext, &mut alice_rng)
        .now_or_never()
        .expect("in-memory reply decryption is synchronous")
        .expect("Rust decrypts Android libsignal reply");

    assert_eq!(decrypted, expected_plaintext);
    assert!(!ciphertext
        .serialized
        .windows(expected_plaintext.len())
        .any(|window| window == expected_plaintext));
}
