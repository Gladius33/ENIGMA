use std::time::{Duration, SystemTime};

use enigma_signal::session::LibsignalSessionBackend;
use futures_util::FutureExt;
use libsignal_protocol::{kem, DeviceId, IdentityKeyPair, KeyPair, PreKeyBundle, ProtocolAddress};
use rand::{rngs::StdRng, SeedableRng};

fn address(name: &str) -> ProtocolAddress {
    ProtocolAddress::new(name.into(), DeviceId::new(1).expect("valid device id"))
}

#[test]
fn public_backend_rejects_identity_substitution_without_creating_session() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut alice_rng = StdRng::from_seed([0x81; 32]);
    let mut bob_rng = StdRng::from_seed([0x82; 32]);

    let alice_identity = IdentityKeyPair::generate(&mut alice_rng);
    let bob_identity = IdentityKeyPair::generate(&mut bob_rng);
    let substituted_identity = IdentityKeyPair::generate(&mut bob_rng);
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
        .expect("sign Kyber pre-key");

    // The attacker substitutes only the advertised identity key while keeping Bob's signed
    // pre-keys and signatures. Session establishment must authenticate the bundle as one
    // transcript and reject this identity/pre-key mismatch.
    let substituted_bundle = PreKeyBundle::new(
        0x3202,
        DeviceId::new(1).expect("valid device id"),
        Some((41u32.into(), pre_key_pair.public_key)),
        42u32.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        43u32.into(),
        kyber_pre_key_pair.public_key,
        kyber_signature.to_vec(),
        *substituted_identity.identity_key(),
    )
    .expect("construct syntactically valid identity-substituted bundle");

    let mut alice =
        LibsignalSessionBackend::new(alice_identity, 0x3101).expect("initialize alice backend");

    let rejected = alice
        .process_remote_prekey_bundle(&address("bob"), &substituted_bundle, now, &mut alice_rng)
        .now_or_never()
        .expect("in-memory session setup is synchronous");
    assert!(rejected.is_err());

    // Authentication failure must be atomic. A rejected identity substitution must not leave a
    // partially initialized outbound session that could subsequently encrypt traffic.
    let encrypt_after_rejection = alice
        .encrypt(
            &address("bob"),
            b"must not encrypt after identity substitution",
            now + Duration::from_secs(1),
            &mut alice_rng,
        )
        .now_or_never()
        .expect("in-memory post-rejection encryption is synchronous");
    assert!(encrypt_after_rejection.is_err());
}
