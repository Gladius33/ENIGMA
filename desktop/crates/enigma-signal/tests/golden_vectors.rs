use libsignal_protocol::{IdentityKey, PrivateKey};

/// Cross-runtime libsignal identity key-derivation/serialization vector shared with
/// Android `LibsignalProtocolSmokeTest.identityDerivationMatchesDesktopGoldenVectorV1`.
///
/// This proves that the pinned Android and Rust libsignal runtimes derive and serialize the same
/// public identity from identical private key material. SIG-001 remains blocked until session,
/// pre-key and ciphertext vectors are also certified across Android, Rust, Windows and Linux.
#[test]
fn android_identity_derivation_golden_vector_v1_matches_rust() {
    let private_key_bytes = [0x42; 32];
    let expected_public_key = [
        0x05, 0x13, 0x2c, 0x44, 0x2b, 0xe0, 0x10, 0xfb, 0xd5, 0x7e, 0x72, 0x60, 0x33, 0x28, 0xaa,
        0x76, 0xe7, 0x1f, 0xcc, 0xc1, 0x50, 0x3a, 0xae, 0x21, 0x93, 0x27, 0xd1, 0x4d, 0x9c, 0x99,
        0x93, 0xf4, 0x72,
    ];

    let private_key = PrivateKey::deserialize(&private_key_bytes).expect("fixed private key");
    let derived_identity = IdentityKey::new(private_key.public_key().expect("derive public key"));

    assert_eq!(private_key.serialize(), private_key_bytes);
    assert_eq!(
        derived_identity.serialize().as_ref(),
        expected_public_key.as_slice()
    );
    assert_eq!(
        IdentityKey::decode(&expected_public_key)
            .expect("Android identity vector must decode")
            .serialize()
            .as_ref(),
        expected_public_key.as_slice()
    );
}
