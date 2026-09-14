use libsignal_protocol::{IdentityKey, PrivateKey, PublicKey};

/// Cross-runtime libsignal identity key-derivation/serialization vector shared with
/// Android `LibsignalProtocolSmokeTest.identityDerivationMatchesDesktopGoldenVectorV1`.
///
/// This proves that the pinned Android and Rust libsignal runtimes derive and serialize the same
/// public identity from identical input private-key material. The private-key serialization itself
/// is deliberately not asserted: libsignal normalizes/clamps private material during construction,
/// and that internal representation is not the cross-runtime wire contract being certified here.
/// SIG-001 remains blocked until session, pre-key and ciphertext vectors are also certified across
/// Android, Rust, Windows and Linux.
#[test]
fn android_identity_derivation_golden_vector_v1_matches_rust() {
    let private_key_input = [0x42; 32];
    let expected_public_key = [
        0x05, 0x13, 0x2c, 0x44, 0x2b, 0xe0, 0x10, 0xfb, 0xd5, 0x7e, 0x72, 0x60, 0x33, 0x28, 0xaa,
        0x76, 0xe7, 0x1f, 0xcc, 0xc1, 0x50, 0x3a, 0xae, 0x21, 0x93, 0x27, 0xd1, 0x4d, 0x9c, 0x99,
        0x93, 0xf4, 0x72,
    ];

    let private_key = PrivateKey::deserialize(&private_key_input).expect("fixed private key input");
    let derived_identity = IdentityKey::new(private_key.public_key().expect("derive public key"));

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

/// Cross-runtime deterministic Curve25519 public pre-key vector shared with Android
/// `LibsignalProtocolSmokeTest.preKeyDerivationMatchesDesktopGoldenVectorV1`.
///
/// This deliberately certifies only public pre-key derivation/serialization from fixed private
/// input. It does not claim session/ciphertext interoperability; SIG-001 remains blocked until the
/// complete pre-key bundle, session establishment and ciphertext vectors are certified.
#[test]
fn android_prekey_derivation_golden_vector_v1_matches_rust() {
    let private_key_input = [0x24; 32];
    let expected_public_key = [
        0x05, 0x04, 0xbc, 0xd2, 0xe0, 0xd0, 0x0f, 0x2c, 0xce, 0x5f, 0xe8, 0xf1, 0xc6, 0xc2, 0xfb,
        0xec, 0x5c, 0x07, 0xfa, 0x56, 0xe3, 0xaa, 0x5c, 0x88, 0xa5, 0x68, 0x99, 0x75, 0xd8, 0x8b,
        0x3f, 0xce, 0x05,
    ];

    let private_key = PrivateKey::deserialize(&private_key_input).expect("fixed pre-key input");
    let derived_public = private_key.public_key().expect("derive pre-key public key");

    assert_eq!(
        derived_public.serialize().as_ref(),
        expected_public_key.as_slice()
    );
}

/// XEdDSA verification vector copied from the exact pinned libsignal revision and shared with
/// Android `LibsignalProtocolSmokeTest.xeddsaVerificationMatchesDesktopGoldenVectorV1`.
///
/// Unlike key serialization alone, this exercises a signed-pre-key primitive used when validating
/// a pre-key bundle. Both runtimes must accept the authentic signature and fail closed after a
/// one-bit mutation. Signature generation remains owned entirely by libsignal; ENIGMA implements
/// no custom Curve25519/XEdDSA logic.
#[test]
fn android_xeddsa_verification_golden_vector_v1_matches_rust() {
    let identity_public_key = [
        0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9, 0xdc,
        0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35, 0x6b, 0xe8, 0x4d, 0x88, 0x7e, 0x32,
        0x2c, 0x64,
    ];
    let signed_prekey_public = [
        0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2, 0xc4,
        0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d, 0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d,
        0x99, 0xfb, 0x4a,
    ];
    let signature = [
        0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c, 0x9c,
        0x74, 0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb, 0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28,
        0x6d, 0xfb, 0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb, 0xb8, 0x21, 0x56,
        0x9b, 0x3d, 0x90, 0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86, 0xce, 0xf0, 0x47, 0xbd,
        0x60, 0xb8, 0x6e, 0x88,
    ];

    let identity_public = PublicKey::from_djb_public_key_bytes(&identity_public_key)
        .expect("fixed libsignal identity public key");

    assert!(identity_public.verify_signature(&signed_prekey_public, &signature));

    let mut tampered_signature = signature;
    tampered_signature[0] ^= 0x01;
    assert!(!identity_public.verify_signature(&signed_prekey_public, &tampered_signature));
}
