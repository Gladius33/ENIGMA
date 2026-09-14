use libsignal_protocol::IdentityKey;

/// Cross-runtime libsignal identity serialization vector shared with
/// Android `LibsignalProtocolSmokeTest.identitySerializationMatchesDesktopGoldenVectorV1`.
///
/// This is deliberately a wire-format vector only. SIG-001 remains blocked until
/// session/pre-key/ciphertext vectors are also certified across Android, Rust,
/// Windows and Linux.
#[test]
fn android_identity_serialization_golden_vector_v1_roundtrips_in_rust() {
    let expected = [
        0x05, 0x13, 0x2c, 0x44, 0x2b, 0xe0, 0x10, 0xfb, 0xd5, 0x7e, 0x72, 0x60, 0x33, 0x28, 0xaa,
        0x76, 0xe7, 0x1f, 0xcc, 0xc1, 0x50, 0x3a, 0xae, 0x21, 0x93, 0x27, 0xd1, 0x4d, 0x9c, 0x99,
        0x93, 0xf4, 0x72,
    ];

    let identity = IdentityKey::decode(&expected).expect("Android identity vector must decode");

    assert_eq!(identity.serialize().as_ref(), expected.as_slice());
}
