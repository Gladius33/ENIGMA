use base64::{engine::general_purpose::STANDARD, Engine as _};
use enigma_signal::{
    verify_device_authorization_proof, DeviceAuthorizationExpectation,
    LibsignalIdentityProofVerifier, SignalAdapterError,
};
use libsignal_protocol::{IdentityKey, PrivateKey};
use rand::{rngs::StdRng, SeedableRng};

fn transcript(target_identity_key: &str, authorizer_identity_key: &str) -> String {
    format!(
        concat!(
            "ENIGMA_DEVICE_LINK_V1\n",
            "account_id=33333333-3333-4333-8333-333333333333\n",
            "new_device_id=11111111-1111-4111-8111-111111111111\n",
            "authorizing_device_id=44444444-4444-4444-8444-444444444444\n",
            "pairing_session_id=22222222-2222-4222-8222-222222222222\n",
            "platform=linux\n",
            "protocol_version=1\n",
            "min_supported_version=1\n",
            "capabilities=127\n",
            "issued_at_unix_ms=1700000000000\n",
            "target_identity_key={}\n",
            "authorizer_identity_key={}\n",
        ),
        target_identity_key, authorizer_identity_key
    )
}

fn expectation<'a>(
    target_identity_key: &'a str,
    authorizer_identity_key: &'a str,
) -> DeviceAuthorizationExpectation<'a> {
    DeviceAuthorizationExpectation {
        account_id: "33333333-3333-4333-8333-333333333333",
        new_device_id: "11111111-1111-4111-8111-111111111111",
        authorizing_device_id: "44444444-4444-4444-8444-444444444444",
        pairing_session_id: "22222222-2222-4222-8222-222222222222",
        platform: "linux",
        protocol_version: 1,
        min_supported_version: 1,
        capabilities: 127,
        issued_at_unix_ms: 1_700_000_000_000,
        target_identity_key,
        authorizer_identity_key,
    }
}

#[test]
fn real_libsignal_identity_authorizes_only_its_own_declared_transcript() {
    let authorizer_private = PrivateKey::deserialize(&[0x42; 32]).expect("fixed private key");
    let authorizer_public = authorizer_private
        .public_key()
        .expect("derive authorizer public key");
    let authorizer_identity = IdentityKey::new(authorizer_public).serialize();
    let authorizer_identity_b64 = STANDARD.encode(authorizer_identity.as_ref());
    let target_identity_b64 = STANDARD.encode([0x11; 33]);

    let valid_transcript = transcript(&target_identity_b64, &authorizer_identity_b64);
    let mut valid_rng = StdRng::from_seed([0x24; 32]);
    let valid_signature = authorizer_private
        .calculate_signature(valid_transcript.as_bytes(), &mut valid_rng)
        .expect("libsignal signature");

    assert_eq!(
        verify_device_authorization_proof(
            &LibsignalIdentityProofVerifier,
            authorizer_identity.as_ref(),
            &valid_transcript,
            &valid_signature,
            expectation(&target_identity_b64, &authorizer_identity_b64),
        ),
        Ok(())
    );

    // This transcript is internally consistent and is genuinely signed by the
    // authorizer private key, but it lies about which public identity signed it.
    // The explicit identity binding must reject it before accepting the proof.
    let forged_identity_b64 = STANDARD.encode([0x09; 33]);
    let forged_transcript = transcript(&target_identity_b64, &forged_identity_b64);
    let mut forged_rng = StdRng::from_seed([0x25; 32]);
    let forged_signature = authorizer_private
        .calculate_signature(forged_transcript.as_bytes(), &mut forged_rng)
        .expect("libsignal signature");

    assert_eq!(
        verify_device_authorization_proof(
            &LibsignalIdentityProofVerifier,
            authorizer_identity.as_ref(),
            &forged_transcript,
            &forged_signature,
            expectation(&target_identity_b64, &forged_identity_b64),
        ),
        Err(SignalAdapterError::InvalidDeviceAuthorizationProof)
    );
}
