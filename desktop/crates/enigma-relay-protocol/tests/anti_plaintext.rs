use enigma_protocol::{MailboxId, MessageId};
use enigma_relay_protocol::{OpaqueRelayEnvelope, RelayDeliveryState};

fn envelope(ciphertext: Vec<u8>) -> OpaqueRelayEnvelope {
    OpaqueRelayEnvelope::new(
        MailboxId::from_bytes([0x11; 32]),
        MessageId::from_bytes([0x22; 16]),
        1_000,
        2_000,
        ciphertext,
    )
    .expect("valid opaque relay envelope")
}

#[test]
fn public_relay_api_never_exposes_ciphertext_in_debug_output() {
    let marker = b"ENIGMA-RC1-PLAINTEXT-MUST-NOT-APPEAR".to_vec();
    let relay = envelope(marker.clone());

    let rendered = format!("{relay:?}");

    assert!(!rendered.contains("ENIGMA-RC1-PLAINTEXT-MUST-NOT-APPEAR"));
    assert!(!rendered.contains(&format!("{marker:?}")));
    assert!(rendered.contains("ciphertext_len"));
}

#[test]
fn acknowledgement_purges_ciphertext_through_the_public_api() {
    let mut relay = envelope(b"temporary-relay-ciphertext".to_vec());

    relay.acknowledge();

    assert_eq!(relay.state(), RelayDeliveryState::Acknowledged);
    assert!(relay.must_delete());
    assert!(relay.ciphertext.is_empty());
}

#[test]
fn expiry_boundary_purges_ciphertext_through_the_public_api() {
    let mut relay = envelope(b"temporary-relay-ciphertext".to_vec());

    relay.refresh_expiry_state(2_000);

    assert_eq!(relay.state(), RelayDeliveryState::Expired);
    assert!(relay.must_delete());
    assert!(relay.ciphertext.is_empty());
}
