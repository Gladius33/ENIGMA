#![forbid(unsafe_code)]

pub mod coordinator;
pub mod engine;
pub mod signaling;

use base64::{engine::general_purpose::{STANDARD, STANDARD_NO_PAD}, Engine as _};
use serde::{Deserialize, Serialize};

const VERSION: u16 = 1;
const PROTOCOL_LABEL: &str = "ENIGMA_P2P_AUTH_V1";
const MAX_FRAME_BYTES: usize = 768 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
const MAX_FINGERPRINT_BYTES: usize = 256;
const AUTH_NONCE_BYTES: usize = 32;
const MAX_SIGNATURE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum P2pRoute {
    Direct,
    Turn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pAuthProof {
    pub session_id: String,
    pub bubble_id: String,
    pub initiator_device_id: String,
    pub responder_device_id: String,
    pub offer_fingerprint: String,
    pub answer_fingerprint: String,
    pub proof_device_id: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pRouteObservation {
    pub session_id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub route: P2pRoute,
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pMessageEnvelope {
    pub bubble_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub message_type: String,
    pub ciphertext: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum P2pReceiptStatus {
    Delivered,
    Read,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pReceiptEnvelope {
    pub receipt_id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub status: P2pReceiptStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pReceiptAck {
    pub receipt_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedP2pFrame {
    Auth(P2pAuthProof),
    Route(P2pRouteObservation),
    Message(P2pMessageEnvelope),
    Receipt(P2pReceiptEnvelope),
    ReceiptAck(P2pReceiptAck),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum P2pProtocolError {
    InvalidFrame,
    UnsupportedVersion,
    OversizedFrame,
    InvalidField,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireFrame {
    version: u16,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initiator_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    responder_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offer_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    answer_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bubble_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sender_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_candidate_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_candidate_type: Option<String>,
}

impl WireFrame {
    fn base(kind: &str) -> Self {
        Self {
            version: VERSION,
            kind: kind.to_owned(),
            session_id: None,
            initiator_device_id: None,
            responder_device_id: None,
            offer_fingerprint: None,
            answer_fingerprint: None,
            proof_device_id: None,
            nonce: None,
            signature: None,
            bubble_id: None,
            sender_device_id: None,
            recipient_device_id: None,
            client_message_id: None,
            receipt_id: None,
            message_type: None,
            status: None,
            ciphertext: None,
            route: None,
            local_candidate_type: None,
            remote_candidate_type: None,
        }
    }
}

pub fn encode_auth(proof: &P2pAuthProof) -> Result<String, P2pProtocolError> {
    validate_auth(proof)?;
    let mut frame = WireFrame::base("auth");
    frame.session_id = Some(proof.session_id.clone());
    frame.bubble_id = Some(proof.bubble_id.clone());
    frame.initiator_device_id = Some(proof.initiator_device_id.clone());
    frame.responder_device_id = Some(proof.responder_device_id.clone());
    frame.offer_fingerprint = Some(proof.offer_fingerprint.clone());
    frame.answer_fingerprint = Some(proof.answer_fingerprint.clone());
    frame.proof_device_id = Some(proof.proof_device_id.clone());
    frame.nonce = Some(proof.nonce.clone());
    frame.signature = Some(proof.signature.clone());
    encode_frame(&frame)
}

pub fn encode_route(observation: &P2pRouteObservation) -> Result<String, P2pProtocolError> {
    validate_uuid(&observation.session_id)?;
    validate_uuid(&observation.bubble_id)?;
    validate_uuid(&observation.sender_device_id)?;
    validate_candidate_type(&observation.local_candidate_type)?;
    validate_candidate_type(&observation.remote_candidate_type)?;
    let mut frame = WireFrame::base("route");
    frame.session_id = Some(observation.session_id.clone());
    frame.bubble_id = Some(observation.bubble_id.clone());
    frame.sender_device_id = Some(observation.sender_device_id.clone());
    frame.route = Some(match observation.route {
        P2pRoute::Direct => "DIRECT",
        P2pRoute::Turn => "TURN",
    }.to_owned());
    frame.local_candidate_type = Some(observation.local_candidate_type.clone());
    frame.remote_candidate_type = Some(observation.remote_candidate_type.clone());
    encode_frame(&frame)
}

pub fn encode_message(message: &P2pMessageEnvelope) -> Result<String, P2pProtocolError> {
    validate_message(message)?;
    let mut frame = WireFrame::base("message");
    frame.bubble_id = Some(message.bubble_id.clone());
    frame.sender_device_id = Some(message.sender_device_id.clone());
    frame.recipient_device_id = Some(message.recipient_device_id.clone());
    frame.client_message_id = Some(message.client_message_id.clone());
    frame.message_type = Some(message.message_type.clone());
    frame.ciphertext = Some(message.ciphertext.clone());
    encode_frame(&frame)
}

pub fn encode_receipt(receipt: &P2pReceiptEnvelope) -> Result<String, P2pProtocolError> {
    validate_receipt(receipt)?;
    let mut frame = WireFrame::base("receipt");
    frame.receipt_id = Some(receipt.receipt_id.clone());
    frame.bubble_id = Some(receipt.bubble_id.clone());
    frame.sender_device_id = Some(receipt.sender_device_id.clone());
    frame.recipient_device_id = Some(receipt.recipient_device_id.clone());
    frame.client_message_id = Some(receipt.client_message_id.clone());
    frame.status = Some(match receipt.status {
        P2pReceiptStatus::Delivered => "DELIVERED",
        P2pReceiptStatus::Read => "READ",
    }.to_owned());
    encode_frame(&frame)
}

pub fn encode_receipt_ack(ack: &P2pReceiptAck) -> Result<String, P2pProtocolError> {
    validate_uuid(&ack.receipt_id)?;
    let mut frame = WireFrame::base("receipt_ack");
    frame.receipt_id = Some(ack.receipt_id.clone());
    encode_frame(&frame)
}

pub fn decode(value: &str) -> Result<DecodedP2pFrame, P2pProtocolError> {
    if value.is_empty() || value.len() > MAX_FRAME_BYTES {
        return Err(P2pProtocolError::OversizedFrame);
    }
    let frame = serde_json::from_str::<WireFrame>(value).map_err(|_| P2pProtocolError::InvalidFrame)?;
    if frame.version != VERSION {
        return Err(P2pProtocolError::UnsupportedVersion);
    }

    match frame.kind.as_str() {
        "auth" => {
            let proof = P2pAuthProof {
                session_id: required(frame.session_id)?,
                bubble_id: required(frame.bubble_id)?,
                initiator_device_id: required(frame.initiator_device_id)?,
                responder_device_id: required(frame.responder_device_id)?,
                offer_fingerprint: required(frame.offer_fingerprint)?,
                answer_fingerprint: required(frame.answer_fingerprint)?,
                proof_device_id: required(frame.proof_device_id)?,
                nonce: required(frame.nonce)?,
                signature: required(frame.signature)?,
            };
            validate_auth(&proof)?;
            Ok(DecodedP2pFrame::Auth(proof))
        }
        "route" => {
            let route = match required(frame.route)?.as_str() {
                "DIRECT" => P2pRoute::Direct,
                "TURN" => P2pRoute::Turn,
                _ => return Err(P2pProtocolError::InvalidField),
            };
            let observation = P2pRouteObservation {
                session_id: required(frame.session_id)?,
                bubble_id: required(frame.bubble_id)?,
                sender_device_id: required(frame.sender_device_id)?,
                route,
                local_candidate_type: required(frame.local_candidate_type)?,
                remote_candidate_type: required(frame.remote_candidate_type)?,
            };
            validate_uuid(&observation.session_id)?;
            validate_uuid(&observation.bubble_id)?;
            validate_uuid(&observation.sender_device_id)?;
            validate_candidate_type(&observation.local_candidate_type)?;
            validate_candidate_type(&observation.remote_candidate_type)?;
            Ok(DecodedP2pFrame::Route(observation))
        }
        "message" => {
            let message = P2pMessageEnvelope {
                bubble_id: required(frame.bubble_id)?,
                sender_device_id: required(frame.sender_device_id)?,
                recipient_device_id: required(frame.recipient_device_id)?,
                client_message_id: required(frame.client_message_id)?,
                message_type: required(frame.message_type)?,
                ciphertext: required(frame.ciphertext)?,
            };
            validate_message(&message)?;
            Ok(DecodedP2pFrame::Message(message))
        }
        "receipt" => {
            let status = match required(frame.status)?.as_str() {
                "DELIVERED" => P2pReceiptStatus::Delivered,
                "READ" => P2pReceiptStatus::Read,
                _ => return Err(P2pProtocolError::InvalidField),
            };
            let receipt = P2pReceiptEnvelope {
                receipt_id: required(frame.receipt_id)?,
                bubble_id: required(frame.bubble_id)?,
                sender_device_id: required(frame.sender_device_id)?,
                recipient_device_id: required(frame.recipient_device_id)?,
                client_message_id: required(frame.client_message_id)?,
                status,
            };
            validate_receipt(&receipt)?;
            Ok(DecodedP2pFrame::Receipt(receipt))
        }
        "receipt_ack" => {
            let ack = P2pReceiptAck {
                receipt_id: required(frame.receipt_id)?,
            };
            validate_uuid(&ack.receipt_id)?;
            Ok(DecodedP2pFrame::ReceiptAck(ack))
        }
        _ => Err(P2pProtocolError::InvalidFrame),
    }
}

pub fn auth_transcript(proof: &P2pAuthProof) -> Result<Vec<u8>, P2pProtocolError> {
    validate_auth(proof)?;
    Ok([
        PROTOCOL_LABEL,
        &proof.session_id,
        &proof.bubble_id,
        &proof.initiator_device_id,
        &proof.responder_device_id,
        &proof.offer_fingerprint,
        &proof.answer_fingerprint,
        &proof.proof_device_id,
        &proof.nonce,
    ]
    .join("\n")
    .into_bytes())
}

pub fn consensus_route(local: &P2pRouteObservation, remote: &P2pRouteObservation) -> P2pRoute {
    if local.route == P2pRoute::Turn || remote.route == P2pRoute::Turn {
        P2pRoute::Turn
    } else {
        P2pRoute::Direct
    }
}

pub fn encode_bytes(value: &[u8]) -> String {
    STANDARD_NO_PAD.encode(value)
}

pub fn decode_bytes(value: &str, max_len: usize) -> Result<Vec<u8>, P2pProtocolError> {
    if value.is_empty() || value.len() > max_len.saturating_mul(2).saturating_add(16) {
        return Err(P2pProtocolError::InvalidField);
    }
    let decoded = STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| P2pProtocolError::InvalidField)?;
    if decoded.is_empty() || decoded.len() > max_len {
        return Err(P2pProtocolError::InvalidField);
    }
    Ok(decoded)
}

fn encode_frame(frame: &WireFrame) -> Result<String, P2pProtocolError> {
    let encoded = serde_json::to_string(frame).map_err(|_| P2pProtocolError::InvalidFrame)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(P2pProtocolError::OversizedFrame);
    }
    Ok(encoded)
}

fn validate_message(message: &P2pMessageEnvelope) -> Result<(), P2pProtocolError> {
    validate_uuid(&message.bubble_id)?;
    validate_uuid(&message.sender_device_id)?;
    validate_uuid(&message.recipient_device_id)?;
    validate_uuid(&message.client_message_id)?;
    if message.sender_device_id == message.recipient_device_id
        || !matches!(message.message_type.as_str(), "text" | "file" | "opaque")
        || message.ciphertext.is_empty()
        || message.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(P2pProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_receipt(receipt: &P2pReceiptEnvelope) -> Result<(), P2pProtocolError> {
    validate_uuid(&receipt.receipt_id)?;
    validate_uuid(&receipt.bubble_id)?;
    validate_uuid(&receipt.sender_device_id)?;
    validate_uuid(&receipt.recipient_device_id)?;
    validate_uuid(&receipt.client_message_id)?;
    if receipt.sender_device_id == receipt.recipient_device_id {
        return Err(P2pProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_auth(proof: &P2pAuthProof) -> Result<(), P2pProtocolError> {
    validate_uuid(&proof.session_id)?;
    validate_uuid(&proof.bubble_id)?;
    validate_uuid(&proof.initiator_device_id)?;
    validate_uuid(&proof.responder_device_id)?;
    validate_uuid(&proof.proof_device_id)?;
    if proof.initiator_device_id == proof.responder_device_id
        || (proof.proof_device_id != proof.initiator_device_id
            && proof.proof_device_id != proof.responder_device_id)
        || proof.offer_fingerprint.is_empty()
        || proof.offer_fingerprint.len() > MAX_FINGERPRINT_BYTES
        || proof.answer_fingerprint.is_empty()
        || proof.answer_fingerprint.len() > MAX_FINGERPRINT_BYTES
        || decode_bytes(&proof.nonce, AUTH_NONCE_BYTES)?.len() != AUTH_NONCE_BYTES
        || decode_bytes(&proof.signature, MAX_SIGNATURE_BYTES)?.is_empty()
    {
        return Err(P2pProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_candidate_type(value: &str) -> Result<(), P2pProtocolError> {
    if matches!(value, "host" | "srflx" | "prflx" | "relay") {
        Ok(())
    } else {
        Err(P2pProtocolError::InvalidField)
    }
}

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn validate_uuid(value: &str) -> Result<(), P2pProtocolError> {
    if is_canonical_uuid(value) {
        Ok(())
    } else {
        Err(P2pProtocolError::InvalidField)
    }
}

fn required(value: Option<String>) -> Result<String, P2pProtocolError> {
    value.filter(|value| !value.is_empty()).ok_or(P2pProtocolError::InvalidField)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> P2pAuthProof {
        P2pAuthProof {
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            bubble_id: "22222222-2222-4222-8222-222222222222".into(),
            initiator_device_id: "33333333-3333-4333-8333-333333333333".into(),
            responder_device_id: "44444444-4444-4444-8444-444444444444".into(),
            offer_fingerprint: "sha-256 AA:BB".into(),
            answer_fingerprint: "sha-256 CC:DD".into(),
            proof_device_id: "33333333-3333-4333-8333-333333333333".into(),
            nonce: encode_bytes(&[7; 32]),
            signature: encode_bytes(&[9; 64]),
        }
    }

    #[test]
    fn decodes_literal_android_message_and_receipt_frames() {
        let message = r#"{"version":1,"kind":"message","bubble_id":"22222222-2222-4222-8222-222222222222","sender_device_id":"33333333-3333-4333-8333-333333333333","recipient_device_id":"44444444-4444-4444-8444-444444444444","client_message_id":"55555555-5555-4555-8555-555555555555","message_type":"text","ciphertext":"opaque"}"#;
        assert_eq!(
            decode(message),
            Ok(DecodedP2pFrame::Message(P2pMessageEnvelope {
                bubble_id: "22222222-2222-4222-8222-222222222222".into(),
                sender_device_id: "33333333-3333-4333-8333-333333333333".into(),
                recipient_device_id: "44444444-4444-4444-8444-444444444444".into(),
                client_message_id: "55555555-5555-4555-8555-555555555555".into(),
                message_type: "text".into(),
                ciphertext: "opaque".into(),
            }))
        );

        let receipt = r#"{"version":1,"kind":"receipt","bubble_id":"22222222-2222-4222-8222-222222222222","sender_device_id":"44444444-4444-4444-8444-444444444444","recipient_device_id":"33333333-3333-4333-8333-333333333333","client_message_id":"55555555-5555-4555-8555-555555555555","receipt_id":"66666666-6666-4666-8666-666666666666","status":"DELIVERED"}"#;
        assert_eq!(
            decode(receipt),
            Ok(DecodedP2pFrame::Receipt(P2pReceiptEnvelope {
                receipt_id: "66666666-6666-4666-8666-666666666666".into(),
                bubble_id: "22222222-2222-4222-8222-222222222222".into(),
                sender_device_id: "44444444-4444-4444-8444-444444444444".into(),
                recipient_device_id: "33333333-3333-4333-8333-333333333333".into(),
                client_message_id: "55555555-5555-4555-8555-555555555555".into(),
                status: P2pReceiptStatus::Delivered,
            }))
        );
    }

    #[test]
    fn android_auth_frame_round_trips() {
        let proof = auth();
        let encoded = encode_auth(&proof).expect("encode");
        assert_eq!(decode(&encoded), Ok(DecodedP2pFrame::Auth(proof)));
    }

    #[test]
    fn transcript_matches_android_join_order() {
        let proof = auth();
        let transcript = String::from_utf8(auth_transcript(&proof).expect("transcript"))
            .expect("utf8");
        assert_eq!(
            transcript,
            format!(
                "ENIGMA_P2P_AUTH_V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
                proof.session_id,
                proof.bubble_id,
                proof.initiator_device_id,
                proof.responder_device_id,
                proof.offer_fingerprint,
                proof.answer_fingerprint,
                proof.proof_device_id,
                proof.nonce,
            )
        );
    }

    #[test]
    fn turn_wins_route_consensus() {
        let direct = P2pRouteObservation {
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            bubble_id: "22222222-2222-4222-8222-222222222222".into(),
            sender_device_id: "33333333-3333-4333-8333-333333333333".into(),
            route: P2pRoute::Direct,
            local_candidate_type: "host".into(),
            remote_candidate_type: "srflx".into(),
        };
        let turn = P2pRouteObservation {
            route: P2pRoute::Turn,
            local_candidate_type: "relay".into(),
            ..direct.clone()
        };
        assert_eq!(consensus_route(&direct, &turn), P2pRoute::Turn);
        assert_eq!(consensus_route(&direct, &direct), P2pRoute::Direct);
    }

    #[test]
    fn rejects_wrong_auth_nonce_size() {
        let mut proof = auth();
        proof.nonce = encode_bytes(&[1; 31]);
        assert_eq!(encode_auth(&proof), Err(P2pProtocolError::InvalidField));
    }
}
