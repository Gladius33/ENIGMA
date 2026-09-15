use std::collections::HashMap;

use crate::{
    auth_transcript, consensus_route, decode_bytes, encode_bytes,
    engine::P2pSelectedRoute, P2pAuthProof, P2pMessageEnvelope, P2pProtocolError, P2pReceiptAck,
    P2pReceiptEnvelope, P2pRoute, P2pRouteObservation,
};

const AUTH_NONCE_BYTES: usize = 32;
const MAX_SESSIONS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pSessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pSessionMetadata {
    pub session_id: String,
    pub bubble_id: String,
    pub local_device_id: String,
    pub remote_device_id: String,
    pub initiator_device_id: String,
    pub responder_device_id: String,
    pub role: P2pSessionRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAuthChallenge {
    pub proof_device_id: String,
    pub transcript: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedP2pSession {
    pub session_id: String,
    pub route: P2pRoute,
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum P2pCoordinatorError {
    InvalidSession,
    SessionExists,
    SessionMissing,
    SessionLimit,
    MissingFingerprint,
    AuthenticationRequired,
    AuthenticationFailed,
    InvalidPeerFrame,
    Protocol,
}

impl From<P2pProtocolError> for P2pCoordinatorError {
    fn from(_: P2pProtocolError) -> Self {
        Self::Protocol
    }
}

#[derive(Clone, Debug)]
struct SessionState {
    metadata: P2pSessionMetadata,
    offer_fingerprint: Option<String>,
    answer_fingerprint: Option<String>,
    local_auth_sent: bool,
    remote_auth_verified: bool,
    local_route: Option<P2pSelectedRoute>,
    remote_route: Option<P2pRouteObservation>,
}

impl SessionState {
    fn fingerprints(&self) -> Result<(&str, &str), P2pCoordinatorError> {
        Ok((
            self.offer_fingerprint
                .as_deref()
                .ok_or(P2pCoordinatorError::MissingFingerprint)?,
            self.answer_fingerprint
                .as_deref()
                .ok_or(P2pCoordinatorError::MissingFingerprint)?,
        ))
    }

    fn authenticated(&self) -> Option<AuthenticatedP2pSession> {
        if !self.remote_auth_verified || !self.local_auth_sent {
            return None;
        }
        let local = self.local_route.as_ref()?;
        let remote = self.remote_route.as_ref()?;
        let route = consensus_route(
            &P2pRouteObservation {
                session_id: self.metadata.session_id.clone(),
                bubble_id: self.metadata.bubble_id.clone(),
                sender_device_id: self.metadata.local_device_id.clone(),
                route: local.route,
                local_candidate_type: local.local_candidate_type.clone(),
                remote_candidate_type: local.remote_candidate_type.clone(),
            },
            remote,
        );
        Some(AuthenticatedP2pSession {
            session_id: self.metadata.session_id.clone(),
            route,
            local_candidate_type: local.local_candidate_type.clone(),
            remote_candidate_type: local.remote_candidate_type.clone(),
        })
    }
}

#[derive(Default)]
pub struct P2pSessionCoordinator {
    sessions: HashMap<String, SessionState>,
}

impl P2pSessionCoordinator {
    pub fn register_outgoing(
        &mut self,
        session_id: &str,
        bubble_id: &str,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), P2pCoordinatorError> {
        self.register(
            session_id,
            bubble_id,
            local_device_id,
            remote_device_id,
            local_device_id,
            remote_device_id,
            P2pSessionRole::Initiator,
        )
    }

    pub fn register_incoming(
        &mut self,
        session_id: &str,
        bubble_id: &str,
        local_device_id: &str,
        remote_device_id: &str,
    ) -> Result<(), P2pCoordinatorError> {
        self.register(
            session_id,
            bubble_id,
            local_device_id,
            remote_device_id,
            remote_device_id,
            local_device_id,
            P2pSessionRole::Responder,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        session_id: &str,
        bubble_id: &str,
        local_device_id: &str,
        remote_device_id: &str,
        initiator_device_id: &str,
        responder_device_id: &str,
        role: P2pSessionRole,
    ) -> Result<(), P2pCoordinatorError> {
        if !crate::is_canonical_uuid(session_id)
            || !crate::is_canonical_uuid(bubble_id)
            || !crate::is_canonical_uuid(local_device_id)
            || !crate::is_canonical_uuid(remote_device_id)
            || local_device_id == remote_device_id
        {
            return Err(P2pCoordinatorError::InvalidSession);
        }
        if self.sessions.contains_key(session_id) {
            return Err(P2pCoordinatorError::SessionExists);
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(P2pCoordinatorError::SessionLimit);
        }
        self.sessions.insert(
            session_id.to_owned(),
            SessionState {
                metadata: P2pSessionMetadata {
                    session_id: session_id.to_owned(),
                    bubble_id: bubble_id.to_owned(),
                    local_device_id: local_device_id.to_owned(),
                    remote_device_id: remote_device_id.to_owned(),
                    initiator_device_id: initiator_device_id.to_owned(),
                    responder_device_id: responder_device_id.to_owned(),
                    role,
                },
                offer_fingerprint: None,
                answer_fingerprint: None,
                local_auth_sent: false,
                remote_auth_verified: false,
                local_route: None,
                remote_route: None,
            },
        );
        Ok(())
    }

    pub fn set_dtls_fingerprints(
        &mut self,
        session_id: &str,
        local_fingerprint: &str,
        remote_fingerprint: &str,
    ) -> Result<(), P2pCoordinatorError> {
        if local_fingerprint.is_empty()
            || local_fingerprint.len() > 256
            || remote_fingerprint.is_empty()
            || remote_fingerprint.len() > 256
        {
            return Err(P2pCoordinatorError::MissingFingerprint);
        }
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let (offer, answer) = match state.metadata.role {
            P2pSessionRole::Initiator => (local_fingerprint, remote_fingerprint),
            P2pSessionRole::Responder => (remote_fingerprint, local_fingerprint),
        };
        state.offer_fingerprint = Some(offer.to_owned());
        state.answer_fingerprint = Some(answer.to_owned());
        Ok(())
    }

    pub fn build_local_auth(
        &mut self,
        session_id: &str,
        nonce: &[u8],
        signature: &[u8],
    ) -> Result<P2pAuthProof, P2pCoordinatorError> {
        if nonce.len() != AUTH_NONCE_BYTES || signature.is_empty() || signature.len() > 4096 {
            return Err(P2pCoordinatorError::Protocol);
        }
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let (offer_fingerprint, answer_fingerprint) = state.fingerprints()?;
        let proof = P2pAuthProof {
            session_id: state.metadata.session_id.clone(),
            bubble_id: state.metadata.bubble_id.clone(),
            initiator_device_id: state.metadata.initiator_device_id.clone(),
            responder_device_id: state.metadata.responder_device_id.clone(),
            offer_fingerprint: offer_fingerprint.to_owned(),
            answer_fingerprint: answer_fingerprint.to_owned(),
            proof_device_id: state.metadata.local_device_id.clone(),
            nonce: encode_bytes(nonce),
            signature: encode_bytes(signature),
        };
        auth_transcript(&proof)?;
        state.local_auth_sent = true;
        Ok(proof)
    }

    pub fn local_auth_transcript(
        &self,
        session_id: &str,
        nonce: &[u8],
    ) -> Result<Vec<u8>, P2pCoordinatorError> {
        if nonce.len() != AUTH_NONCE_BYTES {
            return Err(P2pCoordinatorError::Protocol);
        }
        let state = self
            .sessions
            .get(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let (offer_fingerprint, answer_fingerprint) = state.fingerprints()?;
        let proof = P2pAuthProof {
            session_id: state.metadata.session_id.clone(),
            bubble_id: state.metadata.bubble_id.clone(),
            initiator_device_id: state.metadata.initiator_device_id.clone(),
            responder_device_id: state.metadata.responder_device_id.clone(),
            offer_fingerprint: offer_fingerprint.to_owned(),
            answer_fingerprint: answer_fingerprint.to_owned(),
            proof_device_id: state.metadata.local_device_id.clone(),
            nonce: encode_bytes(nonce),
            signature: encode_bytes(&[1]),
        };
        auth_transcript(&proof).map_err(Into::into)
    }

    pub fn remote_auth_challenge(
        &self,
        session_id: &str,
        proof: &P2pAuthProof,
    ) -> Result<RemoteAuthChallenge, P2pCoordinatorError> {
        let state = self
            .sessions
            .get(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let (offer_fingerprint, answer_fingerprint) = state.fingerprints()?;

        if proof.session_id != state.metadata.session_id
            || proof.bubble_id != state.metadata.bubble_id
            || proof.initiator_device_id != state.metadata.initiator_device_id
            || proof.responder_device_id != state.metadata.responder_device_id
            || proof.offer_fingerprint != offer_fingerprint
            || proof.answer_fingerprint != answer_fingerprint
            || proof.proof_device_id != state.metadata.remote_device_id
        {
            return Err(P2pCoordinatorError::AuthenticationFailed);
        }
        if decode_bytes(&proof.nonce, AUTH_NONCE_BYTES)?.len() != AUTH_NONCE_BYTES {
            return Err(P2pCoordinatorError::AuthenticationFailed);
        }
        let signature = decode_bytes(&proof.signature, 4096)?;
        let transcript = auth_transcript(proof)?;
        Ok(RemoteAuthChallenge {
            proof_device_id: proof.proof_device_id.clone(),
            transcript,
            signature,
        })
    }

    pub fn confirm_remote_auth(
        &mut self,
        session_id: &str,
        verified: bool,
    ) -> Result<(), P2pCoordinatorError> {
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        if !verified {
            return Err(P2pCoordinatorError::AuthenticationFailed);
        }
        state.remote_auth_verified = true;
        Ok(())
    }

    pub fn set_local_route(
        &mut self,
        session_id: &str,
        route: P2pSelectedRoute,
    ) -> Result<P2pRouteObservation, P2pCoordinatorError> {
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        if !state.remote_auth_verified {
            return Err(P2pCoordinatorError::AuthenticationRequired);
        }
        let observation = P2pRouteObservation {
            session_id: state.metadata.session_id.clone(),
            bubble_id: state.metadata.bubble_id.clone(),
            sender_device_id: state.metadata.local_device_id.clone(),
            route: route.route,
            local_candidate_type: route.local_candidate_type.clone(),
            remote_candidate_type: route.remote_candidate_type.clone(),
        };
        state.local_route = Some(route);
        Ok(observation)
    }

    pub fn accept_remote_route(
        &mut self,
        session_id: &str,
        observation: P2pRouteObservation,
    ) -> Result<Option<AuthenticatedP2pSession>, P2pCoordinatorError> {
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        if !state.remote_auth_verified {
            return Err(P2pCoordinatorError::AuthenticationRequired);
        }
        if observation.session_id != state.metadata.session_id
            || observation.bubble_id != state.metadata.bubble_id
            || observation.sender_device_id != state.metadata.remote_device_id
        {
            return Err(P2pCoordinatorError::InvalidPeerFrame);
        }
        state.remote_route = Some(observation);
        Ok(state.authenticated())
    }

    pub fn authenticated_session(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthenticatedP2pSession>, P2pCoordinatorError> {
        let state = self
            .sessions
            .get(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        Ok(state.authenticated())
    }

    pub fn validate_incoming_message(
        &self,
        session_id: &str,
        envelope: &P2pMessageEnvelope,
    ) -> Result<AuthenticatedP2pSession, P2pCoordinatorError> {
        let state = self
            .sessions
            .get(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let authenticated = state
            .authenticated()
            .ok_or(P2pCoordinatorError::AuthenticationRequired)?;
        if envelope.bubble_id != state.metadata.bubble_id
            || envelope.sender_device_id != state.metadata.remote_device_id
            || envelope.recipient_device_id != state.metadata.local_device_id
        {
            return Err(P2pCoordinatorError::InvalidPeerFrame);
        }
        Ok(authenticated)
    }

    pub fn validate_incoming_receipt(
        &self,
        session_id: &str,
        receipt: &P2pReceiptEnvelope,
    ) -> Result<AuthenticatedP2pSession, P2pCoordinatorError> {
        let state = self
            .sessions
            .get(session_id)
            .ok_or(P2pCoordinatorError::SessionMissing)?;
        let authenticated = state
            .authenticated()
            .ok_or(P2pCoordinatorError::AuthenticationRequired)?;
        if receipt.bubble_id != state.metadata.bubble_id
            || receipt.sender_device_id != state.metadata.remote_device_id
            || receipt.recipient_device_id != state.metadata.local_device_id
        {
            return Err(P2pCoordinatorError::InvalidPeerFrame);
        }
        Ok(authenticated)
    }

    pub fn validate_receipt_ack(
        &self,
        session_id: &str,
        ack: &P2pReceiptAck,
    ) -> Result<AuthenticatedP2pSession, P2pCoordinatorError> {
        if !crate::is_canonical_uuid(&ack.receipt_id) {
            return Err(P2pCoordinatorError::InvalidPeerFrame);
        }
        self.authenticated_session(session_id)?
            .ok_or(P2pCoordinatorError::AuthenticationRequired)
    }

    pub fn metadata(
        &self,
        session_id: &str,
    ) -> Result<&P2pSessionMetadata, P2pCoordinatorError> {
        self.sessions
            .get(session_id)
            .map(|state| &state.metadata)
            .ok_or(P2pCoordinatorError::SessionMissing)
    }

    pub fn invalidate(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u8) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    #[test]
    fn auth_transcript_is_bound_to_session_devices_and_fingerprints() {
        let local = uuid(1);
        let remote = uuid(2);
        let bubble = uuid(3);
        let session = uuid(4);
        let mut coordinator = P2pSessionCoordinator::default();
        coordinator
            .register_outgoing(&session, &bubble, &local, &remote)
            .expect("register");
        coordinator
            .set_dtls_fingerprints(
                &session,
                "sha-256 AA:BB",
                "sha-256 CC:DD",
            )
            .expect("fingerprints");

        let nonce = [7_u8; 32];
        let transcript = coordinator
            .local_auth_transcript(&session, &nonce)
            .expect("transcript");
        let proof = coordinator
            .build_local_auth(&session, &nonce, &[9_u8; 64])
            .expect("proof");
        assert_eq!(transcript, auth_transcript(&proof).expect("same transcript"));
        assert_eq!(proof.initiator_device_id, local);
        assert_eq!(proof.responder_device_id, remote);
    }

    #[test]
    fn remote_auth_must_be_signed_by_exact_remote_device() {
        let local = uuid(1);
        let remote = uuid(2);
        let bubble = uuid(3);
        let session = uuid(4);
        let mut coordinator = P2pSessionCoordinator::default();
        coordinator
            .register_outgoing(&session, &bubble, &local, &remote)
            .expect("register");
        coordinator
            .set_dtls_fingerprints(&session, "sha-256 AA", "sha-256 BB")
            .expect("fingerprints");

        let proof = P2pAuthProof {
            session_id: session.clone(),
            bubble_id: bubble,
            initiator_device_id: local,
            responder_device_id: remote.clone(),
            offer_fingerprint: "sha-256 AA".into(),
            answer_fingerprint: "sha-256 BB".into(),
            proof_device_id: uuid(99),
            nonce: encode_bytes(&[7; 32]),
            signature: encode_bytes(&[9; 64]),
        };
        assert_eq!(
            coordinator.remote_auth_challenge(&session, &proof),
            Err(P2pCoordinatorError::AuthenticationFailed)
        );
    }

    #[test]
    fn session_authenticates_only_after_both_routes_and_remote_proof() {
        let local = uuid(1);
        let remote = uuid(2);
        let bubble = uuid(3);
        let session = uuid(4);
        let mut coordinator = P2pSessionCoordinator::default();
        coordinator
            .register_outgoing(&session, &bubble, &local, &remote)
            .expect("register");
        coordinator
            .set_dtls_fingerprints(&session, "sha-256 AA", "sha-256 BB")
            .expect("fingerprints");
        coordinator
            .build_local_auth(&session, &[7; 32], &[9; 64])
            .expect("local auth");
        coordinator
            .confirm_remote_auth(&session, true)
            .expect("remote auth");
        let local_observation = coordinator
            .set_local_route(
                &session,
                P2pSelectedRoute {
                    route: P2pRoute::Direct,
                    local_candidate_type: "host".into(),
                    remote_candidate_type: "srflx".into(),
                },
            )
            .expect("local route");
        assert!(coordinator
            .authenticated_session(&session)
            .expect("query")
            .is_none());

        let authenticated = coordinator
            .accept_remote_route(
                &session,
                P2pRouteObservation {
                    sender_device_id: remote,
                    route: P2pRoute::Turn,
                    local_candidate_type: "relay".into(),
                    remote_candidate_type: "host".into(),
                    ..local_observation
                },
            )
            .expect("remote route")
            .expect("authenticated");
        assert_eq!(authenticated.route, P2pRoute::Turn);
    }
}
