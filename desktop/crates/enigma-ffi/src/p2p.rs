#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use enigma_p2p::{
    coordinator::P2pSessionCoordinator,
    decode, encode_auth, encode_message, encode_receipt, encode_receipt_ack, encode_route,
    engine::{P2pIceCandidate, P2pIceServer, WebRtcP2pEngine, WebRtcP2pEvent},
    signaling::{P2pSignalCommand, P2pSignalingEvent, SignalingClient},
    DecodedP2pFrame, P2pMessageEnvelope, P2pReceiptAck, P2pReceiptEnvelope, P2pReceiptStatus,
};
use enigma_signal::{
    session::LibsignalSessionBackend, LibsignalIdentityProofVerifier, SignalAdapter,
};
use enigma_sodium::random_public_bytes;
use futures_executor::block_on;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_TIMEOUT: Duration = Duration::from_millis(2_500);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_DEFERRED_SIGNAL_EVENTS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct P2pDelivery {
    pub route: &'static str,
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct P2pIncomingOffer {
    pub sender_user_id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub session_id: String,
    pub offer_sdp: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct P2pInboundMessage {
    pub sender_user_id: String,
    pub session_id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub message_type: String,
    pub ciphertext: String,
}

pub(crate) struct DesktopP2pManager {
    engine: WebRtcP2pEngine,
    signaling: SignalingClient,
    coordinator: P2pSessionCoordinator,
    deferred_signaling: VecDeque<P2pSignalingEvent>,
}

struct P2pSend<'a> {
    session_id: &'a str,
    bubble_id: &'a str,
    sender_device_id: &'a str,
    recipient_device_id: &'a str,
    client_message_id: &'a str,
    message_type: &'a str,
    ciphertext: &'a str,
    remote_identity_key: &'a [u8],
    ice_servers: &'a [P2pIceServer],
}

impl DesktopP2pManager {
    pub(crate) fn connect(
        base_url: &str,
        device_id: &str,
        access_token: &[u8],
    ) -> Result<Self, ()> {
        Ok(Self {
            engine: WebRtcP2pEngine::new().map_err(|_| ())?,
            signaling: SignalingClient::connect_blocking(base_url, device_id, access_token)
                .map_err(|_| ())?,
            coordinator: P2pSessionCoordinator::default(),
            deferred_signaling: VecDeque::new(),
        })
    }

    pub(crate) fn take_incoming_offer(&mut self) -> Option<P2pIncomingOffer> {
        if let Some(index) = self.deferred_signaling.iter().position(|event| {
            matches!(
                event,
                P2pSignalingEvent::Signal {
                    signal_kind,
                    ..
                } if signal_kind == "offer"
            )
        }) {
            let event = self.deferred_signaling.remove(index)?;
            return incoming_offer_from_event(event);
        }

        loop {
            let event = self.signaling.try_next_event()?;
            if matches!(
                &event,
                P2pSignalingEvent::Signal {
                    signal_kind,
                    ..
                } if signal_kind == "offer"
            ) {
                return incoming_offer_from_event(event);
            }
            if matches!(&event, P2pSignalingEvent::Disconnected) {
                return None;
            }
            if self.deferred_signaling.len() >= MAX_DEFERRED_SIGNAL_EVENTS {
                self.deferred_signaling.pop_front();
            }
            self.deferred_signaling.push_back(event);
        }
    }

    pub(crate) fn accept_incoming_until_message(
        &mut self,
        backend: &LibsignalSessionBackend,
        local_device_id: &str,
        offer: &P2pIncomingOffer,
        remote_identity_key: &[u8],
        ice_servers: &[P2pIceServer],
    ) -> Result<Option<P2pInboundMessage>, ()> {
        self.coordinator
            .register_incoming(
                &offer.session_id,
                &offer.bubble_id,
                local_device_id,
                &offer.sender_device_id,
            )
            .map_err(|_| ())?;

        let answer = self
            .engine
            .accept_incoming_blocking(
                &offer.session_id,
                ice_servers,
                &offer.offer_sdp,
            )
            .map_err(|_| ())?;
        self.bind_fingerprints(&offer.session_id)?;
        self.signal_to(
            &offer.bubble_id,
            &offer.sender_device_id,
            &offer.session_id,
            "answer",
            answer,
        )?;

        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut channel_open = false;
        let mut auth_sent = false;
        let mut remote_auth_verified = false;
        let mut local_route_sent = false;

        loop {
            if Instant::now() >= deadline {
                self.invalidate(
                    &offer.session_id,
                    &offer.bubble_id,
                    &offer.sender_device_id,
                );
                return Ok(None);
            }

            while let Some(event) = self.engine.try_next_event() {
                match event {
                    WebRtcP2pEvent::LocalIceCandidate {
                        session_id,
                        candidate,
                    } if session_id == offer.session_id => {
                        let payload = serde_json::to_string(&candidate).map_err(|_| ())?;
                        self.signal_to(
                            &offer.bubble_id,
                            &offer.sender_device_id,
                            &offer.session_id,
                            "ice",
                            payload,
                        )?;
                    }
                    WebRtcP2pEvent::IceGatheringComplete { session_id }
                        if session_id == offer.session_id =>
                    {
                        self.signal_to(
                            &offer.bubble_id,
                            &offer.sender_device_id,
                            &offer.session_id,
                            "ice_complete",
                            String::new(),
                        )?;
                    }
                    WebRtcP2pEvent::ChannelOpen { session_id }
                        if session_id == offer.session_id =>
                    {
                        channel_open = true;
                    }
                    WebRtcP2pEvent::Payload {
                        session_id,
                        payload,
                    } if session_id == offer.session_id => {
                        match decode(&payload).map_err(|_| ())? {
                            DecodedP2pFrame::Auth(proof) => {
                                let challenge = self
                                    .coordinator
                                    .remote_auth_challenge(&offer.session_id, &proof)
                                    .map_err(|_| ())?;
                                let verifier = LibsignalIdentityProofVerifier;
                                let verified = verifier
                                    .verify_identity_proof(
                                        remote_identity_key,
                                        &challenge.transcript,
                                        &challenge.signature,
                                    )
                                    .map_err(|_| ())?;
                                self.coordinator
                                    .confirm_remote_auth(&offer.session_id, verified)
                                    .map_err(|_| ())?;
                                remote_auth_verified = true;
                            }
                            DecodedP2pFrame::Route(observation) => {
                                self.coordinator
                                    .accept_remote_route(&offer.session_id, observation)
                                    .map_err(|_| ())?;
                            }
                            DecodedP2pFrame::Message(message) => {
                                self.coordinator
                                    .validate_incoming_message(&offer.session_id, &message)
                                    .map_err(|_| ())?;
                                return Ok(Some(P2pInboundMessage {
                                    sender_user_id: offer.sender_user_id.clone(),
                                    session_id: offer.session_id.clone(),
                                    bubble_id: message.bubble_id,
                                    sender_device_id: message.sender_device_id,
                                    recipient_device_id: message.recipient_device_id,
                                    client_message_id: message.client_message_id,
                                    message_type: message.message_type,
                                    ciphertext: message.ciphertext,
                                }));
                            }
                            DecodedP2pFrame::Receipt(_)
                            | DecodedP2pFrame::ReceiptAck(_) => {}
                        }
                    }
                    WebRtcP2pEvent::StateChanged { session_id, state }
                        if session_id == offer.session_id
                            && matches!(
                                state.as_str(),
                                "failed" | "disconnected" | "closed" | "ended"
                            ) =>
                    {
                        self.invalidate(
                            &offer.session_id,
                            &offer.bubble_id,
                            &offer.sender_device_id,
                        );
                        return Ok(None);
                    }
                    _ => {}
                }
            }

            while let Some(event) = self.next_signaling_event(&offer.session_id) {
                match event {
                    P2pSignalingEvent::Signal {
                        bubble_id,
                        sender_user_id,
                        sender_device_id,
                        session_id,
                        signal_kind,
                        payload,
                    } => {
                        if bubble_id != offer.bubble_id
                            || sender_user_id != offer.sender_user_id
                            || sender_device_id != offer.sender_device_id
                            || session_id != offer.session_id
                        {
                            return Err(());
                        }
                        match signal_kind.as_str() {
                            "ice" => {
                                let candidate =
                                    serde_json::from_str::<P2pIceCandidate>(&payload)
                                        .map_err(|_| ())?;
                                self.engine
                                    .add_remote_ice_candidate_blocking(
                                        &offer.session_id,
                                        &candidate,
                                    )
                                    .map_err(|_| ())?;
                            }
                            "ice_complete" => {}
                            "cancel" => {
                                self.invalidate(
                                    &offer.session_id,
                                    &offer.bubble_id,
                                    &offer.sender_device_id,
                                );
                                return Ok(None);
                            }
                            "offer" | "answer" => return Err(()),
                            _ => return Err(()),
                        }
                    }
                    P2pSignalingEvent::Unavailable { .. } => {}
                    P2pSignalingEvent::Disconnected => return Ok(None),
                }
            }

            if channel_open && !auth_sent {
                self.send_local_auth(backend, &offer.session_id)?;
                auth_sent = true;
            }

            if remote_auth_verified && auth_sent && !local_route_sent {
                if let Some(route) = self
                    .engine
                    .selected_route_blocking(&offer.session_id)
                    .map_err(|_| ())?
                {
                    let observation = self
                        .coordinator
                        .set_local_route(&offer.session_id, route)
                        .map_err(|_| ())?;
                    let frame = encode_route(&observation).map_err(|_| ())?;
                    self.engine
                        .send_text_blocking(&offer.session_id, &frame)
                        .map_err(|_| ())?;
                    local_route_sent = true;
                }
            }

            thread::sleep(POLL_INTERVAL);
        }
    }

    pub(crate) fn acknowledge_incoming_delivery(
        &mut self,
        session_id: &str,
        client_message_id: &str,
    ) -> Result<(), ()> {
        let metadata = self
            .coordinator
            .metadata(session_id)
            .map_err(|_| ())?
            .clone();
        self.coordinator
            .authenticated_session(session_id)
            .map_err(|_| ())?
            .ok_or(())?;

        let receipt_id = crate::random_uuid_v4()?;
        let receipt = P2pReceiptEnvelope {
            receipt_id: receipt_id.clone(),
            bubble_id: metadata.bubble_id.clone(),
            sender_device_id: metadata.local_device_id.clone(),
            recipient_device_id: metadata.remote_device_id.clone(),
            client_message_id: client_message_id.to_owned(),
            status: P2pReceiptStatus::Delivered,
        };
        let frame = encode_receipt(&receipt).map_err(|_| ())?;
        self.engine
            .send_text_blocking(session_id, &frame)
            .map_err(|_| ())?;

        let deadline = Instant::now() + ACK_TIMEOUT;
        while Instant::now() < deadline {
            while let Some(event) = self.engine.try_next_event() {
                match event {
                    WebRtcP2pEvent::Payload {
                        session_id: event_session_id,
                        payload,
                    } if event_session_id == session_id => {
                        if let DecodedP2pFrame::ReceiptAck(ack) =
                            decode(&payload).map_err(|_| ())?
                        {
                            if ack.receipt_id == receipt_id {
                                self.coordinator
                                    .validate_receipt_ack(session_id, &ack)
                                    .map_err(|_| ())?;
                                self.engine.release_blocking(session_id);
                                self.coordinator.invalidate(session_id);
                                return Ok(());
                            }
                        }
                    }
                    WebRtcP2pEvent::StateChanged {
                        session_id: event_session_id,
                        state,
                    } if event_session_id == session_id
                        && matches!(
                            state.as_str(),
                            "failed" | "disconnected" | "closed" | "ended"
                        ) =>
                    {
                        self.engine.release_blocking(session_id);
                        self.coordinator.invalidate(session_id);
                        return Ok(());
                    }
                    _ => {}
                }
            }
            thread::sleep(POLL_INTERVAL);
        }

        self.engine.release_blocking(session_id);
        self.coordinator.invalidate(session_id);
        Ok(())
    }

    pub(crate) fn try_send(
        &mut self,
        backend: &LibsignalSessionBackend,
        session_id: &str,
        bubble_id: &str,
        sender_device_id: &str,
        recipient_device_id: &str,
        client_message_id: &str,
        message_type: &str,
        ciphertext: &str,
        remote_identity_key: &[u8],
        ice_servers: &[P2pIceServer],
    ) -> Result<Option<P2pDelivery>, ()> {
        let request = P2pSend {
            session_id,
            bubble_id,
            sender_device_id,
            recipient_device_id,
            client_message_id,
            message_type,
            ciphertext,
            remote_identity_key,
            ice_servers,
        };
        let result = self.try_send_once(backend, &request);
        if result.is_err() || matches!(result, Ok(None)) {
            self.invalidate(session_id, bubble_id, recipient_device_id);
        }
        result
    }

    fn try_send_once(
        &mut self,
        backend: &LibsignalSessionBackend,
        request: &P2pSend<'_>,
    ) -> Result<Option<P2pDelivery>, ()> {
        self.coordinator
            .register_outgoing(
                request.session_id,
                request.bubble_id,
                request.sender_device_id,
                request.recipient_device_id,
            )
            .map_err(|_| ())?;

        let offer = self
            .engine
            .start_outgoing_blocking(request.session_id, request.ice_servers)
            .map_err(|_| ())?;
        self.signal(
            request,
            "offer",
            offer,
        )?;

        let connect_deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut remote_description_ready = false;
        let mut pending_remote_ice = Vec::new();
        let mut channel_open = false;
        let mut auth_sent = false;
        let mut remote_auth_verified = false;
        let mut local_route_sent = false;
        let mut message_sent = false;
        let mut ack_deadline = None;

        loop {
            let now = Instant::now();
            if !message_sent && now >= connect_deadline {
                return Ok(None);
            }
            if let Some(deadline) = ack_deadline {
                if now >= deadline {
                    return Ok(None);
                }
            }

            while let Some(event) = self.engine.try_next_event() {
                match event {
                    WebRtcP2pEvent::LocalIceCandidate {
                        session_id,
                        candidate,
                    } if session_id == request.session_id => {
                        let payload = serde_json::to_string(&candidate).map_err(|_| ())?;
                        self.signal(request, "ice", payload)?;
                    }
                    WebRtcP2pEvent::IceGatheringComplete { session_id }
                        if session_id == request.session_id =>
                    {
                        self.signal(request, "ice_complete", String::new())?;
                    }
                    WebRtcP2pEvent::ChannelOpen { session_id }
                        if session_id == request.session_id =>
                    {
                        channel_open = true;
                    }
                    WebRtcP2pEvent::Payload {
                        session_id,
                        payload,
                    } if session_id == request.session_id => {
                        match decode(&payload).map_err(|_| ())? {
                            DecodedP2pFrame::Auth(proof) => {
                                let challenge = self
                                    .coordinator
                                    .remote_auth_challenge(request.session_id, &proof)
                                    .map_err(|_| ())?;
                                let verifier = LibsignalIdentityProofVerifier;
                                let verified = verifier
                                    .verify_identity_proof(
                                        request.remote_identity_key,
                                        &challenge.transcript,
                                        &challenge.signature,
                                    )
                                    .map_err(|_| ())?;
                                self.coordinator
                                    .confirm_remote_auth(request.session_id, verified)
                                    .map_err(|_| ())?;
                                remote_auth_verified = true;
                            }
                            DecodedP2pFrame::Route(observation) => {
                                self.coordinator
                                    .accept_remote_route(request.session_id, observation)
                                    .map_err(|_| ())?;
                            }
                            DecodedP2pFrame::Receipt(receipt) => {
                                self.coordinator
                                    .validate_incoming_receipt(request.session_id, &receipt)
                                    .map_err(|_| ())?;
                                if receipt.client_message_id == request.client_message_id
                                    && receipt.status == P2pReceiptStatus::Delivered
                                {
                                    let ack = encode_receipt_ack(&P2pReceiptAck {
                                        receipt_id: receipt.receipt_id,
                                    })
                                    .map_err(|_| ())?;
                                    self.engine
                                        .send_text_blocking(request.session_id, &ack)
                                        .map_err(|_| ())?;
                                    let authenticated = self
                                        .coordinator
                                        .authenticated_session(request.session_id)
                                        .map_err(|_| ())?
                                        .ok_or(())?;
                                    let delivered = P2pDelivery {
                                        route: match authenticated.route {
                                            enigma_p2p::P2pRoute::Direct => "DIRECT",
                                            enigma_p2p::P2pRoute::Turn => "TURN",
                                        },
                                        local_candidate_type: authenticated
                                            .local_candidate_type,
                                        remote_candidate_type: authenticated
                                            .remote_candidate_type,
                                    };
                                    thread::sleep(Duration::from_millis(20));
                                    self.engine.release_blocking(request.session_id);
                                    self.coordinator.invalidate(request.session_id);
                                    return Ok(Some(delivered));
                                }
                            }
                            DecodedP2pFrame::Message(_)
                            | DecodedP2pFrame::ReceiptAck(_) => {}
                        }
                    }
                    WebRtcP2pEvent::StateChanged { session_id, state }
                        if session_id == request.session_id
                            && matches!(
                                state.as_str(),
                                "failed" | "disconnected" | "closed" | "ended"
                            ) =>
                    {
                        return Ok(None);
                    }
                    _ => {}
                }
            }

            while let Some(event) = self.next_signaling_event(request.session_id) {
                match event {
                    P2pSignalingEvent::Signal {
                        bubble_id,
                        sender_user_id: _,
                        sender_device_id,
                        session_id,
                        signal_kind,
                        payload,
                    } => {
                        if bubble_id != request.bubble_id
                            || sender_device_id != request.recipient_device_id
                            || session_id != request.session_id
                        {
                            return Err(());
                        }
                        match signal_kind.as_str() {
                            "answer" => {
                                self.engine
                                    .set_remote_answer_blocking(request.session_id, &payload)
                                    .map_err(|_| ())?;
                                remote_description_ready = true;
                                self.bind_fingerprints(request.session_id)?;
                                for candidate in pending_remote_ice.drain(..) {
                                    self.engine
                                        .add_remote_ice_candidate_blocking(
                                            request.session_id,
                                            &candidate,
                                        )
                                        .map_err(|_| ())?;
                                }
                            }
                            "ice" => {
                                let candidate =
                                    serde_json::from_str::<P2pIceCandidate>(&payload)
                                        .map_err(|_| ())?;
                                if remote_description_ready {
                                    self.engine
                                        .add_remote_ice_candidate_blocking(
                                            request.session_id,
                                            &candidate,
                                        )
                                        .map_err(|_| ())?;
                                } else if pending_remote_ice.len() < 256 {
                                    pending_remote_ice.push(candidate);
                                } else {
                                    return Err(());
                                }
                            }
                            "ice_complete" => {}
                            "cancel" => return Ok(None),
                            "offer" => return Err(()),
                            _ => return Err(()),
                        }
                    }
                    P2pSignalingEvent::Unavailable {
                        bubble_id,
                        recipient_device_id,
                        session_id,
                    } => {
                        if bubble_id == request.bubble_id
                            && recipient_device_id == request.recipient_device_id
                            && session_id == request.session_id
                        {
                            return Ok(None);
                        }
                    }
                    P2pSignalingEvent::Disconnected => return Ok(None),
                }
            }

            if channel_open && remote_description_ready && !auth_sent {
                self.send_local_auth(backend, request.session_id)?;
                auth_sent = true;
            }

            if remote_auth_verified && auth_sent && !local_route_sent {
                if let Some(route) = self
                    .engine
                    .selected_route_blocking(request.session_id)
                    .map_err(|_| ())?
                {
                    let observation = self
                        .coordinator
                        .set_local_route(request.session_id, route)
                        .map_err(|_| ())?;
                    let frame = encode_route(&observation).map_err(|_| ())?;
                    self.engine
                        .send_text_blocking(request.session_id, &frame)
                        .map_err(|_| ())?;
                    local_route_sent = true;
                }
            }

            if !message_sent
                && self
                    .coordinator
                    .authenticated_session(request.session_id)
                    .map_err(|_| ())?
                    .is_some()
            {
                let frame = encode_message(&P2pMessageEnvelope {
                    bubble_id: request.bubble_id.to_owned(),
                    sender_device_id: request.sender_device_id.to_owned(),
                    recipient_device_id: request.recipient_device_id.to_owned(),
                    client_message_id: request.client_message_id.to_owned(),
                    message_type: request.message_type.to_owned(),
                    ciphertext: request.ciphertext.to_owned(),
                })
                .map_err(|_| ())?;
                self.engine
                    .send_text_blocking(request.session_id, &frame)
                    .map_err(|_| ())?;
                message_sent = true;
                ack_deadline = Some(Instant::now() + ACK_TIMEOUT);
            }

            thread::sleep(POLL_INTERVAL);
        }
    }

    fn bind_fingerprints(&mut self, session_id: &str) -> Result<(), ()> {
        let local = self
            .engine
            .local_dtls_fingerprint(session_id)
            .ok_or(())?
            .to_owned();
        let remote = self
            .engine
            .remote_dtls_fingerprint(session_id)
            .ok_or(())?
            .to_owned();
        self.coordinator
            .set_dtls_fingerprints(session_id, &local, &remote)
            .map_err(|_| ())
    }

    fn send_local_auth(
        &mut self,
        backend: &LibsignalSessionBackend,
        session_id: &str,
    ) -> Result<(), ()> {
        let mut nonce = random_public_bytes::<32>().map_err(|_| ())?;
        let mut transcript = self
            .coordinator
            .local_auth_transcript(session_id, &nonce)
            .map_err(|_| ())?;
        let mut rng = rand::rng();
        let mut signature =
            block_on(backend.sign_identity_proof(&transcript, &mut rng)).map_err(|_| ())?;
        transcript.fill(0);
        let proof = self
            .coordinator
            .build_local_auth(session_id, &nonce, &signature)
            .map_err(|_| ())?;
        nonce.fill(0);
        signature.fill(0);
        let frame = encode_auth(&proof).map_err(|_| ())?;
        self.engine
            .send_text_blocking(session_id, &frame)
            .map_err(|_| ())
    }

    fn signal(
        &self,
        request: &P2pSend<'_>,
        signal_kind: &str,
        payload: String,
    ) -> Result<(), ()> {
        self.signal_to(
            request.bubble_id,
            request.recipient_device_id,
            request.session_id,
            signal_kind,
            payload,
        )
    }

    fn signal_to(
        &self,
        bubble_id: &str,
        recipient_device_id: &str,
        session_id: &str,
        signal_kind: &str,
        payload: String,
    ) -> Result<(), ()> {
        self.signaling
            .send_now(P2pSignalCommand {
                bubble_id: bubble_id.to_owned(),
                recipient_device_id: recipient_device_id.to_owned(),
                session_id: session_id.to_owned(),
                signal_kind: signal_kind.to_owned(),
                payload,
            })
            .map_err(|_| ())
    }

    fn next_signaling_event(&mut self, session_id: &str) -> Option<P2pSignalingEvent> {
        if let Some(index) = self.deferred_signaling.iter().position(|event| {
            matches!(
                event,
                P2pSignalingEvent::Signal {
                    session_id: event_session_id,
                    ..
                } | P2pSignalingEvent::Unavailable {
                    session_id: event_session_id,
                    ..
                } if event_session_id == session_id
            )
        }) {
            return self.deferred_signaling.remove(index);
        }

        loop {
            let event = self.signaling.try_next_event()?;
            let belongs = matches!(
                &event,
                P2pSignalingEvent::Signal {
                    session_id: event_session_id,
                    ..
                } | P2pSignalingEvent::Unavailable {
                    session_id: event_session_id,
                    ..
                } if event_session_id == session_id
            ) || matches!(&event, P2pSignalingEvent::Disconnected);
            if belongs {
                return Some(event);
            }
            if self.deferred_signaling.len() >= MAX_DEFERRED_SIGNAL_EVENTS {
                self.deferred_signaling.pop_front();
            }
            self.deferred_signaling.push_back(event);
        }
    }

    fn invalidate(&mut self, session_id: &str, bubble_id: &str, recipient_device_id: &str) {
        let _ = self.signaling.send_now(P2pSignalCommand {
            bubble_id: bubble_id.to_owned(),
            recipient_device_id: recipient_device_id.to_owned(),
            session_id: session_id.to_owned(),
            signal_kind: "cancel".to_owned(),
            payload: String::new(),
        });
        self.engine.release_blocking(session_id);
        self.coordinator.invalidate(session_id);
    }
}

fn incoming_offer_from_event(event: P2pSignalingEvent) -> Option<P2pIncomingOffer> {
    match event {
        P2pSignalingEvent::Signal {
            bubble_id,
            sender_user_id,
            sender_device_id,
            session_id,
            signal_kind,
            payload,
        } if signal_kind == "offer" => Some(P2pIncomingOffer {
            sender_user_id,
            bubble_id,
            sender_device_id,
            session_id,
            offer_sdp: payload,
        }),
        _ => None,
    }
}

pub(crate) fn turn_ice_servers(
    uris: &[String],
    username: &str,
    credential: &str,
) -> Result<Vec<P2pIceServer>, ()> {
    if uris.is_empty() || username.is_empty() || credential.is_empty() {
        return Err(());
    }
    Ok(vec![P2pIceServer {
        urls: uris.to_vec(),
        username: Some(username.to_owned()),
        credential: Some(credential.to_owned()),
    }])
}

pub(crate) fn delivery_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}
