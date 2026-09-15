use std::{
    collections::HashMap,
    sync::{mpsc, Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
use rtc::{
    peer_connection::transport::RTCIceCandidateType,
    statistics::report::RTCStatsReportEntry,
};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent},
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
        RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceGatheringState, RTCIceServer,
        RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, StatsSelector,
    },
    runtime::{default_runtime, Runtime},
};

use crate::P2pRoute;

const DATA_CHANNEL_LABEL: &str = "enigma-p2p-v1";
const MAX_SIGNAL_SDP_BYTES: usize = 128 * 1024;
const MAX_DATA_CHANNEL_TEXT_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pIceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct P2pIceCandidate {
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: u16,
    pub candidate: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pSelectedRoute {
    pub route: P2pRoute,
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebRtcP2pEvent {
    LocalIceCandidate {
        session_id: String,
        candidate: P2pIceCandidate,
    },
    IceGatheringComplete {
        session_id: String,
    },
    ChannelOpen {
        session_id: String,
    },
    Payload {
        session_id: String,
        payload: String,
    },
    StateChanged {
        session_id: String,
        state: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebRtcP2pError {
    RuntimeUnavailable,
    InvalidInput,
    SessionMissing,
    WebRtcFailure,
    ChannelUnavailable,
}

struct WebRtcSession {
    peer_connection: Box<dyn PeerConnection>,
    data_channel: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    local_fingerprint: Option<String>,
    remote_fingerprint: Option<String>,
}

#[derive(Clone)]
struct SessionHandler {
    session_id: String,
    runtime: Arc<dyn Runtime>,
    events: mpsc::Sender<WebRtcP2pEvent>,
    data_channel: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
}

impl SessionHandler {
    fn attach_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        let session_id = self.session_id.clone();
        let events = self.events.clone();
        let stored = Arc::clone(&self.data_channel);
        self.runtime.spawn(Box::pin(async move {
            let Ok(label) = data_channel.label().await else {
                return;
            };
            if label != DATA_CHANNEL_LABEL {
                return;
            }
            let Ok(mut slot) = stored.lock() else {
                return;
            };
            *slot = Some(Arc::clone(&data_channel));
            drop(slot);

            while let Some(event) = data_channel.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        let _ = events.send(WebRtcP2pEvent::ChannelOpen {
                            session_id: session_id.clone(),
                        });
                    }
                    DataChannelEvent::OnMessage(message) => {
                        if message.data.len() > MAX_DATA_CHANNEL_TEXT_BYTES {
                            continue;
                        }
                        let Ok(payload) = String::from_utf8(message.data.to_vec()) else {
                            continue;
                        };
                        let _ = events.send(WebRtcP2pEvent::Payload {
                            session_id: session_id.clone(),
                            payload,
                        });
                    }
                    DataChannelEvent::OnClose => {
                        let _ = events.send(WebRtcP2pEvent::StateChanged {
                            session_id: session_id.clone(),
                            state: "closed".to_owned(),
                        });
                        break;
                    }
                    _ => {}
                }
            }
        }));
    }
}

#[async_trait]
impl PeerConnectionEventHandler for SessionHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let Ok(candidate) = event.candidate.to_json() else {
            return;
        };
        if candidate.candidate.is_empty() || candidate.candidate.len() > MAX_SIGNAL_SDP_BYTES {
            return;
        }
        let _ = self.events.send(WebRtcP2pEvent::LocalIceCandidate {
            session_id: self.session_id.clone(),
            candidate: P2pIceCandidate {
                sdp_mid: candidate.sdp_mid,
                sdp_mline_index: candidate.sdp_mline_index.unwrap_or(0),
                candidate: candidate.candidate,
            },
        });
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.events.send(WebRtcP2pEvent::IceGatheringComplete {
                session_id: self.session_id.clone(),
            });
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let normalized = match state {
            RTCPeerConnectionState::Connected => "connected",
            RTCPeerConnectionState::Failed => "failed",
            RTCPeerConnectionState::Disconnected => "disconnected",
            RTCPeerConnectionState::Closed => "ended",
            _ => "connecting",
        };
        let _ = self.events.send(WebRtcP2pEvent::StateChanged {
            session_id: self.session_id.clone(),
            state: normalized.to_owned(),
        });
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        self.attach_data_channel(data_channel);
    }
}

pub struct WebRtcP2pEngine {
    runtime: Arc<dyn Runtime>,
    events_tx: mpsc::Sender<WebRtcP2pEvent>,
    events_rx: Mutex<mpsc::Receiver<WebRtcP2pEvent>>,
    sessions: HashMap<String, WebRtcSession>,
}

impl WebRtcP2pEngine {
    pub fn new() -> Result<Self, WebRtcP2pError> {
        let runtime = default_runtime().ok_or(WebRtcP2pError::RuntimeUnavailable)?;
        let (events_tx, events_rx) = mpsc::channel();
        Ok(Self {
            runtime,
            events_tx,
            events_rx: Mutex::new(events_rx),
            sessions: HashMap::new(),
        })
    }

    pub fn try_next_event(&self) -> Option<WebRtcP2pEvent> {
        self.events_rx.lock().ok()?.try_recv().ok()
    }

    pub fn start_outgoing_blocking(
        &mut self,
        session_id: &str,
        ice_servers: &[P2pIceServer],
    ) -> Result<String, WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(self.start_outgoing(session_id, ice_servers).await);
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn accept_incoming_blocking(
        &mut self,
        session_id: &str,
        ice_servers: &[P2pIceServer],
        remote_offer_sdp: &str,
    ) -> Result<String, WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(
                self.accept_incoming(session_id, ice_servers, remote_offer_sdp)
                    .await,
            );
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn set_remote_answer_blocking(
        &mut self,
        session_id: &str,
        remote_answer_sdp: &str,
    ) -> Result<(), WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(
                self.set_remote_answer(session_id, remote_answer_sdp)
                    .await,
            );
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn add_remote_ice_candidate_blocking(
        &self,
        session_id: &str,
        candidate: &P2pIceCandidate,
    ) -> Result<(), WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(
                self.add_remote_ice_candidate(session_id, candidate)
                    .await,
            );
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn selected_route_blocking(
        &self,
        session_id: &str,
    ) -> Result<Option<P2pSelectedRoute>, WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(self.selected_route(session_id).await);
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn send_text_blocking(
        &self,
        session_id: &str,
        payload: &str,
    ) -> Result<(), WebRtcP2pError> {
        let runtime = Arc::clone(&self.runtime);
        let mut result = None;
        runtime.block_on(Box::pin(async {
            result = Some(self.send_text(session_id, payload).await);
        }));
        result.ok_or(WebRtcP2pError::RuntimeUnavailable)?
    }

    pub fn release_blocking(&mut self, session_id: &str) {
        let runtime = Arc::clone(&self.runtime);
        runtime.block_on(Box::pin(async {
            self.release(session_id).await;
        }));
    }

    pub async fn start_outgoing(
        &mut self,
        session_id: &str,
        ice_servers: &[P2pIceServer],
    ) -> Result<String, WebRtcP2pError> {
        validate_session_id(session_id)?;
        self.release(session_id).await;
        let (session, handler) = self.build_session(session_id, ice_servers).await?;
        let data_channel = session
            .peer_connection
            .create_data_channel(DATA_CHANNEL_LABEL, None)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        handler.attach_data_channel(data_channel);

        let offer = session
            .peer_connection
            .create_offer(None)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        session
            .peer_connection
            .set_local_description(offer)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        let local = session
            .peer_connection
            .local_description()
            .await
            .ok_or(WebRtcP2pError::WebRtcFailure)?;
        if local.sdp.is_empty() || local.sdp.len() > MAX_SIGNAL_SDP_BYTES {
            return Err(WebRtcP2pError::WebRtcFailure);
        }

        let mut session = session;
        session.local_fingerprint = extract_dtls_fingerprint(&local.sdp);
        self.sessions.insert(session_id.to_owned(), session);
        Ok(local.sdp)
    }

    pub async fn accept_incoming(
        &mut self,
        session_id: &str,
        ice_servers: &[P2pIceServer],
        remote_offer_sdp: &str,
    ) -> Result<String, WebRtcP2pError> {
        validate_session_id(session_id)?;
        validate_sdp(remote_offer_sdp)?;
        self.release(session_id).await;
        let (mut session, _handler) = self.build_session(session_id, ice_servers).await?;
        let offer = RTCSessionDescription::offer(remote_offer_sdp.to_owned())
            .map_err(|_| WebRtcP2pError::InvalidInput)?;
        session
            .peer_connection
            .set_remote_description(offer)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        session.remote_fingerprint = extract_dtls_fingerprint(remote_offer_sdp);

        let answer = session
            .peer_connection
            .create_answer(None)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        session
            .peer_connection
            .set_local_description(answer)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        let local = session
            .peer_connection
            .local_description()
            .await
            .ok_or(WebRtcP2pError::WebRtcFailure)?;
        validate_sdp(&local.sdp)?;
        session.local_fingerprint = extract_dtls_fingerprint(&local.sdp);
        self.sessions.insert(session_id.to_owned(), session);
        Ok(local.sdp)
    }

    pub async fn set_remote_answer(
        &mut self,
        session_id: &str,
        remote_answer_sdp: &str,
    ) -> Result<(), WebRtcP2pError> {
        validate_sdp(remote_answer_sdp)?;
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(WebRtcP2pError::SessionMissing)?;
        let answer = RTCSessionDescription::answer(remote_answer_sdp.to_owned())
            .map_err(|_| WebRtcP2pError::InvalidInput)?;
        session
            .peer_connection
            .set_remote_description(answer)
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;
        session.remote_fingerprint = extract_dtls_fingerprint(remote_answer_sdp);
        Ok(())
    }

    pub async fn add_remote_ice_candidate(
        &self,
        session_id: &str,
        candidate: &P2pIceCandidate,
    ) -> Result<(), WebRtcP2pError> {
        validate_ice_candidate(candidate)?;
        let session = self
            .sessions
            .get(session_id)
            .ok_or(WebRtcP2pError::SessionMissing)?;
        session
            .peer_connection
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: candidate.candidate.clone(),
                sdp_mid: candidate.sdp_mid.clone(),
                sdp_mline_index: Some(candidate.sdp_mline_index),
                username_fragment: None,
                url: None,
            })
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)
    }

    pub async fn selected_route(
        &self,
        session_id: &str,
    ) -> Result<Option<P2pSelectedRoute>, WebRtcP2pError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or(WebRtcP2pError::SessionMissing)?;
        let report = session
            .peer_connection
            .get_stats(Instant::now(), StatsSelector::None)
            .await;

        let selected_pair_id = report
            .transport()
            .map(|transport| transport.selected_candidate_pair_id.as_str())
            .filter(|value| !value.is_empty());

        let pair = selected_pair_id
            .and_then(|id| report.get(id))
            .and_then(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) => Some(pair),
                _ => None,
            })
            .or_else(|| report.candidate_pairs().find(|pair| pair.nominated));

        let Some(pair) = pair else {
            return Ok(None);
        };

        let local = report
            .get(&pair.local_candidate_id)
            .and_then(|entry| match entry {
                RTCStatsReportEntry::LocalCandidate(candidate) => Some(candidate),
                _ => None,
            });
        let remote = report
            .get(&pair.remote_candidate_id)
            .and_then(|entry| match entry {
                RTCStatsReportEntry::RemoteCandidate(candidate) => Some(candidate),
                _ => None,
            });
        let (Some(local), Some(remote)) = (local, remote) else {
            return Ok(None);
        };

        let local_type = local.candidate_type;
        let remote_type = remote.candidate_type;
        if matches!(local_type, RTCIceCandidateType::Unspecified)
            || matches!(remote_type, RTCIceCandidateType::Unspecified)
        {
            return Ok(None);
        }

        Ok(Some(P2pSelectedRoute {
            route: if matches!(local_type, RTCIceCandidateType::Relay)
                || matches!(remote_type, RTCIceCandidateType::Relay)
            {
                P2pRoute::Turn
            } else {
                P2pRoute::Direct
            },
            local_candidate_type: local_type.to_string(),
            remote_candidate_type: remote_type.to_string(),
        }))
    }

    pub fn local_dtls_fingerprint(&self, session_id: &str) -> Option<&str> {
        self.sessions
            .get(session_id)?
            .local_fingerprint
            .as_deref()
    }

    pub fn remote_dtls_fingerprint(&self, session_id: &str) -> Option<&str> {
        self.sessions
            .get(session_id)?
            .remote_fingerprint
            .as_deref()
    }

    pub async fn send_text(
        &self,
        session_id: &str,
        payload: &str,
    ) -> Result<(), WebRtcP2pError> {
        if payload.is_empty() || payload.len() > MAX_DATA_CHANNEL_TEXT_BYTES {
            return Err(WebRtcP2pError::InvalidInput);
        }
        let session = self
            .sessions
            .get(session_id)
            .ok_or(WebRtcP2pError::SessionMissing)?;
        let channel = session
            .data_channel
            .lock()
            .map_err(|_| WebRtcP2pError::ChannelUnavailable)?
            .clone()
            .ok_or(WebRtcP2pError::ChannelUnavailable)?;
        channel
            .send_text(payload)
            .await
            .map_err(|_| WebRtcP2pError::ChannelUnavailable)
    }

    pub async fn release(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.remove(session_id) {
            let _ = session.peer_connection.close().await;
        }
    }

    async fn build_session(
        &self,
        session_id: &str,
        ice_servers: &[P2pIceServer],
    ) -> Result<(WebRtcSession, Arc<SessionHandler>), WebRtcP2pError> {
        if ice_servers.len() > 16 || ice_servers.iter().any(|server| !valid_ice_server(server)) {
            return Err(WebRtcP2pError::InvalidInput);
        }
        let rtc_servers = ice_servers
            .iter()
            .map(|server| RTCIceServer {
                urls: server.urls.clone(),
                username: server.username.clone().unwrap_or_default(),
                credential: server.credential.clone().unwrap_or_default(),
                ..Default::default()
            })
            .collect();

        let data_channel = Arc::new(Mutex::new(None));
        let handler = Arc::new(SessionHandler {
            session_id: session_id.to_owned(),
            runtime: Arc::clone(&self.runtime),
            events: self.events_tx.clone(),
            data_channel: Arc::clone(&data_channel),
        });
        let configuration = RTCConfigurationBuilder::new()
            .with_ice_servers(rtc_servers)
            .build();
        let peer_connection = PeerConnectionBuilder::new()
            .with_configuration(configuration)
            .with_handler(handler.clone())
            .with_runtime(Arc::clone(&self.runtime))
            .with_udp_addrs(vec!["0.0.0.0:0".to_owned()])
            .build()
            .await
            .map_err(|_| WebRtcP2pError::WebRtcFailure)?;

        Ok((
            WebRtcSession {
                peer_connection: Box::new(peer_connection),
                data_channel,
                local_fingerprint: None,
                remote_fingerprint: None,
            },
            handler,
        ))
    }
}

fn validate_session_id(value: &str) -> Result<(), WebRtcP2pError> {
    if super::is_canonical_uuid(value) {
        Ok(())
    } else {
        Err(WebRtcP2pError::InvalidInput)
    }
}

fn validate_sdp(value: &str) -> Result<(), WebRtcP2pError> {
    if value.is_empty() || value.len() > MAX_SIGNAL_SDP_BYTES {
        Err(WebRtcP2pError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_ice_candidate(candidate: &P2pIceCandidate) -> Result<(), WebRtcP2pError> {
    if candidate.candidate.is_empty()
        || candidate.candidate.len() > MAX_SIGNAL_SDP_BYTES
        || candidate
            .sdp_mid
            .as_ref()
            .is_some_and(|value| value.len() > 128)
    {
        Err(WebRtcP2pError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_ice_server(server: &P2pIceServer) -> bool {
    !server.urls.is_empty()
        && server.urls.len() <= 16
        && server.urls.iter().all(|url| {
            !url.is_empty()
                && url.len() <= 2048
                && (url.starts_with("stun:")
                    || url.starts_with("stuns:")
                    || url.starts_with("turn:")
                    || url.starts_with("turns:"))
        })
        && server
            .username
            .as_ref()
            .is_none_or(|value| value.len() <= 1024)
        && server
            .credential
            .as_ref()
            .is_none_or(|value| value.len() <= 4096)
}

fn extract_dtls_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("a=fingerprint:"))
        .and_then(|value| {
            let (algorithm, fingerprint) = value.trim().split_once(char::is_whitespace)?;
            if algorithm.is_empty()
                || fingerprint.is_empty()
                || algorithm.len() > 32
                || fingerprint.len() > 192
            {
                return None;
            }
            Some(format!(
                "{} {}",
                algorithm.to_ascii_lowercase(),
                fingerprint.to_ascii_uppercase()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_candidate_forces_turn_route() {
        fn route(local: RTCIceCandidateType, remote: RTCIceCandidateType) -> P2pRoute {
            if matches!(local, RTCIceCandidateType::Relay)
                || matches!(remote, RTCIceCandidateType::Relay)
            {
                P2pRoute::Turn
            } else {
                P2pRoute::Direct
            }
        }
        assert_eq!(
            route(RTCIceCandidateType::Host, RTCIceCandidateType::Srflx),
            P2pRoute::Direct
        );
        assert_eq!(
            route(RTCIceCandidateType::Relay, RTCIceCandidateType::Host),
            P2pRoute::Turn
        );
        assert_eq!(
            route(RTCIceCandidateType::Prflx, RTCIceCandidateType::Relay),
            P2pRoute::Turn
        );
    }

    #[test]
    fn dtls_fingerprint_normalizes_like_android() {
        let sdp = "v=0\r\na=fingerprint:SHA-256 aa:bb:cc\r\n";
        assert_eq!(
            extract_dtls_fingerprint(sdp).as_deref(),
            Some("sha-256 AA:BB:CC")
        );
    }

    #[test]
    fn ice_servers_are_bounded_and_scheme_checked() {
        assert!(valid_ice_server(&P2pIceServer {
            urls: vec!["turn:relay.example:3478?transport=udp".into()],
            username: Some("user".into()),
            credential: Some("secret".into()),
        }));
        assert!(!valid_ice_server(&P2pIceServer {
            urls: vec!["https://relay.example".into()],
            username: None,
            credential: None,
        }));
    }
}
