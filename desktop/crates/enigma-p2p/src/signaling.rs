use std::sync::{mpsc, Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc as async_mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, protocol::Message},
};

const MAX_SIGNAL_PAYLOAD_BYTES: usize = 131_072;
const MAX_SERVER_EVENT_BYTES: usize = MAX_SIGNAL_PAYLOAD_BYTES + 4_096;
const COMMAND_QUEUE_CAPACITY: usize = 256;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pSignalCommand {
    pub bubble_id: String,
    pub recipient_device_id: String,
    pub session_id: String,
    pub signal_kind: String,
    pub payload: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P2pSignalingEvent {
    Signal {
        bubble_id: String,
        sender_user_id: String,
        sender_device_id: String,
        session_id: String,
        signal_kind: String,
        payload: String,
    },
    Unavailable {
        bubble_id: String,
        recipient_device_id: String,
        session_id: String,
    },
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pSignalingError {
    InvalidEndpoint,
    InvalidCredential,
    InvalidCommand,
    RuntimeUnavailable,
    ConnectionFailed,
    QueueClosed,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsClientCommand<'a> {
    P2pSignal {
        bubble_id: &'a str,
        recipient_device_id: &'a str,
        session_id: &'a str,
        signal_kind: &'a str,
        payload: &'a str,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsServerEvent {
    P2pSignal {
        bubble_id: String,
        sender_user_id: String,
        sender_device_id: String,
        session_id: String,
        signal_kind: String,
        payload: String,
    },
    P2pSignalUnavailable {
        bubble_id: String,
        recipient_device_id: String,
        session_id: String,
    },
    #[serde(other)]
    Other,
}

pub struct SignalingClient {
    outgoing: async_mpsc::Sender<P2pSignalCommand>,
    incoming: Mutex<mpsc::Receiver<P2pSignalingEvent>>,
    _runtime: tokio::runtime::Runtime,
}

impl SignalingClient {
    pub fn connect_blocking(
        base_url: &str,
        device_id: &str,
        access_token: &[u8],
    ) -> Result<Self, P2pSignalingError> {
        if !super::is_canonical_uuid(device_id) {
            return Err(P2pSignalingError::InvalidEndpoint);
        }
        let endpoint = websocket_endpoint(base_url, device_id)?;
        let token =
            std::str::from_utf8(access_token).map_err(|_| P2pSignalingError::InvalidCredential)?;
        if token.is_empty()
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(P2pSignalingError::InvalidCredential);
        }

        let mut request = endpoint
            .into_client_request()
            .map_err(|_| P2pSignalingError::InvalidEndpoint)?;
        let authorization = format!("Bearer {token}")
            .parse()
            .map_err(|_| P2pSignalingError::InvalidCredential)?;
        request.headers_mut().insert(AUTHORIZATION, authorization);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("enigma-p2p-ws")
            .build()
            .map_err(|_| P2pSignalingError::RuntimeUnavailable)?;
        let (socket, _) = runtime
            .block_on(connect_async(request))
            .map_err(|_| P2pSignalingError::ConnectionFailed)?;
        let (mut writer, mut reader) = socket.split();
        let (outgoing, mut commands) = async_mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (events, incoming) = mpsc::channel();

        runtime.spawn(async move {
            loop {
                tokio::select! {
                    command = commands.recv() => {
                        let Some(command) = command else {
                            let _ = writer.close().await;
                            break;
                        };
                        if validate_command(&command).is_err() {
                            continue;
                        }
                        let encoded = match serde_json::to_string(&WsClientCommand::P2pSignal {
                            bubble_id: &command.bubble_id,
                            recipient_device_id: &command.recipient_device_id,
                            session_id: &command.session_id,
                            signal_kind: &command.signal_kind,
                            payload: &command.payload,
                        }) {
                            Ok(value) if value.len() <= MAX_SERVER_EVENT_BYTES => value,
                            Ok(_) | Err(_) => continue,
                        };
                        if writer.send(Message::Text(encoded.into())).await.is_err() {
                            let _ = events.send(P2pSignalingEvent::Disconnected);
                            break;
                        }
                    }
                    message = reader.next() => {
                        let Some(message) = message else {
                            let _ = events.send(P2pSignalingEvent::Disconnected);
                            break;
                        };
                        match message {
                            Ok(Message::Text(text)) => {
                                if text.len() > MAX_SERVER_EVENT_BYTES {
                                    let _ = events.send(P2pSignalingEvent::Disconnected);
                                    break;
                                }
                                if let Some(event) = parse_server_event(text.as_str()) {
                                    let _ = events.send(event);
                                }
                            }
                            Ok(Message::Ping(payload)) => {
                                if writer.send(Message::Pong(payload)).await.is_err() {
                                    let _ = events.send(P2pSignalingEvent::Disconnected);
                                    break;
                                }
                            }
                            Ok(Message::Close(_)) | Err(_) => {
                                let _ = events.send(P2pSignalingEvent::Disconnected);
                                break;
                            }
                            Ok(_) => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            outgoing,
            incoming: Mutex::new(incoming),
            _runtime: runtime,
        })
    }

    pub fn send_now(&self, command: P2pSignalCommand) -> Result<(), P2pSignalingError> {
        validate_command(&command)?;
        self.outgoing
            .try_send(command)
            .map_err(|_| P2pSignalingError::QueueClosed)
    }

    pub fn try_next_event(&self) -> Option<P2pSignalingEvent> {
        self.incoming.lock().ok()?.try_recv().ok()
    }
}

fn websocket_endpoint(base_url: &str, device_id: &str) -> Result<String, P2pSignalingError> {
    if base_url.is_empty()
        || base_url.len() > 4096
        || base_url.contains('?')
        || base_url.contains('#')
    {
        return Err(P2pSignalingError::InvalidEndpoint);
    }
    let (scheme, rest) = if let Some(rest) = base_url.strip_prefix("https://") {
        ("wss://", rest)
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        ("ws://", rest)
    } else {
        return Err(P2pSignalingError::InvalidEndpoint);
    };
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() || rest.contains('@') {
        return Err(P2pSignalingError::InvalidEndpoint);
    }
    Ok(format!("{scheme}{rest}/v1/ws?device_id={device_id}"))
}

fn validate_command(command: &P2pSignalCommand) -> Result<(), P2pSignalingError> {
    if !super::is_canonical_uuid(&command.bubble_id)
        || !super::is_canonical_uuid(&command.recipient_device_id)
        || !super::is_canonical_uuid(&command.session_id)
        || !matches!(
            command.signal_kind.as_str(),
            "offer" | "answer" | "ice" | "ice_complete" | "cancel"
        )
        || command.payload.len() > MAX_SIGNAL_PAYLOAD_BYTES
        || (!matches!(command.signal_kind.as_str(), "ice_complete" | "cancel")
            && command.payload.is_empty())
    {
        return Err(P2pSignalingError::InvalidCommand);
    }
    Ok(())
}

fn parse_server_event(value: &str) -> Option<P2pSignalingEvent> {
    let event = serde_json::from_str::<WsServerEvent>(value).ok()?;
    match event {
        WsServerEvent::P2pSignal {
            bubble_id,
            sender_user_id,
            sender_device_id,
            session_id,
            signal_kind,
            payload,
        } => {
            if !super::is_canonical_uuid(&bubble_id)
                || !super::is_canonical_uuid(&sender_user_id)
                || !super::is_canonical_uuid(&sender_device_id)
                || !super::is_canonical_uuid(&session_id)
                || !matches!(
                    signal_kind.as_str(),
                    "offer" | "answer" | "ice" | "ice_complete" | "cancel"
                )
                || payload.len() > MAX_SIGNAL_PAYLOAD_BYTES
                || (!matches!(signal_kind.as_str(), "ice_complete" | "cancel")
                    && payload.is_empty())
            {
                return None;
            }
            Some(P2pSignalingEvent::Signal {
                bubble_id,
                sender_user_id,
                sender_device_id,
                session_id,
                signal_kind,
                payload,
            })
        }
        WsServerEvent::P2pSignalUnavailable {
            bubble_id,
            recipient_device_id,
            session_id,
        } => {
            if !super::is_canonical_uuid(&bubble_id)
                || !super::is_canonical_uuid(&recipient_device_id)
                || !super::is_canonical_uuid(&session_id)
            {
                return None;
            }
            Some(P2pSignalingEvent::Unavailable {
                bubble_id,
                recipient_device_id,
                session_id,
            })
        }
        WsServerEvent::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_preserves_server_prefix_and_upgrades_scheme() {
        assert_eq!(
            websocket_endpoint(
                "https://chat.example/api/",
                "11111111-1111-4111-8111-111111111111",
            ),
            Ok(
                "wss://chat.example/api/v1/ws?device_id=11111111-1111-4111-8111-111111111111"
                    .to_owned()
            )
        );
    }

    #[test]
    fn server_signal_contract_matches_axum_event_shape() {
        let value = r#"{"type":"p2p_signal","bubble_id":"11111111-1111-4111-8111-111111111111","sender_user_id":"44444444-4444-4444-8444-444444444444","sender_device_id":"22222222-2222-4222-8222-222222222222","session_id":"33333333-3333-4333-8333-333333333333","signal_kind":"offer","payload":"v=0"}"#;
        assert_eq!(
            parse_server_event(value),
            Some(P2pSignalingEvent::Signal {
                bubble_id: "11111111-1111-4111-8111-111111111111".into(),
                sender_user_id: "44444444-4444-4444-8444-444444444444".into(),
                sender_device_id: "22222222-2222-4222-8222-222222222222".into(),
                session_id: "33333333-3333-4333-8333-333333333333".into(),
                signal_kind: "offer".into(),
                payload: "v=0".into(),
            })
        );
    }

    #[test]
    fn rejects_signal_payload_above_server_limit() {
        let command = P2pSignalCommand {
            bubble_id: "11111111-1111-4111-8111-111111111111".into(),
            recipient_device_id: "22222222-2222-4222-8222-222222222222".into(),
            session_id: "33333333-3333-4333-8333-333333333333".into(),
            signal_kind: "offer".into(),
            payload: "x".repeat(MAX_SIGNAL_PAYLOAD_BYTES + 1),
        };
        assert_eq!(
            validate_command(&command),
            Err(P2pSignalingError::InvalidCommand)
        );
    }
}
