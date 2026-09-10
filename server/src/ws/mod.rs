pub mod hub;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sqlx::FromRow;
use std::time::{Duration, Instant};
use tokio::time;
use uuid::Uuid;

use crate::{auth, devices, error::AppError, AppState};

const P2P_SIGNAL_MAX_BYTES: usize = 131_072;
const P2P_COMMAND_MAX_BYTES: usize = P2P_SIGNAL_MAX_BYTES + 4_096;
const P2P_SIGNAL_WINDOW: Duration = Duration::from_secs(60);
const P2P_SIGNAL_MAX_PER_WINDOW: u32 = 256;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    device_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsClientCommand {
    P2pSignal {
        bubble_id: Uuid,
        recipient_device_id: Uuid,
        session_id: Uuid,
        signal_kind: String,
        payload: String,
    },
}

#[derive(Debug, FromRow)]
struct BubbleAccessRow {
    mode: String,
    sender_member: bool,
    recipient_member: bool,
}

pub async fn handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let token = auth::bearer_token(&headers)?;
    let auth = auth::validate_bearer_token(&state, token).await?;
    auth.ensure_device_id(query.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, query.device_id).await?;

    Ok(ws.on_upgrade(move |socket| socket_loop(state, auth.user_id, query.device_id, socket)))
}

async fn socket_loop(state: AppState, user_id: Uuid, device_id: Uuid, socket: WebSocket) {
    let mut events = state.ws.subscribe(device_id).await;
    let (mut sender, mut receiver) = socket.split();
    let mut ping = time::interval(Duration::from_secs(30));
    let mut signal_window_started = Instant::now();
    let mut signal_count = 0u32;

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        match serde_json::to_string(&event) {
                            Ok(text) => {
                                if sender.send(Message::Text(text)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ping.tick() => {
                if sender.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > P2P_COMMAND_MAX_BYTES {
                            break;
                        }
                        if signal_window_started.elapsed() >= P2P_SIGNAL_WINDOW {
                            signal_window_started = Instant::now();
                            signal_count = 0;
                        }
                        if signal_count >= P2P_SIGNAL_MAX_PER_WINDOW {
                            continue;
                        }
                        signal_count += 1;

                        let Ok(command) = serde_json::from_str::<WsClientCommand>(&text) else {
                            continue;
                        };
                        let WsClientCommand::P2pSignal {
                            bubble_id,
                            recipient_device_id,
                            session_id,
                            signal_kind,
                            payload,
                        } = command;
                        let _ = route_p2p_signal(
                            &state,
                            user_id,
                            device_id,
                            bubble_id,
                            recipient_device_id,
                            session_id,
                            signal_kind,
                            payload,
                        )
                        .await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn route_p2p_signal(
    state: &AppState,
    sender_user_id: Uuid,
    sender_device_id: Uuid,
    bubble_id: Uuid,
    recipient_device_id: Uuid,
    session_id: Uuid,
    signal_kind: String,
    payload: String,
) -> Result<(), AppError> {
    if sender_device_id == recipient_device_id {
        return Err(AppError::BadRequest("P2P_SELF_TARGET".into()));
    }
    if !matches!(
        signal_kind.as_str(),
        "offer" | "answer" | "ice" | "ice_complete" | "cancel"
    ) {
        return Err(AppError::BadRequest("INVALID_P2P_SIGNAL_KIND".into()));
    }
    if !valid_p2p_signal_payload(&payload) {
        return Err(AppError::BadRequest("INVALID_P2P_SIGNAL_PAYLOAD".into()));
    }

    devices::ensure_device_exists(state, recipient_device_id).await?;
    ensure_direct_bubble_scope(state, bubble_id, sender_user_id, recipient_device_id).await?;

    let delivered = state
        .ws
        .notify_p2p_signal(
            recipient_device_id,
            bubble_id,
            sender_device_id,
            session_id,
            signal_kind,
            payload,
        )
        .await;

    if !delivered {
        state
            .ws
            .notify_p2p_unavailable(sender_device_id, bubble_id, recipient_device_id, session_id)
            .await;
    }
    Ok(())
}

fn valid_p2p_signal_payload(payload: &str) -> bool {
    !payload.is_empty() && payload.len() <= P2P_SIGNAL_MAX_BYTES
}

async fn ensure_direct_bubble_scope(
    state: &AppState,
    bubble_id: Uuid,
    sender_user_id: Uuid,
    recipient_device_id: Uuid,
) -> Result<(), AppError> {
    let access = sqlx::query_as::<_, BubbleAccessRow>(
        "SELECT b.mode,
                EXISTS (
                    SELECT 1 FROM bubble_members bm
                    WHERE bm.bubble_id = b.id
                      AND bm.identity_id = $2
                      AND bm.status = 'active'
                ) AS sender_member,
                EXISTS (
                    SELECT 1 FROM bubble_members bm
                    WHERE bm.bubble_id = b.id
                      AND bm.identity_id = recipient.user_id
                      AND bm.status = 'active'
                ) AS recipient_member
         FROM bubbles b
         JOIN devices recipient ON recipient.id = $3 AND recipient.revoked_at IS NULL
         WHERE b.id = $1 AND b.deleted_at IS NULL",
    )
    .bind(bubble_id)
    .bind(sender_user_id)
    .bind(recipient_device_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;

    if access.mode == "PRIVATE_ISOLATED" {
        if access.sender_member && access.recipient_member {
            return Ok(());
        }
        return Err(AppError::Forbidden);
    }

    if access.sender_member || access.recipient_member {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::{valid_p2p_signal_payload, WsClientCommand, P2P_SIGNAL_MAX_BYTES};

    #[test]
    fn p2p_signal_command_deserializes_without_sender_identity() {
        let json = r#"{
            "type":"p2p_signal",
            "bubble_id":"00000000-0000-0000-0000-000000000001",
            "recipient_device_id":"00000000-0000-0000-0000-000000000002",
            "session_id":"00000000-0000-0000-0000-000000000003",
            "signal_kind":"offer",
            "payload":"opaque"
        }"#;
        let parsed = serde_json::from_str::<WsClientCommand>(json).expect("command");
        let WsClientCommand::P2pSignal {
            signal_kind,
            payload,
            ..
        } = parsed;
        assert_eq!(signal_kind, "offer");
        assert_eq!(payload, "opaque");
    }

    #[test]
    fn p2p_signal_payload_validation_enforces_runtime_bounds() {
        let at_limit = "x".repeat(P2P_SIGNAL_MAX_BYTES);
        let oversized = "x".repeat(P2P_SIGNAL_MAX_BYTES + 1);

        assert!(!valid_p2p_signal_payload(""));
        assert!(valid_p2p_signal_payload("opaque"));
        assert!(valid_p2p_signal_payload(&at_limit));
        assert!(!valid_p2p_signal_payload(&oversized));
    }
}
