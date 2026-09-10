use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    NewMessage {
        conversation_kind: &'static str,
        bubble_id: Uuid,
        message_id: Uuid,
    },
    ReceiptUpdated {
        conversation_kind: &'static str,
        bubble_id: Uuid,
        message_id: Uuid,
        client_message_id: Uuid,
        status: &'static str,
    },
    NewGroupMessage {
        bubble_id: Uuid,
        group_id: Uuid,
        message_id: Uuid,
    },
    NewChannelPost {
        bubble_id: Uuid,
        channel_id: Uuid,
        post_id: Uuid,
    },
    IncomingCall {
        bubble_id: Uuid,
        call_id: Uuid,
    },
    CallSignaling {
        bubble_id: Uuid,
        call_id: Uuid,
        event_kind: &'static str,
    },
    P2pSignal {
        bubble_id: Uuid,
        sender_device_id: Uuid,
        session_id: Uuid,
        signal_kind: String,
        payload: String,
    },
    P2pSignalUnavailable {
        bubble_id: Uuid,
        recipient_device_id: Uuid,
        session_id: Uuid,
    },
}

#[derive(Clone, Default)]
pub struct WsHub {
    inner: Arc<RwLock<HashMap<Uuid, broadcast::Sender<WsEvent>>>>,
}

impl WsHub {
    pub async fn subscribe(&self, device_id: Uuid) -> broadcast::Receiver<WsEvent> {
        let mut inner = self.inner.write().await;
        inner
            .entry(device_id)
            .or_insert_with(|| broadcast::channel(128).0)
            .subscribe()
    }

    pub async fn notify_new_message(&self, device_id: Uuid, bubble_id: Uuid, message_id: Uuid) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::NewMessage {
                conversation_kind: "direct",
                bubble_id,
                message_id,
            });
        }
    }

    pub async fn notify_receipt_updated(
        &self,
        device_id: Uuid,
        bubble_id: Uuid,
        message_id: Uuid,
        client_message_id: Uuid,
        status: &'static str,
    ) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::ReceiptUpdated {
                conversation_kind: "direct",
                bubble_id,
                message_id,
                client_message_id,
                status,
            });
        }
    }

    pub async fn notify_group_message(
        &self,
        device_id: Uuid,
        bubble_id: Uuid,
        group_id: Uuid,
        message_id: Uuid,
    ) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::NewGroupMessage {
                bubble_id,
                group_id,
                message_id,
            });
        }
    }

    pub async fn notify_channel_post(
        &self,
        device_id: Uuid,
        bubble_id: Uuid,
        channel_id: Uuid,
        post_id: Uuid,
    ) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::NewChannelPost {
                bubble_id,
                channel_id,
                post_id,
            });
        }
    }

    pub async fn notify_incoming_call(&self, device_id: Uuid, bubble_id: Uuid, call_id: Uuid) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::IncomingCall { bubble_id, call_id });
        }
    }

    pub async fn notify_call_signaling(
        &self,
        device_id: Uuid,
        bubble_id: Uuid,
        call_id: Uuid,
        event_kind: &'static str,
    ) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&device_id) {
            let _ = sender.send(WsEvent::CallSignaling {
                bubble_id,
                call_id,
                event_kind,
            });
        }
    }

    pub async fn notify_p2p_signal(
        &self,
        recipient_device_id: Uuid,
        bubble_id: Uuid,
        sender_device_id: Uuid,
        session_id: Uuid,
        signal_kind: String,
        payload: String,
    ) -> bool {
        let inner = self.inner.read().await;
        let Some(sender) = inner.get(&recipient_device_id) else {
            return false;
        };
        sender
            .send(WsEvent::P2pSignal {
                bubble_id,
                sender_device_id,
                session_id,
                signal_kind,
                payload,
            })
            .is_ok()
    }

    pub async fn notify_p2p_unavailable(
        &self,
        sender_device_id: Uuid,
        bubble_id: Uuid,
        recipient_device_id: Uuid,
        session_id: Uuid,
    ) {
        let inner = self.inner.read().await;
        if let Some(sender) = inner.get(&sender_device_id) {
            let _ = sender.send(WsEvent::P2pSignalUnavailable {
                bubble_id,
                recipient_device_id,
                session_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WsEvent;
    use uuid::Uuid;

    #[test]
    fn receipt_updated_serializes_client_message_id() {
        let message_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let client_message_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let bubble_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();

        let json = serde_json::to_value(WsEvent::ReceiptUpdated {
            conversation_kind: "direct",
            bubble_id,
            message_id,
            client_message_id,
            status: "delivered",
        })
        .unwrap();

        assert_eq!(json["type"], "receipt_updated");
        assert_eq!(json["conversation_kind"], "direct");
        assert_eq!(json["bubble_id"], bubble_id.to_string());
        assert_eq!(json["message_id"], message_id.to_string());
        assert_eq!(json["client_message_id"], client_message_id.to_string());
        assert_eq!(json["status"], "delivered");
    }

    #[test]
    fn p2p_signal_serializes_only_signaling_metadata() {
        let bubble_id = Uuid::parse_str("00000000-0000-0000-0000-000000000010").unwrap();
        let sender_device_id = Uuid::parse_str("00000000-0000-0000-0000-000000000011").unwrap();
        let session_id = Uuid::parse_str("00000000-0000-0000-0000-000000000012").unwrap();
        let json = serde_json::to_value(WsEvent::P2pSignal {
            bubble_id,
            sender_device_id,
            session_id,
            signal_kind: "offer".into(),
            payload: "opaque-sdp".into(),
        })
        .unwrap();

        assert_eq!(json["type"], "p2p_signal");
        assert_eq!(json["sender_device_id"], sender_device_id.to_string());
        assert_eq!(json["session_id"], session_id.to_string());
        assert_eq!(json["signal_kind"], "offer");
        assert_eq!(json["payload"], "opaque-sdp");
        assert!(json.get("p2p").is_none());
        assert!(json.get("transport").is_none());
    }
}
