use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{config::FcmConfig, error::AppError, AppState};

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushEventKind {
    DirectMessage,
    GroupMessage,
    ChannelPost,
    IncomingCall,
    OfficialAnnouncement,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushNotification {
    pub kind: PushEventKind,
    pub direct_message_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub group_message_id: Option<Uuid>,
    pub channel_id: Option<Uuid>,
    pub channel_post_id: Option<Uuid>,
    pub call_id: Option<Uuid>,
}

impl PushNotification {
    pub fn official_sync_hint() -> Self {
        Self {
            kind: PushEventKind::OfficialAnnouncement,
            direct_message_id: None,
            group_id: None,
            group_message_id: None,
            channel_id: None,
            channel_post_id: None,
            call_id: None,
        }
    }

    pub fn direct_message(message_id: Uuid) -> Self {
        Self {
            kind: PushEventKind::DirectMessage,
            direct_message_id: Some(message_id),
            group_id: None,
            group_message_id: None,
            channel_id: None,
            channel_post_id: None,
            call_id: None,
        }
    }

    pub fn group_message(group_id: Uuid, message_id: Uuid) -> Self {
        Self {
            kind: PushEventKind::GroupMessage,
            direct_message_id: None,
            group_id: Some(group_id),
            group_message_id: Some(message_id),
            channel_id: None,
            channel_post_id: None,
            call_id: None,
        }
    }

    pub fn channel_post(channel_id: Uuid, post_id: Uuid) -> Self {
        Self {
            kind: PushEventKind::ChannelPost,
            direct_message_id: None,
            group_id: None,
            group_message_id: None,
            channel_id: Some(channel_id),
            channel_post_id: Some(post_id),
            call_id: None,
        }
    }

    pub fn incoming_call(call_id: Uuid) -> Self {
        Self {
            kind: PushEventKind::IncomingCall,
            direct_message_id: None,
            group_id: None,
            group_message_id: None,
            channel_id: None,
            channel_post_id: None,
            call_id: Some(call_id),
        }
    }

    fn data(&self) -> HashMap<String, String> {
        let _ = self;
        HashMap::from([("type".into(), "sync_hint".into())])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushSendOutcome {
    Sent,
    InvalidToken,
}

#[async_trait]
pub trait PushSender: Send + Sync {
    async fn send(
        &self,
        token: &str,
        notification: &PushNotification,
    ) -> Result<PushSendOutcome, AppError>;
}

#[derive(Debug, Clone, Default)]
pub struct NoopPushSender;

#[async_trait]
impl PushSender for NoopPushSender {
    async fn send(
        &self,
        token: &str,
        notification: &PushNotification,
    ) -> Result<PushSendOutcome, AppError> {
        let _ = token;
        let _ = notification;
        Ok(PushSendOutcome::Sent)
    }
}

pub struct FcmPushSender {
    client_email: String,
    private_key: EncodingKey,
    http: reqwest::Client,
    token_endpoint: String,
    message_endpoint: String,
    cached_token: Mutex<Option<CachedAccessToken>>,
}

impl FcmPushSender {
    pub fn new(config: &FcmConfig) -> Result<Self, AppError> {
        let account = serde_json::from_str::<ServiceAccount>(&config.service_account_json)
            .map_err(|_| AppError::Internal)?;
        let private_key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|_| AppError::Internal)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| AppError::Internal)?;

        Ok(Self {
            client_email: account.client_email,
            private_key,
            http,
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_owned(),
            message_endpoint: fcm_message_endpoint(&config.project_id),
            cached_token: Mutex::new(None),
        })
    }

    async fn access_token(&self) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        {
            let cached = self.cached_token.lock().await;
            if let Some(token) = cached
                .as_ref()
                .filter(|token| token.expires_at_epoch > now + 60)
            {
                return Ok(token.value.clone());
            }
        }

        let assertion = self.jwt_assertion(now)?;
        let response = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| AppError::Internal)?;

        if !response.status().is_success() {
            return Err(AppError::Internal);
        }

        let token = response
            .json::<TokenResponse>()
            .await
            .map_err(|_| AppError::Internal)?;
        let cached = CachedAccessToken {
            value: token.access_token.clone(),
            expires_at_epoch: now + token.expires_in,
        };
        *self.cached_token.lock().await = Some(cached);
        Ok(token.access_token)
    }

    fn jwt_assertion(&self, now: i64) -> Result<String, AppError> {
        let claims = TokenClaims {
            iss: &self.client_email,
            scope: FCM_SCOPE,
            aud: &self.token_endpoint,
            iat: now,
            exp: now + 3600,
        };
        encode(&Header::new(Algorithm::RS256), &claims, &self.private_key)
            .map_err(|_| AppError::Internal)
    }
}

#[async_trait]
impl PushSender for FcmPushSender {
    async fn send(
        &self,
        token: &str,
        notification: &PushNotification,
    ) -> Result<PushSendOutcome, AppError> {
        let access_token = self.access_token().await?;
        let response = self
            .http
            .post(&self.message_endpoint)
            .bearer_auth(access_token)
            .json(&fcm_send_request(token, notification))
            .send()
            .await
            .map_err(|_| AppError::Internal)?;

        fcm_outcome_from_status(response.status())
    }
}

fn fcm_message_endpoint(project_id: &str) -> String {
    format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send")
}

fn fcm_send_request<'a>(token: &'a str, notification: &PushNotification) -> FcmSendRequest<'a> {
    FcmSendRequest {
        message: FcmMessage {
            token,
            data: notification.data(),
            android: FcmAndroidConfig { priority: "HIGH" },
        },
    }
}

fn fcm_outcome_from_status(status: StatusCode) -> Result<PushSendOutcome, AppError> {
    if status.is_success() {
        return Ok(PushSendOutcome::Sent);
    }
    if matches!(status, StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND) {
        return Ok(PushSendOutcome::InvalidToken);
    }
    Err(AppError::Internal)
}

#[derive(Debug, FromRow)]
struct PushDeviceRow {
    device_id: Uuid,
    fcm_token: String,
}

pub async fn notify_devices(
    state: &AppState,
    device_ids: &[Uuid],
    notification: PushNotification,
) -> Result<(), AppError> {
    if device_ids.is_empty() {
        return Ok(());
    }

    let rows = sqlx::query_as::<_, PushDeviceRow>(
        "SELECT id AS device_id, fcm_token
         FROM devices
         WHERE id = ANY($1)
           AND fcm_token IS NOT NULL
           AND push_enabled = TRUE
           AND revoked_at IS NULL",
    )
    .bind(device_ids)
    .fetch_all(&state.pg)
    .await?;

    for row in rows {
        if state.push.send(&row.fcm_token, &notification).await? == PushSendOutcome::InvalidToken {
            sqlx::query(
                "UPDATE devices
                 SET push_enabled = FALSE,
                     fcm_token = NULL,
                     fcm_token_updated_at = NULL
                 WHERE id = $1",
            )
            .bind(row.device_id)
            .execute(&state.pg)
            .await?;
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Serialize)]
struct TokenClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug)]
struct CachedAccessToken {
    value: String,
    expires_at_epoch: i64,
}

#[derive(Debug, Serialize)]
struct FcmSendRequest<'a> {
    message: FcmMessage<'a>,
}

#[derive(Debug, Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    data: HashMap<String, String>,
    android: FcmAndroidConfig<'a>,
}

#[derive(Debug, Serialize)]
struct FcmAndroidConfig<'a> {
    priority: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_value;

    #[test]
    fn fcm_payload_is_only_sync_hint_for_all_events() {
        let notifications = [
            PushNotification::direct_message(Uuid::new_v4()),
            PushNotification::group_message(Uuid::new_v4(), Uuid::new_v4()),
            PushNotification::channel_post(Uuid::new_v4(), Uuid::new_v4()),
            PushNotification::incoming_call(Uuid::new_v4()),
        ];

        for notification in notifications {
            let data = notification.data();
            assert_eq!(data.len(), 1);
            assert_eq!(data.get("type").map(String::as_str), Some("sync_hint"));
            assert!(!data.contains_key("message_id"));
            assert!(!data.contains_key("group_id"));
            assert!(!data.contains_key("channel_id"));
            assert!(!data.contains_key("call_id"));
            assert!(!data.contains_key("sender"));
        }
    }

    #[test]
    fn fcm_sender_posts_only_opaque_sync_hint_payload() {
        let message_id = Uuid::new_v4();
        let outcome = fcm_outcome_from_status(StatusCode::OK).expect("status");

        assert_eq!(outcome, PushSendOutcome::Sent);
        let body = to_value(fcm_send_request(
            "fcm-token-secret",
            &PushNotification::direct_message(message_id),
        ))
        .expect("json body");
        let message = &body["message"];
        assert_eq!(message["token"], "fcm-token-secret");
        assert_eq!(message["android"]["priority"], "HIGH");
        assert_eq!(message["data"]["type"], "sync_hint");
        assert_eq!(message["data"].as_object().expect("data object").len(), 1);
        assert!(message.get("notification").is_none());
        assert!(!body.to_string().contains(&message_id.to_string()));
    }

    #[test]
    fn fcm_sender_marks_bad_request_and_not_found_as_invalid_token() {
        for status in [StatusCode::BAD_REQUEST, StatusCode::NOT_FOUND] {
            let outcome = fcm_outcome_from_status(status).expect("status");

            assert_eq!(outcome, PushSendOutcome::InvalidToken);
        }
    }
}
