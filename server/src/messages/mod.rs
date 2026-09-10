use axum::{
    extract::{Path, Query},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    attachments::lifecycle, auth::AuthUser, devices, error::AppError, push, security::validation,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(send_message))
        .route("/pending", get(pending_messages))
        .route("/receipts", get(sent_receipts))
        .route("/:id/receipt", post(ack_message))
}

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    recipient_device_id: Uuid,
    client_message_id: Uuid,
    message_type: String,
    ciphertext: String,
    #[serde(default)]
    attachment_blob_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
struct SendMessageResponse {
    id: Uuid,
    bubble_id: Uuid,
    client_message_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct PendingQuery {
    device_id: Uuid,
}

#[derive(Debug, Serialize)]
struct PendingMessagesResponse {
    messages: Vec<PendingMessage>,
}

#[derive(Debug, Serialize, FromRow)]
struct PendingMessage {
    id: Uuid,
    bubble_id: Uuid,
    sender_device_id: Uuid,
    sender_user_id: Uuid,
    sender_public_id: String,
    recipient_device_id: Uuid,
    client_message_id: Uuid,
    message_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct ReceiptRequest {
    device_id: Uuid,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceiptResponse {
    id: Uuid,
    status: &'static str,
}

#[derive(Debug, FromRow)]
struct MessageRecipientRow {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    recipient_device_id: Uuid,
    client_message_id: Uuid,
}

#[derive(Debug, FromRow)]
struct ExistingReceiptRow {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    client_message_id: Uuid,
    status: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptsQuery {
    device_id: Uuid,
}

#[derive(Debug, Serialize)]
struct SentReceiptsResponse {
    receipts: Vec<SentReceipt>,
}

#[derive(Debug, Serialize, FromRow)]
struct SentReceipt {
    message_id: Uuid,
    bubble_id: Uuid,
    client_message_id: Uuid,
    recipient_device_id: Uuid,
    status: String,
    delivered_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ExistingMessageRow {
    id: Uuid,
    bubble_id: Uuid,
    recipient_device_id: Uuid,
    message_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct BubbleAccessRow {
    mode: String,
    sender_member: bool,
    recipient_member: bool,
}

async fn send_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, AppError> {
    validation::ciphertext(
        &payload.ciphertext,
        state.config.limits.max_ciphertext_bytes,
    )?;
    validation::message_type(&payload.message_type)?;
    let attachments = lifecycle::prepare(&payload.attachment_blob_ids)?;
    auth.ensure_device_id(payload.sender_device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.sender_device_id).await?;
    devices::ensure_device_exists(&state, payload.recipient_device_id).await?;
    ensure_direct_bubble_scope(
        &state,
        payload.bubble_id,
        auth.user_id,
        payload.recipient_device_id,
    )
    .await?;

    let id = Uuid::new_v4();
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.limits.message_ttl)
            .map_err(|_| AppError::Internal)?;

    let mut tx = state.pg.begin().await?;
    let inserted: Option<(Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO message_queue
            (id, bubble_id, sender_device_id, recipient_device_id, client_message_id, message_type, ciphertext, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (sender_device_id, client_message_id) DO NOTHING
         RETURNING id, created_at, expires_at",
    )
    .bind(id)
    .bind(payload.bubble_id)
    .bind(payload.sender_device_id)
    .bind(payload.recipient_device_id)
    .bind(payload.client_message_id)
    .bind(&payload.message_type)
    .bind(&payload.ciphertext)
    .bind(expires_at)
    .fetch_optional(&mut *tx)
    .await?;

    let (message_id, created_at, expires_at, notify) = if let Some((
        message_id,
        created_at,
        expires_at,
    )) = inserted
    {
        lifecycle::bind_direct(
            &mut tx,
            auth.user_id,
            payload.bubble_id,
            message_id,
            payload.recipient_device_id,
            expires_at,
            &attachments,
        )
        .await?;
        (message_id, created_at, expires_at, true)
    } else {
        let existing = sqlx::query_as::<_, ExistingMessageRow>(
            "SELECT id, bubble_id, recipient_device_id, message_type, ciphertext, created_at, expires_at
             FROM message_queue
             WHERE sender_device_id = $1 AND client_message_id = $2 AND expires_at > now()",
        )
        .bind(payload.sender_device_id)
        .bind(payload.client_message_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::Conflict(
            "client_message_id was already delivered or expired".into(),
        ))?;

        if existing.bubble_id != payload.bubble_id
            || existing.recipient_device_id != payload.recipient_device_id
            || existing.message_type != payload.message_type
            || existing.ciphertext != payload.ciphertext
        {
            return Err(AppError::Conflict(
                "client_message_id is already used by a different message".into(),
            ));
        }
        lifecycle::ensure_direct_matches(&mut tx, existing.id, &attachments).await?;
        (existing.id, existing.created_at, existing.expires_at, false)
    };
    tx.commit().await?;

    if notify {
        state
            .ws
            .notify_new_message(payload.recipient_device_id, payload.bubble_id, message_id)
            .await;
        push::notify_devices(
            &state,
            &[payload.recipient_device_id],
            push::PushNotification::direct_message(message_id),
        )
        .await?;
    }

    Ok(Json(SendMessageResponse {
        id: message_id,
        bubble_id: payload.bubble_id,
        client_message_id: payload.client_message_id,
        created_at,
        expires_at,
    }))
}

async fn pending_messages(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Query(query): Query<PendingQuery>,
) -> Result<Json<PendingMessagesResponse>, AppError> {
    auth.ensure_device_id(query.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, query.device_id).await?;
    cleanup_expired_messages(&state).await?;

    let messages = sqlx::query_as::<_, PendingMessage>(
        "SELECT mq.id,
            mq.bubble_id,
            mq.sender_device_id,
            d.user_id AS sender_user_id,
            u.public_id AS sender_public_id,
            mq.recipient_device_id,
            mq.client_message_id,
            mq.message_type,
            mq.ciphertext,
            mq.created_at,
            mq.expires_at
         FROM message_queue mq
         JOIN devices d ON d.id = mq.sender_device_id
         JOIN users u ON u.id = d.user_id
         WHERE mq.recipient_device_id = $1 AND mq.expires_at > now()
         ORDER BY mq.created_at ASC
         LIMIT 500",
    )
    .bind(query.device_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(PendingMessagesResponse { messages }))
}

async fn ack_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<Uuid>,
    Json(payload): Json<ReceiptRequest>,
) -> Result<Json<ReceiptResponse>, AppError> {
    auth.ensure_device_id(payload.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.device_id).await?;
    let receipt_status = receipt_status(payload.status.as_deref())?;

    let mut tx = state.pg.begin().await?;
    let message = sqlx::query_as::<_, MessageRecipientRow>(
        "SELECT bubble_id, sender_device_id, recipient_device_id, client_message_id
         FROM message_queue
         WHERE id = $1 AND expires_at > now()
         FOR UPDATE",
    )
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(message) = message else {
        let already_acked = sqlx::query_as::<_, ExistingReceiptRow>(
            "SELECT bubble_id, sender_device_id, client_message_id, status
             FROM message_receipts
             WHERE message_id = $1 AND recipient_device_id = $2",
        )
        .bind(message_id)
        .bind(payload.device_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing) = already_acked {
            let status = if receipt_status == "read" && existing.status != "read" {
                sqlx::query(
                    "UPDATE message_receipts
                     SET status = 'read'
                     WHERE message_id = $1 AND recipient_device_id = $2",
                )
                .bind(message_id)
                .bind(payload.device_id)
                .execute(&mut *tx)
                .await?;
                "read"
            } else if existing.status == "read" {
                "read"
            } else {
                "delivered"
            };
            tx.commit().await?;
            if status == "read" && existing.status != "read" {
                state
                    .ws
                    .notify_receipt_updated(
                        existing.sender_device_id,
                        existing.bubble_id,
                        message_id,
                        existing.client_message_id,
                        status,
                    )
                    .await;
            }
            return Ok(Json(ReceiptResponse {
                id: message_id,
                status,
            }));
        }

        return Err(AppError::NotFound);
    };

    if message.recipient_device_id != payload.device_id {
        return Err(AppError::Forbidden);
    }

    sqlx::query(
        "INSERT INTO message_receipts
            (id, message_id, bubble_id, sender_device_id, recipient_device_id, client_message_id, status, delivered_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (message_id, recipient_device_id) DO UPDATE
         SET status = CASE
            WHEN message_receipts.status = 'read' OR EXCLUDED.status = 'read' THEN 'read'
            ELSE 'delivered'
         END,
         delivered_at = COALESCE(message_receipts.delivered_at, EXCLUDED.delivered_at)",
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(message.bubble_id)
    .bind(message.sender_device_id)
    .bind(payload.device_id)
    .bind(message.client_message_id)
    .bind(receipt_status)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM message_queue WHERE id = $1 AND recipient_device_id = $2")
        .bind(message_id)
        .bind(payload.device_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    state
        .ws
        .notify_receipt_updated(
            message.sender_device_id,
            message.bubble_id,
            message_id,
            message.client_message_id,
            receipt_status,
        )
        .await;

    Ok(Json(ReceiptResponse {
        id: message_id,
        status: receipt_status,
    }))
}

async fn sent_receipts(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Query(query): Query<ReceiptsQuery>,
) -> Result<Json<SentReceiptsResponse>, AppError> {
    auth.ensure_device_id(query.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, query.device_id).await?;

    let receipts = sqlx::query_as::<_, SentReceipt>(
        "SELECT message_id, bubble_id, client_message_id, recipient_device_id, status, delivered_at
         FROM message_receipts
         WHERE sender_device_id = $1
            AND client_message_id IS NOT NULL
            AND delivered_at IS NOT NULL
         ORDER BY delivered_at DESC
         LIMIT 500",
    )
    .bind(query.device_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(SentReceiptsResponse { receipts }))
}

async fn cleanup_expired_messages(state: &AppState) -> Result<(), AppError> {
    sqlx::query("DELETE FROM message_queue WHERE expires_at <= now()")
        .execute(&state.pg)
        .await?;
    Ok(())
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
         JOIN devices recipient ON recipient.id = $3
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

fn receipt_status(value: Option<&str>) -> Result<&'static str, AppError> {
    match value.unwrap_or("delivered") {
        "delivered" => Ok("delivered"),
        "read" => Ok("read"),
        _ => Err(AppError::BadRequest("INVALID_RECEIPT_STATUS".into())),
    }
}
