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
        .route("/", post(create_channel).get(list_channels))
        .route("/:channel_id", get(get_channel))
        .route("/:channel_id/subscribers", get(list_subscribers))
        .route(
            "/:channel_id/subscribe",
            post(subscribe).delete(unsubscribe),
        )
        .route("/:channel_id/posts", post(create_post))
        .route("/:channel_id/posts/pending", get(pending_posts))
}

#[derive(Debug, Deserialize)]
struct CreateChannelRequest {
    bubble_id: Uuid,
    title: String,
    #[serde(default)]
    description: String,
    avatar_blob_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct ListChannelsQuery {
    bubble_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct CreatePostRequest {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    client_post_id: Uuid,
    #[serde(default = "default_opaque_type")]
    post_type: String,
    ciphertext: String,
    #[serde(default)]
    attachment_blob_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
struct ChannelResponse {
    id: Uuid,
    bubble_id: Uuid,
    title: String,
    description: Option<String>,
    avatar_blob_id: Option<Uuid>,
    owner_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ChannelsResponse {
    channels: Vec<ChannelResponse>,
}

#[derive(Debug, Serialize)]
struct ChannelSubscribersResponse {
    subscribers: Vec<ChannelSubscriberResponse>,
}

#[derive(Debug, Serialize, FromRow)]
struct ChannelSubscriberResponse {
    user_id: Uuid,
    public_id: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct PostResponse {
    id: Uuid,
    bubble_id: Uuid,
    client_post_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct PendingPostsResponse {
    posts: Vec<PendingPost>,
}

#[derive(Debug, Serialize, FromRow)]
struct PendingPost {
    id: Uuid,
    bubble_id: Uuid,
    channel_id: Uuid,
    sender_device_id: Uuid,
    client_post_id: Uuid,
    post_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

#[derive(Debug, FromRow)]
struct ChannelRow {
    id: Uuid,
    bubble_id: Uuid,
    title: String,
    description: Option<String>,
    avatar_blob_id: Option<Uuid>,
    owner_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ExistingChannelPostRow {
    id: Uuid,
    bubble_id: Uuid,
    channel_id: Uuid,
    post_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn create_channel(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<ChannelResponse>, AppError> {
    ensure_bubble_member(&state, payload.bubble_id, auth.user_id).await?;
    validation::title("title", &payload.title)?;
    validation::description("description", &payload.description)?;
    let channel_id = Uuid::new_v4();

    let mut tx = state.pg.begin().await?;
    let row = sqlx::query_as::<_, ChannelRow>(
        "INSERT INTO channels (id, bubble_id, title, description, avatar_blob_id, owner_user_id)
         VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)
         RETURNING id, bubble_id, title, description, avatar_blob_id, owner_user_id, created_at",
    )
    .bind(channel_id)
    .bind(payload.bubble_id)
    .bind(&payload.title)
    .bind(&payload.description)
    .bind(payload.avatar_blob_id)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO channel_subscribers (channel_id, user_id, role)
         VALUES ($1, $2, 'owner')",
    )
    .bind(channel_id)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(to_channel_response(row)))
}

async fn list_channels(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Query(query): Query<ListChannelsQuery>,
) -> Result<Json<ChannelsResponse>, AppError> {
    if let Some(bubble_id) = query.bubble_id {
        ensure_bubble_member(&state, bubble_id, auth.user_id).await?;
    }
    let rows = sqlx::query_as::<_, ChannelRow>(
        "SELECT c.id, c.bubble_id, c.title, c.description, c.avatar_blob_id, c.owner_user_id, c.created_at
         FROM channels c
         JOIN channel_subscribers cs ON cs.channel_id = c.id
         WHERE cs.user_id = $1
           AND cs.unsubscribed_at IS NULL
           AND c.archived_at IS NULL
           AND ($2::uuid IS NULL OR c.bubble_id = $2)
         ORDER BY c.created_at DESC
         LIMIT 200",
    )
    .bind(auth.user_id)
    .bind(query.bubble_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(ChannelsResponse {
        channels: rows.into_iter().map(to_channel_response).collect(),
    }))
}

async fn get_channel(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelResponse>, AppError> {
    subscriber_role(&state, channel_id, auth.user_id).await?;
    channel(&state, channel_id)
        .await
        .map(to_channel_response)
        .map(Json)
}

async fn list_subscribers(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelSubscribersResponse>, AppError> {
    subscriber_role(&state, channel_id, auth.user_id).await?;
    let subscribers = sqlx::query_as::<_, ChannelSubscriberResponse>(
        "SELECT cs.user_id, u.public_id, cs.role
         FROM channel_subscribers cs
         JOIN users u ON u.id = cs.user_id
         WHERE cs.channel_id = $1
           AND cs.unsubscribed_at IS NULL
           AND u.disabled_at IS NULL
         ORDER BY cs.created_at ASC",
    )
    .bind(channel_id)
    .fetch_all(&state.pg)
    .await?;
    Ok(Json(ChannelSubscribersResponse { subscribers }))
}

async fn subscribe(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    channel(&state, channel_id).await?;
    sqlx::query(
        "INSERT INTO channel_subscribers (channel_id, user_id, role, unsubscribed_at)
         VALUES ($1, $2, 'subscriber', NULL)
         ON CONFLICT (channel_id, user_id)
         DO UPDATE SET unsubscribed_at = NULL",
    )
    .bind(channel_id)
    .bind(auth.user_id)
    .execute(&state.pg)
    .await?;
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn unsubscribe(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    let role = subscriber_role(&state, channel_id, auth.user_id).await?;
    if role == "owner" {
        return Err(AppError::Forbidden);
    }
    let updated = sqlx::query(
        "UPDATE channel_subscribers
         SET unsubscribed_at = now()
         WHERE channel_id = $1 AND user_id = $2 AND unsubscribed_at IS NULL",
    )
    .bind(channel_id)
    .bind(auth.user_id)
    .execute(&state.pg)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn create_post(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(payload): Json<CreatePostRequest>,
) -> Result<Json<PostResponse>, AppError> {
    auth.ensure_device_id(payload.sender_device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.sender_device_id).await?;
    ensure_publisher(&state, channel_id, auth.user_id).await?;
    ensure_channel_scope(&state, channel_id, payload.bubble_id).await?;
    validation::message_type(&payload.post_type)?;
    validation::ciphertext(
        &payload.ciphertext,
        state.config.limits.max_ciphertext_bytes,
    )?;
    let attachments = lifecycle::prepare(&payload.attachment_blob_ids)?;

    let id = Uuid::new_v4();
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.limits.message_ttl)
            .map_err(|_| AppError::Internal)?;
    let mut tx = state.pg.begin().await?;
    let inserted: Option<(Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "INSERT INTO channel_posts_queue
            (id, bubble_id, channel_id, sender_device_id, client_post_id, post_type, ciphertext, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (sender_device_id, client_post_id) DO NOTHING
         RETURNING id, created_at, expires_at",
    )
    .bind(id)
    .bind(payload.bubble_id)
    .bind(channel_id)
    .bind(payload.sender_device_id)
    .bind(payload.client_post_id)
    .bind(&payload.post_type)
    .bind(&payload.ciphertext)
    .bind(expires_at)
    .fetch_optional(&mut *tx)
    .await?;

    let (post_id, created_at, expires_at, notify) =
        if let Some((post_id, created_at, expires_at)) = inserted {
            lifecycle::bind_channel(
                &mut tx,
                auth.user_id,
                payload.bubble_id,
                post_id,
                expires_at,
                &attachments,
            )
            .await?;
            (post_id, created_at, expires_at, true)
        } else {
            let existing = sqlx::query_as::<_, ExistingChannelPostRow>(
                "SELECT id, bubble_id, channel_id, post_type, ciphertext, created_at, expires_at
                 FROM channel_posts_queue
                 WHERE sender_device_id = $1 AND client_post_id = $2 AND expires_at > now()",
            )
            .bind(payload.sender_device_id)
            .bind(payload.client_post_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::Conflict(
                "client_post_id was already delivered or expired".into(),
            ))?;

            if existing.bubble_id != payload.bubble_id
                || existing.channel_id != channel_id
                || existing.post_type != payload.post_type
                || existing.ciphertext != payload.ciphertext
            {
                return Err(AppError::Conflict(
                    "client_post_id is already used by a different channel post".into(),
                ));
            }
            lifecycle::ensure_channel_matches(&mut tx, existing.id, &attachments).await?;
            (existing.id, existing.created_at, existing.expires_at, false)
        };
    tx.commit().await?;

    if notify {
        notify_subscriber_devices(&state, payload.bubble_id, channel_id, post_id).await?;
    }

    Ok(Json(PostResponse {
        id: post_id,
        bubble_id: payload.bubble_id,
        client_post_id: payload.client_post_id,
        created_at,
        expires_at,
    }))
}

async fn pending_posts(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<PendingPostsResponse>, AppError> {
    let device_id = auth.require_device_id()?;
    subscriber_role(&state, channel_id, auth.user_id).await?;
    devices::ensure_device_owner(&state, auth.user_id, device_id).await?;

    let posts = sqlx::query_as::<_, PendingPost>(
        "SELECT id, bubble_id, channel_id, sender_device_id, client_post_id, post_type, ciphertext, created_at, expires_at
         FROM channel_posts_queue cp
         WHERE channel_id = $1
           AND expires_at > now()
           AND NOT EXISTS (
             SELECT 1 FROM channel_post_receipts r
             WHERE r.post_id = cp.id AND r.recipient_device_id = $2
           )
         ORDER BY created_at ASC
         LIMIT 500",
    )
    .bind(channel_id)
    .bind(device_id)
    .fetch_all(&state.pg)
    .await?;

    for post in &posts {
        sqlx::query(
            "INSERT INTO channel_post_receipts (id, post_id, bubble_id, channel_id, recipient_device_id, status)
             VALUES ($1, $2, $3, $4, $5, 'delivered')
             ON CONFLICT (post_id, recipient_device_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(post.id)
        .bind(post.bubble_id)
        .bind(channel_id)
        .bind(device_id)
        .execute(&state.pg)
        .await?;
    }

    Ok(Json(PendingPostsResponse { posts }))
}

async fn channel(state: &AppState, channel_id: Uuid) -> Result<ChannelRow, AppError> {
    sqlx::query_as::<_, ChannelRow>(
        "SELECT id, bubble_id, title, description, avatar_blob_id, owner_user_id, created_at
         FROM channels
         WHERE id = $1 AND archived_at IS NULL",
    )
    .bind(channel_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)
}

async fn subscriber_role(
    state: &AppState,
    channel_id: Uuid,
    user_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar(
        "SELECT role FROM channel_subscribers
         WHERE channel_id = $1 AND user_id = $2 AND unsubscribed_at IS NULL",
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::Forbidden)
}

async fn ensure_publisher(
    state: &AppState,
    channel_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let role = subscriber_role(state, channel_id, user_id).await?;
    if matches!(role.as_str(), "owner" | "admin") {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn ensure_bubble_member(
    state: &AppState,
    bubble_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let exists: Option<Uuid> = sqlx::query_scalar(
        "SELECT bubble_id FROM bubble_members
         WHERE bubble_id = $1 AND identity_id = $2 AND status = 'active'",
    )
    .bind(bubble_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?;
    exists.map(|_| ()).ok_or(AppError::Forbidden)
}

async fn ensure_channel_scope(
    state: &AppState,
    channel_id: Uuid,
    bubble_id: Uuid,
) -> Result<(), AppError> {
    let exists: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM channels WHERE id = $1 AND bubble_id = $2 AND archived_at IS NULL",
    )
    .bind(channel_id)
    .bind(bubble_id)
    .fetch_optional(&state.pg)
    .await?;
    exists.map(|_| ()).ok_or(AppError::NotFound)
}

async fn notify_subscriber_devices(
    state: &AppState,
    bubble_id: Uuid,
    channel_id: Uuid,
    post_id: Uuid,
) -> Result<(), AppError> {
    let devices = sqlx::query_scalar::<_, Uuid>(
        "SELECT d.id
         FROM devices d
         JOIN channel_subscribers cs ON cs.user_id = d.user_id
         WHERE cs.channel_id = $1 AND cs.unsubscribed_at IS NULL AND d.revoked_at IS NULL",
    )
    .bind(channel_id)
    .fetch_all(&state.pg)
    .await?;
    for device_id in &devices {
        state
            .ws
            .notify_channel_post(*device_id, bubble_id, channel_id, post_id)
            .await;
    }
    push::notify_devices(
        state,
        &devices,
        push::PushNotification::channel_post(channel_id, post_id),
    )
    .await?;
    Ok(())
}

fn to_channel_response(row: ChannelRow) -> ChannelResponse {
    ChannelResponse {
        id: row.id,
        bubble_id: row.bubble_id,
        title: row.title,
        description: row.description,
        avatar_blob_id: row.avatar_blob_id,
        owner_user_id: row.owner_user_id,
        created_at: row.created_at,
    }
}

fn default_opaque_type() -> String {
    "opaque".into()
}
