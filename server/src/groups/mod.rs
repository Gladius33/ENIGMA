use axum::{
    extract::{Path, Query},
    routing::{delete, get, post},
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
        .route("/", post(create_group).get(list_groups))
        .route("/:group_id", get(get_group))
        .route("/:group_id/members", post(add_member))
        .route("/:group_id/members/:user_id", delete(remove_member))
        .route("/:group_id/messages", post(send_group_message))
        .route("/:group_id/messages/pending", get(pending_group_messages))
        .route(
            "/:group_id/messages/:message_id/receipt",
            post(ack_group_message),
        )
}

#[derive(Debug, Deserialize)]
struct CreateGroupRequest {
    bubble_id: Uuid,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ListGroupsQuery {
    bubble_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct AddMemberRequest {
    user_id: Uuid,
    #[serde(default = "default_member_role")]
    role: String,
}

#[derive(Debug, Deserialize)]
struct SendGroupMessageRequest {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    client_message_id: Uuid,
    #[serde(default = "default_opaque_type")]
    message_type: String,
    ciphertext: String,
    #[serde(default)]
    attachment_blob_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
struct ReceiptRequest {
    device_id: Uuid,
    #[serde(default = "default_delivered_status")]
    status: String,
}

#[derive(Debug, Serialize)]
struct GroupResponse {
    id: Uuid,
    bubble_id: Uuid,
    title: String,
    owner_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct GroupDetailResponse {
    group: GroupResponse,
    members: Vec<GroupMemberResponse>,
}

#[derive(Debug, Serialize)]
struct GroupMemberResponse {
    user_id: Uuid,
    public_id: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct GroupsResponse {
    groups: Vec<GroupResponse>,
}

#[derive(Debug, Serialize)]
struct SendGroupMessageResponse {
    id: Uuid,
    bubble_id: Uuid,
    client_message_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct PendingGroupMessagesResponse {
    messages: Vec<PendingGroupMessage>,
}

#[derive(Debug, Serialize, FromRow)]
struct PendingGroupMessage {
    id: Uuid,
    bubble_id: Uuid,
    group_id: Uuid,
    sender_device_id: Uuid,
    client_message_id: Uuid,
    message_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

#[derive(Debug, FromRow)]
struct GroupRow {
    id: Uuid,
    bubble_id: Uuid,
    title: String,
    owner_user_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct MemberRow {
    user_id: Uuid,
    public_id: String,
    role: String,
}

#[derive(Debug, FromRow)]
struct ExistingGroupMessageRow {
    id: Uuid,
    bubble_id: Uuid,
    group_id: Uuid,
    message_type: String,
    ciphertext: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn create_group(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<GroupDetailResponse>, AppError> {
    ensure_bubble_member(&state, payload.bubble_id, auth.user_id).await?;
    validation::title("title", &payload.title)?;
    let group_id = Uuid::new_v4();

    let mut tx = state.pg.begin().await?;
    let group = sqlx::query_as::<_, GroupRow>(
        "INSERT INTO groups (id, bubble_id, title, owner_user_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id, bubble_id, title, owner_user_id, created_at",
    )
    .bind(group_id)
    .bind(payload.bubble_id)
    .bind(&payload.title)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query("INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(group_id)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(GroupDetailResponse {
        group: to_group_response(group),
        members: members(&state, group_id).await?,
    }))
}

async fn list_groups(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<GroupsResponse>, AppError> {
    if let Some(bubble_id) = query.bubble_id {
        ensure_bubble_member(&state, bubble_id, auth.user_id).await?;
    }
    let groups = sqlx::query_as::<_, GroupRow>(
        "SELECT g.id, g.bubble_id, g.title, g.owner_user_id, g.created_at
         FROM groups g
         JOIN group_members gm ON gm.group_id = g.id
         WHERE gm.user_id = $1
           AND gm.removed_at IS NULL
           AND g.archived_at IS NULL
           AND ($2::uuid IS NULL OR g.bubble_id = $2)
         ORDER BY g.updated_at DESC",
    )
    .bind(auth.user_id)
    .bind(query.bubble_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(GroupsResponse {
        groups: groups.into_iter().map(to_group_response).collect(),
    }))
}

async fn get_group(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupDetailResponse>, AppError> {
    ensure_member(&state, group_id, auth.user_id).await?;
    let group = group(&state, group_id).await?;
    Ok(Json(GroupDetailResponse {
        group: to_group_response(group),
        members: members(&state, group_id).await?,
    }))
}

async fn add_member(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
    Json(payload): Json<AddMemberRequest>,
) -> Result<Json<GroupMemberResponse>, AppError> {
    ensure_admin(&state, group_id, auth.user_id).await?;
    validation::role(&payload.role, &["admin", "member"])?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND disabled_at IS NULL")
            .bind(payload.user_id)
            .fetch_optional(&state.pg)
            .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }

    sqlx::query(
        "INSERT INTO group_members (group_id, user_id, role, removed_at)
         VALUES ($1, $2, $3, NULL)
         ON CONFLICT (group_id, user_id)
         DO UPDATE SET role = EXCLUDED.role, removed_at = NULL",
    )
    .bind(group_id)
    .bind(payload.user_id)
    .bind(&payload.role)
    .execute(&state.pg)
    .await?;

    member(&state, group_id, payload.user_id).await.map(Json)
}

async fn remove_member(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_admin(&state, group_id, auth.user_id).await?;
    let role = member_role(&state, group_id, user_id).await?;
    if role == "owner" {
        return Err(AppError::Forbidden);
    }

    let updated = sqlx::query(
        "UPDATE group_members
         SET removed_at = now()
         WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(group_id)
    .bind(user_id)
    .execute(&state.pg)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn send_group_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
    Json(payload): Json<SendGroupMessageRequest>,
) -> Result<Json<SendGroupMessageResponse>, AppError> {
    auth.ensure_device_id(payload.sender_device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.sender_device_id).await?;
    ensure_member(&state, group_id, auth.user_id).await?;
    ensure_group_scope(&state, group_id, payload.bubble_id).await?;
    validation::message_type(&payload.message_type)?;
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
        "INSERT INTO group_message_queue
            (id, bubble_id, group_id, sender_device_id, client_message_id, message_type, ciphertext, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (sender_device_id, client_message_id) DO NOTHING
         RETURNING id, created_at, expires_at",
    )
    .bind(id)
    .bind(payload.bubble_id)
    .bind(group_id)
    .bind(payload.sender_device_id)
    .bind(payload.client_message_id)
    .bind(&payload.message_type)
    .bind(&payload.ciphertext)
    .bind(expires_at)
    .fetch_optional(&mut *tx)
    .await?;

    let (message_id, created_at, expires_at, notify) =
        if let Some((message_id, created_at, expires_at)) = inserted {
            lifecycle::bind_group(
                &mut tx,
                auth.user_id,
                payload.bubble_id,
                message_id,
                expires_at,
                &attachments,
            )
            .await?;
            (message_id, created_at, expires_at, true)
        } else {
            let existing = sqlx::query_as::<_, ExistingGroupMessageRow>(
                "SELECT id, bubble_id, group_id, message_type, ciphertext, created_at, expires_at
                 FROM group_message_queue
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
                || existing.group_id != group_id
                || existing.message_type != payload.message_type
                || existing.ciphertext != payload.ciphertext
            {
                return Err(AppError::Conflict(
                    "client_message_id is already used by a different group message".into(),
                ));
            }
            lifecycle::ensure_group_matches(&mut tx, existing.id, &attachments).await?;
            (existing.id, existing.created_at, existing.expires_at, false)
        };
    tx.commit().await?;

    if notify {
        notify_group_devices(&state, payload.bubble_id, group_id, message_id).await?;
    }

    Ok(Json(SendGroupMessageResponse {
        id: message_id,
        bubble_id: payload.bubble_id,
        client_message_id: payload.client_message_id,
        created_at,
        expires_at,
    }))
}

async fn pending_group_messages(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<PendingGroupMessagesResponse>, AppError> {
    let device_id = auth.require_device_id()?;
    ensure_member(&state, group_id, auth.user_id).await?;
    devices::ensure_device_owner(&state, auth.user_id, device_id).await?;

    let messages = sqlx::query_as::<_, PendingGroupMessage>(
        "SELECT id, bubble_id, group_id, sender_device_id, client_message_id, message_type, ciphertext, created_at, expires_at
         FROM group_message_queue gm
         WHERE group_id = $1
           AND expires_at > now()
           AND NOT EXISTS (
             SELECT 1 FROM group_receipts gr
             WHERE gr.message_id = gm.id AND gr.recipient_device_id = $2
           )
         ORDER BY created_at ASC
         LIMIT 500",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(PendingGroupMessagesResponse { messages }))
}

async fn ack_group_message(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path((group_id, message_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<ReceiptRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    auth.ensure_device_id(payload.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.device_id).await?;
    ensure_member(&state, group_id, auth.user_id).await?;
    validation::role(&payload.status, &["delivered", "read"])?;

    let message_bubble: Option<Uuid> = sqlx::query_scalar(
        "SELECT bubble_id FROM group_message_queue WHERE id = $1 AND group_id = $2 AND expires_at > now()",
    )
    .bind(message_id)
    .bind(group_id)
    .fetch_optional(&state.pg)
    .await?;
    let message_bubble = message_bubble.ok_or(AppError::NotFound)?;

    sqlx::query(
        "INSERT INTO group_receipts (id, message_id, bubble_id, group_id, recipient_device_id, status)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (message_id, recipient_device_id, status) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(message_bubble)
    .bind(group_id)
    .bind(payload.device_id)
    .bind(&payload.status)
    .execute(&state.pg)
    .await?;

    Ok(Json(StatusResponse { status: "ok" }))
}

async fn group(state: &AppState, group_id: Uuid) -> Result<GroupRow, AppError> {
    sqlx::query_as::<_, GroupRow>(
        "SELECT id, bubble_id, title, owner_user_id, created_at
         FROM groups
         WHERE id = $1 AND archived_at IS NULL",
    )
    .bind(group_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)
}

async fn member(
    state: &AppState,
    group_id: Uuid,
    user_id: Uuid,
) -> Result<GroupMemberResponse, AppError> {
    let row = sqlx::query_as::<_, MemberRow>(
        "SELECT gm.user_id, u.public_id, gm.role
         FROM group_members gm
         JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1 AND gm.user_id = $2 AND gm.removed_at IS NULL",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(GroupMemberResponse {
        user_id: row.user_id,
        public_id: row.public_id,
        role: row.role,
    })
}

async fn members(state: &AppState, group_id: Uuid) -> Result<Vec<GroupMemberResponse>, AppError> {
    let rows = sqlx::query_as::<_, MemberRow>(
        "SELECT gm.user_id, u.public_id, gm.role
         FROM group_members gm
         JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1 AND gm.removed_at IS NULL
         ORDER BY gm.created_at ASC",
    )
    .bind(group_id)
    .fetch_all(&state.pg)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| GroupMemberResponse {
            user_id: row.user_id,
            public_id: row.public_id,
            role: row.role,
        })
        .collect())
}

async fn ensure_member(state: &AppState, group_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    member_role(state, group_id, user_id).await.map(|_| ())
}

async fn ensure_admin(state: &AppState, group_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let role = member_role(state, group_id, user_id).await?;
    if matches!(role.as_str(), "owner" | "admin") {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn member_role(state: &AppState, group_id: Uuid, user_id: Uuid) -> Result<String, AppError> {
    sqlx::query_scalar(
        "SELECT role FROM group_members
         WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::Forbidden)
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

async fn ensure_group_scope(
    state: &AppState,
    group_id: Uuid,
    bubble_id: Uuid,
) -> Result<(), AppError> {
    let exists: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM groups WHERE id = $1 AND bubble_id = $2 AND archived_at IS NULL",
    )
    .bind(group_id)
    .bind(bubble_id)
    .fetch_optional(&state.pg)
    .await?;
    exists.map(|_| ()).ok_or(AppError::NotFound)
}

async fn notify_group_devices(
    state: &AppState,
    bubble_id: Uuid,
    group_id: Uuid,
    message_id: Uuid,
) -> Result<(), AppError> {
    let devices = sqlx::query_scalar::<_, Uuid>(
        "SELECT d.id
         FROM devices d
         JOIN group_members gm ON gm.user_id = d.user_id
         WHERE gm.group_id = $1 AND gm.removed_at IS NULL AND d.revoked_at IS NULL",
    )
    .bind(group_id)
    .fetch_all(&state.pg)
    .await?;
    for device_id in &devices {
        state
            .ws
            .notify_group_message(*device_id, bubble_id, group_id, message_id)
            .await;
    }
    push::notify_devices(
        state,
        &devices,
        push::PushNotification::group_message(group_id, message_id),
    )
    .await?;
    Ok(())
}

fn to_group_response(row: GroupRow) -> GroupResponse {
    GroupResponse {
        id: row.id,
        bubble_id: row.bubble_id,
        title: row.title,
        owner_user_id: row.owner_user_id,
        created_at: row.created_at,
    }
}

fn default_member_role() -> String {
    "member".into()
}

fn default_opaque_type() -> String {
    "opaque".into()
}

fn default_delivered_status() -> String {
    "delivered".into()
}
