use axum::{extract::Path, routing::post, Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, error::AppError, push, security::validation, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_call))
        .route("/:call_id/accept", post(accept_call))
        .route("/:call_id/reject", post(reject_call))
        .route("/:call_id/hangup", post(hangup_call))
        .route("/:call_id/offer", post(offer))
        .route("/:call_id/answer", post(answer))
        .route(
            "/:call_id/ice-candidates",
            post(add_ice_candidates).get(ice_candidates),
        )
        .route("/:call_id/signaling", axum::routing::get(signaling_events))
}

#[derive(Debug, Deserialize)]
struct CreateCallRequest {
    bubble_id: Uuid,
    callee_user_id: Uuid,
    #[serde(default = "default_audio_kind")]
    call_kind: String,
}

#[derive(Debug, Deserialize)]
struct SdpRequest {
    bubble_id: Uuid,
    sdp: String,
}

#[derive(Debug, Deserialize)]
struct IceCandidatesRequest {
    bubble_id: Uuid,
    candidates: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CallResponse {
    id: Uuid,
    bubble_id: Uuid,
    call_kind: String,
    state: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct IceCandidatesResponse {
    candidates: Vec<SignalingEventResponse>,
}

#[derive(Debug, Serialize)]
struct SignalingEventsResponse {
    events: Vec<SignalingEventResponse>,
}

#[derive(Debug, Serialize, FromRow)]
struct SignalingEventResponse {
    id: Uuid,
    bubble_id: Uuid,
    sender_user_id: Uuid,
    event_kind: String,
    payload: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct CallRow {
    id: Uuid,
    bubble_id: Uuid,
    call_kind: String,
    state: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn create_call(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateCallRequest>,
) -> Result<Json<CallResponse>, AppError> {
    ensure_bubble_member(&state, payload.bubble_id, auth.user_id).await?;
    validation::role(&payload.call_kind, &["audio", "video"])?;
    if payload.callee_user_id == auth.user_id {
        return Err(AppError::BadRequest("cannot call yourself".into()));
    }
    let callee_exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND disabled_at IS NULL")
            .bind(payload.callee_user_id)
            .fetch_optional(&state.pg)
            .await?;
    if callee_exists.is_none() {
        return Err(AppError::NotFound);
    }

    let call_id = Uuid::new_v4();
    let expires_at = Utc::now() + ChronoDuration::minutes(2);
    let mut tx = state.pg.begin().await?;
    let call = sqlx::query_as::<_, CallRow>(
        "INSERT INTO calls (id, bubble_id, creator_user_id, call_kind, state, expires_at)
         VALUES ($1, $2, $3, $4, 'ringing', $5)
         RETURNING id, bubble_id, call_kind, state, created_at, expires_at",
    )
    .bind(call_id)
    .bind(payload.bubble_id)
    .bind(auth.user_id)
    .bind(&payload.call_kind)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO call_participants (call_id, user_id, role)
         VALUES ($1, $2, 'caller'), ($1, $3, 'callee')",
    )
    .bind(call_id)
    .bind(auth.user_id)
    .bind(payload.callee_user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    notify_incoming_call_to_user(&state, payload.callee_user_id, payload.bubble_id, call_id)
        .await?;

    Ok(Json(to_call_response(call)))
}

async fn accept_call(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    transition_call(state, auth, call_id, "accepted", "accept").await
}

async fn reject_call(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    transition_call(state, auth, call_id, "rejected", "reject").await
}

async fn hangup_call(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    transition_call(state, auth, call_id, "ended", "hangup").await
}

async fn offer(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
    Json(payload): Json<SdpRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    validation::opaque_payload("sdp", &payload.sdp, 128 * 1024)?;
    ensure_participant(&state, call_id, auth.user_id).await?;
    ensure_call_scope(&state, call_id, payload.bubble_id).await?;
    insert_event(
        &state,
        call_id,
        payload.bubble_id,
        auth.user_id,
        "offer",
        Some(payload.sdp),
    )
    .await?;
    notify_other_participants(&state, call_id, payload.bubble_id, auth.user_id, "offer").await?;
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn answer(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
    Json(payload): Json<SdpRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    validation::opaque_payload("sdp", &payload.sdp, 128 * 1024)?;
    ensure_participant(&state, call_id, auth.user_id).await?;
    ensure_call_scope(&state, call_id, payload.bubble_id).await?;
    insert_event(
        &state,
        call_id,
        payload.bubble_id,
        auth.user_id,
        "answer",
        Some(payload.sdp),
    )
    .await?;
    notify_other_participants(&state, call_id, payload.bubble_id, auth.user_id, "answer").await?;
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn add_ice_candidates(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
    Json(payload): Json<IceCandidatesRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_participant(&state, call_id, auth.user_id).await?;
    ensure_call_scope(&state, call_id, payload.bubble_id).await?;
    if payload.candidates.len() > 50 {
        return Err(AppError::BadRequest(
            "candidates may contain at most 50 entries".into(),
        ));
    }
    for candidate in payload.candidates {
        validation::opaque_payload("candidate", &candidate, 16 * 1024)?;
        insert_event(
            &state,
            call_id,
            payload.bubble_id,
            auth.user_id,
            "ice",
            Some(candidate),
        )
        .await?;
    }
    notify_other_participants(&state, call_id, payload.bubble_id, auth.user_id, "ice").await?;
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn ice_candidates(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
) -> Result<Json<IceCandidatesResponse>, AppError> {
    ensure_participant(&state, call_id, auth.user_id).await?;
    let candidates = sqlx::query_as::<_, SignalingEventResponse>(
        "SELECT id, bubble_id, sender_user_id, event_kind, payload, created_at
         FROM call_signaling_events
         WHERE call_id = $1 AND event_kind = 'ice' AND sender_user_id <> $2
         ORDER BY created_at ASC
         LIMIT 200",
    )
    .bind(call_id)
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;
    Ok(Json(IceCandidatesResponse { candidates }))
}

async fn signaling_events(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(call_id): Path<Uuid>,
) -> Result<Json<SignalingEventsResponse>, AppError> {
    ensure_participant(&state, call_id, auth.user_id).await?;
    let events = sqlx::query_as::<_, SignalingEventResponse>(
        "SELECT id, bubble_id, sender_user_id, event_kind, payload, created_at
         FROM call_signaling_events
         WHERE call_id = $1 AND sender_user_id <> $2
         ORDER BY created_at ASC
         LIMIT 500",
    )
    .bind(call_id)
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;
    Ok(Json(SignalingEventsResponse { events }))
}

async fn transition_call(
    state: AppState,
    auth: AuthUser,
    call_id: Uuid,
    state_value: &'static str,
    event_kind: &'static str,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_participant(&state, call_id, auth.user_id).await?;
    let bubble_id = call_bubble_id(&state, call_id).await?;
    sqlx::query("UPDATE calls SET state = $1, updated_at = now() WHERE id = $2")
        .bind(state_value)
        .bind(call_id)
        .execute(&state.pg)
        .await?;
    insert_event(&state, call_id, bubble_id, auth.user_id, event_kind, None).await?;
    notify_other_participants(&state, call_id, bubble_id, auth.user_id, event_kind).await?;
    Ok(Json(StatusResponse { status: "ok" }))
}

async fn ensure_participant(
    state: &AppState,
    call_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM call_participants WHERE call_id = $1 AND user_id = $2",
    )
    .bind(call_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?;
    found.map(|_| ()).ok_or(AppError::Forbidden)
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

async fn ensure_call_scope(
    state: &AppState,
    call_id: Uuid,
    bubble_id: Uuid,
) -> Result<(), AppError> {
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM calls WHERE id = $1 AND bubble_id = $2")
            .bind(call_id)
            .bind(bubble_id)
            .fetch_optional(&state.pg)
            .await?;
    exists.map(|_| ()).ok_or(AppError::NotFound)
}

async fn call_bubble_id(state: &AppState, call_id: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar("SELECT bubble_id FROM calls WHERE id = $1")
        .bind(call_id)
        .fetch_optional(&state.pg)
        .await?
        .ok_or(AppError::NotFound)
}

async fn insert_event(
    state: &AppState,
    call_id: Uuid,
    bubble_id: Uuid,
    sender_user_id: Uuid,
    event_kind: &'static str,
    payload: Option<String>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO call_signaling_events (id, call_id, bubble_id, sender_user_id, event_kind, payload)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(call_id)
    .bind(bubble_id)
    .bind(sender_user_id)
    .bind(event_kind)
    .bind(payload)
    .execute(&state.pg)
    .await?;
    Ok(())
}

async fn notify_other_participants(
    state: &AppState,
    call_id: Uuid,
    bubble_id: Uuid,
    sender_user_id: Uuid,
    event_kind: &'static str,
) -> Result<(), AppError> {
    let users = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM call_participants WHERE call_id = $1 AND user_id <> $2",
    )
    .bind(call_id)
    .bind(sender_user_id)
    .fetch_all(&state.pg)
    .await?;
    for user_id in users {
        notify_call_signaling_to_user(state, user_id, bubble_id, call_id, event_kind).await?;
    }
    Ok(())
}

async fn notify_incoming_call_to_user(
    state: &AppState,
    user_id: Uuid,
    bubble_id: Uuid,
    call_id: Uuid,
) -> Result<(), AppError> {
    let devices = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM devices WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(&state.pg)
    .await?;
    for device_id in &devices {
        state
            .ws
            .notify_incoming_call(*device_id, bubble_id, call_id)
            .await;
    }
    push::notify_devices(
        state,
        &devices,
        push::PushNotification::incoming_call(call_id),
    )
    .await?;
    Ok(())
}

async fn notify_call_signaling_to_user(
    state: &AppState,
    user_id: Uuid,
    bubble_id: Uuid,
    call_id: Uuid,
    event_kind: &'static str,
) -> Result<(), AppError> {
    let devices = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM devices WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(&state.pg)
    .await?;
    for device_id in devices {
        state
            .ws
            .notify_call_signaling(device_id, bubble_id, call_id, event_kind)
            .await;
    }
    Ok(())
}

fn to_call_response(row: CallRow) -> CallResponse {
    CallResponse {
        id: row.id,
        bubble_id: row.bubble_id,
        call_kind: row.call_kind,
        state: row.state,
        created_at: row.created_at,
        expires_at: row.expires_at,
    }
}

fn default_audio_kind() -> String {
    "audio".into()
}
