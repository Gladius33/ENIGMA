use axum::{extract::Path, routing::get, Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser, error::AppError, relay_constants::OFFICIAL_RELAY_ID, security::validation,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_bubbles).post(create_bubble))
        .route("/:bubble_id", get(get_bubble))
        .route("/:bubble_id/members", get(list_members))
        .route("/:bubble_id/relays", get(list_relays).post(add_relay))
}

#[derive(Debug, Deserialize)]
struct CreateBubbleRequest {
    slug: Option<String>,
    name: String,
    description: Option<String>,
    mode: String,
    visibility: String,
    join_policy: String,
    index_policy: String,
}

#[derive(Debug, Deserialize)]
struct AddBubbleRelayRequest {
    relay_id: Uuid,
    #[serde(default = "default_primary_role")]
    role: String,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    required: bool,
    #[serde(default = "default_true")]
    fallback_allowed: bool,
}

#[derive(Debug, Serialize)]
struct BubblesResponse {
    bubbles: Vec<BubbleResponse>,
}

#[derive(Debug, Serialize)]
struct BubbleResponse {
    id: Uuid,
    slug: String,
    name: String,
    description: Option<String>,
    mode: String,
    visibility: String,
    join_policy: String,
    index_policy: String,
    owner_identity_id: Option<Uuid>,
    public_key: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct BubbleMembersResponse {
    members: Vec<BubbleMemberResponse>,
}

#[derive(Debug, Serialize)]
struct BubbleMemberResponse {
    identity_id: Uuid,
    role: String,
    status: String,
    joined_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct BubbleRelaysResponse {
    relays: Vec<BubbleRelayResponse>,
}

#[derive(Debug, Serialize)]
struct BubbleRelayResponse {
    bubble_id: Uuid,
    relay_id: Uuid,
    role: String,
    priority: i32,
    required: bool,
    fallback_allowed: bool,
}

#[derive(Debug, FromRow)]
struct BubbleRow {
    id: Uuid,
    slug: String,
    name: String,
    description: Option<String>,
    mode: String,
    visibility: String,
    join_policy: String,
    index_policy: String,
    owner_identity_id: Option<Uuid>,
    public_key: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct BubbleMemberRow {
    identity_id: Uuid,
    role: String,
    status: String,
    joined_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct BubbleRelayRow {
    bubble_id: Uuid,
    relay_id: Uuid,
    role: String,
    priority: i32,
    required: bool,
    fallback_allowed: bool,
}

async fn list_bubbles(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
) -> Result<Json<BubblesResponse>, AppError> {
    ensure_main_bubble(&state, auth.user_id).await?;
    let rows = sqlx::query_as::<_, BubbleRow>(
        "SELECT b.id, b.slug, b.name, b.description, b.mode, b.visibility, b.join_policy,
                b.index_policy, b.owner_identity_id, b.public_key, b.created_at, b.updated_at
         FROM bubbles b
         JOIN bubble_members bm ON bm.bubble_id = b.id
         WHERE bm.identity_id = $1 AND bm.status = 'active' AND b.deleted_at IS NULL
         ORDER BY b.updated_at DESC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(BubblesResponse {
        bubbles: rows.into_iter().map(to_bubble_response).collect(),
    }))
}

async fn create_bubble(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<CreateBubbleRequest>,
) -> Result<Json<BubbleResponse>, AppError> {
    validation::title("name", &payload.name)?;
    if let Some(description) = &payload.description {
        validation::description("description", description)?;
    }
    validate_bubble_mode(&payload.mode)?;
    validate_visibility(&payload.visibility)?;
    validate_join_policy(&payload.join_policy)?;
    validate_index_policy(&payload.index_policy)?;
    let slug = payload
        .slug
        .unwrap_or_else(|| slug_from_name(&payload.name));
    validation::public_id(&slug)?;

    let bubble_id = Uuid::new_v4();
    let mut tx = state.pg.begin().await?;
    let row = sqlx::query_as::<_, BubbleRow>(
        "INSERT INTO bubbles
            (id, slug, name, description, mode, visibility, join_policy, index_policy, owner_identity_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, slug, name, description, mode, visibility, join_policy, index_policy,
                   owner_identity_id, public_key, created_at, updated_at",
    )
    .bind(bubble_id)
    .bind(slug)
    .bind(payload.name.trim())
    .bind(payload.description)
    .bind(payload.mode)
    .bind(payload.visibility)
    .bind(payload.join_policy)
    .bind(payload.index_policy)
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bubble_members (bubble_id, identity_id, role, status)
         VALUES ($1, $2, 'owner', 'active')",
    )
    .bind(bubble_id)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
         VALUES ($1, $2, 'fallback', 100, false, true)",
    )
    .bind(bubble_id)
    .bind(OFFICIAL_RELAY_ID)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(to_bubble_response(row)))
}

async fn get_bubble(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(bubble_id): Path<Uuid>,
) -> Result<Json<BubbleResponse>, AppError> {
    ensure_member(&state, bubble_id, auth.user_id).await?;
    let row = bubble(&state, bubble_id).await?;
    Ok(Json(to_bubble_response(row)))
}

async fn list_members(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(bubble_id): Path<Uuid>,
) -> Result<Json<BubbleMembersResponse>, AppError> {
    ensure_member(&state, bubble_id, auth.user_id).await?;
    let rows = sqlx::query_as::<_, BubbleMemberRow>(
        "SELECT identity_id, role, status, joined_at
         FROM bubble_members
         WHERE bubble_id = $1
         ORDER BY joined_at ASC",
    )
    .bind(bubble_id)
    .fetch_all(&state.pg)
    .await?;
    Ok(Json(BubbleMembersResponse {
        members: rows.into_iter().map(to_member_response).collect(),
    }))
}

async fn list_relays(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(bubble_id): Path<Uuid>,
) -> Result<Json<BubbleRelaysResponse>, AppError> {
    ensure_member(&state, bubble_id, auth.user_id).await?;
    Ok(Json(BubbleRelaysResponse {
        relays: bubble_relays(&state, bubble_id)
            .await?
            .into_iter()
            .map(to_relay_response)
            .collect(),
    }))
}

async fn add_relay(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(bubble_id): Path<Uuid>,
    Json(payload): Json<AddBubbleRelayRequest>,
) -> Result<Json<BubbleRelayResponse>, AppError> {
    ensure_owner_or_admin(&state, bubble_id, auth.user_id).await?;
    validate_relay_role(&payload.role)?;
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM relays WHERE id = $1")
        .bind(payload.relay_id)
        .fetch_optional(&state.pg)
        .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }
    let row = sqlx::query_as::<_, BubbleRelayRow>(
        "INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (bubble_id, relay_id)
         DO UPDATE SET role = EXCLUDED.role,
                       priority = EXCLUDED.priority,
                       required = EXCLUDED.required,
                       fallback_allowed = EXCLUDED.fallback_allowed
         RETURNING bubble_id, relay_id, role, priority, required, fallback_allowed",
    )
    .bind(bubble_id)
    .bind(payload.relay_id)
    .bind(payload.role)
    .bind(payload.priority)
    .bind(payload.required)
    .bind(payload.fallback_allowed)
    .fetch_one(&state.pg)
    .await?;
    Ok(Json(to_relay_response(row)))
}

async fn ensure_main_bubble(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    let slug = format!("main-{}", user_id.simple());
    let bubble_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM bubbles WHERE slug = $1")
        .bind(&slug)
        .fetch_optional(&state.pg)
        .await?
        .unwrap_or_else(Uuid::new_v4);
    let mut tx = state.pg.begin().await?;
    sqlx::query(
        "INSERT INTO bubbles
            (id, slug, name, description, mode, visibility, join_policy, index_policy, owner_identity_id)
         VALUES ($1, $2, 'Main Bubble', 'Conversations Enigma globales', 'MAIN_GLOBAL',
                 'PRIVATE', 'CLOSED', 'INDEX_FORBIDDEN', $3)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(bubble_id)
    .bind(slug)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bubble_members (bubble_id, identity_id, role, status)
         VALUES ($1, $2, 'owner', 'active')
         ON CONFLICT (bubble_id, identity_id)
         DO UPDATE SET status = 'active'",
    )
    .bind(bubble_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
         VALUES ($1, $2, 'primary', 0, true, false)
         ON CONFLICT (bubble_id, relay_id) DO NOTHING",
    )
    .bind(bubble_id)
    .bind(OFFICIAL_RELAY_ID)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn bubble(state: &AppState, bubble_id: Uuid) -> Result<BubbleRow, AppError> {
    sqlx::query_as::<_, BubbleRow>(
        "SELECT id, slug, name, description, mode, visibility, join_policy, index_policy,
                owner_identity_id, public_key, created_at, updated_at
         FROM bubbles
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(bubble_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)
}

async fn ensure_member(state: &AppState, bubble_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
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

async fn ensure_owner_or_admin(
    state: &AppState,
    bubble_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM bubble_members
         WHERE bubble_id = $1 AND identity_id = $2 AND status = 'active'",
    )
    .bind(bubble_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?;
    match role.as_deref() {
        Some("owner" | "admin") => Ok(()),
        Some(_) => Err(AppError::Forbidden),
        None => Err(AppError::NotFound),
    }
}

async fn bubble_relays(state: &AppState, bubble_id: Uuid) -> Result<Vec<BubbleRelayRow>, AppError> {
    sqlx::query_as::<_, BubbleRelayRow>(
        "SELECT bubble_id, relay_id, role, priority, required, fallback_allowed
         FROM bubble_relays
         WHERE bubble_id = $1
         ORDER BY priority ASC",
    )
    .bind(bubble_id)
    .fetch_all(&state.pg)
    .await
    .map_err(AppError::from)
}

fn to_bubble_response(row: BubbleRow) -> BubbleResponse {
    BubbleResponse {
        id: row.id,
        slug: row.slug,
        name: row.name,
        description: row.description,
        mode: row.mode,
        visibility: row.visibility,
        join_policy: row.join_policy,
        index_policy: row.index_policy,
        owner_identity_id: row.owner_identity_id,
        public_key: row.public_key,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn to_member_response(row: BubbleMemberRow) -> BubbleMemberResponse {
    BubbleMemberResponse {
        identity_id: row.identity_id,
        role: row.role,
        status: row.status,
        joined_at: row.joined_at,
    }
}

fn to_relay_response(row: BubbleRelayRow) -> BubbleRelayResponse {
    BubbleRelayResponse {
        bubble_id: row.bubble_id,
        relay_id: row.relay_id,
        role: row.role,
        priority: row.priority,
        required: row.required,
        fallback_allowed: row.fallback_allowed,
    }
}

fn slug_from_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

fn validate_bubble_mode(value: &str) -> Result<(), AppError> {
    match value {
        "MAIN_GLOBAL" | "PRIVATE_CONNECTED" | "PRIVATE_ISOLATED" | "COMMUNITY" | "ORGANIZATION" => {
            Ok(())
        }
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn validate_visibility(value: &str) -> Result<(), AppError> {
    match value {
        "PUBLIC" | "UNLISTED" | "PRIVATE" | "SECRET" => Ok(()),
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn validate_join_policy(value: &str) -> Result<(), AppError> {
    match value {
        "OPEN" | "REQUEST_APPROVAL" | "INVITE_ONLY" | "ADMIN_MANAGED" | "CLOSED" => Ok(()),
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn validate_index_policy(value: &str) -> Result<(), AppError> {
    match value {
        "INDEX_ALLOWED_BY_DEFAULT"
        | "INDEX_OPT_IN"
        | "INDEX_OPT_OUT"
        | "INDEX_FORBIDDEN"
        | "PRIVATE_ONLY" => Ok(()),
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn validate_relay_role(value: &str) -> Result<(), AppError> {
    match value {
        "primary" | "fallback" | "community" | "organization" => Ok(()),
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn default_primary_role() -> String {
    "primary".into()
}

fn default_true() -> bool {
    true
}
