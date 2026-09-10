use axum::{
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    error::AppError,
    relay_constants::{OFFICIAL_RELAY_ID, OFFICIAL_RELAY_NAME, OFFICIAL_RELAY_URL},
    security::validation,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_relays))
        .route("/custom", post(create_custom_relay))
        .route("/official-descriptor", get(official_descriptor))
}

#[derive(Debug, Deserialize)]
struct CreateCustomRelayRequest {
    name: String,
    url: String,
    #[serde(default = "default_private_type")]
    relay_type: String,
    public_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct RelaysResponse {
    relays: Vec<RelayResponse>,
}

#[derive(Debug, Serialize)]
struct RelayResponse {
    id: Uuid,
    name: String,
    url: String,
    public_key: Option<String>,
    #[serde(rename = "type")]
    relay_type: String,
    trust_level: String,
    is_official: bool,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
    region: Option<&'static str>,
}

#[derive(Debug, FromRow)]
struct RelayRow {
    id: Uuid,
    name: String,
    url: String,
    public_key: Option<String>,
    #[sqlx(rename = "type")]
    relay_type: String,
    trust_level: String,
    is_official: bool,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

async fn list_relays(
    axum::extract::State(state): axum::extract::State<AppState>,
    _auth: AuthUser,
) -> Result<Json<RelaysResponse>, AppError> {
    ensure_official_relay(&state).await?;
    let rows = sqlx::query_as::<_, RelayRow>(
        "SELECT id, name, url, public_key, type, trust_level, is_official, created_at, last_seen_at
         FROM relays
         ORDER BY is_official DESC, created_at DESC",
    )
    .fetch_all(&state.pg)
    .await?;
    Ok(Json(RelaysResponse {
        relays: rows.into_iter().map(to_response).collect(),
    }))
}

async fn official_descriptor(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<RelayResponse>, AppError> {
    ensure_official_relay(&state).await?;
    let row = sqlx::query_as::<_, RelayRow>(
        "SELECT id, name, url, public_key, type, trust_level, is_official, created_at, last_seen_at
         FROM relays
         WHERE id = $1",
    )
    .bind(OFFICIAL_RELAY_ID)
    .fetch_one(&state.pg)
    .await?;
    Ok(Json(to_response(row)))
}

async fn create_custom_relay(
    axum::extract::State(state): axum::extract::State<AppState>,
    _auth: AuthUser,
    Json(payload): Json<CreateCustomRelayRequest>,
) -> Result<Json<RelayResponse>, AppError> {
    validation::title("name", &payload.name)?;
    validate_relay_url(&payload.url)?;
    validate_relay_type(&payload.relay_type)?;

    let row = sqlx::query_as::<_, RelayRow>(
        "INSERT INTO relays (id, name, url, public_key, type, trust_level, is_official)
         VALUES ($1, $2, $3, $4, $5, 'UNVERIFIED', false)
         RETURNING id, name, url, public_key, type, trust_level, is_official, created_at, last_seen_at",
    )
    .bind(Uuid::new_v4())
    .bind(payload.name.trim())
    .bind(normalize_relay_url(&payload.url))
    .bind(payload.public_key)
    .bind(payload.relay_type)
    .fetch_one(&state.pg)
    .await?;

    Ok(Json(to_response(row)))
}

async fn ensure_official_relay(state: &AppState) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO relays (id, name, url, type, trust_level, is_official, last_seen_at)
         VALUES ($1, $2, $3, 'OFFICIAL', 'VERIFIED', true, now())
         ON CONFLICT (id) DO UPDATE
         SET name = EXCLUDED.name,
             url = EXCLUDED.url,
             trust_level = 'VERIFIED',
             is_official = true,
             last_seen_at = now()",
    )
    .bind(OFFICIAL_RELAY_ID)
    .bind(OFFICIAL_RELAY_NAME)
    .bind(OFFICIAL_RELAY_URL)
    .execute(&state.pg)
    .await?;
    Ok(())
}

fn to_response(row: RelayRow) -> RelayResponse {
    RelayResponse {
        id: row.id,
        name: row.name,
        url: row.url,
        public_key: row.public_key,
        relay_type: row.relay_type,
        trust_level: row.trust_level,
        is_official: row.is_official,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        region: row.is_official.then_some("automatic"),
    }
}

fn validate_relay_type(value: &str) -> Result<(), AppError> {
    match value {
        "CUSTOM" | "COMMUNITY" | "PRIVATE" | "ORGANIZATION" | "LOCAL" => Ok(()),
        _ => Err(AppError::BadRequest("VALIDATION_ERROR".into())),
    }
}

fn validate_relay_url(value: &str) -> Result<(), AppError> {
    let normalized = normalize_relay_url(value);
    if normalized.starts_with("https://") || normalized.starts_with("wss://") {
        Ok(())
    } else {
        Err(AppError::BadRequest("VALIDATION_ERROR".into()))
    }
}

fn normalize_relay_url(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.ends_with('/') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/")
    }
}

fn default_private_type() -> String {
    "PRIVATE".into()
}
