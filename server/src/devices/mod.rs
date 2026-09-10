use axum::{
    extract::Path,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser, business, error::AppError, security::jwt, security::validation, AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_device))
        .route("/fcm-token", post(update_fcm_token))
        .route("/", get(list_devices))
        .route("/:device_id", delete(revoke_device))
}

#[derive(Debug, Deserialize)]
struct RegisterDeviceRequest {
    device_id: Option<Uuid>,
    display_name: String,
    platform: String,
}

#[derive(Debug, Deserialize)]
struct FcmTokenRequest {
    fcm_token: String,
    platform: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct DevicesResponse {
    devices: Vec<DeviceResponse>,
}

#[derive(Debug, Serialize)]
struct RegisterDeviceResponse {
    device: DeviceResponse,
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub display_name: String,
    pub platform: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct DeviceRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub display_name: String,
    pub platform: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ExistingDeviceRow {
    id: Uuid,
    user_id: Uuid,
    revoked_at: Option<DateTime<Utc>>,
}

async fn register_device(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>, AppError> {
    validation::device_name(&payload.display_name)?;
    validation::platform(&payload.platform)?;

    let id = payload.device_id.unwrap_or_else(Uuid::new_v4);
    let mut tx = state.pg.begin().await?;

    let existing = sqlx::query_as::<_, ExistingDeviceRow>(
        "SELECT id, user_id, revoked_at
         FROM devices
         WHERE id = $1
         FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;

    let device = if let Some(existing) = existing {
        if existing.revoked_at.is_some() || existing.user_id != auth.user_id {
            return Err(AppError::Conflict(
                "DEVICE_ID_ALREADY_REGISTERED".to_string(),
            ));
        }
        sqlx::query_as::<_, DeviceRow>(
            "UPDATE devices
             SET display_name = $1, platform = $2
             WHERE id = $3 AND user_id = $4
             RETURNING id, user_id, display_name, platform, created_at",
        )
        .bind(&payload.display_name)
        .bind(&payload.platform)
        .bind(existing.id)
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await?
    } else {
        if state.config.business.official_relay_mode {
            sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
                .bind(auth.user_id)
                .execute(&mut *tx)
                .await?;
            let plan = business::active_plan_tx(&mut tx, auth.user_id).await?;
            let active_devices: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM devices WHERE user_id=$1 AND revoked_at IS NULL",
            )
            .bind(auth.user_id)
            .fetch_one(&mut *tx)
            .await?;
            if active_devices >= i64::from(plan.max_devices.max(0)) {
                return Err(AppError::BadRequest("DEVICE_PLAN_LIMIT_REACHED".into()));
            }
        }

        sqlx::query_as::<_, DeviceRow>(
            "INSERT INTO devices (id, user_id, display_name, platform)
             VALUES ($1, $2, $3, $4)
             RETURNING id, user_id, display_name, platform, created_at",
        )
        .bind(id)
        .bind(auth.user_id)
        .bind(&payload.display_name)
        .bind(&payload.platform)
        .fetch_one(&mut *tx)
        .await?
    };

    sqlx::query("UPDATE sessions SET device_id = $1 WHERE id = $2 AND user_id = $3")
        .bind(device.id)
        .bind(auth.session_id)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let access_token = jwt::issue_token(
        &state.config.jwt,
        auth.user_id,
        auth.session_id,
        Some(device.id),
        jwt::TokenType::Device,
    )?;

    Ok(Json(RegisterDeviceResponse {
        device: DeviceResponse {
            id: device.id,
            display_name: device.display_name,
            platform: device.platform,
            created_at: device.created_at,
        },
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_ttl.as_secs(),
    }))
}

async fn update_fcm_token(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<FcmTokenRequest>,
) -> Result<Json<StatusResponse>, AppError> {
    validation::platform(&payload.platform)?;
    validation::bounded("fcm_token", &payload.fcm_token, 16, 4096)?;
    let device_id = auth.require_device_id()?;

    let updated = sqlx::query(
        "UPDATE devices
         SET fcm_token = $1, fcm_token_updated_at = now(), push_enabled = TRUE
         WHERE id = $2 AND user_id = $3 AND platform = $4 AND revoked_at IS NULL",
    )
    .bind(&payload.fcm_token)
    .bind(device_id)
    .bind(auth.user_id)
    .bind(&payload.platform)
    .execute(&state.pg)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(Json(StatusResponse { status: "ok" }))
}

async fn list_devices(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
) -> Result<Json<DevicesResponse>, AppError> {
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, user_id, display_name, platform, created_at
         FROM devices
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY created_at ASC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;

    let devices = rows
        .into_iter()
        .map(|device| DeviceResponse {
            id: device.id,
            display_name: device.display_name,
            platform: device.platform,
            created_at: device.created_at,
        })
        .collect();

    Ok(Json(DevicesResponse { devices }))
}

async fn revoke_device(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    devices_bound_or_owner(&auth, device_id)?;

    let mut tx = state.pg.begin().await?;
    let updated = sqlx::query(
        "UPDATE devices
         SET revoked_at = now(), fcm_token = NULL, fcm_token_updated_at = NULL, push_enabled = FALSE
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // A device revocation must invalidate every bearer token bound to that device.
    // Otherwise a previously issued JWT can remain usable until its natural expiry.
    sqlx::query(
        "UPDATE sessions
         SET revoked_at = now()
         WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    )
    .bind(auth.user_id)
    .bind(device_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(StatusResponse { status: "ok" }))
}

fn devices_bound_or_owner(auth: &AuthUser, device_id: Uuid) -> Result<(), AppError> {
    if auth.device_id.is_some() {
        auth.ensure_device_id(device_id)
    } else {
        Ok(())
    }
}

pub async fn ensure_device_owner(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<(), AppError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM devices
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(&state.pg)
    .await?;

    found.map(|_| ()).ok_or(AppError::Forbidden)
}

pub async fn ensure_device_exists(state: &AppState, device_id: Uuid) -> Result<(), AppError> {
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE id = $1 AND revoked_at IS NULL")
            .bind(device_id)
            .fetch_optional(&state.pg)
            .await?;

    found.map(|_| ()).ok_or(AppError::NotFound)
}
