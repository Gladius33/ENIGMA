use axum::{
    extract::Path,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser, business, error::AppError, security::jwt, security::validation, AppState,
};

const MULTIDEVICE_PROTOCOL_VERSION: i32 = 1;
const LINK_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_device))
        .route("/link/authorize", post(authorize_linked_desktop))
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
struct AuthorizeLinkedDesktopRequest {
    device_id: Uuid,
    display_name: String,
    platform: String,
    pairing_session_id: Uuid,
    protocol_version: i32,
    min_supported_version: i32,
    capabilities: i64,
    issued_at_unix_ms: i64,
    target_identity_key: String,
    authorizer_signature: String,
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
struct LinkedDesktopResponse {
    device: DeviceResponse,
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    pub authorizing_device_id: Uuid,
    pub canonical_payload: String,
    pub authorizer_signature: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub display_name: String,
    pub platform: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<DeviceAuthorizationResponse>,
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
struct DeviceListRow {
    id: Uuid,
    display_name: String,
    platform: String,
    created_at: DateTime<Utc>,
    authorizing_device_id: Option<Uuid>,
    canonical_payload: Option<String>,
    authorizer_signature: Option<String>,
}

#[derive(Debug, FromRow)]
struct ExistingDeviceRow {
    id: Uuid,
    user_id: Uuid,
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct AuthorizerRow {
    platform: String,
    identity_key: String,
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
        enforce_device_plan_limit(&state, &mut tx, auth.user_id).await?;

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
            authorization: None,
        },
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_ttl.as_secs(),
    }))
}

async fn authorize_linked_desktop(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<AuthorizeLinkedDesktopRequest>,
) -> Result<Json<LinkedDesktopResponse>, AppError> {
    auth.require_device_token()?;
    let authorizing_device_id = auth.require_device_id()?;
    validate_link_request(&payload, authorizing_device_id)?;

    let authorizer = sqlx::query_as::<_, AuthorizerRow>(
        "SELECT d.platform, ik.public_key AS identity_key
         FROM devices d
         JOIN identity_keys ik ON ik.device_id = d.id
         WHERE d.id = $1 AND d.user_id = $2 AND d.revoked_at IS NULL",
    )
    .bind(authorizing_device_id)
    .bind(auth.user_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or_else(|| AppError::BadRequest("AUTHORIZER_SIGNAL_IDENTITY_REQUIRED".into()))?;

    if authorizer.platform != "android" {
        return Err(AppError::Forbidden);
    }

    let canonical_payload = canonical_device_authorization_payload(
        auth.user_id,
        authorizing_device_id,
        &payload,
        &authorizer.identity_key,
    );

    let mut tx = state.pg.begin().await?;

    let existing_device: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE id = $1 FOR UPDATE")
            .bind(payload.device_id)
            .fetch_optional(&mut *tx)
            .await?;
    if existing_device.is_some() {
        return Err(AppError::Conflict(
            "DEVICE_ID_ALREADY_REGISTERED".to_string(),
        ));
    }

    let used_pairing_session: Option<Uuid> = sqlx::query_scalar(
        "SELECT device_id
         FROM device_authorizations
         WHERE pairing_session_id = $1
         FOR UPDATE",
    )
    .bind(payload.pairing_session_id)
    .fetch_optional(&mut *tx)
    .await?;
    if used_pairing_session.is_some() {
        return Err(AppError::Conflict(
            "PAIRING_SESSION_ALREADY_USED".to_string(),
        ));
    }

    enforce_device_plan_limit(&state, &mut tx, auth.user_id).await?;

    let device = sqlx::query_as::<_, DeviceRow>(
        "INSERT INTO devices (id, user_id, display_name, platform)
         VALUES ($1, $2, $3, $4)
         RETURNING id, user_id, display_name, platform, created_at",
    )
    .bind(payload.device_id)
    .bind(auth.user_id)
    .bind(&payload.display_name)
    .bind(&payload.platform)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO device_authorizations (
            device_id,
            authorizing_device_id,
            pairing_session_id,
            protocol_version,
            min_supported_version,
            capabilities,
            target_identity_key,
            authorizer_identity_key,
            canonical_payload,
            authorizer_signature,
            issued_at_unix_ms
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(device.id)
    .bind(authorizing_device_id)
    .bind(payload.pairing_session_id)
    .bind(payload.protocol_version)
    .bind(payload.min_supported_version)
    .bind(payload.capabilities)
    .bind(&payload.target_identity_key)
    .bind(&authorizer.identity_key)
    .bind(&canonical_payload)
    .bind(&payload.authorizer_signature)
    .bind(payload.issued_at_unix_ms)
    .execute(&mut *tx)
    .await?;

    let linked_session_id = Uuid::new_v4();
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.jwt.access_ttl).map_err(|_| AppError::Internal)?;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(linked_session_id)
    .bind(auth.user_id)
    .bind(device.id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let access_token = jwt::issue_token(
        &state.config.jwt,
        auth.user_id,
        linked_session_id,
        Some(device.id),
        jwt::TokenType::Device,
    )?;

    let authorization = DeviceAuthorizationResponse {
        authorizing_device_id,
        canonical_payload,
        authorizer_signature: payload.authorizer_signature,
    };

    Ok(Json(LinkedDesktopResponse {
        device: DeviceResponse {
            id: device.id,
            display_name: device.display_name,
            platform: device.platform,
            created_at: device.created_at,
            authorization: Some(authorization),
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
    let rows = sqlx::query_as::<_, DeviceListRow>(
        "SELECT
            d.id,
            d.display_name,
            d.platform,
            d.created_at,
            da.authorizing_device_id,
            da.canonical_payload,
            da.authorizer_signature
         FROM devices d
         LEFT JOIN device_authorizations da ON da.device_id = d.id
         WHERE d.user_id = $1 AND d.revoked_at IS NULL
         ORDER BY d.created_at ASC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;

    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        devices.push(DeviceResponse {
            id: row.id,
            display_name: row.display_name,
            platform: row.platform,
            created_at: row.created_at,
            authorization: authorization_from_parts(
                row.authorizing_device_id,
                row.canonical_payload,
                row.authorizer_signature,
            )?,
        });
    }

    Ok(Json(DevicesResponse { devices }))
}

async fn revoke_device(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    ensure_revoke_authorized(&state, &auth, device_id).await?;

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

fn validate_link_request(
    payload: &AuthorizeLinkedDesktopRequest,
    authorizing_device_id: Uuid,
) -> Result<(), AppError> {
    validation::device_name(&payload.display_name)?;
    validation::platform(&payload.platform)?;
    if !matches!(payload.platform.as_str(), "windows" | "linux") {
        return Err(AppError::BadRequest("DESKTOP_PLATFORM_REQUIRED".into()));
    }
    if payload.device_id == authorizing_device_id {
        return Err(AppError::BadRequest("DEVICE_SELF_AUTHORIZATION".into()));
    }
    if payload.protocol_version != MULTIDEVICE_PROTOCOL_VERSION
        || payload.min_supported_version < 1
        || payload.min_supported_version > MULTIDEVICE_PROTOCOL_VERSION
    {
        return Err(AppError::BadRequest(
            "UNSUPPORTED_MULTIDEVICE_PROTOCOL_VERSION".into(),
        ));
    }
    if payload.capabilities < 0 {
        return Err(AppError::BadRequest("INVALID_DEVICE_CAPABILITIES".into()));
    }
    validation::base64_field(
        "target_identity_key",
        &payload.target_identity_key,
        16,
        8192,
    )?;
    validation::base64_field(
        "authorizer_signature",
        &payload.authorizer_signature,
        16,
        8192,
    )?;

    let now_ms = Utc::now().timestamp_millis();
    if payload.issued_at_unix_ms < now_ms - LINK_CLOCK_SKEW_MS
        || payload.issued_at_unix_ms > now_ms + LINK_CLOCK_SKEW_MS
    {
        return Err(AppError::BadRequest(
            "DEVICE_AUTHORIZATION_TIMESTAMP_OUT_OF_RANGE".into(),
        ));
    }

    Ok(())
}

fn canonical_device_authorization_payload(
    account_id: Uuid,
    authorizing_device_id: Uuid,
    payload: &AuthorizeLinkedDesktopRequest,
    authorizer_identity_key: &str,
) -> String {
    format!(
        "ENIGMA_DEVICE_LINK_V1\naccount_id={account_id}\nnew_device_id={}\nauthorizing_device_id={authorizing_device_id}\npairing_session_id={}\nplatform={}\nprotocol_version={}\nmin_supported_version={}\ncapabilities={}\nissued_at_unix_ms={}\ntarget_identity_key={}\nauthorizer_identity_key={}\n",
        payload.device_id,
        payload.pairing_session_id,
        payload.platform,
        payload.protocol_version,
        payload.min_supported_version,
        payload.capabilities,
        payload.issued_at_unix_ms,
        payload.target_identity_key,
        authorizer_identity_key,
    )
}

fn authorization_from_parts(
    authorizing_device_id: Option<Uuid>,
    canonical_payload: Option<String>,
    authorizer_signature: Option<String>,
) -> Result<Option<DeviceAuthorizationResponse>, AppError> {
    match (
        authorizing_device_id,
        canonical_payload,
        authorizer_signature,
    ) {
        (None, None, None) => Ok(None),
        (Some(authorizing_device_id), Some(canonical_payload), Some(authorizer_signature)) => {
            Ok(Some(DeviceAuthorizationResponse {
                authorizing_device_id,
                canonical_payload,
                authorizer_signature,
            }))
        }
        _ => Err(AppError::Internal),
    }
}

async fn ensure_revoke_authorized(
    state: &AppState,
    auth: &AuthUser,
    target_device_id: Uuid,
) -> Result<(), AppError> {
    ensure_device_owner(state, auth.user_id, target_device_id).await?;

    let Some(authorizing_device_id) = auth.device_id else {
        return Ok(());
    };
    if authorizing_device_id == target_device_id {
        return Ok(());
    }

    let platform: Option<String> = sqlx::query_scalar(
        "SELECT platform
         FROM devices
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(authorizing_device_id)
    .bind(auth.user_id)
    .fetch_optional(&state.pg)
    .await?;

    match platform.as_deref() {
        Some("android") => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

async fn enforce_device_plan_limit(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), AppError> {
    if !state.config.business.official_relay_mode {
        return Ok(());
    }

    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    let plan = business::active_plan_tx(tx, user_id).await?;
    let active_devices: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE user_id=$1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    if active_devices >= i64::from(plan.max_devices.max(0)) {
        return Err(AppError::BadRequest("DEVICE_PLAN_LIMIT_REACHED".into()));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AuthorizeLinkedDesktopRequest {
        AuthorizeLinkedDesktopRequest {
            device_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                .expect("device id"),
            display_name: "Desktop".into(),
            platform: "windows".into(),
            pairing_session_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .expect("pairing id"),
            protocol_version: 1,
            min_supported_version: 1,
            capabilities: 127,
            issued_at_unix_ms: 1_700_000_000_000,
            target_identity_key: "dGFyZ2V0LWlkZW50aXR5LWtleS0wMDAx".into(),
            authorizer_signature: "YXV0aG9yaXplci1zaWduYXR1cmUtMDAwMQ==".into(),
        }
    }

    #[test]
    fn canonical_device_authorization_is_deterministic() {
        let payload = request();
        let account_id =
            Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("account id");
        let authorizer =
            Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("authorizer id");

        let first = canonical_device_authorization_payload(
            account_id,
            authorizer,
            &payload,
            "YXV0aG9yaXplci1pZGVudGl0eS1rZXktMDAwMQ==",
        );
        let second = canonical_device_authorization_payload(
            account_id,
            authorizer,
            &payload,
            "YXV0aG9yaXplci1pZGVudGl0eS1rZXktMDAwMQ==",
        );

        assert_eq!(first, second);
        assert!(first.starts_with("ENIGMA_DEVICE_LINK_V1\n"));
        assert!(first.contains("new_device_id=11111111-1111-4111-8111-111111111111\n"));
        assert!(first.contains("authorizing_device_id=44444444-4444-4444-8444-444444444444\n"));
        assert!(first.contains("target_identity_key=dGFyZ2V0LWlkZW50aXR5LWtleS0wMDAx\n"));
    }

    #[test]
    fn partial_authorization_record_fails_closed() {
        let result = authorization_from_parts(
            Some(Uuid::new_v4()),
            Some("payload".into()),
            None,
        );
        assert!(matches!(result, Err(AppError::Internal)));
    }
}
