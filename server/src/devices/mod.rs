use axum::{
    extract::Path,
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser, business, error::AppError, security::jwt, security::validation, AppState,
};

const MULTIDEVICE_PROTOCOL_VERSION: i32 = 1;
const LINK_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
const MAX_PAIRING_TTL_MS: i64 = 5 * 60 * 1_000;
const PAIRING_CANDIDATE_DOMAIN: &str = "ENIGMA_PAIRING_CANDIDATE_V1";
const PAIRING_CLAIM_SECRET_BYTES: usize = 32;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register_device))
        .route("/link/candidate", post(create_pairing_candidate))
        .route("/link/candidate/:pairing_session_id", get(get_pairing_candidate))
        .route("/link/authorize", post(authorize_linked_desktop))
        .route("/link/claim", post(claim_linked_desktop))
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
struct CreatePairingCandidateRequest {
    pairing_session_id: Uuid,
    device_id: Uuid,
    display_name: String,
    platform: String,
    protocol_version: i32,
    min_supported_version: i32,
    capabilities: i64,
    expires_at_unix_ms: i64,
    pairing_public_key: String,
    target_identity_key: String,
    claim_secret_hash: String,
    candidate_commitment: String,
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
    candidate_commitment: String,
    authorizer_signature: String,
}

#[derive(Debug, Deserialize)]
struct ClaimLinkedDesktopRequest {
    pairing_session_id: Uuid,
    claim_secret: String,
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
struct PairingCandidateResponse {
    pairing_session_id: Uuid,
    device_id: Uuid,
    display_name: String,
    platform: String,
    protocol_version: i32,
    min_supported_version: i32,
    capabilities: i64,
    expires_at_unix_ms: i64,
    pairing_public_key: String,
    target_identity_key: String,
    claim_secret_hash: String,
    candidate_commitment: String,
}

#[derive(Debug, Serialize)]
struct AuthorizedLinkedDesktopResponse {
    device: DeviceResponse,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ClaimedLinkedDesktopResponse {
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

#[derive(Debug, FromRow)]
struct PairingRendezvousRow {
    pairing_session_id: Uuid,
    device_id: Uuid,
    display_name: String,
    platform: String,
    protocol_version: i32,
    min_supported_version: i32,
    capabilities: i64,
    expires_at_unix_ms: i64,
    pairing_public_key: String,
    target_identity_key: String,
    claim_secret_hash: String,
    candidate_commitment: String,
    authorized_user_id: Option<Uuid>,
    authorizing_device_id: Option<Uuid>,
    authorized_at: Option<DateTime<Utc>>,
    claimed_at: Option<DateTime<Utc>>,
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

async fn create_pairing_candidate(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<CreatePairingCandidateRequest>,
) -> Result<Json<PairingCandidateResponse>, AppError> {
    validate_pairing_candidate(&payload)?;
    let expected_commitment = pairing_candidate_commitment(&payload);
    if !constant_time_eq(
        expected_commitment.as_bytes(),
        payload.candidate_commitment.as_bytes(),
    ) {
        return Err(AppError::BadRequest("PAIRING_CANDIDATE_COMMITMENT_MISMATCH".into()));
    }

    let inserted = sqlx::query(
        "INSERT INTO pairing_rendezvous (
            pairing_session_id, device_id, display_name, platform,
            protocol_version, min_supported_version, capabilities,
            expires_at_unix_ms, pairing_public_key, target_identity_key,
            claim_secret_hash, candidate_commitment
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT DO NOTHING",
    )
    .bind(payload.pairing_session_id)
    .bind(payload.device_id)
    .bind(&payload.display_name)
    .bind(&payload.platform)
    .bind(payload.protocol_version)
    .bind(payload.min_supported_version)
    .bind(payload.capabilities)
    .bind(payload.expires_at_unix_ms)
    .bind(&payload.pairing_public_key)
    .bind(&payload.target_identity_key)
    .bind(&payload.claim_secret_hash)
    .bind(&payload.candidate_commitment)
    .execute(&state.pg)
    .await?;

    if inserted.rows_affected() != 1 {
        return Err(AppError::Conflict("PAIRING_RENDEZVOUS_ALREADY_EXISTS".into()));
    }

    Ok(Json(pairing_candidate_response_from_request(payload)))
}

async fn get_pairing_candidate(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(pairing_session_id): Path<Uuid>,
) -> Result<Json<PairingCandidateResponse>, AppError> {
    let row = sqlx::query_as::<_, PairingRendezvousRow>(
        "SELECT pairing_session_id, device_id, display_name, platform,
                protocol_version, min_supported_version, capabilities,
                expires_at_unix_ms, pairing_public_key, target_identity_key,
                claim_secret_hash, candidate_commitment, authorized_user_id,
                authorizing_device_id, authorized_at, claimed_at
         FROM pairing_rendezvous
         WHERE pairing_session_id = $1",
    )
    .bind(pairing_session_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;

    if row.expires_at_unix_ms <= Utc::now().timestamp_millis() || row.claimed_at.is_some() {
        return Err(AppError::NotFound);
    }

    Ok(Json(pairing_candidate_response(&row)))
}

async fn authorize_linked_desktop(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<AuthorizeLinkedDesktopRequest>,
) -> Result<Json<AuthorizedLinkedDesktopResponse>, AppError> {
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

    let rendezvous = sqlx::query_as::<_, PairingRendezvousRow>(
        "SELECT pairing_session_id, device_id, display_name, platform,
                protocol_version, min_supported_version, capabilities,
                expires_at_unix_ms, pairing_public_key, target_identity_key,
                claim_secret_hash, candidate_commitment, authorized_user_id,
                authorizing_device_id, authorized_at, claimed_at
         FROM pairing_rendezvous
         WHERE pairing_session_id = $1
         FOR UPDATE",
    )
    .bind(payload.pairing_session_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    validate_authorization_against_rendezvous(&payload, &rendezvous)?;
    if rendezvous.authorized_at.is_some() || rendezvous.claimed_at.is_some() {
        return Err(AppError::Conflict("PAIRING_SESSION_ALREADY_USED".into()));
    }
    if rendezvous.expires_at_unix_ms <= Utc::now().timestamp_millis() {
        return Err(AppError::BadRequest("PAIRING_RENDEZVOUS_EXPIRED".into()));
    }

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

    sqlx::query(
        "UPDATE pairing_rendezvous
         SET authorized_user_id = $1,
             authorizing_device_id = $2,
             authorized_at = now()
         WHERE pairing_session_id = $3",
    )
    .bind(auth.user_id)
    .bind(authorizing_device_id)
    .bind(payload.pairing_session_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let authorization = DeviceAuthorizationResponse {
        authorizing_device_id,
        canonical_payload,
        authorizer_signature: payload.authorizer_signature,
    };

    Ok(Json(AuthorizedLinkedDesktopResponse {
        device: DeviceResponse {
            id: device.id,
            display_name: device.display_name,
            platform: device.platform,
            created_at: device.created_at,
            authorization: Some(authorization),
        },
        status: "authorized",
    }))
}

async fn claim_linked_desktop(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<ClaimLinkedDesktopRequest>,
) -> Result<Json<ClaimedLinkedDesktopResponse>, AppError> {
    validation::base64_field(
        "claim_secret",
        &payload.claim_secret,
        PAIRING_CLAIM_SECRET_BYTES,
        PAIRING_CLAIM_SECRET_BYTES,
    )?;
    let secret = STANDARD_NO_PAD
        .decode(&payload.claim_secret)
        .map_err(|_| AppError::BadRequest("INVALID_PAIRING_CLAIM_SECRET".into()))?;
    let presented_hash = hex_lower(&Sha256::digest(&secret));

    let mut tx = state.pg.begin().await?;
    let rendezvous = sqlx::query_as::<_, PairingRendezvousRow>(
        "SELECT pairing_session_id, device_id, display_name, platform,
                protocol_version, min_supported_version, capabilities,
                expires_at_unix_ms, pairing_public_key, target_identity_key,
                claim_secret_hash, candidate_commitment, authorized_user_id,
                authorizing_device_id, authorized_at, claimed_at
         FROM pairing_rendezvous
         WHERE pairing_session_id = $1
         FOR UPDATE",
    )
    .bind(payload.pairing_session_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    if rendezvous.expires_at_unix_ms <= Utc::now().timestamp_millis() {
        return Err(AppError::BadRequest("PAIRING_RENDEZVOUS_EXPIRED".into()));
    }
    if rendezvous.claimed_at.is_some() {
        return Err(AppError::Conflict("PAIRING_CLAIM_ALREADY_USED".into()));
    }
    if !constant_time_eq(
        rendezvous.claim_secret_hash.as_bytes(),
        presented_hash.as_bytes(),
    ) {
        return Err(AppError::Unauthorized);
    }

    let user_id = rendezvous
        .authorized_user_id
        .ok_or_else(|| AppError::BadRequest("PAIRING_NOT_AUTHORIZED".into()))?;
    if rendezvous.authorized_at.is_none() || rendezvous.authorizing_device_id.is_none() {
        return Err(AppError::BadRequest("PAIRING_NOT_AUTHORIZED".into()));
    }

    let device = sqlx::query_as::<_, DeviceRow>(
        "SELECT id, user_id, display_name, platform, created_at
         FROM devices
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(rendezvous.device_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Forbidden)?;

    let linked_session_id = Uuid::new_v4();
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.jwt.access_ttl).map_err(|_| AppError::Internal)?;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(linked_session_id)
    .bind(user_id)
    .bind(device.id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    let consumed = sqlx::query(
        "UPDATE pairing_rendezvous
         SET claimed_at = now()
         WHERE pairing_session_id = $1 AND claimed_at IS NULL",
    )
    .bind(payload.pairing_session_id)
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() != 1 {
        return Err(AppError::Conflict("PAIRING_CLAIM_ALREADY_USED".into()));
    }

    tx.commit().await?;

    let access_token = jwt::issue_token(
        &state.config.jwt,
        user_id,
        linked_session_id,
        Some(device.id),
        jwt::TokenType::Device,
    )?;

    let authorization = sqlx::query_as::<_, DeviceListRow>(
        "SELECT d.id, d.display_name, d.platform, d.created_at,
                da.authorizing_device_id, da.canonical_payload, da.authorizer_signature
         FROM devices d
         LEFT JOIN device_authorizations da ON da.device_id = d.id
         WHERE d.id = $1 AND d.user_id = $2",
    )
    .bind(device.id)
    .bind(user_id)
    .fetch_one(&state.pg)
    .await?;

    Ok(Json(ClaimedLinkedDesktopResponse {
        device: DeviceResponse {
            id: authorization.id,
            display_name: authorization.display_name,
            platform: authorization.platform,
            created_at: authorization.created_at,
            authorization: authorization_from_parts(
                authorization.authorizing_device_id,
                authorization.canonical_payload,
                authorization.authorizer_signature,
            )?,
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
        "ENIGMA_DEVICE_LINK_V1\naccount_id={account_id}\nnew_device_id={}\nauthorizing_device_id={authorizing_device_id}\npairing_session_id={}\nplatform={}\nprotocol_version={}\nmin_supported_version={}\ncapabilities={}\nissued_at_unix_ms={}\ntarget_identity_key={}\ncandidate_commitment={}\nauthorizer_identity_key={}\n",
        payload.device_id,
        payload.pairing_session_id,
        payload.platform,
        payload.protocol_version,
        payload.min_supported_version,
        payload.capabilities,
        payload.issued_at_unix_ms,
        payload.target_identity_key,
        payload.candidate_commitment,
        authorizer_identity_key,
    )
}

fn validate_pairing_candidate(payload: &CreatePairingCandidateRequest) -> Result<(), AppError> {
    validation::device_name(&payload.display_name)?;
    validation::platform(&payload.platform)?;
    if !matches!(payload.platform.as_str(), "windows" | "linux") {
        return Err(AppError::BadRequest("DESKTOP_PLATFORM_REQUIRED".into()));
    }
    if payload.protocol_version != MULTIDEVICE_PROTOCOL_VERSION
        || payload.min_supported_version < 1
        || payload.min_supported_version > MULTIDEVICE_PROTOCOL_VERSION
    {
        return Err(AppError::BadRequest(
            "UNSUPPORTED_MULTIDEVICE_PROTOCOL_VERSION".into(),
        ));
    }
    if payload.capabilities < 0 || payload.capabilities & (1_i64 << 2) == 0 {
        return Err(AppError::BadRequest("INVALID_DEVICE_CAPABILITIES".into()));
    }
    let now_ms = Utc::now().timestamp_millis();
    if payload.expires_at_unix_ms <= now_ms
        || payload.expires_at_unix_ms > now_ms + MAX_PAIRING_TTL_MS
    {
        return Err(AppError::BadRequest("PAIRING_RENDEZVOUS_EXPIRY_INVALID".into()));
    }
    validation::base64_field("pairing_public_key", &payload.pairing_public_key, 32, 32)?;
    validation::base64_field("target_identity_key", &payload.target_identity_key, 1, 4096)?;
    validation::base64_field("candidate_commitment", &payload.candidate_commitment, 32, 32)?;
    if payload.claim_secret_hash.len() != 64
        || !payload
            .claim_secret_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::BadRequest("INVALID_PAIRING_CLAIM_SECRET_HASH".into()));
    }
    Ok(())
}

fn pairing_candidate_commitment(payload: &CreatePairingCandidateRequest) -> String {
    let canonical = format!(
        concat!(
            "{}\n",
            "pairing_session_id={}\n",
            "device_id={}\n",
            "display_name={}\n",
            "platform={}\n",
            "protocol_version={}\n",
            "min_supported_version={}\n",
            "capabilities={}\n",
            "expires_at_unix_ms={}\n",
            "pairing_public_key={}\n",
            "target_identity_key={}\n",
            "claim_secret_hash={}\n"
        ),
        PAIRING_CANDIDATE_DOMAIN,
        payload.pairing_session_id,
        payload.device_id,
        payload.display_name,
        payload.platform,
        payload.protocol_version,
        payload.min_supported_version,
        payload.capabilities,
        payload.expires_at_unix_ms,
        payload.pairing_public_key,
        payload.target_identity_key,
        payload.claim_secret_hash,
    );
    STANDARD_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn validate_authorization_against_rendezvous(
    payload: &AuthorizeLinkedDesktopRequest,
    rendezvous: &PairingRendezvousRow,
) -> Result<(), AppError> {
    let matches = payload.pairing_session_id == rendezvous.pairing_session_id
        && payload.device_id == rendezvous.device_id
        && payload.display_name == rendezvous.display_name
        && payload.platform == rendezvous.platform
        && payload.protocol_version == rendezvous.protocol_version
        && payload.min_supported_version == rendezvous.min_supported_version
        && payload.capabilities == rendezvous.capabilities
        && payload.target_identity_key == rendezvous.target_identity_key
        && constant_time_eq(
            payload.candidate_commitment.as_bytes(),
            rendezvous.candidate_commitment.as_bytes(),
        );
    if !matches {
        return Err(AppError::BadRequest("PAIRING_CANDIDATE_SUBSTITUTION".into()));
    }
    Ok(())
}

fn pairing_candidate_response_from_request(
    payload: CreatePairingCandidateRequest,
) -> PairingCandidateResponse {
    PairingCandidateResponse {
        pairing_session_id: payload.pairing_session_id,
        device_id: payload.device_id,
        display_name: payload.display_name,
        platform: payload.platform,
        protocol_version: payload.protocol_version,
        min_supported_version: payload.min_supported_version,
        capabilities: payload.capabilities,
        expires_at_unix_ms: payload.expires_at_unix_ms,
        pairing_public_key: payload.pairing_public_key,
        target_identity_key: payload.target_identity_key,
        claim_secret_hash: payload.claim_secret_hash,
        candidate_commitment: payload.candidate_commitment,
    }
}

fn pairing_candidate_response(row: &PairingRendezvousRow) -> PairingCandidateResponse {
    PairingCandidateResponse {
        pairing_session_id: row.pairing_session_id,
        device_id: row.device_id,
        display_name: row.display_name.clone(),
        platform: row.platform.clone(),
        protocol_version: row.protocol_version,
        min_supported_version: row.min_supported_version,
        capabilities: row.capabilities,
        expires_at_unix_ms: row.expires_at_unix_ms,
        pairing_public_key: row.pairing_public_key.clone(),
        target_identity_key: row.target_identity_key.clone(),
        claim_secret_hash: row.claim_secret_hash.clone(),
        candidate_commitment: row.candidate_commitment.clone(),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
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
    let active_devices: i64 =
        sqlx::query_scalar("SELECT count(*) FROM devices WHERE user_id=$1 AND revoked_at IS NULL")
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
            device_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("device id"),
            display_name: "Desktop".into(),
            platform: "windows".into(),
            pairing_session_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .expect("pairing id"),
            protocol_version: 1,
            min_supported_version: 1,
            capabilities: 127,
            issued_at_unix_ms: 1_700_000_000_000,
            target_identity_key: "dGFyZ2V0LWlkZW50aXR5LWtleS0wMDAx".into(),
            candidate_commitment: "Y2FuZGlkYXRlLWNvbW1pdG1lbnQtMDAwMDAwMDAwMDA=".into(),
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
        assert!(first.contains("candidate_commitment="));
    }

    #[test]
    fn partial_authorization_record_fails_closed() {
        let result = authorization_from_parts(Some(Uuid::new_v4()), Some("payload".into()), None);
        assert!(matches!(result, Err(AppError::Internal)));
    }
}
