use axum::{
    extract::{Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    error::AppError,
    security::{jwt, password, validation},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/check", get(check_handle))
        .route("/", post(create_identity))
        .route("/me", delete(delete_me))
        .route("/recover/start", post(recover_start))
        .route("/recover/complete", post(recover_complete))
}

#[derive(Debug, Deserialize)]
struct CheckHandleQuery {
    handle: String,
}

#[derive(Debug, Serialize)]
struct CheckHandleResponse {
    handle: String,
    canonical_handle: Option<String>,
    available: bool,
    reason: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
struct CreateIdentityRequest {
    display_name: String,
    #[serde(default)]
    password: Option<String>,
    identity_public_key: String,
    #[serde(default)]
    registration_id: Option<i32>,
    #[serde(default)]
    protocol_device_id: Option<i32>,
    #[serde(default)]
    signed_prekey_id: Option<i64>,
    signed_prekey: String,
    signed_prekey_signature: String,
    #[serde(default)]
    kyber_prekey: Option<KyberPrekeyRequest>,
    #[serde(default)]
    one_time_prekeys: Vec<String>,
    device_name: String,
    #[serde(default = "default_platform")]
    platform: String,
    #[serde(default)]
    device_public_key: Option<String>,
    #[serde(default)]
    recovery_key_verifier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecoverStartRequest {
    handle: String,
}

#[derive(Debug, Serialize)]
struct RecoverStartResponse {
    canonical_handle: String,
    recovery_configured: bool,
}

#[derive(Debug, Deserialize)]
struct RecoverCompleteRequest {
    handle: String,
    recovery_secret: String,
    identity_public_key: String,
    #[serde(default)]
    registration_id: Option<i32>,
    #[serde(default)]
    protocol_device_id: Option<i32>,
    #[serde(default)]
    signed_prekey_id: Option<i64>,
    signed_prekey: String,
    signed_prekey_signature: String,
    #[serde(default)]
    kyber_prekey: Option<KyberPrekeyRequest>,
    #[serde(default)]
    one_time_prekeys: Vec<String>,
    device_name: String,
    #[serde(default = "default_platform")]
    platform: String,
    #[serde(default)]
    device_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdentityResponse {
    identity_id: Uuid,
    display_name: String,
    canonical_handle: String,
    public_handle: String,
    device_id: Uuid,
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct DeleteIdentityResponse {
    status: &'static str,
    canonical_handle: String,
    reserved_forever: bool,
}

#[derive(Debug, Deserialize)]
struct KyberPrekeyRequest {
    key_id: i64,
    public_key: String,
    signature: String,
}

#[derive(Debug, FromRow)]
struct IdentityRow {
    id: Uuid,
    display_name: String,
    canonical_handle: String,
    public_handle: String,
    created_at: DateTime<Utc>,
    recovery_key_verifier: Option<String>,
}

async fn check_handle(
    State(state): State<AppState>,
    Query(query): Query<CheckHandleQuery>,
) -> Result<Json<CheckHandleResponse>, AppError> {
    let Ok(handle) = validation::handle(&query.handle) else {
        return Ok(Json(CheckHandleResponse {
            handle: query.handle,
            canonical_handle: None,
            available: false,
            reason: Some("INVALID_HANDLE_FORMAT"),
        }));
    };

    let tombstone: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM identity_tombstones WHERE canonical_handle = $1")
            .bind(&handle.canonical_handle)
            .fetch_optional(&state.pg)
            .await?;
    if tombstone.is_some() {
        return Ok(Json(CheckHandleResponse {
            handle: handle.display_name,
            canonical_handle: Some(handle.canonical_handle),
            available: false,
            reason: Some("HANDLE_RESERVED"),
        }));
    }

    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE canonical_handle = $1")
            .bind(&handle.canonical_handle)
            .fetch_optional(&state.pg)
            .await?;
    Ok(Json(CheckHandleResponse {
        handle: handle.display_name,
        canonical_handle: Some(handle.canonical_handle),
        available: existing.is_none(),
        reason: existing.map(|_| "HANDLE_ALREADY_TAKEN"),
    }))
}

async fn create_identity(
    State(state): State<AppState>,
    Json(payload): Json<CreateIdentityRequest>,
) -> Result<Json<IdentityResponse>, AppError> {
    let handle = validation::handle(&payload.display_name)?;
    validate_key_material(KeyMaterialValidation {
        identity_public_key: &payload.identity_public_key,
        registration_id: payload.registration_id,
        protocol_device_id: payload.protocol_device_id,
        signed_prekey_id: payload.signed_prekey_id,
        signed_prekey: &payload.signed_prekey,
        signed_prekey_signature: &payload.signed_prekey_signature,
        kyber_prekey: payload.kyber_prekey.as_ref(),
        one_time_prekeys: &payload.one_time_prekeys,
    })?;
    validation::device_name(&payload.device_name)?;
    validation::platform(&payload.platform)?;
    if let Some(device_public_key) = &payload.device_public_key {
        validation::opaque_key("device_public_key", device_public_key)?;
    }
    if let Some(password) = &payload.password {
        validation::password(password)?;
    }
    if let Some(verifier) = &payload.recovery_key_verifier {
        validation::bounded("recovery_key_verifier", verifier, 16, 1024)?;
    }

    ensure_handle_not_reserved(&state, &handle.canonical_handle).await?;

    let password_material = payload
        .password
        .clone()
        .unwrap_or_else(|| format!("identity-only-{}", Uuid::new_v4()));
    let password_hash = hash_secret(password_material).await?;

    let identity_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let expires_at = session_expires_at(&state)?;

    let mut tx = state.pg.begin().await?;
    let identity = sqlx::query_as::<_, IdentityRow>(
        "INSERT INTO users
            (id, public_id, display_name, canonical_handle, public_handle, password_hash, recovery_key_verifier)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, display_name, canonical_handle, public_handle, created_at, recovery_key_verifier",
    )
    .bind(identity_id)
    .bind(&handle.canonical_handle)
    .bind(&handle.display_name)
    .bind(&handle.canonical_handle)
    .bind(&handle.public_handle)
    .bind(password_hash)
    .bind(&payload.recovery_key_verifier)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_identity_insert_error)?;

    create_device_session_and_keys(
        &mut tx,
        DeviceBootstrap {
            identity_id: identity.id,
            device_id,
            session_id,
            session_expires_at: expires_at,
            device_name: &payload.device_name,
            platform: &payload.platform,
            device_public_key: payload.device_public_key.as_deref(),
            identity_public_key: &payload.identity_public_key,
            registration_id: payload.registration_id,
            protocol_device_id: payload.protocol_device_id,
            signed_prekey_id: payload.signed_prekey_id.unwrap_or(1),
            signed_prekey: &payload.signed_prekey,
            signed_prekey_signature: &payload.signed_prekey_signature,
            kyber_prekey: payload.kyber_prekey.as_ref(),
            one_time_prekeys: &payload.one_time_prekeys,
        },
    )
    .await?;
    tx.commit().await?;

    Ok(Json(identity_response(
        &state, identity, device_id, session_id,
    )?))
}

async fn recover_start(
    State(state): State<AppState>,
    Json(payload): Json<RecoverStartRequest>,
) -> Result<Json<RecoverStartResponse>, AppError> {
    let handle = validation::handle(&payload.handle)?;
    let configured: Option<bool> = sqlx::query_scalar(
        "SELECT recovery_key_verifier IS NOT NULL
         FROM users
         WHERE canonical_handle = $1 AND disabled_at IS NULL AND deleted_at IS NULL",
    )
    .bind(&handle.canonical_handle)
    .fetch_optional(&state.pg)
    .await?;

    let Some(recovery_configured) = configured else {
        return Err(AppError::NotFound);
    };

    Ok(Json(RecoverStartResponse {
        canonical_handle: handle.canonical_handle,
        recovery_configured,
    }))
}

async fn recover_complete(
    State(state): State<AppState>,
    Json(payload): Json<RecoverCompleteRequest>,
) -> Result<Json<IdentityResponse>, AppError> {
    let handle = validation::handle(&payload.handle)?;
    validation::bounded("recovery_secret", &payload.recovery_secret, 16, 1024)?;
    validate_key_material(KeyMaterialValidation {
        identity_public_key: &payload.identity_public_key,
        registration_id: payload.registration_id,
        protocol_device_id: payload.protocol_device_id,
        signed_prekey_id: payload.signed_prekey_id,
        signed_prekey: &payload.signed_prekey,
        signed_prekey_signature: &payload.signed_prekey_signature,
        kyber_prekey: payload.kyber_prekey.as_ref(),
        one_time_prekeys: &payload.one_time_prekeys,
    })?;
    validation::device_name(&payload.device_name)?;
    validation::platform(&payload.platform)?;
    if let Some(device_public_key) = &payload.device_public_key {
        validation::opaque_key("device_public_key", device_public_key)?;
    }

    let identity = sqlx::query_as::<_, IdentityRow>(
        "SELECT id, display_name, canonical_handle, public_handle, created_at, recovery_key_verifier
         FROM users
         WHERE canonical_handle = $1 AND disabled_at IS NULL AND deleted_at IS NULL",
    )
    .bind(&handle.canonical_handle)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;

    let verifier = identity
        .recovery_key_verifier
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("RECOVERY_NOT_CONFIGURED".into()))?;
    let valid = password::verify_recovery_secret(&payload.recovery_secret, verifier)
        .map_err(|_| AppError::BadRequest("INVALID_RECOVERY_SECRET".into()))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    let device_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let expires_at = session_expires_at(&state)?;
    let mut tx = state.pg.begin().await?;
    create_device_session_and_keys(
        &mut tx,
        DeviceBootstrap {
            identity_id: identity.id,
            device_id,
            session_id,
            session_expires_at: expires_at,
            device_name: &payload.device_name,
            platform: &payload.platform,
            device_public_key: payload.device_public_key.as_deref(),
            identity_public_key: &payload.identity_public_key,
            registration_id: payload.registration_id,
            protocol_device_id: payload.protocol_device_id,
            signed_prekey_id: payload.signed_prekey_id.unwrap_or(1),
            signed_prekey: &payload.signed_prekey,
            signed_prekey_signature: &payload.signed_prekey_signature,
            kyber_prekey: payload.kyber_prekey.as_ref(),
            one_time_prekeys: &payload.one_time_prekeys,
        },
    )
    .await?;
    tx.commit().await?;

    Ok(Json(identity_response(
        &state, identity, device_id, session_id,
    )?))
}

async fn delete_me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<DeleteIdentityResponse>, AppError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT canonical_handle FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(auth.user_id)
            .fetch_optional(&state.pg)
            .await?;
    let (canonical_handle,) = row.ok_or(AppError::NotFound)?;
    let handle_hash = handle_hash(&canonical_handle);

    let mut tx = state.pg.begin().await?;
    let device_ids = sqlx::query_scalar::<_, Uuid>("SELECT id FROM devices WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_all(&mut *tx)
        .await?;

    sqlx::query(
        "UPDATE users
         SET status = 'deleted', disabled_at = now(), deleted_at = now(), updated_at = now()
         WHERE id = $1",
    )
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE devices
         SET revoked_at = now(), fcm_token = NULL, fcm_token_updated_at = NULL, push_enabled = FALSE
         WHERE user_id = $1",
    )
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1")
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys WHERE device_id = ANY($1)")
        .bind(&device_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM signed_prekeys WHERE device_id = ANY($1)")
        .bind(&device_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM identity_keys WHERE device_id = ANY($1)")
        .bind(&device_ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO identity_tombstones
            (canonical_handle, handle_hash, deleted_identity_id, reason)
         VALUES ($1, $2, $3, 'user_deleted')
         ON CONFLICT (canonical_handle) DO NOTHING",
    )
    .bind(&canonical_handle)
    .bind(&handle_hash)
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(DeleteIdentityResponse {
        status: "deleted",
        canonical_handle,
        reserved_forever: true,
    }))
}

struct DeviceBootstrap<'a> {
    identity_id: Uuid,
    device_id: Uuid,
    session_id: Uuid,
    session_expires_at: DateTime<Utc>,
    device_name: &'a str,
    platform: &'a str,
    device_public_key: Option<&'a str>,
    identity_public_key: &'a str,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey_id: i64,
    signed_prekey: &'a str,
    signed_prekey_signature: &'a str,
    kyber_prekey: Option<&'a KyberPrekeyRequest>,
    one_time_prekeys: &'a [String],
}

async fn create_device_session_and_keys(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    bootstrap: DeviceBootstrap<'_>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO devices (id, user_id, display_name, platform, device_public_key)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(bootstrap.device_id)
    .bind(bootstrap.identity_id)
    .bind(bootstrap.device_name)
    .bind(bootstrap.platform)
    .bind(bootstrap.device_public_key)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(bootstrap.session_id)
    .bind(bootstrap.identity_id)
    .bind(bootstrap.device_id)
    .bind(bootstrap.session_expires_at)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_keys (device_id, public_key, registration_id, protocol_device_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(bootstrap.device_id)
    .bind(bootstrap.identity_public_key)
    .bind(bootstrap.registration_id)
    .bind(bootstrap.protocol_device_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO signed_prekeys
            (device_id, key_id, public_key, signature, kyber_key_id, kyber_public_key, kyber_signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(bootstrap.device_id)
    .bind(bootstrap.signed_prekey_id)
    .bind(bootstrap.signed_prekey)
    .bind(bootstrap.signed_prekey_signature)
    .bind(bootstrap.kyber_prekey.map(|prekey| prekey.key_id))
    .bind(bootstrap.kyber_prekey.map(|prekey| &prekey.public_key))
    .bind(bootstrap.kyber_prekey.map(|prekey| &prekey.signature))
    .execute(&mut **tx)
    .await?;
    for (index, prekey) in bootstrap.one_time_prekeys.iter().enumerate() {
        sqlx::query(
            "INSERT INTO one_time_prekeys (id, device_id, key_id, public_key)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(bootstrap.device_id)
        .bind((index + 1) as i64)
        .bind(prekey)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn identity_response(
    state: &AppState,
    identity: IdentityRow,
    device_id: Uuid,
    session_id: Uuid,
) -> Result<IdentityResponse, AppError> {
    let access_token = jwt::issue_token(
        &state.config.jwt,
        identity.id,
        session_id,
        Some(device_id),
        jwt::TokenType::Device,
    )?;
    Ok(IdentityResponse {
        identity_id: identity.id,
        display_name: identity.display_name,
        canonical_handle: identity.canonical_handle,
        public_handle: identity.public_handle,
        device_id,
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_ttl.as_secs(),
        created_at: identity.created_at,
    })
}

struct KeyMaterialValidation<'a> {
    identity_public_key: &'a str,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey_id: Option<i64>,
    signed_prekey: &'a str,
    signed_prekey_signature: &'a str,
    kyber_prekey: Option<&'a KyberPrekeyRequest>,
    one_time_prekeys: &'a [String],
}

fn validate_key_material(material: KeyMaterialValidation<'_>) -> Result<(), AppError> {
    validation::opaque_key("identity_public_key", material.identity_public_key)?;
    validate_signal_metadata(material.registration_id, material.protocol_device_id)?;
    if let Some(signed_prekey_id) = material.signed_prekey_id {
        validate_key_id("signed_prekey_id", signed_prekey_id)?;
    }
    validation::opaque_key("signed_prekey", material.signed_prekey)?;
    validation::opaque_key("signed_prekey_signature", material.signed_prekey_signature)?;
    if let Some(kyber_prekey) = material.kyber_prekey {
        validate_key_id("kyber_prekey.key_id", kyber_prekey.key_id)?;
        validation::opaque_key("kyber_prekey.public_key", &kyber_prekey.public_key)?;
        validation::opaque_key("kyber_prekey.signature", &kyber_prekey.signature)?;
    }
    if material.one_time_prekeys.len() > 100 {
        return Err(AppError::BadRequest(
            "one_time_prekeys may contain at most 100 entries".into(),
        ));
    }
    for prekey in material.one_time_prekeys {
        validation::opaque_key("one_time_prekey", prekey)?;
    }
    Ok(())
}

fn validate_signal_metadata(
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
) -> Result<(), AppError> {
    match (registration_id, protocol_device_id) {
        (None, None) => Ok(()),
        (Some(registration_id), Some(protocol_device_id)) => {
            if registration_id <= 0 {
                return Err(AppError::BadRequest(
                    "registration_id must be positive".into(),
                ));
            }
            if !(1..=127).contains(&protocol_device_id) {
                return Err(AppError::BadRequest(
                    "protocol_device_id must be between 1 and 127".into(),
                ));
            }
            Ok(())
        }
        _ => Err(AppError::BadRequest(
            "registration_id and protocol_device_id must be provided together".into(),
        )),
    }
}

fn validate_key_id(field: &str, key_id: i64) -> Result<(), AppError> {
    if key_id < 0 {
        return Err(AppError::BadRequest(format!(
            "{field} must be non-negative"
        )));
    }
    Ok(())
}

async fn ensure_handle_not_reserved(
    state: &AppState,
    canonical_handle: &str,
) -> Result<(), AppError> {
    let reserved: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM identity_tombstones WHERE canonical_handle = $1")
            .bind(canonical_handle)
            .fetch_optional(&state.pg)
            .await?;
    if reserved.is_some() {
        return Err(AppError::Conflict("HANDLE_RESERVED".into()));
    }
    Ok(())
}

async fn hash_secret(secret: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || password::hash_password(&secret))
        .await
        .map_err(|_| AppError::Internal)?
}

fn session_expires_at(state: &AppState) -> Result<DateTime<Utc>, AppError> {
    Ok(Utc::now()
        + ChronoDuration::from_std(state.config.jwt.access_ttl).map_err(|_| AppError::Internal)?)
}

fn map_identity_insert_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23505") {
            return AppError::Conflict("HANDLE_ALREADY_TAKEN".into());
        }
    }
    AppError::Database(error)
}

fn handle_hash(canonical_handle: &str) -> String {
    let digest = Sha256::digest(canonical_handle.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn default_platform() -> String {
    "android".into()
}
