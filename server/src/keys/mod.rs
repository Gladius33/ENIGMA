use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, devices, error::AppError, security::validation, AppState};

const PREKEY_LOW_WATERMARK: i64 = 10;
const PREKEY_RECOMMENDED_UPLOAD_COUNT: i64 = 50;
const PREKEY_MAX_UPLOAD_COUNT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/upload", post(upload_keys))
        .route("/status", get(key_status))
        .route("/:user_id", get(discover_key_bundle))
        .route("/:user_id/devices", get(discover_key_bundle))
        .route(
            "/:user_id/devices/:device_id/claim-prekey",
            post(claim_prekey),
        )
}

#[derive(Debug, Deserialize)]
struct UploadKeysRequest {
    device_id: Uuid,
    identity_key: String,
    #[serde(default)]
    registration_id: Option<i32>,
    #[serde(default)]
    protocol_device_id: Option<i32>,
    signed_prekey: SignedPrekeyUpload,
    #[serde(default)]
    kyber_prekey: Option<KyberPrekeyUpload>,
    #[serde(default)]
    one_time_prekeys: Vec<OneTimePrekeyUpload>,
}

#[derive(Debug, Deserialize)]
struct SignedPrekeyUpload {
    key_id: i64,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct OneTimePrekeyUpload {
    key_id: i64,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct KyberPrekeyUpload {
    key_id: i64,
    public_key: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct UploadKeysResponse {
    device_id: Uuid,
    one_time_prekeys_received: usize,
    one_time_prekey_count: i64,
    prekey_low: bool,
}

#[derive(Debug, Serialize)]
struct KeyBundleResponse {
    user_id: Uuid,
    devices: Vec<DeviceKeyDiscoveryBundle>,
}

#[derive(Debug, Serialize)]
struct DeviceAuthorizationProof {
    authorizing_device_id: Uuid,
    canonical_payload: String,
    authorizer_signature: String,
}

#[derive(Debug, Serialize)]
struct DeviceKeyDiscoveryBundle {
    device_id: Uuid,
    identity_key: String,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey: SignedPrekeyBundle,
    kyber_prekey: Option<KyberPrekeyBundle>,
    one_time_prekey_count: i64,
    prekey_low: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<DeviceAuthorizationProof>,
}

#[derive(Debug, Serialize)]
struct ClaimPrekeyResponse {
    user_id: Uuid,
    device: ClaimedDeviceKeyBundle,
}

#[derive(Debug, Serialize)]
struct ClaimedDeviceKeyBundle {
    device_id: Uuid,
    identity_key: String,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey: SignedPrekeyBundle,
    kyber_prekey: Option<KyberPrekeyBundle>,
    one_time_prekey: Option<OneTimePrekeyBundle>,
    one_time_prekey_count_after_claim: i64,
    prekey_low: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<DeviceAuthorizationProof>,
}

#[derive(Debug, Serialize)]
struct KeyStatusResponse {
    device_id: Uuid,
    one_time_prekey_count: i64,
    prekey_low: bool,
    recommended_upload_count: i64,
    max_upload_count: i64,
}

#[derive(Debug, Serialize)]
struct SignedPrekeyBundle {
    key_id: i64,
    public_key: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct OneTimePrekeyBundle {
    key_id: i64,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct KyberPrekeyBundle {
    key_id: i64,
    public_key: String,
    signature: String,
}

#[derive(Debug, FromRow)]
struct JoinedDeviceKeys {
    device_id: Uuid,
    identity_key: String,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey_key_id: i64,
    signed_prekey_public_key: String,
    signed_prekey_signature: String,
    kyber_key_id: Option<i64>,
    kyber_public_key: Option<String>,
    kyber_signature: Option<String>,
    authorization_authorizing_device_id: Option<Uuid>,
    authorization_payload: Option<String>,
    authorization_signature: Option<String>,
}

#[derive(Debug, FromRow)]
struct OneTimePrekeyRow {
    id: Uuid,
    key_id: i64,
    public_key: String,
}

async fn upload_keys(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(payload): Json<UploadKeysRequest>,
) -> Result<Json<UploadKeysResponse>, AppError> {
    auth.ensure_device_id(payload.device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.device_id).await?;
    validate_upload(&payload)?;
    ensure_authorized_identity_match(&state, payload.device_id, &payload.identity_key).await?;

    let mut tx = state.pg.begin().await?;
    sqlx::query(
        "INSERT INTO identity_keys (device_id, public_key, registration_id, protocol_device_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (device_id)
         DO UPDATE SET
            public_key = EXCLUDED.public_key,
            registration_id = EXCLUDED.registration_id,
            protocol_device_id = EXCLUDED.protocol_device_id,
            updated_at = now()",
    )
    .bind(payload.device_id)
    .bind(&payload.identity_key)
    .bind(payload.registration_id)
    .bind(payload.protocol_device_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO signed_prekeys
            (device_id, key_id, public_key, signature, kyber_key_id, kyber_public_key, kyber_signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (device_id)
         DO UPDATE SET
            key_id = EXCLUDED.key_id,
            public_key = EXCLUDED.public_key,
            signature = EXCLUDED.signature,
            kyber_key_id = EXCLUDED.kyber_key_id,
            kyber_public_key = EXCLUDED.kyber_public_key,
            kyber_signature = EXCLUDED.kyber_signature,
            updated_at = now()",
    )
    .bind(payload.device_id)
    .bind(payload.signed_prekey.key_id)
    .bind(&payload.signed_prekey.public_key)
    .bind(&payload.signed_prekey.signature)
    .bind(payload.kyber_prekey.as_ref().map(|prekey| prekey.key_id))
    .bind(payload.kyber_prekey.as_ref().map(|prekey| &prekey.public_key))
    .bind(payload.kyber_prekey.as_ref().map(|prekey| &prekey.signature))
    .execute(&mut *tx)
    .await?;

    for prekey in &payload.one_time_prekeys {
        sqlx::query(
            "INSERT INTO one_time_prekeys (id, device_id, key_id, public_key)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (device_id, key_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(payload.device_id)
        .bind(prekey.key_id)
        .bind(&prekey.public_key)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    let one_time_prekey_count = count_one_time_prekeys(&state, payload.device_id).await?;
    Ok(Json(UploadKeysResponse {
        device_id: payload.device_id,
        one_time_prekeys_received: payload.one_time_prekeys.len(),
        one_time_prekey_count,
        prekey_low: one_time_prekey_count < PREKEY_LOW_WATERMARK,
    }))
}

async fn key_status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<KeyStatusResponse>, AppError> {
    let device_id = auth.require_device_id()?;
    devices::ensure_device_owner(&state, auth.user_id, device_id).await?;
    let one_time_prekey_count = count_one_time_prekeys(&state, device_id).await?;
    Ok(Json(KeyStatusResponse {
        device_id,
        one_time_prekey_count,
        prekey_low: one_time_prekey_count < PREKEY_LOW_WATERMARK,
        recommended_upload_count: PREKEY_RECOMMENDED_UPLOAD_COUNT,
        max_upload_count: PREKEY_MAX_UPLOAD_COUNT,
    }))
}

async fn discover_key_bundle(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<KeyBundleResponse>, AppError> {
    ensure_user_exists(&state, user_id).await?;

    let rows = fetch_stable_device_keys(&state, user_id).await?;
    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let authorization = authorization_proof(&row)?;
        let one_time_prekey_count = count_one_time_prekeys(&state, row.device_id).await?;
        devices.push(DeviceKeyDiscoveryBundle {
            device_id: row.device_id,
            identity_key: row.identity_key,
            registration_id: row.registration_id,
            protocol_device_id: row.protocol_device_id,
            signed_prekey: SignedPrekeyBundle {
                key_id: row.signed_prekey_key_id,
                public_key: row.signed_prekey_public_key,
                signature: row.signed_prekey_signature,
            },
            kyber_prekey: kyber_bundle(row.kyber_key_id, row.kyber_public_key, row.kyber_signature),
            one_time_prekey_count,
            prekey_low: one_time_prekey_count < PREKEY_LOW_WATERMARK,
            authorization,
        });
    }

    Ok(Json(KeyBundleResponse { user_id, devices }))
}

async fn claim_prekey(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((user_id, device_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ClaimPrekeyResponse>, AppError> {
    auth.require_device_token()?;
    ensure_user_exists(&state, user_id).await?;

    let mut tx = state.pg.begin().await?;
    let row = sqlx::query_as::<_, JoinedDeviceKeys>(
        "SELECT
            d.id AS device_id,
            ik.public_key AS identity_key,
            ik.registration_id,
            ik.protocol_device_id,
            sp.key_id AS signed_prekey_key_id,
            sp.public_key AS signed_prekey_public_key,
            sp.signature AS signed_prekey_signature,
            sp.kyber_key_id,
            sp.kyber_public_key,
            sp.kyber_signature,
            da.authorizing_device_id AS authorization_authorizing_device_id,
            da.canonical_payload AS authorization_payload,
            da.authorizer_signature AS authorization_signature
         FROM devices d
         JOIN identity_keys ik ON ik.device_id = d.id
         JOIN signed_prekeys sp ON sp.device_id = d.id
         LEFT JOIN device_authorizations da ON da.device_id = d.id
         WHERE d.user_id = $1 AND d.id = $2 AND d.revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    let authorization = authorization_proof(&row)?;
    let one_time_prekey = pop_one_time_prekey(&mut tx, device_id).await?;
    let one_time_prekey_count = count_one_time_prekeys_tx(&mut tx, device_id).await?;
    tx.commit().await?;

    Ok(Json(ClaimPrekeyResponse {
        user_id,
        device: ClaimedDeviceKeyBundle {
            device_id: row.device_id,
            identity_key: row.identity_key,
            registration_id: row.registration_id,
            protocol_device_id: row.protocol_device_id,
            signed_prekey: SignedPrekeyBundle {
                key_id: row.signed_prekey_key_id,
                public_key: row.signed_prekey_public_key,
                signature: row.signed_prekey_signature,
            },
            kyber_prekey: kyber_bundle(row.kyber_key_id, row.kyber_public_key, row.kyber_signature),
            one_time_prekey: one_time_prekey.map(|prekey| OneTimePrekeyBundle {
                key_id: prekey.key_id,
                public_key: prekey.public_key,
            }),
            one_time_prekey_count_after_claim: one_time_prekey_count,
            prekey_low: one_time_prekey_count < PREKEY_LOW_WATERMARK,
            authorization,
        },
    }))
}

async fn ensure_user_exists(state: &AppState, user_id: Uuid) -> Result<(), AppError> {
    let user_exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND disabled_at IS NULL")
            .bind(user_id)
            .fetch_optional(&state.pg)
            .await?;
    user_exists.map(|_| ()).ok_or(AppError::NotFound)
}

async fn fetch_stable_device_keys(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<JoinedDeviceKeys>, AppError> {
    Ok(sqlx::query_as::<_, JoinedDeviceKeys>(
        "SELECT
            d.id AS device_id,
            ik.public_key AS identity_key,
            ik.registration_id,
            ik.protocol_device_id,
            sp.key_id AS signed_prekey_key_id,
            sp.public_key AS signed_prekey_public_key,
            sp.signature AS signed_prekey_signature,
            sp.kyber_key_id,
            sp.kyber_public_key,
            sp.kyber_signature,
            da.authorizing_device_id AS authorization_authorizing_device_id,
            da.canonical_payload AS authorization_payload,
            da.authorizer_signature AS authorization_signature
         FROM devices d
         JOIN identity_keys ik ON ik.device_id = d.id
         JOIN signed_prekeys sp ON sp.device_id = d.id
         LEFT JOIN device_authorizations da ON da.device_id = d.id
         WHERE d.user_id = $1 AND d.revoked_at IS NULL
         ORDER BY d.created_at ASC",
    )
    .bind(user_id)
    .fetch_all(&state.pg)
    .await?)
}

async fn ensure_authorized_identity_match(
    state: &AppState,
    device_id: Uuid,
    identity_key: &str,
) -> Result<(), AppError> {
    let certified_identity: Option<String> = sqlx::query_scalar(
        "SELECT target_identity_key
         FROM device_authorizations
         WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.pg)
    .await?;

    if let Some(certified_identity) = certified_identity {
        if certified_identity != identity_key {
            return Err(AppError::Conflict("LINKED_DEVICE_IDENTITY_MISMATCH".into()));
        }
    }

    Ok(())
}

fn authorization_proof(
    row: &JoinedDeviceKeys,
) -> Result<Option<DeviceAuthorizationProof>, AppError> {
    match (
        row.authorization_authorizing_device_id,
        row.authorization_payload.as_ref(),
        row.authorization_signature.as_ref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(authorizing_device_id), Some(canonical_payload), Some(authorizer_signature)) => {
            Ok(Some(DeviceAuthorizationProof {
                authorizing_device_id,
                canonical_payload: canonical_payload.clone(),
                authorizer_signature: authorizer_signature.clone(),
            }))
        }
        _ => Err(AppError::Internal),
    }
}

fn kyber_bundle(
    key_id: Option<i64>,
    public_key: Option<String>,
    signature: Option<String>,
) -> Option<KyberPrekeyBundle> {
    match (key_id, public_key, signature) {
        (Some(key_id), Some(public_key), Some(signature)) => Some(KyberPrekeyBundle {
            key_id,
            public_key,
            signature,
        }),
        _ => None,
    }
}

async fn pop_one_time_prekey(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: Uuid,
) -> Result<Option<OneTimePrekeyRow>, AppError> {
    let prekey = sqlx::query_as::<_, OneTimePrekeyRow>(
        "SELECT id, key_id, public_key
         FROM one_time_prekeys
         WHERE device_id = $1
         ORDER BY created_at ASC
         LIMIT 1
         FOR UPDATE SKIP LOCKED",
    )
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(prekey) = &prekey {
        sqlx::query("DELETE FROM one_time_prekeys WHERE id = $1")
            .bind(prekey.id)
            .execute(&mut **tx)
            .await?;
    }

    Ok(prekey)
}

async fn count_one_time_prekeys(state: &AppState, device_id: Uuid) -> Result<i64, AppError> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(&state.pg)
            .await?,
    )
}

async fn count_one_time_prekeys_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    device_id: Uuid,
) -> Result<i64, AppError> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(&mut **tx)
            .await?,
    )
}

fn validate_upload(payload: &UploadKeysRequest) -> Result<(), AppError> {
    validation::base64_field("identity_key", &payload.identity_key, 16, 8192)?;
    validate_signal_metadata(payload.registration_id, payload.protocol_device_id)?;
    if payload.registration_id.is_some() && payload.kyber_prekey.is_none() {
        return Err(AppError::BadRequest("MISSING_KYBER_PREKEY".into()));
    }

    validate_key_id(payload.signed_prekey.key_id)?;
    validation::base64_field(
        "signed_prekey.public_key",
        &payload.signed_prekey.public_key,
        16,
        8192,
    )?;
    validation::base64_field(
        "signed_prekey.signature",
        &payload.signed_prekey.signature,
        16,
        8192,
    )?;

    if let Some(kyber_prekey) = &payload.kyber_prekey {
        validate_key_id(kyber_prekey.key_id)?;
        validation::base64_field(
            "kyber_prekey.public_key",
            &kyber_prekey.public_key,
            16,
            8192,
        )?;
        validation::base64_field("kyber_prekey.signature", &kyber_prekey.signature, 16, 8192)?;
    }

    if payload.one_time_prekeys.len() > PREKEY_MAX_UPLOAD_COUNT as usize {
        return Err(AppError::BadRequest("TOO_MANY_PREKEYS".into()));
    }

    let mut key_ids = HashSet::with_capacity(payload.one_time_prekeys.len());
    for prekey in &payload.one_time_prekeys {
        validate_key_id(prekey.key_id)?;
        if !key_ids.insert(prekey.key_id) {
            return Err(AppError::BadRequest("DUPLICATE_PREKEY_ID".into()));
        }
        validation::base64_field("one_time_prekey.public_key", &prekey.public_key, 16, 8192)?;
    }

    Ok(())
}

fn validate_key_id(key_id: i64) -> Result<(), AppError> {
    if !(0..=i32::MAX as i64).contains(&key_id) {
        return Err(AppError::BadRequest("INVALID_KEY_ID".into()));
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
            if !(1..=16_380).contains(&registration_id) {
                return Err(AppError::BadRequest("INVALID_REGISTRATION_ID".into()));
            }
            if !(1..=127).contains(&protocol_device_id) {
                return Err(AppError::BadRequest("INVALID_PROTOCOL_DEVICE_ID".into()));
            }
            Ok(())
        }
        _ => Err(AppError::BadRequest("INVALID_REGISTRATION_METADATA".into())),
    }
}
