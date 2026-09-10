pub mod lifecycle;
pub mod s3;

use std::collections::BTreeMap;

use aws_sdk_s3::presigning::PresigningConfig;
use axum::{extract::Path, routing::post, Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, devices, error::AppError, security::validation, AppState};

pub(crate) const P2P_OBJECT_DELETE_PENDING: &str = "P2P_OBJECT_DELETE_PENDING";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/presign-upload", post(presign_upload))
        .route("/:blob_id/presign-upload", post(represign_upload))
        .route("/presign-download", post(presign_download))
        .route("/p2p-grant", post(grant_p2p_attachments))
        .route("/p2p-commit", post(commit_p2p_attachments))
        .route("/:blob_id/complete", post(complete_upload))
}

#[derive(Debug, Deserialize)]
struct PresignUploadRequest {
    bubble_id: Uuid,
    size_bytes: i64,
    sha256: String,
    content_type: String,
}

#[derive(Debug, Serialize)]
struct PresignUploadResponse {
    blob_id: Uuid,
    bubble_id: Uuid,
    download_secret: String,
    url: String,
    method: &'static str,
    headers: BTreeMap<String, String>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RepresignUploadRequest {
    bubble_id: Uuid,
    download_secret: String,
}

#[derive(Debug, Serialize)]
struct RepresignUploadResponse {
    blob_id: Uuid,
    bubble_id: Uuid,
    status: &'static str,
    url: Option<String>,
    method: Option<&'static str>,
    headers: BTreeMap<String, String>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct RepresignUploadRow {
    blob_id: Uuid,
    bubble_id: Uuid,
    object_key: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct PresignDownloadRequest {
    blob_id: Uuid,
    bubble_id: Uuid,
    download_secret: String,
}

#[derive(Debug, Deserialize)]
struct CompleteUploadRequest {
    download_secret: String,
    sha256: String,
    size_bytes: i64,
}

#[derive(Debug, Deserialize)]
struct P2pAttachmentGrantRequest {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    recipient_device_id: Uuid,
    client_message_id: Uuid,
    attachment_blob_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
struct P2pAttachmentCommitRequest {
    bubble_id: Uuid,
    sender_device_id: Uuid,
    recipient_device_id: Uuid,
    client_message_id: Uuid,
    attachment_blob_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
struct P2pAttachmentGrantResponse {
    status: &'static str,
    attachment_count: usize,
}

#[derive(Debug, Serialize)]
struct P2pAttachmentCommitResponse {
    status: &'static str,
    attachment_count: usize,
    released_bytes: i64,
}

#[derive(Debug, Serialize)]
struct PresignDownloadResponse {
    blob_id: Uuid,
    bubble_id: Uuid,
    url: String,
    method: &'static str,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct CompleteUploadResponse {
    blob_id: Uuid,
    bubble_id: Uuid,
    status: &'static str,
    size_bytes: i64,
    sha256: String,
    verified_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct AttachmentVerificationRow {
    blob_id: Uuid,
    bubble_id: Uuid,
    object_key: String,
    size_bytes: i64,
    sha256: String,
    content_type: String,
    status: String,
}

#[derive(Debug, FromRow)]
struct P2pPendingReleaseRow {
    blob_id: Uuid,
    object_key: String,
    size_bytes: i64,
    status: String,
    last_error: Option<String>,
}

#[derive(Debug, FromRow)]
struct DirectBubbleAccessRow {
    mode: String,
    sender_member: bool,
    recipient_member: bool,
}

async fn presign_upload(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<PresignUploadRequest>,
) -> Result<Json<PresignUploadResponse>, AppError> {
    auth.require_device_id()?;
    ensure_bubble_member(&state, payload.bubble_id, auth.user_id).await?;
    validation::sha256_hex(&payload.sha256)?;
    validation::content_type(&payload.content_type)?;
    let plan = crate::business::active_plan(&state, auth.user_id).await?;
    if payload.size_bytes <= 0 {
        return Err(AppError::BadRequest("INVALID_ATTACHMENT_SIZE".into()));
    }
    if payload.size_bytes > plan.max_attachment_bytes {
        return Err(AppError::BadRequest("ATTACHMENT_TOO_LARGE_FOR_PLAN".into()));
    }
    if plan.attachment_retention_seconds <= 0 {
        return Err(AppError::Internal);
    }

    let presign_config = PresigningConfig::expires_in(state.config.s3.upload_presign_ttl)
        .map_err(|err| AppError::S3(err.to_string()))?;

    let blob_id = Uuid::new_v4();
    let download_secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let download_secret_hash = sha256_hex(download_secret.as_bytes());
    let attachment_id = Uuid::new_v4();
    let object_key = format!("attachments/{}/{}", auth.user_id, blob_id);
    let expires_at = Utc::now() + ChronoDuration::seconds(plan.attachment_retention_seconds);

    let mut tx = state.pg.begin().await?;
    sqlx::query(
        "INSERT INTO identity_usage_counters(identity_id) VALUES($1) ON CONFLICT DO NOTHING",
    )
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await?;
    let usage: (i64, i64, i64, i32, chrono::NaiveDate) = sqlx::query_as(
        "SELECT storage_verified_bytes,storage_pending_bytes,uploads_today_bytes,uploads_today_count,uploads_window_date FROM identity_usage_counters WHERE identity_id=$1 FOR UPDATE",
    )
    .bind(auth.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let (daily_bytes, daily_count) = if usage.4 == Utc::now().date_naive() {
        (usage.2, usage.3)
    } else {
        (0, 0)
    };
    if usage
        .0
        .saturating_add(usage.1)
        .saturating_add(payload.size_bytes)
        > plan.storage_quota_bytes
    {
        return Err(AppError::BadRequest("STORAGE_QUOTA_EXCEEDED".into()));
    }
    if usage.1.saturating_add(payload.size_bytes) > plan.pending_storage_quota_bytes {
        return Err(AppError::BadRequest(
            "PENDING_STORAGE_QUOTA_EXCEEDED".into(),
        ));
    }
    if plan.code == "free"
        && (daily_bytes.saturating_add(payload.size_bytes)
            > state.config.business.free_upload_daily_bytes
            || daily_count >= state.config.business.free_upload_daily_count)
    {
        return Err(AppError::BadRequest("DAILY_UPLOAD_LIMIT_EXCEEDED".into()));
    }
    sqlx::query(
        "INSERT INTO attachments
            (id, blob_id, bubble_id, owner_id, object_key, size_bytes, sha256, content_type, expires_at, download_secret_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(attachment_id)
    .bind(blob_id)
    .bind(payload.bubble_id)
    .bind(auth.user_id)
    .bind(&object_key)
    .bind(payload.size_bytes)
    .bind(&payload.sha256)
    .bind(&payload.content_type)
    .bind(expires_at)
    .bind(&download_secret_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE identity_usage_counters SET storage_pending_bytes=storage_pending_bytes+$2,uploads_today_bytes=CASE WHEN uploads_window_date=CURRENT_DATE THEN uploads_today_bytes+$2 ELSE $2 END,uploads_today_count=CASE WHEN uploads_window_date=CURRENT_DATE THEN uploads_today_count+1 ELSE 1 END,uploads_window_date=CURRENT_DATE,updated_at=now() WHERE identity_id=$1")
        .bind(auth.user_id).bind(payload.size_bytes).execute(&mut *tx).await?;
    tx.commit().await?;

    let presigned = match state
        .s3
        .put_object()
        .bucket(&state.config.s3.bucket)
        .key(&object_key)
        .presigned(presign_config)
        .await
    {
        Ok(presigned) => presigned,
        Err(err) => {
            let original = AppError::S3(err.to_string());
            if let Err(compensation_error) =
                compensate_failed_presign(&state, blob_id, auth.user_id, payload.size_bytes).await
            {
                tracing::error!(
                    blob_id=%blob_id,
                    owner_id=%auth.user_id,
                    error=?compensation_error,
                    "failed to compensate attachment reservation after presign failure"
                );
            }
            return Err(original);
        }
    };

    Ok(Json(PresignUploadResponse {
        blob_id,
        bubble_id: payload.bubble_id,
        download_secret,
        url: presigned.uri().to_string(),
        method: "PUT",
        headers: BTreeMap::new(),
        expires_at,
    }))
}

async fn represign_upload(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<Uuid>,
    Json(payload): Json<RepresignUploadRequest>,
) -> Result<Json<RepresignUploadResponse>, AppError> {
    auth.require_device_id()?;
    validation::bounded("download_secret", &payload.download_secret, 32, 128)?;
    ensure_bubble_member(&state, payload.bubble_id, auth.user_id).await?;

    let row = sqlx::query_as::<_, RepresignUploadRow>(
        "SELECT blob_id,bubble_id,object_key,status
         FROM attachments
         WHERE blob_id=$1 AND bubble_id=$2 AND owner_id=$3
           AND download_secret_hash=$4
           AND status IN ('pending','verified')
           AND expires_at>now()",
    )
    .bind(blob_id)
    .bind(payload.bubble_id)
    .bind(auth.user_id)
    .bind(sha256_hex(payload.download_secret.as_bytes()))
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;

    if row.status == "verified" {
        return Ok(Json(RepresignUploadResponse {
            blob_id: row.blob_id,
            bubble_id: row.bubble_id,
            status: "verified",
            url: None,
            method: None,
            headers: BTreeMap::new(),
            expires_at: None,
        }));
    }
    if row.status != "pending" {
        return Err(AppError::Conflict("ATTACHMENT_NOT_UPLOADABLE".into()));
    }

    let presign_config = PresigningConfig::expires_in(state.config.s3.upload_presign_ttl)
        .map_err(|err| AppError::S3(err.to_string()))?;
    let presigned = state
        .s3
        .put_object()
        .bucket(&state.config.s3.bucket)
        .key(&row.object_key)
        .presigned(presign_config)
        .await
        .map_err(|err| AppError::S3(err.to_string()))?;
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.s3.upload_presign_ttl)
            .map_err(|_| AppError::Internal)?;

    Ok(Json(RepresignUploadResponse {
        blob_id: row.blob_id,
        bubble_id: row.bubble_id,
        status: "pending",
        url: Some(presigned.uri().to_string()),
        method: Some("PUT"),
        headers: BTreeMap::new(),
        expires_at: Some(expires_at),
    }))
}

async fn grant_p2p_attachments(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<P2pAttachmentGrantRequest>,
) -> Result<Json<P2pAttachmentGrantResponse>, AppError> {
    auth.ensure_device_id(payload.sender_device_id)?;
    if payload.sender_device_id == payload.recipient_device_id {
        return Err(AppError::BadRequest("P2P_ATTACHMENT_SELF_TARGET".into()));
    }
    devices::ensure_device_owner(&state, auth.user_id, payload.sender_device_id).await?;
    devices::ensure_device_exists(&state, payload.recipient_device_id).await?;
    ensure_direct_bubble_scope(
        &state,
        payload.bubble_id,
        auth.user_id,
        payload.recipient_device_id,
    )
    .await?;
    let attachments = lifecycle::prepare(&payload.attachment_blob_ids)?;
    if attachments.blob_ids.is_empty() {
        return Err(AppError::BadRequest("P2P_ATTACHMENTS_REQUIRED".into()));
    }

    let mut tx = state.pg.begin().await?;
    lifecycle::grant_direct_p2p(
        &mut tx,
        auth.user_id,
        payload.bubble_id,
        payload.client_message_id,
        payload.recipient_device_id,
        &attachments,
    )
    .await?;
    tx.commit().await?;

    Ok(Json(P2pAttachmentGrantResponse {
        status: "granted",
        attachment_count: attachments.blob_ids.len(),
    }))
}

async fn commit_p2p_attachments(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<P2pAttachmentCommitRequest>,
) -> Result<Json<P2pAttachmentCommitResponse>, AppError> {
    auth.ensure_device_id(payload.sender_device_id)?;
    devices::ensure_device_owner(&state, auth.user_id, payload.sender_device_id).await?;
    let attachments = lifecycle::prepare(&payload.attachment_blob_ids)?;
    if attachments.blob_ids.is_empty() {
        return Err(AppError::BadRequest("P2P_ATTACHMENTS_REQUIRED".into()));
    }

    let mut tx = state.pg.begin().await?;
    let rows = sqlx::query_as::<_, P2pPendingReleaseRow>(
        "SELECT a.blob_id,a.object_key,a.size_bytes,a.status,a.last_error
         FROM attachments a
         WHERE a.owner_id=$1 AND a.bubble_id=$2
           AND a.blob_id=ANY($3)
           AND (
               (a.status='pending' AND a.expires_at>now())
               OR (
                   a.status='deleted'
                   AND (a.last_error IS NULL OR a.last_error=$6)
               )
           )
           AND EXISTS (
               SELECT 1 FROM attachment_references r
               WHERE r.blob_id=a.blob_id
                 AND r.owner_id=$1 AND r.bubble_id=$2
                 AND r.conversation_kind='direct'
                 AND r.recipient_device_id=$4
                 AND r.client_message_id=$5
                 AND r.direct_message_id IS NULL
           )
         FOR UPDATE",
    )
    .bind(auth.user_id)
    .bind(payload.bubble_id)
    .bind(&attachments.blob_ids)
    .bind(payload.recipient_device_id)
    .bind(payload.client_message_id)
    .bind(P2P_OBJECT_DELETE_PENDING)
    .fetch_all(&mut *tx)
    .await?;

    if rows.len() != attachments.blob_ids.len() {
        return Err(AppError::Conflict(
            "P2P_ATTACHMENT_GRANT_NOT_COMMITTABLE".into(),
        ));
    }

    let released_bytes = rows.iter().try_fold(0_i64, |total, row| {
        total.checked_add(row.size_bytes).ok_or(AppError::Internal)
    })?;
    let pending_rows: Vec<&P2pPendingReleaseRow> =
        rows.iter().filter(|row| row.status == "pending").collect();
    let newly_released_bytes = pending_rows.iter().try_fold(0_i64, |total, row| {
        total.checked_add(row.size_bytes).ok_or(AppError::Internal)
    })?;

    if !pending_rows.is_empty() {
        let released = sqlx::query(
            "UPDATE attachments
             SET status='deleted',last_error=$4
             WHERE owner_id=$1 AND bubble_id=$2 AND status='pending' AND blob_id=ANY($3)",
        )
        .bind(auth.user_id)
        .bind(payload.bubble_id)
        .bind(&attachments.blob_ids)
        .bind(P2P_OBJECT_DELETE_PENDING)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if usize::try_from(released).map_err(|_| AppError::Internal)? != pending_rows.len() {
            return Err(AppError::Conflict(
                "P2P_ATTACHMENT_RESERVATION_CHANGED".into(),
            ));
        }

        // Successful direct P2P delivery frees reserved storage, but it does not
        // refund the daily attachment counters. Otherwise a modified client could
        // reserve/upload/delete repeatedly and recycle the bandwidth-abuse limit.
        sqlx::query(
            "UPDATE identity_usage_counters
             SET storage_pending_bytes=GREATEST(0,storage_pending_bytes-$2),updated_at=now()
             WHERE identity_id=$1",
        )
        .bind(auth.user_id)
        .bind(newly_released_bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    for row in &rows {
        let needs_delete =
            row.status == "pending" || row.last_error.as_deref() == Some(P2P_OBJECT_DELETE_PENDING);
        if !needs_delete {
            continue;
        }
        match state
            .s3
            .delete_object()
            .bucket(&state.config.s3.bucket)
            .key(&row.object_key)
            .send()
            .await
        {
            Ok(_) => {
                if let Err(error) = sqlx::query(
                    "UPDATE attachments
                     SET last_error=NULL
                     WHERE blob_id=$1 AND status='deleted' AND last_error=$2",
                )
                .bind(row.blob_id)
                .bind(P2P_OBJECT_DELETE_PENDING)
                .execute(&state.pg)
                .await
                {
                    tracing::warn!(
                        blob_id=%row.blob_id,
                        error=?error,
                        "P2P attachment object deleted but tombstone cleanup was deferred"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    blob_id=%row.blob_id,
                    error=?error,
                    "P2P attachment object cleanup deferred"
                );
            }
        }
    }

    Ok(Json(P2pAttachmentCommitResponse {
        status: "released",
        attachment_count: rows.len(),
        released_bytes,
    }))
}

async fn presign_download(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<PresignDownloadRequest>,
) -> Result<Json<PresignDownloadResponse>, AppError> {
    let device_id = auth.require_device_id()?;

    let row: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT blob_id, bubble_id, owner_id, object_key
         FROM attachments
         WHERE blob_id=$1 AND bubble_id=$2 AND download_secret_hash=$3
           AND status='verified' AND expires_at>now()",
    )
    .bind(payload.blob_id)
    .bind(payload.bubble_id)
    .bind(sha256_hex(payload.download_secret.as_bytes()))
    .fetch_optional(&state.pg)
    .await?;
    let (blob_id, bubble_id, owner_id, object_key) = row.ok_or(AppError::NotFound)?;

    if owner_id != auth.user_id {
        let authorized: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM attachment_references r
                WHERE r.blob_id=$1
                  AND r.bubble_id=$2
                  AND r.expires_at>now()
                  AND (
                    (r.conversation_kind='direct' AND r.recipient_device_id=$3)
                    OR (
                        r.conversation_kind='group'
                        AND r.group_id IS NOT NULL
                        AND EXISTS(
                            SELECT 1 FROM group_members gm
                            WHERE gm.group_id=r.group_id
                              AND gm.user_id=$4
                              AND gm.removed_at IS NULL
                        )
                    )
                    OR (
                        r.conversation_kind='channel'
                        AND r.channel_id IS NOT NULL
                        AND EXISTS(
                            SELECT 1 FROM channel_subscribers cs
                            WHERE cs.channel_id=r.channel_id
                              AND cs.user_id=$4
                              AND cs.unsubscribed_at IS NULL
                        )
                    )
                  )
            )",
        )
        .bind(blob_id)
        .bind(bubble_id)
        .bind(device_id)
        .bind(auth.user_id)
        .fetch_one(&state.pg)
        .await?;
        if !authorized {
            return Err(AppError::Forbidden);
        }
    }

    let presign_config = PresigningConfig::expires_in(state.config.s3.download_presign_ttl)
        .map_err(|err| AppError::S3(err.to_string()))?;
    let presigned = state
        .s3
        .get_object()
        .bucket(&state.config.s3.bucket)
        .key(object_key)
        .presigned(presign_config)
        .await
        .map_err(|err| AppError::S3(err.to_string()))?;
    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.s3.download_presign_ttl)
            .map_err(|_| AppError::Internal)?;
    Ok(Json(PresignDownloadResponse {
        blob_id,
        bubble_id,
        url: presigned.uri().to_string(),
        method: "GET",
        expires_at,
    }))
}

async fn complete_upload(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<Uuid>,
    Json(payload): Json<CompleteUploadRequest>,
) -> Result<Json<CompleteUploadResponse>, AppError> {
    auth.require_device_id()?;
    validate_complete_request(&payload)?;
    let row = sqlx::query_as::<_, AttachmentVerificationRow>(
        "SELECT blob_id, bubble_id, object_key, size_bytes, sha256, content_type, status FROM attachments WHERE blob_id = $1 AND owner_id = $2 AND download_secret_hash = $3 AND expires_at > now()",
    )
    .bind(blob_id).bind(auth.user_id).bind(sha256_hex(payload.download_secret.as_bytes()))
    .fetch_optional(&state.pg).await?.ok_or(AppError::NotFound)?;

    if row.status == "verified" {
        return Ok(Json(CompleteUploadResponse {
            blob_id: row.blob_id,
            bubble_id: row.bubble_id,
            status: "verified",
            size_bytes: row.size_bytes,
            sha256: row.sha256,
            verified_at: Utc::now(),
        }));
    }
    if row.status != "pending" {
        return Err(AppError::Conflict("ATTACHMENT_NOT_COMPLETABLE".into()));
    }
    if row.size_bytes != payload.size_bytes || row.sha256 != payload.sha256 {
        record_attachment_error(&state, row.blob_id, "ATTACHMENT_METADATA_MISMATCH").await?;
        return Err(AppError::BadRequest("ATTACHMENT_METADATA_MISMATCH".into()));
    }

    let head = state
        .s3
        .head_object()
        .bucket(&state.config.s3.bucket)
        .key(&row.object_key)
        .send()
        .await
        .map_err(|_| AppError::BadRequest("ATTACHMENT_OBJECT_NOT_FOUND".into()))?;
    let actual_size = head.content_length().unwrap_or(-1);
    if actual_size != row.size_bytes {
        record_attachment_error(&state, row.blob_id, "ATTACHMENT_SIZE_MISMATCH").await?;
        return Err(AppError::BadRequest("ATTACHMENT_SIZE_MISMATCH".into()));
    }
    if let Some(content_type) = head.content_type() {
        if content_type != row.content_type {
            record_attachment_error(&state, row.blob_id, "ATTACHMENT_CONTENT_TYPE_MISMATCH")
                .await?;
            return Err(AppError::BadRequest(
                "ATTACHMENT_CONTENT_TYPE_MISMATCH".into(),
            ));
        }
    }

    let get = state
        .s3
        .get_object()
        .bucket(&state.config.s3.bucket)
        .key(&row.object_key)
        .send()
        .await
        .map_err(|err| AppError::S3(err.to_string()))?;
    let mut body = get.body;
    let mut hasher = Sha256::new();
    let mut streamed_size: i64 = 0;
    while let Some(chunk) = body
        .try_next()
        .await
        .map_err(|err| AppError::S3(err.to_string()))?
    {
        streamed_size = streamed_size
            .checked_add(i64::try_from(chunk.len()).map_err(|_| AppError::Internal)?)
            .ok_or(AppError::Internal)?;
        if streamed_size > row.size_bytes {
            record_attachment_error(&state, row.blob_id, "ATTACHMENT_SIZE_MISMATCH").await?;
            return Err(AppError::BadRequest("ATTACHMENT_SIZE_MISMATCH".into()));
        }
        hasher.update(&chunk);
    }
    if streamed_size != row.size_bytes {
        record_attachment_error(&state, row.blob_id, "ATTACHMENT_SIZE_MISMATCH").await?;
        return Err(AppError::BadRequest("ATTACHMENT_SIZE_MISMATCH".into()));
    }
    let actual_sha256 = hex_digest(&hasher.finalize());
    if actual_sha256 != row.sha256 {
        record_attachment_error(&state, row.blob_id, "ATTACHMENT_HASH_MISMATCH").await?;
        return Err(AppError::BadRequest("ATTACHMENT_HASH_MISMATCH".into()));
    }

    let verified_at = Utc::now();
    let mut tx = state.pg.begin().await?;
    let changed = sqlx::query(
        "UPDATE attachments SET status='verified',completed_at=now(),verified_at=$2,actual_size_bytes=$3,actual_sha256=$4,last_error=NULL WHERE blob_id=$1 AND status='pending'",
    )
    .bind(row.blob_id).bind(verified_at).bind(streamed_size).bind(&actual_sha256)
    .execute(&mut *tx).await?.rows_affected();
    if changed == 1 {
        sqlx::query("UPDATE identity_usage_counters SET storage_pending_bytes=GREATEST(0,storage_pending_bytes-$2),storage_verified_bytes=storage_verified_bytes+$2,updated_at=now() WHERE identity_id=$1")
            .bind(auth.user_id).bind(streamed_size).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(CompleteUploadResponse {
        blob_id: row.blob_id,
        bubble_id: row.bubble_id,
        status: "verified",
        size_bytes: streamed_size,
        sha256: actual_sha256,
        verified_at,
    }))
}

async fn ensure_bubble_member(
    state: &AppState,
    bubble_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT bubble_id FROM bubble_members WHERE bubble_id=$1 AND identity_id=$2 AND status='active'")
        .bind(bubble_id).bind(user_id).fetch_optional(&state.pg).await?;
    exists.map(|_| ()).ok_or(AppError::Forbidden)
}

async fn ensure_direct_bubble_scope(
    state: &AppState,
    bubble_id: Uuid,
    sender_user_id: Uuid,
    recipient_device_id: Uuid,
) -> Result<(), AppError> {
    let access = sqlx::query_as::<_, DirectBubbleAccessRow>(
        "SELECT b.mode,
                EXISTS (
                    SELECT 1 FROM bubble_members bm
                    WHERE bm.bubble_id = b.id
                      AND bm.identity_id = $2
                      AND bm.status = 'active'
                ) AS sender_member,
                EXISTS (
                    SELECT 1 FROM bubble_members bm
                    WHERE bm.bubble_id = b.id
                      AND bm.identity_id = recipient.user_id
                      AND bm.status = 'active'
                ) AS recipient_member
         FROM bubbles b
         JOIN devices recipient ON recipient.id = $3
         WHERE b.id = $1 AND b.deleted_at IS NULL",
    )
    .bind(bubble_id)
    .bind(sender_user_id)
    .bind(recipient_device_id)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::NotFound)?;

    if access.mode == "PRIVATE_ISOLATED" {
        if access.sender_member && access.recipient_member {
            return Ok(());
        }
        return Err(AppError::Forbidden);
    }

    if access.sender_member || access.recipient_member {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn validate_complete_request(payload: &CompleteUploadRequest) -> Result<(), AppError> {
    if payload.size_bytes <= 0 {
        return Err(AppError::BadRequest("INVALID_ATTACHMENT_SIZE".into()));
    }
    validation::sha256_hex(&payload.sha256)?;
    validation::bounded("download_secret", &payload.download_secret, 32, 128)?;
    Ok(())
}

async fn compensate_failed_presign(
    state: &AppState,
    blob_id: Uuid,
    owner_id: Uuid,
    size_bytes: i64,
) -> Result<(), AppError> {
    let mut tx = state.pg.begin().await?;
    let released = sqlx::query(
        "UPDATE attachments
         SET status='deleted',last_error='ATTACHMENT_PRESIGN_FAILED'
         WHERE blob_id=$1 AND owner_id=$2 AND status='pending'",
    )
    .bind(blob_id)
    .bind(owner_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if released == 1 {
        sqlx::query(
            "UPDATE identity_usage_counters
             SET storage_pending_bytes=GREATEST(0,storage_pending_bytes-$2),
                 uploads_today_bytes=CASE
                     WHEN uploads_window_date=CURRENT_DATE THEN GREATEST(0,uploads_today_bytes-$2)
                     ELSE uploads_today_bytes
                 END,
                 uploads_today_count=CASE
                     WHEN uploads_window_date=CURRENT_DATE THEN GREATEST(0,uploads_today_count-1)
                     ELSE uploads_today_count
                 END,
                 updated_at=now()
             WHERE identity_id=$1",
        )
        .bind(owner_id)
        .bind(size_bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn record_attachment_error(
    state: &AppState,
    blob_id: Uuid,
    error: &'static str,
) -> Result<(), AppError> {
    let mut tx = state.pg.begin().await?;
    let released: Option<(Uuid, i64)> = sqlx::query_as("UPDATE attachments SET last_error=$2,status='deleted' WHERE blob_id=$1 AND status='pending' RETURNING owner_id,size_bytes")
        .bind(blob_id).bind(error).fetch_optional(&mut *tx).await?;
    if let Some((owner, size)) = released {
        sqlx::query("UPDATE identity_usage_counters SET storage_pending_bytes=GREATEST(0,storage_pending_bytes-$2),updated_at=now() WHERE identity_id=$1")
            .bind(owner).bind(size).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
