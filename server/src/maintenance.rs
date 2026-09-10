use crate::{attachments::P2P_OBJECT_DELETE_PENDING, error::AppError, AppState};
use chrono::Utc;
use sqlx::FromRow;
use std::time::Instant;
use uuid::Uuid;

#[derive(FromRow)]
struct Candidate {
    blob_id: Uuid,
}

#[derive(FromRow)]
struct LockedCandidate {
    owner_id: Uuid,
    object_key: String,
    size_bytes: i64,
    status: String,
}

#[derive(FromRow)]
struct DeferredDelete {
    blob_id: Uuid,
    object_key: String,
}

pub async fn purge_attachments(state: &AppState) -> Result<u64, AppError> {
    let started = Instant::now();
    let pending = state.config.business.attachment_pending_ttl.as_secs() as i64;
    let unattached = state.config.business.attachment_unattached_ttl.as_secs() as i64;
    let deferred_deleted = cleanup_deferred_p2p_objects(state).await?;

    let rows: Vec<Candidate> = sqlx::query_as(
        "SELECT a.blob_id
         FROM attachments a
         WHERE (a.status='pending' AND a.created_at<now()-make_interval(secs=>$1))
            OR (a.status='verified' AND (
                a.expires_at<=now()
                OR (
                    a.verified_at<now()-make_interval(secs=>$2)
                    AND NOT EXISTS(
                        SELECT 1 FROM attachment_references r
                        WHERE r.blob_id=a.blob_id AND r.expires_at>now()
                    )
                    AND NOT EXISTS(
                        SELECT 1 FROM channels c
                        WHERE c.avatar_blob_id=a.blob_id AND c.archived_at IS NULL
                    )
                )
            ))
         ORDER BY a.created_at
         LIMIT $3",
    )
    .bind(pending)
    .bind(unattached)
    .bind(state.config.business.attachment_purge_batch_size)
    .fetch_all(&state.pg)
    .await?;

    let mut purged = 0;
    for row in rows {
        let mut tx = state.pg.begin().await?;

        let locked: Option<LockedCandidate> = sqlx::query_as(
            "SELECT a.owner_id,a.object_key,a.size_bytes,a.status
             FROM attachments a
             WHERE a.blob_id=$1
               AND (
                   (a.status='pending' AND a.created_at<now()-make_interval(secs=>$2))
                   OR (a.status='verified' AND (
                       a.expires_at<=now()
                       OR (
                           a.verified_at<now()-make_interval(secs=>$3)
                           AND NOT EXISTS(
                               SELECT 1 FROM attachment_references r
                               WHERE r.blob_id=a.blob_id AND r.expires_at>now()
                           )
                           AND NOT EXISTS(
                               SELECT 1 FROM channels c
                               WHERE c.avatar_blob_id=a.blob_id AND c.archived_at IS NULL
                           )
                       )
                   ))
               )
             FOR UPDATE",
        )
        .bind(row.blob_id)
        .bind(pending)
        .bind(unattached)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };

        if let Err(error) = state
            .s3
            .delete_object()
            .bucket(&state.config.s3.bucket)
            .key(&locked.object_key)
            .send()
            .await
        {
            tx.rollback().await?;
            tracing::warn!(
                blob_id=%row.blob_id,
                "attachment object deletion deferred: {}",
                error.as_service_error().map(|_| "service error").unwrap_or("transport error")
            );
            continue;
        }

        sqlx::query("UPDATE channels SET avatar_blob_id=NULL WHERE avatar_blob_id=$1")
            .bind(row.blob_id)
            .execute(&mut *tx)
            .await?;

        if sqlx::query(
            "UPDATE attachments
             SET status=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'deleted' END,last_error=NULL
             WHERE blob_id=$1 AND status=$2",
        )
        .bind(row.blob_id)
        .bind(&locked.status)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1
        {
            let col = if locked.status == "pending" {
                "storage_pending_bytes"
            } else {
                "storage_verified_bytes"
            };
            let query = format!(
                "UPDATE identity_usage_counters SET {col}=GREATEST(0,{col}-$2),updated_at=now() WHERE identity_id=$1"
            );
            sqlx::query(&query)
                .bind(locked.owner_id)
                .bind(locked.size_bytes)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM attachment_references WHERE blob_id=$1")
                .bind(row.blob_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            purged += 1;
        } else {
            tx.rollback().await?;
        }
    }

    sqlx::query("DELETE FROM attachment_references WHERE expires_at<=now()")
        .execute(&state.pg)
        .await?;

    tracing::info!(
        purged,
        deferred_deleted,
        duration_ms=started.elapsed().as_millis() as u64,
        at=%Utc::now(),
        "attachment purge completed"
    );
    Ok(purged)
}

async fn cleanup_deferred_p2p_objects(state: &AppState) -> Result<u64, AppError> {
    let rows: Vec<DeferredDelete> = sqlx::query_as(
        "SELECT blob_id,object_key
         FROM attachments
         WHERE status='deleted' AND last_error=$1
         ORDER BY created_at
         LIMIT $2",
    )
    .bind(P2P_OBJECT_DELETE_PENDING)
    .bind(state.config.business.attachment_purge_batch_size)
    .fetch_all(&state.pg)
    .await?;

    let mut cleaned = 0;
    for row in rows {
        match state
            .s3
            .delete_object()
            .bucket(&state.config.s3.bucket)
            .key(&row.object_key)
            .send()
            .await
        {
            Ok(_) => {
                let changed = sqlx::query(
                    "UPDATE attachments
                     SET last_error=NULL
                     WHERE blob_id=$1 AND status='deleted' AND last_error=$2",
                )
                .bind(row.blob_id)
                .bind(P2P_OBJECT_DELETE_PENDING)
                .execute(&state.pg)
                .await?
                .rows_affected();
                if changed == 1 {
                    cleaned += 1;
                }
            }
            Err(error) => {
                tracing::warn!(
                    blob_id=%row.blob_id,
                    "deferred P2P attachment object deletion still pending: {}",
                    error.as_service_error().map(|_| "service error").unwrap_or("transport error")
                );
            }
        }
    }
    Ok(cleaned)
}
