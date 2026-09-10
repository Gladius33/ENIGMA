use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::AppError;

const MAX_ATTACHMENTS_PER_CONTAINER: usize = 16;

#[derive(Debug, Clone)]
pub struct PreparedAttachments {
    pub blob_ids: Vec<Uuid>,
}

pub fn prepare(blob_ids: &[Uuid]) -> Result<PreparedAttachments, AppError> {
    if blob_ids.len() > MAX_ATTACHMENTS_PER_CONTAINER {
        return Err(AppError::BadRequest("TOO_MANY_ATTACHMENTS".into()));
    }

    let unique: BTreeSet<Uuid> = blob_ids.iter().copied().collect();
    if unique.len() != blob_ids.len() {
        return Err(AppError::BadRequest(
            "DUPLICATE_ATTACHMENT_REFERENCE".into(),
        ));
    }

    Ok(PreparedAttachments {
        blob_ids: unique.into_iter().collect(),
    })
}

pub async fn lock_verified(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    if attachments.blob_ids.is_empty() {
        return Ok(());
    }

    // Hold a key-share lock until the parent message/post/channel transaction
    // commits. The purge path takes FOR UPDATE on the same attachment row, so a
    // blob cannot become purgeable between validation and reference creation.
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT blob_id
         FROM attachments
         WHERE owner_id=$1 AND bubble_id=$2 AND status='verified' AND expires_at>now()
           AND blob_id = ANY($3)
         FOR KEY SHARE",
    )
    .bind(owner_id)
    .bind(bubble_id)
    .bind(&attachments.blob_ids)
    .fetch_all(&mut **tx)
    .await?;

    if locked.len() != attachments.blob_ids.len() {
        return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
    }

    Ok(())
}

async fn lock_direct_grantable(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    if attachments.blob_ids.is_empty() {
        return Ok(());
    }

    // A P2P-first grant is valid only while no server upload has been completed.
    // This prevents a previously server-stored blob from being presented as a
    // zero-relay attachment transfer.
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT blob_id
         FROM attachments
         WHERE owner_id=$1 AND bubble_id=$2 AND status='pending' AND expires_at>now()
           AND blob_id = ANY($3)
         FOR KEY SHARE",
    )
    .bind(owner_id)
    .bind(bubble_id)
    .bind(&attachments.blob_ids)
    .fetch_all(&mut **tx)
    .await?;

    if locked.len() != attachments.blob_ids.len() {
        return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
    }

    Ok(())
}

pub async fn grant_direct_p2p(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    client_message_id: Uuid,
    recipient_device_id: Uuid,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    lock_direct_grantable(tx, owner_id, bubble_id, attachments).await?;
    for blob_id in &attachments.blob_ids {
        let inserted = sqlx::query(
            "INSERT INTO attachment_references
                (id,blob_id,owner_id,bubble_id,conversation_kind,client_message_id,recipient_device_id,expires_at)
             SELECT gen_random_uuid(),a.blob_id,$1,$2,'direct',$3,$4,a.expires_at
             FROM attachments a
             WHERE a.blob_id=$5 AND a.owner_id=$1 AND a.bubble_id=$2
               AND a.status='pending' AND a.expires_at>now()
             ON CONFLICT (owner_id,bubble_id,recipient_device_id,client_message_id,blob_id)
             WHERE conversation_kind='direct' AND client_message_id IS NOT NULL
             DO UPDATE SET expires_at=EXCLUDED.expires_at",
        )
        .bind(owner_id)
        .bind(bubble_id)
        .bind(client_message_id)
        .bind(recipient_device_id)
        .bind(*blob_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
        }
    }
    Ok(())
}

pub async fn bind_direct(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    message_id: Uuid,
    recipient_device_id: Uuid,
    _parent_expires_at: DateTime<Utc>,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    lock_verified(tx, owner_id, bubble_id, attachments).await?;
    for blob_id in &attachments.blob_ids {
        // If this logical message first attempted P2P, promote the existing grant
        // into the durable relay reference instead of creating a second ACL row.
        let promoted = sqlx::query(
            "UPDATE attachment_references r
             SET direct_message_id=$3,expires_at=a.expires_at
             FROM attachments a,message_queue mq
             WHERE mq.id=$3
               AND r.conversation_kind='direct'
               AND r.owner_id=$1 AND r.bubble_id=$2
               AND r.client_message_id=mq.client_message_id
               AND r.recipient_device_id=$4
               AND r.blob_id=$5
               AND r.direct_message_id IS NULL
               AND a.blob_id=r.blob_id AND a.owner_id=$1 AND a.bubble_id=$2
               AND a.status='verified' AND a.expires_at>now()",
        )
        .bind(owner_id)
        .bind(bubble_id)
        .bind(message_id)
        .bind(recipient_device_id)
        .bind(*blob_id)
        .execute(&mut **tx)
        .await?;

        if promoted.rows_affected() == 1 {
            continue;
        }

        let inserted = sqlx::query(
            "INSERT INTO attachment_references
                (id,blob_id,owner_id,bubble_id,conversation_kind,direct_message_id,client_message_id,recipient_device_id,expires_at)
             SELECT gen_random_uuid(),a.blob_id,$1,$2,'direct',$3,mq.client_message_id,$4,a.expires_at
             FROM attachments a
             JOIN message_queue mq ON mq.id=$3
             WHERE a.blob_id=$5 AND a.owner_id=$1 AND a.bubble_id=$2
               AND a.status='verified' AND a.expires_at>now()",
        )
        .bind(owner_id)
        .bind(bubble_id)
        .bind(message_id)
        .bind(recipient_device_id)
        .bind(*blob_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
        }
    }
    Ok(())
}

pub async fn bind_group(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    message_id: Uuid,
    _parent_expires_at: DateTime<Utc>,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    lock_verified(tx, owner_id, bubble_id, attachments).await?;
    for blob_id in &attachments.blob_ids {
        let inserted = sqlx::query(
            "INSERT INTO attachment_references
                (id,blob_id,owner_id,bubble_id,conversation_kind,group_message_id,group_id,expires_at)
             SELECT gen_random_uuid(),a.blob_id,$1,$2,'group',$3,gm.group_id,a.expires_at
             FROM attachments a
             JOIN group_message_queue gm ON gm.id=$3
             WHERE a.blob_id=$4 AND a.owner_id=$1 AND a.bubble_id=$2
               AND gm.bubble_id=$2
               AND a.status='verified' AND a.expires_at>now()",
        )
        .bind(owner_id)
        .bind(bubble_id)
        .bind(message_id)
        .bind(*blob_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
        }
    }
    Ok(())
}

pub async fn bind_channel(
    tx: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    bubble_id: Uuid,
    post_id: Uuid,
    _parent_expires_at: DateTime<Utc>,
    attachments: &PreparedAttachments,
) -> Result<(), AppError> {
    lock_verified(tx, owner_id, bubble_id, attachments).await?;
    for blob_id in &attachments.blob_ids {
        let inserted = sqlx::query(
            "INSERT INTO attachment_references
                (id,blob_id,owner_id,bubble_id,conversation_kind,channel_post_id,channel_id,expires_at)
             SELECT gen_random_uuid(),a.blob_id,$1,$2,'channel',$3,cp.channel_id,a.expires_at
             FROM attachments a
             JOIN channel_posts_queue cp ON cp.id=$3
             WHERE a.blob_id=$4 AND a.owner_id=$1 AND a.bubble_id=$2
               AND cp.bubble_id=$2
               AND a.status='verified' AND a.expires_at>now()",
        )
        .bind(owner_id)
        .bind(bubble_id)
        .bind(post_id)
        .bind(*blob_id)
        .execute(&mut **tx)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(AppError::BadRequest("INVALID_ATTACHMENT_REFERENCE".into()));
        }
    }
    Ok(())
}

pub async fn ensure_direct_matches(
    tx: &mut Transaction<'_, Postgres>,
    message_id: Uuid,
    requested: &PreparedAttachments,
) -> Result<(), AppError> {
    ensure_matches(
        tx,
        "SELECT blob_id FROM attachment_references WHERE conversation_kind='direct' AND direct_message_id=$1",
        message_id,
        requested,
    )
    .await
}

pub async fn ensure_group_matches(
    tx: &mut Transaction<'_, Postgres>,
    message_id: Uuid,
    requested: &PreparedAttachments,
) -> Result<(), AppError> {
    ensure_matches(
        tx,
        "SELECT blob_id FROM attachment_references WHERE conversation_kind='group' AND group_message_id=$1",
        message_id,
        requested,
    )
    .await
}

pub async fn ensure_channel_matches(
    tx: &mut Transaction<'_, Postgres>,
    post_id: Uuid,
    requested: &PreparedAttachments,
) -> Result<(), AppError> {
    ensure_matches(
        tx,
        "SELECT blob_id FROM attachment_references WHERE conversation_kind='channel' AND channel_post_id=$1",
        post_id,
        requested,
    )
    .await
}

async fn ensure_matches(
    tx: &mut Transaction<'_, Postgres>,
    query: &'static str,
    parent_id: Uuid,
    requested: &PreparedAttachments,
) -> Result<(), AppError> {
    let existing: BTreeSet<Uuid> = sqlx::query_scalar::<_, Uuid>(query)
        .bind(parent_id)
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .collect();
    let requested: BTreeSet<Uuid> = requested.blob_ids.iter().copied().collect();
    if existing == requested {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "client id is already used with different attachments".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::prepare;
    use uuid::Uuid;

    #[test]
    fn prepare_sorts_and_rejects_duplicates() {
        let a = Uuid::from_u128(2);
        let b = Uuid::from_u128(1);
        let prepared = prepare(&[a, b]).expect("valid attachments");
        assert_eq!(prepared.blob_ids, vec![b, a]);
        assert!(prepare(&[a, a]).is_err());
    }

    #[test]
    fn prepare_rejects_more_than_sixteen_attachments() {
        let ids: Vec<Uuid> = (1..=17).map(Uuid::from_u128).collect();
        assert!(prepare(&ids).is_err());
    }
}
