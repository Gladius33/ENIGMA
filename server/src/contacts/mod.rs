use axum::{
    extract::Path,
    routing::{delete, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{auth::AuthUser, error::AppError, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(add_contact).get(list_contacts))
        .route("/:contact_user_id", delete(delete_contact))
}

#[derive(Debug, Deserialize)]
struct AddContactRequest {
    contact_user_id: Uuid,
}

#[derive(Debug, Serialize)]
struct ContactResponse {
    user_id: Uuid,
    public_id: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ContactsResponse {
    contacts: Vec<ContactResponse>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

#[derive(Debug, FromRow)]
struct ContactRow {
    user_id: Uuid,
    public_id: String,
    created_at: DateTime<Utc>,
}

async fn add_contact(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Json(payload): Json<AddContactRequest>,
) -> Result<Json<ContactResponse>, AppError> {
    if payload.contact_user_id == auth.user_id {
        return Err(AppError::BadRequest(
            "cannot add yourself as a contact".into(),
        ));
    }

    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND disabled_at IS NULL")
            .bind(payload.contact_user_id)
            .fetch_optional(&state.pg)
            .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }

    let row = sqlx::query_as::<_, ContactRow>(
        "INSERT INTO contacts (owner_user_id, contact_user_id)
         VALUES ($1, $2)
         ON CONFLICT (owner_user_id, contact_user_id) DO UPDATE SET contact_user_id = EXCLUDED.contact_user_id
         RETURNING contact_user_id AS user_id,
            (SELECT public_id FROM users WHERE id = contact_user_id) AS public_id,
            created_at",
    )
    .bind(auth.user_id)
    .bind(payload.contact_user_id)
    .fetch_one(&state.pg)
    .await?;

    Ok(Json(ContactResponse {
        user_id: row.user_id,
        public_id: row.public_id,
        created_at: row.created_at,
    }))
}

async fn list_contacts(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
) -> Result<Json<ContactsResponse>, AppError> {
    let rows = sqlx::query_as::<_, ContactRow>(
        "SELECT c.contact_user_id AS user_id, u.public_id, c.created_at
         FROM contacts c
         JOIN users u ON u.id = c.contact_user_id
         WHERE c.owner_user_id = $1 AND u.disabled_at IS NULL
         ORDER BY u.public_id ASC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pg)
    .await?;

    Ok(Json(ContactsResponse {
        contacts: rows
            .into_iter()
            .map(|row| ContactResponse {
                user_id: row.user_id,
                public_id: row.public_id,
                created_at: row.created_at,
            })
            .collect(),
    }))
}

async fn delete_contact(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
    Path(contact_user_id): Path<Uuid>,
) -> Result<Json<StatusResponse>, AppError> {
    let deleted =
        sqlx::query("DELETE FROM contacts WHERE owner_user_id = $1 AND contact_user_id = $2")
            .bind(auth.user_id)
            .bind(contact_user_id)
            .execute(&state.pg)
            .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(Json(StatusResponse { status: "ok" }))
}
