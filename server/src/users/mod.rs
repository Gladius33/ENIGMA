use axum::{extract::Path, routing::get, Json, Router};
use serde::Serialize;
use uuid::Uuid;

use crate::{auth::AuthUser, error::AppError, security::validation, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/resolve/:public_id", get(resolve_user))
}

#[derive(Debug, Serialize)]
struct ResolveUserResponse {
    id: Uuid,
    public_id: String,
    display_name: String,
    canonical_handle: String,
    public_handle: String,
}

async fn resolve_user(
    axum::extract::State(state): axum::extract::State<AppState>,
    _auth: AuthUser,
    Path(public_id): Path<String>,
) -> Result<Json<ResolveUserResponse>, AppError> {
    let handle = validation::handle(&public_id)?;

    let row: Option<(Uuid, String, String, String, String)> = sqlx::query_as(
        "SELECT id, public_id, display_name, canonical_handle, public_handle
         FROM users
         WHERE canonical_handle = $1 AND disabled_at IS NULL AND deleted_at IS NULL",
    )
    .bind(&handle.canonical_handle)
    .fetch_optional(&state.pg)
    .await?;

    let (id, public_id, display_name, canonical_handle, public_handle) =
        row.ok_or(AppError::NotFound)?;
    Ok(Json(ResolveUserResponse {
        id,
        public_id,
        display_name,
        canonical_handle,
        public_handle,
    }))
}
