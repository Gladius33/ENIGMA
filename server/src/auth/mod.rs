use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    error::AppError,
    security::{jwt, password, validation},
    AppState,
};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub device_id: Option<Uuid>,
    pub token_type: jwt::TokenType,
}

impl AuthUser {
    pub fn require_device_id(&self) -> Result<Uuid, AppError> {
        self.device_id.ok_or(AppError::Forbidden)
    }

    pub fn ensure_device_id(&self, device_id: Uuid) -> Result<(), AppError> {
        match self.device_id {
            Some(auth_device_id) if auth_device_id == device_id => Ok(()),
            _ => Err(AppError::Forbidden),
        }
    }

    pub fn require_device_token(&self) -> Result<(), AppError> {
        if self.token_type == jwt::TokenType::Device && self.device_id.is_some() {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    public_id: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    public_id: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    user: PublicUser,
}

#[derive(Debug, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub public_id: String,
    pub display_name: String,
    pub canonical_handle: String,
    pub public_handle: String,
}

#[derive(Debug, FromRow)]
struct UserAuthRow {
    id: Uuid,
    public_id: String,
    display_name: String,
    canonical_handle: String,
    public_handle: String,
    password_hash: String,
    disabled_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct SessionAuthRow {
    user_id: Uuid,
    device_id: Option<Uuid>,
}

async fn register(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let handle = validation::handle(&payload.public_id)?;
    validation::password(&payload.password)?;

    let password_to_hash = payload.password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || password::hash_password(&password_to_hash))
            .await
            .map_err(|_| AppError::Internal)??;

    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let expires_at = session_expires_at(&state)?;

    let mut tx = state.pg.begin().await?;
    sqlx::query(
        "INSERT INTO users
            (id, public_id, display_name, canonical_handle, public_handle, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(user_id)
    .bind(&handle.canonical_handle)
    .bind(&handle.display_name)
    .bind(&handle.canonical_handle)
    .bind(&handle.public_handle)
    .bind(password_hash)
    .execute(&mut *tx)
    .await
    .map_err(map_register_insert_error)?;

    insert_session(&mut tx, session_id, user_id, expires_at).await?;
    tx.commit().await?;

    let access_token = jwt::issue_token(
        &state.config.jwt,
        user_id,
        session_id,
        None,
        jwt::TokenType::Bootstrap,
    )?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_ttl.as_secs(),
        user: PublicUser {
            id: user_id,
            public_id: handle.canonical_handle.clone(),
            display_name: handle.display_name,
            canonical_handle: handle.canonical_handle,
            public_handle: handle.public_handle,
        },
    }))
}

async fn login(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let handle = validation::handle(&payload.public_id)?;
    validation::password(&payload.password)?;

    let user = sqlx::query_as::<_, UserAuthRow>(
        "SELECT id, public_id, display_name, canonical_handle, public_handle, password_hash, disabled_at, deleted_at
         FROM users
         WHERE canonical_handle = $1",
    )
    .bind(&handle.canonical_handle)
    .fetch_optional(&state.pg)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if user.disabled_at.is_some() || user.deleted_at.is_some() {
        return Err(AppError::Forbidden);
    }

    let password_to_verify = payload.password.clone();
    let stored_hash = user.password_hash.clone();
    let valid_password = tokio::task::spawn_blocking(move || {
        password::verify_password(&password_to_verify, &stored_hash)
    })
    .await
    .map_err(|_| AppError::Internal)??;

    if !valid_password {
        return Err(AppError::Unauthorized);
    }

    let session_id = Uuid::new_v4();
    let expires_at = session_expires_at(&state)?;
    let mut tx = state.pg.begin().await?;
    insert_session(&mut tx, session_id, user.id, expires_at).await?;
    tx.commit().await?;

    let access_token = jwt::issue_token(
        &state.config.jwt,
        user.id,
        session_id,
        None,
        jwt::TokenType::Bootstrap,
    )?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt.access_ttl.as_secs(),
        user: PublicUser {
            id: user.id,
            public_id: user.public_id,
            display_name: user.display_name,
            canonical_handle: user.canonical_handle,
            public_handle: user.public_handle,
        },
    }))
}

pub async fn validate_bearer_token(state: &AppState, token: &str) -> Result<AuthUser, AppError> {
    let claims = jwt::verify_token(&state.config.jwt, token).map_err(|_| AppError::Unauthorized)?;
    let session = sqlx::query_as::<_, SessionAuthRow>(
        "SELECT user_id, device_id FROM sessions
         WHERE id = $1 AND user_id = $2 AND expires_at > now() AND revoked_at IS NULL",
    )
    .bind(claims.sid)
    .bind(claims.sub)
    .fetch_optional(&state.pg)
    .await?;

    let session = session.ok_or(AppError::Unauthorized)?;
    if session.device_id != claims.did {
        return Err(AppError::Unauthorized);
    }
    let token_type = jwt::TokenType::from_claim(claims.typ.as_deref(), claims.did)
        .ok_or(AppError::Unauthorized)?;

    Ok(AuthUser {
        user_id: session.user_id,
        session_id: claims.sid,
        device_id: claims.did,
        token_type,
    })
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)?;
        validate_bearer_token(state, token).await
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(AppError::Unauthorized)
}

fn session_expires_at(state: &AppState) -> Result<DateTime<Utc>, AppError> {
    Ok(Utc::now()
        + ChronoDuration::from_std(state.config.jwt.access_ttl).map_err(|_| AppError::Internal)?)
}

async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session_id: Uuid,
    user_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(session_id)
        .bind(user_id)
        .bind(expires_at)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn map_register_insert_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.code().as_deref() == Some("23505") {
            return AppError::Conflict("public_id is already registered".into());
        }
    }
    AppError::Database(error)
}
