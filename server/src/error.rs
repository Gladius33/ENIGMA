use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("redis error")]
    Redis(#[from] redis::RedisError),
    #[error("jwt error")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("s3 error: {0}")]
    S3(String),
    #[error("internal error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error_code: String,
    message: String,
    request_id: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::Database(_)
            | AppError::Redis(_)
            | AppError::Jwt(_)
            | AppError::S3(_)
            | AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let public_message = match &self {
            AppError::BadRequest(message) | AppError::Conflict(message) => message.clone(),
            AppError::Unauthorized => "authentication required".into(),
            AppError::Forbidden => "access denied".into(),
            AppError::NotFound => "resource not found".into(),
            AppError::RateLimited => "too many requests".into(),
            AppError::Database(_)
            | AppError::Redis(_)
            | AppError::Jwt(_)
            | AppError::S3(_)
            | AppError::Internal => "internal server error".into(),
        };
        let error_code = self.error_code(&public_message);
        let request_id = Uuid::new_v4().to_string();

        let body = Json(ErrorBody {
            error_code,
            message: public_message,
            request_id,
        });
        (status, body).into_response()
    }
}

impl AppError {
    fn error_code(&self, public_message: &str) -> String {
        match self {
            AppError::BadRequest(_) | AppError::Conflict(_) if is_stable_code(public_message) => {
                public_message.to_owned()
            }
            AppError::BadRequest(_) => "VALIDATION_ERROR".into(),
            AppError::Unauthorized => "UNAUTHORIZED".into(),
            AppError::Forbidden => "FORBIDDEN".into(),
            AppError::NotFound => "NOT_FOUND".into(),
            AppError::Conflict(_) => "CONFLICT".into(),
            AppError::RateLimited => "RATE_LIMITED".into(),
            AppError::Database(_)
            | AppError::Redis(_)
            | AppError::Jwt(_)
            | AppError::S3(_)
            | AppError::Internal => "INTERNAL_ERROR".into(),
        }
    }
}

fn is_stable_code(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}
