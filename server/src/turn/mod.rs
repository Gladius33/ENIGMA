use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

use crate::{auth::AuthUser, error::AppError, AppState};

type HmacSha1 = Hmac<Sha1>;

pub fn router() -> Router<AppState> {
    Router::new().route("/credentials", post(credentials))
}

#[derive(Debug, Serialize)]
struct TurnCredentialsResponse {
    username: String,
    credential: String,
    ttl_seconds: u64,
    expires_at: DateTime<Utc>,
    uris: Vec<String>,
    realm: String,
}

async fn credentials(
    axum::extract::State(state): axum::extract::State<AppState>,
    auth: AuthUser,
) -> Result<Json<TurnCredentialsResponse>, AppError> {
    if state.config.turn.secret.len() < 16 {
        return Err(AppError::Internal);
    }

    let expires_at = Utc::now()
        + ChronoDuration::from_std(state.config.turn.ttl).map_err(|_| AppError::Internal)?;
    let username = format!("{}:{}", expires_at.timestamp(), auth.user_id);
    let credential = coturn_credential(&username, &state.config.turn.secret)?;

    Ok(Json(TurnCredentialsResponse {
        username,
        credential,
        ttl_seconds: state.config.turn.ttl.as_secs(),
        expires_at,
        uris: state.config.turn.uris.clone(),
        realm: state.config.turn.realm.clone(),
    }))
}

fn coturn_credential(username: &str, secret: &str) -> Result<String, AppError> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Internal)?;
    mac.update(username.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::coturn_credential;

    #[test]
    fn coturn_credential_is_stable() {
        let credential =
            coturn_credential("1700000000:user", "test-shared-secret").expect("credential");
        assert_eq!(credential, "7KElgKCyr/EsUtFskdU5Ch4iRqE=");
    }
}
