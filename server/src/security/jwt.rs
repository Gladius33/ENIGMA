use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{config::JwtConfig, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub sid: Uuid,
    #[serde(default)]
    pub did: Option<Uuid>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub jti: Option<Uuid>,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Bootstrap,
    Device,
}

impl TokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenType::Bootstrap => "bootstrap",
            TokenType::Device => "device",
        }
    }

    pub fn from_claim(value: Option<&str>, device_id: Option<Uuid>) -> Option<Self> {
        match value {
            Some("bootstrap") => Some(Self::Bootstrap),
            Some("device") => Some(Self::Device),
            Some(_) => None,
            None => device_id.map(|_| Self::Device).or(Some(Self::Bootstrap)),
        }
    }
}

pub fn issue_token(
    config: &JwtConfig,
    user_id: Uuid,
    session_id: Uuid,
    device_id: Option<Uuid>,
    token_type: TokenType,
) -> Result<String, AppError> {
    let now = Utc::now();
    let expires_at =
        now + ChronoDuration::from_std(config.access_ttl).map_err(|_| AppError::Internal)?;
    let claims = Claims {
        sub: user_id,
        sid: session_id,
        did: device_id,
        iss: Some(config.issuer.clone()),
        aud: Some(config.audience.clone()),
        typ: Some(token_type.as_str().to_owned()),
        jti: Some(Uuid::new_v4()),
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
    };

    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )?)
}

pub fn verify_token(config: &JwtConfig, token: &str) -> Result<Claims, AppError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation(config),
    )?;
    validate_required_claims(config, &data.claims)?;
    Ok(data.claims)
}

fn validation(_config: &JwtConfig) -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation
}

fn validate_required_claims(config: &JwtConfig, claims: &Claims) -> Result<(), AppError> {
    let has_v1_claims = claims.iss.is_some() || claims.aud.is_some() || claims.typ.is_some();
    if !has_v1_claims && config.accept_legacy_tokens {
        return Ok(());
    }
    if claims.iss.as_deref() != Some(config.issuer.as_str()) {
        return Err(AppError::Unauthorized);
    }
    if claims.aud.as_deref() != Some(config.audience.as_str()) {
        return Err(AppError::Unauthorized);
    }
    if TokenType::from_claim(claims.typ.as_deref(), claims.did).is_none() {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}
