use crate::error::AppError;
use base64::{engine::general_purpose, Engine as _};

const KEY_MAX_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct NormalizedHandle {
    pub display_name: String,
    pub canonical_handle: String,
    pub public_handle: String,
}

pub fn public_id(value: &str) -> Result<(), AppError> {
    handle(value).map(|_| ())
}

pub fn handle(value: &str) -> Result<NormalizedHandle, AppError> {
    let display_name = value.trim().trim_start_matches('@').to_owned();
    bounded("handle", &display_name, 3, 32)?;
    if !display_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AppError::BadRequest(
            "handle may only contain ASCII letters, digits, underscore and hyphen".into(),
        ));
    }

    let canonical_handle = display_name.to_ascii_lowercase();
    Ok(NormalizedHandle {
        display_name,
        public_handle: format!("@{canonical_handle}"),
        canonical_handle,
    })
}

pub fn password(value: &str) -> Result<(), AppError> {
    bounded("password", value, 12, 1024)
}

pub fn device_name(value: &str) -> Result<(), AppError> {
    bounded("device_name", value, 1, 80)
}

pub fn platform(value: &str) -> Result<(), AppError> {
    bounded("platform", value, 1, 32)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(AppError::BadRequest(
            "platform contains invalid characters".into(),
        ));
    }
    Ok(())
}

pub fn opaque_key(field: &str, value: &str) -> Result<(), AppError> {
    bounded(field, value, 16, KEY_MAX_BYTES)
}

pub fn base64_field(
    field: &str,
    value: &str,
    min_decoded_bytes: usize,
    max_decoded_bytes: usize,
) -> Result<(), AppError> {
    bounded(field, value, 1, KEY_MAX_BYTES)?;
    let decoded_len = general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| AppError::BadRequest("INVALID_BASE64".into()))?
        .len();

    if decoded_len < min_decoded_bytes || decoded_len > max_decoded_bytes {
        return Err(AppError::BadRequest("INVALID_KEY_LENGTH".into()));
    }
    Ok(())
}

pub fn ciphertext(value: &str, max_bytes: usize) -> Result<(), AppError> {
    bounded("ciphertext", value, 1, max_bytes)?;
    if value.len() % 4 == 1
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(AppError::BadRequest(
            "ciphertext must be a base64 encoded opaque envelope".into(),
        ));
    }
    Ok(())
}

pub fn message_type(value: &str) -> Result<(), AppError> {
    if !matches!(
        value,
        "text" | "opaque" | "image" | "video" | "audio_message" | "video_message" | "file"
    ) {
        return Err(AppError::BadRequest(
            "message_type is not supported for V1".into(),
        ));
    }
    Ok(())
}

pub fn title(field: &str, value: &str) -> Result<(), AppError> {
    bounded(field, value, 1, 120)
}

pub fn description(field: &str, value: &str) -> Result<(), AppError> {
    bounded(field, value, 0, 512)
}

pub fn role(value: &str, allowed: &[&str]) -> Result<(), AppError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(AppError::BadRequest("role is not allowed".into()))
    }
}

pub fn opaque_payload(field: &str, value: &str, max_bytes: usize) -> Result<(), AppError> {
    bounded(field, value, 0, max_bytes)
}

pub fn sha256_hex(value: &str) -> Result<(), AppError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "sha256 must be a 64 character hex string".into(),
        ));
    }
    Ok(())
}

pub fn content_type(value: &str) -> Result<(), AppError> {
    bounded("content_type", value, 3, 128)?;
    value
        .parse::<mime::Mime>()
        .map(|_| ())
        .map_err(|_| AppError::BadRequest("content_type is not a valid MIME type".into()))
}

pub fn bounded(field: &str, value: &str, min: usize, max: usize) -> Result<(), AppError> {
    let len = value.len();
    if len < min || len > max {
        return Err(AppError::BadRequest(format!(
            "{field} length must be between {min} and {max} bytes"
        )));
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte < 0x20 && byte != b'\n')
    {
        return Err(AppError::BadRequest(format!(
            "{field} contains control characters"
        )));
    }
    Ok(())
}
