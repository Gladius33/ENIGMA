use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Internal)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| AppError::Internal)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn verify_recovery_secret(secret: &str, verifier: &str) -> Result<bool, AppError> {
    if let Some(encoded) = verifier.strip_prefix("pbkdf2-sha256$") {
        return verify_pbkdf2_sha256(secret, encoded);
    }
    verify_password(secret, verifier)
}

fn verify_pbkdf2_sha256(secret: &str, encoded: &str) -> Result<bool, AppError> {
    let mut parts = encoded.split('$');
    let iterations = parts
        .next()
        .ok_or(AppError::Internal)?
        .parse::<u32>()
        .map_err(|_| AppError::Internal)?;
    let salt = parts.next().ok_or(AppError::Internal).and_then(|value| {
        STANDARD_NO_PAD
            .decode(value)
            .map_err(|_| AppError::Internal)
    })?;
    let expected = parts.next().ok_or(AppError::Internal).and_then(|value| {
        STANDARD_NO_PAD
            .decode(value)
            .map_err(|_| AppError::Internal)
    })?;
    if parts.next().is_some() || !(10_000..=1_000_000).contains(&iterations) {
        return Err(AppError::Internal);
    }
    let actual = pbkdf2_sha256(secret.as_bytes(), &salt, iterations, expected.len())?;
    Ok(constant_time_eq(&actual, &expected))
}

fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>, AppError> {
    let mut output = vec![0u8; output_len];
    let mut block_index = 1u32;
    let mut offset = 0usize;

    while offset < output_len {
        let mut mac = HmacSha256::new_from_slice(password).map_err(|_| AppError::Internal)?;
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();

        for _ in 1..iterations {
            let mut mac = HmacSha256::new_from_slice(password).map_err(|_| AppError::Internal)?;
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (target, value) in block.iter_mut().zip(u.iter()) {
                *target ^= value;
            }
        }

        let remaining = output_len - offset;
        let take = remaining.min(block.len());
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.checked_add(1).ok_or(AppError::Internal)?;
    }

    Ok(output)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}
