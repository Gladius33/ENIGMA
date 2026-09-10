use enigma_e2ee_server::security::{password, validation};

#[test]
fn public_id_validation_is_strict_ascii() {
    assert!(validation::public_id("alice_123").is_ok());
    assert!(validation::public_id("a").is_err());
    assert!(validation::public_id("alice@example").is_err());
    assert!(validation::public_id("alicé").is_err());
}

#[test]
fn sha256_validation_requires_hex_digest() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(validation::sha256_hex(digest).is_ok());
    assert!(validation::sha256_hex("not-a-digest").is_err());
}

#[test]
fn content_type_validation_uses_mime_parser() {
    assert!(validation::content_type("application/octet-stream").is_ok());
    assert!(validation::content_type("not a mime type").is_err());
}

#[test]
fn message_type_accepts_v1_product_types() {
    assert!(validation::message_type("text").is_ok());
    assert!(validation::message_type("image").is_ok());
    assert!(validation::message_type("unsupported").is_err());
}

#[test]
fn ciphertext_validation_requires_base64_container() {
    assert!(validation::ciphertext("bWVzc2FnZQ==", 1024).is_ok());
    assert!(validation::ciphertext("not json", 1024).is_err());
}

#[test]
fn base64_field_validation_checks_encoding_and_decoded_length() {
    assert!(validation::base64_field("key", "bWVzc2FnZS1rZXktbWF0ZXJpYWw", 4, 64).is_ok());
    assert!(validation::base64_field("key", "not base64!", 4, 64).is_err());
    assert!(validation::base64_field("key", "bWU", 4, 64).is_err());
}

#[test]
fn password_hash_round_trip() {
    let password_value = "correct horse battery staple";
    let hash = password::hash_password(password_value).expect("password hash");

    assert!(password::verify_password(password_value, &hash).expect("verify password"));
    assert!(!password::verify_password("wrong password", &hash).expect("verify password"));
}
