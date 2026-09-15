use std::{env, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use enigma_e2ee_server::{
    build_state,
    config::{
        BusinessConfig, Config, CorsConfig, DatabaseConfig, Environment, JwtConfig, LimitsConfig,
        ProxyConfig, PublicClientIpHeader, PushConfig, PushProvider, RedisConfig, ReleasesConfig,
        S3Config, ServerConfig, TurnConfig,
    },
    db, http,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn certified_desktop_linking_is_bound_replay_safe_and_revocable() {
    if env::var("SKIP_INTEGRATION").ok().as_deref() == Some("1") {
        eprintln!("skipping integration test by explicit SKIP_INTEGRATION=1 opt-in");
        return;
    }

    let state = build_state(integration_config())
        .await
        .expect("build app state");
    db::migrate(&state.pg).await.expect("run migrations");
    let app = http::router(state.clone());

    let suffix = Uuid::new_v4().simple().to_string();
    let public_id = format!("link_{}", &suffix[..12]);
    let (_, registered) = request_json(
        app.clone(),
        Method::POST,
        "/v1/auth/register",
        None,
        Some(json!({
            "public_id": public_id,
            "password": "correct horse battery staple"
        })),
    )
    .await;
    assert!(registered["user"]["id"].as_str().is_some());

    let (status, login) = request_json(
        app.clone(),
        Method::POST,
        "/v1/auth/login",
        None,
        Some(json!({
            "public_id": public_id,
            "password": "correct horse battery staple"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let bootstrap = login["access_token"].as_str().expect("bootstrap token");

    let (status, android) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/register",
        Some(bootstrap),
        Some(json!({
            "display_name": "Android primary",
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{android}");
    let android_id = android["device"]["id"].as_str().expect("android id");
    let android_token = android["access_token"].as_str().expect("android token");

    let android_identity = key_material("android-authorizer-identity-key-0001");
    upload_keys(app.clone(), android_token, android_id, &android_identity).await;

    let desktop_id = Uuid::new_v4();
    let pairing_session_id = Uuid::new_v4();
    let desktop_identity = key_material("windows-desktop-identity-key-0001");
    let authorizer_signature = key_material("android-authorizer-signature-0001");
    let pairing_public_key = general_purpose::STANDARD_NO_PAD.encode([0x42_u8; 32]);
    let claim_secret = general_purpose::STANDARD_NO_PAD.encode([0x24_u8; 32]);
    let claim_secret_hash = hex_lower(&Sha256::digest([0x24_u8; 32]));
    let expires_at_unix_ms = Utc::now().timestamp_millis() + 120_000;
    let candidate_commitment = candidate_commitment(
        pairing_session_id,
        desktop_id,
        "Windows desktop",
        "windows",
        1,
        1,
        127,
        expires_at_unix_ms,
        &pairing_public_key,
        &desktop_identity,
        &claim_secret_hash,
    );

    let (status, candidate) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/candidate",
        None,
        Some(json!({
            "pairing_session_id": pairing_session_id,
            "device_id": desktop_id,
            "display_name": "Windows desktop",
            "platform": "windows",
            "protocol_version": 1,
            "min_supported_version": 1,
            "capabilities": 127,
            "expires_at_unix_ms": expires_at_unix_ms,
            "pairing_public_key": pairing_public_key,
            "target_identity_key": desktop_identity,
            "claim_secret_hash": claim_secret_hash,
            "candidate_commitment": candidate_commitment
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{candidate}");
    assert_eq!(candidate["device_id"], desktop_id.to_string());

    let (status, fetched) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/devices/link/candidate/{pairing_session_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(fetched["candidate_commitment"], candidate_commitment);

    let (status, substitution) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/authorize",
        Some(android_token),
        Some(json!({
            "device_id": desktop_id,
            "display_name": "Windows desktop",
            "platform": "windows",
            "pairing_session_id": pairing_session_id,
            "protocol_version": 1,
            "min_supported_version": 1,
            "capabilities": 127,
            "issued_at_unix_ms": Utc::now().timestamp_millis(),
            "target_identity_key": key_material("substituted-desktop-identity-key"),
            "candidate_commitment": candidate_commitment,
            "authorizer_signature": authorizer_signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{substitution}");
    assert_eq!(
        substitution["error_code"],
        "PAIRING_CANDIDATE_SUBSTITUTION"
    );

    let issued_at_unix_ms = Utc::now().timestamp_millis();
    let (status, linked) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/authorize",
        Some(android_token),
        Some(json!({
            "device_id": desktop_id,
            "display_name": "Windows desktop",
            "platform": "windows",
            "pairing_session_id": pairing_session_id,
            "protocol_version": 1,
            "min_supported_version": 1,
            "capabilities": 127,
            "issued_at_unix_ms": issued_at_unix_ms,
            "target_identity_key": desktop_identity,
            "candidate_commitment": candidate_commitment,
            "authorizer_signature": authorizer_signature
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{linked}");
    assert_eq!(linked["device"]["id"], desktop_id.to_string());
    assert_eq!(
        linked["device"]["authorization"]["authorizing_device_id"],
        android_id
    );
    assert!(linked["device"]["authorization"]["canonical_payload"]
        .as_str()
        .expect("canonical authorization payload")
        .contains(&format!("pairing_session_id={pairing_session_id}\n")));

    assert_eq!(linked["status"], "authorized");
    assert!(linked.get("access_token").is_none());

    let (status, wrong_claim) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/claim",
        None,
        Some(json!({
            "pairing_session_id": pairing_session_id,
            "claim_secret": general_purpose::STANDARD_NO_PAD.encode([0x25_u8; 32])
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong_claim}");

    let (status, claimed) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/claim",
        None,
        Some(json!({
            "pairing_session_id": pairing_session_id,
            "claim_secret": claim_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    let desktop_token = claimed["access_token"]
        .as_str()
        .expect("claimed desktop token")
        .to_owned();
    assert_eq!(claimed["device"]["id"], desktop_id.to_string());

    let (status, claim_replay) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/claim",
        None,
        Some(json!({
            "pairing_session_id": pairing_session_id,
            "claim_secret": claim_secret
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{claim_replay}");
    assert_eq!(claim_replay["error_code"], "PAIRING_CLAIM_ALREADY_USED");

    let (status, replay) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/link/authorize",
        Some(android_token),
        Some(json!({
            "device_id": Uuid::new_v4(),
            "display_name": "Replay desktop",
            "platform": "linux",
            "pairing_session_id": pairing_session_id,
            "protocol_version": 1,
            "min_supported_version": 1,
            "capabilities": 127,
            "issued_at_unix_ms": Utc::now().timestamp_millis(),
            "target_identity_key": key_material("linux-replay-identity-key-0001"),
            "candidate_commitment": candidate_commitment,
            "authorizer_signature": key_material("android-replay-signature-0001")
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{replay}");

    let (status, mismatch) = upload_keys_raw(
        app.clone(),
        &desktop_token,
        &desktop_id.to_string(),
        &key_material("wrong-desktop-identity-key-0001"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{mismatch}");
    assert_eq!(mismatch["error_code"], "LINKED_DEVICE_IDENTITY_MISMATCH");

    upload_keys(
        app.clone(),
        &desktop_token,
        &desktop_id.to_string(),
        &desktop_identity,
    )
    .await;

    let user_id = registered["user"]["id"].as_str().expect("user id");
    let (status, bundle) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/keys/{user_id}/devices"),
        Some(android_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    let desktop_bundle = bundle["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|device| device["device_id"] == desktop_id.to_string())
        .expect("linked desktop key bundle");
    assert_eq!(
        desktop_bundle["authorization"]["authorizing_device_id"],
        android_id
    );

    let (status, revoked) = request_json(
        app.clone(),
        Method::DELETE,
        &format!("/v1/devices/{desktop_id}"),
        Some(android_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");

    let (status, stale) =
        request_json(app, Method::GET, "/v1/devices", Some(&desktop_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{stale}");
}

async fn upload_keys(app: Router, token: &str, device_id: &str, identity_key: &str) {
    let (status, body) = upload_keys_raw(app, token, device_id, identity_key).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn upload_keys_raw(
    app: Router,
    token: &str,
    device_id: &str,
    identity_key: &str,
) -> (StatusCode, Value) {
    request_json(
        app,
        Method::POST,
        "/v1/keys/upload",
        Some(token),
        Some(json!({
            "device_id": device_id,
            "identity_key": identity_key,
            "registration_id": 12345,
            "protocol_device_id": 1,
            "signed_prekey": {
                "key_id": 1,
                "public_key": key_material("signed-prekey-public-key-0001"),
                "signature": key_material("signed-prekey-signature-0001")
            },
            "kyber_prekey": {
                "key_id": 2,
                "public_key": key_material("kyber-prekey-public-key-0001"),
                "signature": key_material("kyber-prekey-signature-0001")
            },
            "one_time_prekeys": [
                {
                    "key_id": 1,
                    "public_key": key_material("one-time-prekey-public-key-0001")
                }
            ]
        })),
    )
    .await
}

fn key_material(value: &str) -> String {
    general_purpose::STANDARD_NO_PAD.encode(value.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn candidate_commitment(
    pairing_session_id: Uuid,
    device_id: Uuid,
    display_name: &str,
    platform: &str,
    protocol_version: i32,
    min_supported_version: i32,
    capabilities: i64,
    expires_at_unix_ms: i64,
    pairing_public_key: &str,
    target_identity_key: &str,
    claim_secret_hash: &str,
) -> String {
    let canonical = format!(
        concat!(
            "ENIGMA_PAIRING_CANDIDATE_V1\n",
            "pairing_session_id={}\n",
            "device_id={}\n",
            "display_name={}\n",
            "platform={}\n",
            "protocol_version={}\n",
            "min_supported_version={}\n",
            "capabilities={}\n",
            "expires_at_unix_ms={}\n",
            "pairing_public_key={}\n",
            "target_identity_key={}\n",
            "claim_secret_hash={}\n"
        ),
        pairing_session_id,
        device_id,
        display_name,
        platform,
        protocol_version,
        min_supported_version,
        capabilities,
        expires_at_unix_ms,
        pairing_public_key,
        target_identity_key,
        claim_secret_hash,
    );
    general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

async fn request_json(
    app: Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request_body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .oneshot(builder.body(request_body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("body bytes");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, body)
}

fn integration_config() -> Config {
    let database_url = env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://enigma:enigma_dev_password@localhost:15432/enigma".into());
    let redis_url = env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://localhost:16379".into());

    Config {
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
        },
        environment: Environment::Test,
        database: DatabaseConfig {
            url: database_url,
            max_connections: 5,
        },
        redis: RedisConfig { url: redis_url },
        jwt: JwtConfig {
            secret: "test-secret-test-secret-test-secret-32".into(),
            access_ttl: Duration::from_secs(3600),
            issuer: "enigma-v1-test".into(),
            audience: "enigma-api-test".into(),
            accept_legacy_tokens: true,
        },
        proxy: ProxyConfig {
            trusted_proxies: vec![],
            public_client_ip_header: PublicClientIpHeader::None,
        },
        cors: CorsConfig {
            allowed_origins: vec!["*".into()],
        },
        limits: LimitsConfig {
            max_json_body_bytes: 1_048_576,
            max_ciphertext_bytes: 262_144,
            rate_limit_window: Duration::from_secs(60),
            rate_limit_max_requests: 120,
            message_ttl: Duration::from_secs(604_800),
        },
        s3: S3Config {
            endpoint: env::var("TEST_S3_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:19000".into()),
            region: "us-east-1".into(),
            access_key_id: env::var("TEST_S3_ACCESS_KEY_ID")
                .unwrap_or_else(|_| "minioadmin".into()),
            secret_access_key: env::var("TEST_S3_SECRET_ACCESS_KEY")
                .unwrap_or_else(|_| "minioadmin123".into()),
            bucket: env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "enigma-attachments".into()),
            force_path_style: true,
            upload_presign_ttl: Duration::from_secs(900),
            download_presign_ttl: Duration::from_secs(900),
            attachment_ttl: Duration::from_secs(604_800),
            max_attachment_bytes: 104_857_600,
        },
        turn: TurnConfig {
            secret: "test-turn-shared-secret".into(),
            realm: "enigma.test".into(),
            ttl: Duration::from_secs(600),
            uris: vec!["turn:localhost:3478?transport=udp".into()],
        },
        push: PushConfig {
            provider: PushProvider::Noop,
        },
        releases: ReleasesConfig { android: None },
        business: BusinessConfig {
            official_relay_mode: false,
            admin_token: None,
            support_enabled: false,
            donation_urls: [None, None, None],
            premium_urls: [None, None, None],
            attachment_pending_ttl: Duration::from_secs(3600),
            attachment_unattached_ttl: Duration::from_secs(86_400),
            attachment_purge_batch_size: 500,
            free_upload_daily_bytes: 262_144_000,
            free_upload_daily_count: 100,
        },
    }
}
