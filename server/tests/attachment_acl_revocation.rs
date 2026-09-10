use std::{env, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use enigma_e2ee_server::{
    build_state,
    config::{
        BusinessConfig, Config, CorsConfig, DatabaseConfig, Environment, JwtConfig, LimitsConfig,
        ProxyConfig, PublicClientIpHeader, PushConfig, PushProvider, RedisConfig, ReleasesConfig,
        S3Config, ServerConfig, TurnConfig,
    },
    db, http, AppState,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn attachment_acl_revocation_flow() {
    if env::var("SKIP_INTEGRATION").ok().as_deref() == Some("1") {
        eprintln!("skipping integration test by explicit SKIP_INTEGRATION=1 opt-in");
        return;
    }

    let state = build_state(integration_config())
        .await
        .expect("build app state");
    db::migrate(&state.pg).await.expect("run migrations");
    let app = http::router(state.clone());

    let alice = register_identity(app.clone(), "acl_alice").await;
    let bob = register_identity(app.clone(), "acl_bob").await;

    let (status, bubbles) = request_json(
        app.clone(),
        Method::GET,
        "/v1/bubbles",
        Some(&alice.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bubbles}");
    let bubble_id = Uuid::parse_str(
        bubbles["bubbles"][0]["id"]
            .as_str()
            .expect("alice main bubble id"),
    )
    .expect("bubble UUID");

    let (status, group) = request_json(
        app.clone(),
        Method::POST,
        "/v1/groups",
        Some(&alice.device_token),
        Some(json!({"bubble_id": bubble_id, "title": "ACL group"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    let group_id =
        Uuid::parse_str(group["group"]["id"].as_str().expect("group id")).expect("group UUID");

    let (status, member) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/members"),
        Some(&alice.device_token),
        Some(json!({"user_id": bob.user_id, "role": "member"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{member}");

    let group_attachment = seed_verified_attachment(&state, alice.user_id, bubble_id).await;
    sqlx::query(
        "INSERT INTO attachment_references
            (id,blob_id,owner_id,bubble_id,conversation_kind,group_message_id,group_id,expires_at)
         VALUES ($1,$2,$3,$4,'group',$5,$6,now() + interval '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(group_attachment.blob_id)
    .bind(alice.user_id)
    .bind(bubble_id)
    .bind(Uuid::new_v4())
    .bind(group_id)
    .execute(&state.pg)
    .await
    .expect("seed group attachment reference");

    assert_download_status(
        app.clone(),
        &bob.device_token,
        bubble_id,
        &group_attachment,
        StatusCode::OK,
    )
    .await;

    let (status, removed) = request_json(
        app.clone(),
        Method::DELETE,
        &format!("/v1/groups/{group_id}/members/{}", bob.user_id),
        Some(&alice.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");

    assert_download_status(
        app.clone(),
        &bob.device_token,
        bubble_id,
        &group_attachment,
        StatusCode::FORBIDDEN,
    )
    .await;

    let (status, channel) = request_json(
        app.clone(),
        Method::POST,
        "/v1/channels",
        Some(&alice.device_token),
        Some(json!({
            "bubble_id": bubble_id,
            "title": "ACL channel",
            "description": "revocation test"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{channel}");
    let channel_id =
        Uuid::parse_str(channel["id"].as_str().expect("channel id")).expect("channel UUID");

    let (status, subscribed) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/subscribe"),
        Some(&bob.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{subscribed}");

    let channel_attachment = seed_verified_attachment(&state, alice.user_id, bubble_id).await;
    sqlx::query(
        "INSERT INTO attachment_references
            (id,blob_id,owner_id,bubble_id,conversation_kind,channel_post_id,channel_id,expires_at)
         VALUES ($1,$2,$3,$4,'channel',$5,$6,now() + interval '1 hour')",
    )
    .bind(Uuid::new_v4())
    .bind(channel_attachment.blob_id)
    .bind(alice.user_id)
    .bind(bubble_id)
    .bind(Uuid::new_v4())
    .bind(channel_id)
    .execute(&state.pg)
    .await
    .expect("seed channel attachment reference");

    assert_download_status(
        app.clone(),
        &bob.device_token,
        bubble_id,
        &channel_attachment,
        StatusCode::OK,
    )
    .await;

    let (status, unsubscribed) = request_json(
        app.clone(),
        Method::DELETE,
        &format!("/v1/channels/{channel_id}/subscribe"),
        Some(&bob.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{unsubscribed}");

    assert_download_status(
        app.clone(),
        &bob.device_token,
        bubble_id,
        &channel_attachment,
        StatusCode::FORBIDDEN,
    )
    .await;

    let (status, revoked) = request_json(
        app.clone(),
        Method::DELETE,
        &format!("/v1/devices/{}", bob.device_id),
        Some(&bob.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");

    let (status, stale_token) = request_json(
        app,
        Method::GET,
        "/v1/devices",
        Some(&bob.device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{stale_token}");
}

#[derive(Debug)]
struct TestIdentity {
    user_id: Uuid,
    device_id: Uuid,
    device_token: String,
}

#[derive(Debug)]
struct SeededAttachment {
    blob_id: Uuid,
    download_secret: String,
}

async fn register_identity(app: Router, prefix: &str) -> TestIdentity {
    let suffix = Uuid::new_v4().simple().to_string();
    let public_id = format!("{prefix}_{}", &suffix[..12]);
    let (status, registered) = request_json(
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
    assert_eq!(status, StatusCode::OK, "{registered}");
    let user_id = Uuid::parse_str(
        registered["user"]["id"]
            .as_str()
            .expect("registered user id"),
    )
    .expect("user UUID");

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
    let bootstrap_token = login["access_token"]
        .as_str()
        .expect("bootstrap access token")
        .to_owned();

    let (status, device) = request_json(
        app,
        Method::POST,
        "/v1/devices/register",
        Some(&bootstrap_token),
        Some(json!({
            "display_name": format!("{prefix} device"),
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{device}");

    TestIdentity {
        user_id,
        device_id: Uuid::parse_str(device["device"]["id"].as_str().expect("device id"))
            .expect("device UUID"),
        device_token: device["access_token"]
            .as_str()
            .expect("device access token")
            .to_owned(),
    }
}

async fn seed_verified_attachment(
    state: &AppState,
    owner_id: Uuid,
    bubble_id: Uuid,
) -> SeededAttachment {
    let blob_id = Uuid::new_v4();
    let download_secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let secret_hash = sha256_hex(download_secret.as_bytes());
    let sha256 = sha256_hex(b"acl-test-ciphertext");

    sqlx::query(
        "INSERT INTO attachments
            (id,blob_id,bubble_id,owner_id,object_key,size_bytes,sha256,content_type,expires_at,
             download_secret_hash,status,completed_at,verified_at,actual_size_bytes,actual_sha256)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'application/octet-stream',now() + interval '1 hour',
                 $8,'verified',now(),now(),$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(blob_id)
    .bind(bubble_id)
    .bind(owner_id)
    .bind(format!("acl-test/{blob_id}"))
    .bind(19_i64)
    .bind(&sha256)
    .bind(secret_hash)
    .execute(&state.pg)
    .await
    .expect("seed verified attachment");

    SeededAttachment {
        blob_id,
        download_secret,
    }
}

async fn assert_download_status(
    app: Router,
    token: &str,
    bubble_id: Uuid,
    attachment: &SeededAttachment,
    expected: StatusCode,
) {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/attachments/presign-download",
        Some(token),
        Some(json!({
            "blob_id": attachment.blob_id,
            "bubble_id": bubble_id,
            "download_secret": attachment.download_secret
        })),
    )
    .await;
    assert_eq!(status, expected, "{body}");
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
