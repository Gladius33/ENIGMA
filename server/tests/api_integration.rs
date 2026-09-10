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
    db, http,
    security::password,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn core_endpoint_flow() {
    if env::var("SKIP_INTEGRATION").ok().as_deref() == Some("1") {
        eprintln!("skipping integration test by explicit SKIP_INTEGRATION=1 opt-in");
        return;
    }
    let config = integration_config();

    let state = build_state(config).await.expect("build app state");
    db::migrate(&state.pg).await.expect("run migrations");
    let app = http::router(state);

    let (status, _) = request_json(app.clone(), Method::GET, "/v1/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, version) = request_json(app.clone(), Method::GET, "/version", None, None).await;
    assert_eq!(status, StatusCode::OK, "{version}");
    assert_eq!(version["name"], "enigma-e2ee-server");
    let (status, release_error) = request_json(
        app.clone(),
        Method::GET,
        "/v1/releases/android?channel=stable",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{release_error}");
    assert_eq!(release_error["error_code"], "RELEASE_NOT_CONFIGURED");
    assert!(release_error["request_id"].as_str().is_some());

    let identity_suffix = Uuid::new_v4().simple().to_string();
    let identity_handle = format!("Id_{}", &identity_suffix[..12]);
    let (status, available) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/identities/check?handle={identity_handle}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{available}");
    assert_eq!(available["available"], true);

    let recovery_secret = "identity recovery secret 123";
    let recovery_verifier = password::hash_password(recovery_secret).expect("recovery verifier");
    let (status, identity) = request_json(
        app.clone(),
        Method::POST,
        "/v1/identities",
        None,
        Some(json!({
            "display_name": identity_handle,
            "password": "correct horse battery staple",
            "identity_public_key": "opaque-public-identity-key",
            "signed_prekey": "opaque-signed-prekey",
            "signed_prekey_signature": "opaque-signed-prekey-signature",
            "one_time_prekeys": ["opaque-one-time-prekey"],
            "device_name": "Identity Pixel",
            "device_public_key": "opaque-device-public-key",
            "recovery_key_verifier": recovery_verifier
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{identity}");
    assert_eq!(
        identity["canonical_handle"],
        identity_handle.to_ascii_lowercase()
    );
    assert_eq!(
        identity["public_handle"],
        format!("@{}", identity_handle.to_ascii_lowercase())
    );
    let identity_token = identity["access_token"].as_str().expect("identity token");

    let (status, taken) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/identities/check?handle={identity_handle}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{taken}");
    assert_eq!(taken["available"], false);
    assert_eq!(taken["reason"], "HANDLE_ALREADY_TAKEN");

    let (status, deleted) = request_json(
        app.clone(),
        Method::DELETE,
        "/v1/identities/me",
        Some(identity_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["reserved_forever"], true);

    let (status, reserved) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/identities/check?handle={identity_handle}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reserved}");
    assert_eq!(reserved["available"], false);
    assert_eq!(reserved["reason"], "HANDLE_RESERVED");

    let alice_suffix = Uuid::new_v4().simple().to_string();
    let alice_public_id = format!("alice_{}", &alice_suffix[..12]);
    let alice = register_user(app.clone(), &alice_public_id).await;
    let alice_user_id = alice["user"]["id"].as_str().expect("alice user id");
    let alice_login = login_user(app.clone(), &alice_public_id).await;
    let alice_token = alice_login["access_token"].as_str().expect("alice token");

    let bob_suffix = Uuid::new_v4().simple().to_string();
    let bob_public_id = format!("bob_{}", &bob_suffix[..12]);
    let bob = register_user(app.clone(), &bob_public_id).await;
    let bob_user_id = bob["user"]["id"].as_str().expect("bob user id");
    let bob_login = login_user(app.clone(), &bob_public_id).await;
    let bob_token = bob_login["access_token"].as_str().expect("bob token");

    let alice_device = register_device(app.clone(), alice_token, "Alice Pixel").await;
    let alice_device_id = alice_device["device"]["id"]
        .as_str()
        .expect("alice device id");
    let alice_device_token = alice_device["access_token"]
        .as_str()
        .expect("alice device token");
    assert_eq!(alice_device["token_type"], "Bearer");

    let alice_relogin = login_user(app.clone(), &alice_public_id).await;
    let alice_relogin_token = alice_relogin["access_token"]
        .as_str()
        .expect("alice relogin token");
    let alice_same_device = register_device_with_id(
        app.clone(),
        alice_relogin_token,
        "Alice Relay Pixel",
        alice_device_id,
    )
    .await;
    assert_eq!(alice_same_device["device"]["id"], alice_device_id);
    assert_eq!(alice_same_device["token_type"], "Bearer");

    let (status, device_conflict) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/register",
        Some(bob_token),
        Some(json!({
            "device_id": alice_device_id,
            "display_name": "Bob Conflicting Pixel",
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{device_conflict}");
    assert_eq!(
        device_conflict["error_code"],
        "DEVICE_ID_ALREADY_REGISTERED"
    );

    let bob_device = register_device(app.clone(), bob_token, "Bob Pixel").await;
    let bob_device_id = bob_device["device"]["id"].as_str().expect("bob device id");
    let bob_device_token = bob_device["access_token"]
        .as_str()
        .expect("bob device token");
    assert_eq!(bob_device["token_type"], "Bearer");

    let (status, fcm) = request_json(
        app.clone(),
        Method::POST,
        "/v1/devices/fcm-token",
        Some(bob_device_token),
        Some(json!({
            "fcm_token": "fcm_token_for_bob_android_device",
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fcm}");
    assert_eq!(fcm["status"], "ok");

    let (status, resolve_body) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/users/resolve/{bob_public_id}"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resolve_body}");
    assert_eq!(resolve_body["id"], bob_user_id);

    let (status, devices) = request_json(
        app.clone(),
        Method::GET,
        "/v1/devices",
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{devices}");
    assert_eq!(devices["devices"][0]["id"], alice_device_id);

    let (status, official_relay) = request_json(
        app.clone(),
        Method::GET,
        "/v1/relays/official-descriptor",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{official_relay}");
    assert_eq!(official_relay["name"], "Relais officiel Enigma");
    assert_eq!(official_relay["type"], "OFFICIAL");
    assert_eq!(official_relay["trust_level"], "VERIFIED");
    assert_eq!(official_relay["is_official"], true);

    let (status, relays) = request_json(
        app.clone(),
        Method::GET,
        "/v1/relays",
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{relays}");
    let official_relay_id = relays["relays"][0]["id"]
        .as_str()
        .expect("official relay id");
    assert_eq!(relays["relays"][0]["is_official"], true);

    let (status, custom_relay) = request_json(
        app.clone(),
        Method::POST,
        "/v1/relays/custom",
        Some(alice_device_token),
        Some(json!({
            "name": "Relais prive lab",
            "url": "wss://relay-private.example",
            "relay_type": "PRIVATE"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{custom_relay}");
    assert_eq!(custom_relay["type"], "PRIVATE");

    let (status, bubbles) = request_json(
        app.clone(),
        Method::GET,
        "/v1/bubbles",
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bubbles}");
    assert_eq!(bubbles["bubbles"][0]["mode"], "MAIN_GLOBAL");
    let main_bubble_id = bubbles["bubbles"][0]["id"]
        .as_str()
        .expect("main bubble id");

    let (status, bubble_relays) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/bubbles/{main_bubble_id}/relays"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bubble_relays}");
    assert_eq!(bubble_relays["relays"][0]["relay_id"], official_relay_id);

    let (status, attached_relay) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/bubbles/{main_bubble_id}/relays"),
        Some(alice_device_token),
        Some(json!({
            "relay_id": custom_relay["id"],
            "role": "primary",
            "priority": 0,
            "required": false,
            "fallback_allowed": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{attached_relay}");
    assert_eq!(attached_relay["relay_id"], custom_relay["id"]);

    let (status, contact) = request_json(
        app.clone(),
        Method::POST,
        "/v1/contacts",
        Some(alice_device_token),
        Some(json!({ "contact_user_id": bob_user_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{contact}");
    assert_eq!(contact["user_id"], bob_user_id);

    let (status, contacts) = request_json(
        app.clone(),
        Method::GET,
        "/v1/contacts",
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{contacts}");
    assert_eq!(contacts["contacts"][0]["user_id"], bob_user_id);

    upload_keys(app.clone(), bob_device_token, bob_device_id).await;

    let (status, bundle) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/keys/{bob_user_id}"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["user_id"], bob_user_id);
    assert_eq!(bundle["devices"][0]["device_id"], bob_device_id);
    assert_eq!(bundle["devices"][0]["registration_id"], 12345);
    assert_eq!(bundle["devices"][0]["protocol_device_id"], 1);
    assert_eq!(bundle["devices"][0]["kyber_prekey"]["key_id"], 2);
    assert_eq!(
        bundle["devices"][0]["kyber_prekey"]["public_key"],
        key_material("opaque-kyber-prekey-v1")
    );
    assert_eq!(
        bundle["devices"][0]["kyber_prekey"]["signature"],
        key_material("opaque-kyber-prekey-signature-v1")
    );
    assert_eq!(bundle["devices"][0]["one_time_prekey_count"], 1);
    assert!(bundle["devices"][0]["one_time_prekey"].is_null());

    let (status, devices_discovery) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/keys/{bob_user_id}/devices"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{devices_discovery}");
    assert_eq!(devices_discovery["devices"][0]["one_time_prekey_count"], 1);

    let bootstrap_suffix = Uuid::new_v4().simple().to_string();
    let bootstrap_public_id = format!("bootstrap_{}", &bootstrap_suffix[..12]);
    let bootstrap_only = register_user(app.clone(), &bootstrap_public_id).await;
    let bootstrap_only_token = bootstrap_only["access_token"]
        .as_str()
        .expect("bootstrap-only token");

    let (status, bootstrap_claim) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/keys/{bob_user_id}/devices/{bob_device_id}/claim-prekey"),
        Some(bootstrap_only_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{bootstrap_claim}");
    assert_eq!(bootstrap_claim["error_code"], "FORBIDDEN");

    let (status, devices_after_bootstrap_claim) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/keys/{bob_user_id}/devices"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{devices_after_bootstrap_claim}");
    assert_eq!(
        devices_after_bootstrap_claim["devices"][0]["one_time_prekey_count"],
        1
    );

    let (status, claimed) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/keys/{bob_user_id}/devices/{bob_device_id}/claim-prekey"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert!(claimed["device"]["one_time_prekey"].is_object());
    assert_eq!(claimed["device"]["one_time_prekey_count_after_claim"], 0);

    let (status, exhausted_claim) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/keys/{bob_user_id}/devices/{bob_device_id}/claim-prekey"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exhausted_claim}");
    assert!(exhausted_claim["device"]["one_time_prekey"].is_null());
    assert_eq!(
        exhausted_claim["device"]["one_time_prekey_count_after_claim"],
        0
    );

    let (status, bob_key_status) = request_json(
        app.clone(),
        Method::GET,
        "/v1/keys/status",
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bob_key_status}");
    assert_eq!(bob_key_status["one_time_prekey_count"], 0);

    let client_message_id = Uuid::new_v4().to_string();
    let ciphertext = "b3BhcXVlLWNsaWVudC1lbmNyeXB0ZWQtZW52ZWxvcGU=";
    let (status, sent) = request_json(
        app.clone(),
        Method::POST,
        "/v1/messages",
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "recipient_device_id": bob_device_id,
            "client_message_id": client_message_id,
            "message_type": "text",
            "ciphertext": ciphertext
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["id"].as_str().expect("message id");
    assert_eq!(sent["bubble_id"], main_bubble_id);
    assert_eq!(sent["client_message_id"], client_message_id);

    let (status, pending) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/pending?device_id={bob_device_id}"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["messages"][0]["id"], message_id);
    assert_eq!(pending["messages"][0]["bubble_id"], main_bubble_id);
    assert_eq!(
        pending["messages"][0]["client_message_id"],
        client_message_id
    );
    assert_eq!(pending["messages"][0]["message_type"], "text");
    assert_eq!(pending["messages"][0]["ciphertext"], ciphertext);

    let (status, forbidden_pending) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/pending?device_id={bob_device_id}"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{forbidden_pending}");

    let (status, receipt) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({"device_id": bob_device_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["status"], "delivered");

    let (status, sent_receipts) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/receipts?device_id={alice_device_id}"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent_receipts}");
    assert_eq!(sent_receipts["receipts"][0]["message_id"], message_id);
    assert_eq!(sent_receipts["receipts"][0]["bubble_id"], main_bubble_id);
    assert_eq!(
        sent_receipts["receipts"][0]["client_message_id"],
        client_message_id
    );
    assert_eq!(sent_receipts["receipts"][0]["status"], "delivered");

    let (status, read_receipt) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({"device_id": bob_device_id, "status": "read"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{read_receipt}");
    assert_eq!(read_receipt["status"], "read");

    let (status, read_sent_receipts) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/receipts?device_id={alice_device_id}"),
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{read_sent_receipts}");
    assert_eq!(read_sent_receipts["receipts"][0]["status"], "read");

    let (status, delivered_after_read) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({"device_id": bob_device_id, "status": "delivered"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{delivered_after_read}");
    assert_eq!(delivered_after_read["status"], "read");

    let (status, invalid_receipt_status) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({"device_id": bob_device_id, "status": "seen"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid_receipt_status}");
    assert_eq!(
        invalid_receipt_status["error_code"],
        "INVALID_RECEIPT_STATUS"
    );

    let (status, forbidden_receipts) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/receipts?device_id={alice_device_id}"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{forbidden_receipts}");

    let (status, second_receipt) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({"device_id": bob_device_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_receipt}");
    assert_eq!(second_receipt["status"], "read");

    let (status, pending_after_ack) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/pending?device_id={bob_device_id}"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending_after_ack}");
    assert_eq!(
        pending_after_ack["messages"]
            .as_array()
            .expect("messages")
            .len(),
        0
    );

    for message_type in ["text", "image", "file", "audio_message"] {
        send_and_ack_direct_message_type(
            app.clone(),
            DirectDevice {
                token: alice_device_token,
                device_id: alice_device_id,
            },
            DirectDevice {
                token: bob_device_token,
                device_id: bob_device_id,
            },
            main_bubble_id,
            message_type,
            ciphertext,
        )
        .await;
    }

    let attachment_bytes = vec![42_u8; 64];
    let attachment_sha256 = sha256_hex(&attachment_bytes);
    let (status, upload) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-upload",
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "size_bytes": 64,
            "sha256": attachment_sha256,
            "content_type": "application/octet-stream"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{upload}");
    assert_eq!(upload["bubble_id"], main_bubble_id);
    assert_eq!(upload["method"], "PUT");
    assert!(upload["url"]
        .as_str()
        .expect("upload URL")
        .starts_with("http"));

    let (status, denied_download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(bob_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": "wrong-download-secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{denied_download}");

    let (status, pending_download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(bob_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": upload["download_secret"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{pending_download}");

    let upload_response = reqwest::Client::new()
        .put(upload["url"].as_str().expect("upload url"))
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(attachment_bytes)
        .send()
        .await
        .expect("upload object");
    assert!(
        upload_response.status().is_success(),
        "upload object status {}",
        upload_response.status()
    );

    let (status, completed_attachment) = request_json(
        app.clone(),
        Method::POST,
        &format!(
            "/v1/attachments/{}/complete",
            upload["blob_id"].as_str().expect("blob id")
        ),
        Some(alice_device_token),
        Some(json!({
            "download_secret": upload["download_secret"],
            "size_bytes": 64,
            "sha256": attachment_sha256
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed_attachment}");
    assert_eq!(completed_attachment["bubble_id"], main_bubble_id);
    assert_eq!(completed_attachment["status"], "verified");

    let (status, owner_download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(alice_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": upload["download_secret"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{owner_download}");

    let (status, unbound_recipient_download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(bob_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": upload["download_secret"]
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{unbound_recipient_download}"
    );

    let attachment_message_id = Uuid::new_v4().to_string();
    let (status, attachment_sent) = request_json(
        app.clone(),
        Method::POST,
        "/v1/messages",
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "recipient_device_id": bob_device_id,
            "client_message_id": attachment_message_id,
            "message_type": "file",
            "ciphertext": ciphertext,
            "attachment_blob_ids": [upload["blob_id"]]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{attachment_sent}");

    let (status, download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(bob_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": upload["download_secret"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{download}");
    assert_eq!(download["bubble_id"], main_bubble_id);
    assert_eq!(download["method"], "GET");

    let bootstrap_device =
        register_device(app.clone(), bootstrap_only_token, "Bootstrap Pixel").await;
    let bootstrap_device_token = bootstrap_device["access_token"]
        .as_str()
        .expect("bootstrap device token");
    let (status, unrelated_download) = request_json(
        app.clone(),
        Method::POST,
        "/v1/attachments/presign-download",
        Some(bootstrap_device_token),
        Some(json!({
            "blob_id": upload["blob_id"],
            "bubble_id": main_bubble_id,
            "download_secret": upload["download_secret"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{unrelated_download}");

    let (status, group) = request_json(
        app.clone(),
        Method::POST,
        "/v1/groups",
        Some(alice_device_token),
        Some(json!({ "bubble_id": main_bubble_id, "title": "V1 group" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["group"]["bubble_id"], main_bubble_id);
    let group_id = group["group"]["id"].as_str().expect("group id");

    let (status, member) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/members"),
        Some(alice_device_token),
        Some(json!({ "user_id": bob_user_id, "role": "member" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{member}");
    assert_eq!(member["user_id"], bob_user_id);

    let group_client_message_id = Uuid::new_v4().to_string();
    let (status, group_sent) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/messages"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_message_id": group_client_message_id,
            "message_type": "opaque",
            "ciphertext": ciphertext,
            "attachment_blob_ids": [upload["blob_id"]]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group_sent}");
    assert_eq!(group_sent["bubble_id"], main_bubble_id);
    let group_message_id = group_sent["id"].as_str().expect("group message id");

    let (status, group_retry) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/messages"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_message_id": group_client_message_id,
            "message_type": "opaque",
            "ciphertext": ciphertext,
            "attachment_blob_ids": [upload["blob_id"]]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group_retry}");
    assert_eq!(group_retry["id"], group_message_id);

    let (status, group_conflict) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/messages"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_message_id": group_client_message_id,
            "message_type": "opaque",
            "ciphertext": "ZGlmZmVyZW50LWdyb3VwLWNpcGhlcnRleHQ="
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{group_conflict}");

    let (status, group_pending) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/groups/{group_id}/messages/pending"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group_pending}");
    assert_eq!(group_pending["messages"][0]["id"], group_message_id);
    assert_eq!(group_pending["messages"][0]["bubble_id"], main_bubble_id);

    let (status, group_receipt) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/groups/{group_id}/messages/{group_message_id}/receipt"),
        Some(bob_device_token),
        Some(json!({ "device_id": bob_device_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group_receipt}");

    let (status, channel) = request_json(
        app.clone(),
        Method::POST,
        "/v1/channels",
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "title": "V1 channel",
            "description": "opaque posts only"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{channel}");
    assert_eq!(channel["bubble_id"], main_bubble_id);
    let channel_id = channel["id"].as_str().expect("channel id");

    let (status, subscribed) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/subscribe"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{subscribed}");

    let (status, subscribers) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/channels/{channel_id}/subscribers"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{subscribers}");
    let subscriber_public_ids = subscribers["subscribers"]
        .as_array()
        .expect("channel subscribers")
        .iter()
        .map(|member| member["public_id"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert!(subscriber_public_ids.contains(&alice_public_id.as_str()));
    assert!(subscriber_public_ids.contains(&bob_public_id.as_str()));

    let (status, forbidden_post) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/posts"),
        Some(bob_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": bob_device_id,
            "client_post_id": Uuid::new_v4(),
            "post_type": "opaque",
            "ciphertext": ciphertext
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{forbidden_post}");

    let client_post_id = Uuid::new_v4().to_string();
    let (status, post) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/posts"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_post_id": client_post_id,
            "post_type": "opaque",
            "ciphertext": ciphertext,
            "attachment_blob_ids": [upload["blob_id"]]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{post}");
    assert_eq!(post["bubble_id"], main_bubble_id);
    let post_id = post["id"].as_str().expect("channel post id");

    let (status, post_retry) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/posts"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_post_id": client_post_id,
            "post_type": "opaque",
            "ciphertext": ciphertext,
            "attachment_blob_ids": [upload["blob_id"]]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{post_retry}");
    assert_eq!(post_retry["id"], post_id);

    let (status, post_conflict) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/channels/{channel_id}/posts"),
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "sender_device_id": alice_device_id,
            "client_post_id": client_post_id,
            "post_type": "opaque",
            "ciphertext": "ZGlmZmVyZW50LWNoYW5uZWwtY2lwaGVydGV4dA=="
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{post_conflict}");

    let (status, channel_pending) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/channels/{channel_id}/posts/pending"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{channel_pending}");
    assert_eq!(channel_pending["posts"][0]["id"], post_id);
    assert_eq!(channel_pending["posts"][0]["bubble_id"], main_bubble_id);

    let (status, call) = request_json(
        app.clone(),
        Method::POST,
        "/v1/calls",
        Some(alice_device_token),
        Some(json!({
            "bubble_id": main_bubble_id,
            "callee_user_id": bob_user_id,
            "call_kind": "audio"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{call}");
    assert_eq!(call["bubble_id"], main_bubble_id);
    let call_id = call["id"].as_str().expect("call id");

    let (status, accepted) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/calls/{call_id}/accept"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");

    let (status, offer) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/calls/{call_id}/offer"),
        Some(alice_device_token),
        Some(json!({ "bubble_id": main_bubble_id, "sdp": "opaque-sdp-offer" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{offer}");

    let (status, ice) = request_json(
        app.clone(),
        Method::POST,
        &format!("/v1/calls/{call_id}/ice-candidates"),
        Some(bob_device_token),
        Some(json!({ "bubble_id": main_bubble_id, "candidates": ["opaque-ice-candidate"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ice}");

    let (status, signaling) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/calls/{call_id}/signaling"),
        Some(bob_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signaling}");
    assert_eq!(signaling["events"][0]["event_kind"], "offer");
    assert_eq!(signaling["events"][0]["bubble_id"], main_bubble_id);
    assert_eq!(signaling["events"][0]["payload"], "opaque-sdp-offer");

    let (status, turn) = request_json(
        app.clone(),
        Method::POST,
        "/v1/turn/credentials",
        Some(alice_device_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert!(turn["credential"].as_str().expect("turn credential").len() > 16);

    assert_ne!(alice_user_id, bob_user_id);
}

async fn register_user(app: Router, public_id: &str) -> Value {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/auth/register",
        None,
        Some(json!({
            "public_id": public_id,
            "password": "correct horse battery staple"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn login_user(app: Router, public_id: &str) -> Value {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/auth/login",
        None,
        Some(json!({
            "public_id": public_id,
            "password": "correct horse battery staple"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn register_device(app: Router, token: &str, display_name: &str) -> Value {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/devices/register",
        Some(token),
        Some(json!({
            "display_name": display_name,
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn register_device_with_id(
    app: Router,
    token: &str,
    display_name: &str,
    device_id: &str,
) -> Value {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/devices/register",
        Some(token),
        Some(json!({
            "device_id": device_id,
            "display_name": display_name,
            "platform": "android"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn upload_keys(app: Router, token: &str, device_id: &str) {
    let (status, body) = request_json(
        app,
        Method::POST,
        "/v1/keys/upload",
        Some(token),
        Some(json!({
            "device_id": device_id,
            "identity_key": key_material("opaque-public-identity-key-v1"),
            "registration_id": 12345,
            "protocol_device_id": 1,
            "signed_prekey": {
                "key_id": 1,
                "public_key": key_material("opaque-signed-prekey-v1"),
                "signature": key_material("opaque-signed-prekey-signature-v1")
            },
            "kyber_prekey": {
                "key_id": 2,
                "public_key": key_material("opaque-kyber-prekey-v1"),
                "signature": key_material("opaque-kyber-prekey-signature-v1")
            },
            "one_time_prekeys": [
                {"key_id": 1, "public_key": key_material("opaque-one-time-prekey-v1")}
            ]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn key_material(value: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD_NO_PAD.encode(value.as_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct DirectDevice<'a> {
    token: &'a str,
    device_id: &'a str,
}

async fn send_and_ack_direct_message_type(
    app: Router,
    sender: DirectDevice<'_>,
    recipient: DirectDevice<'_>,
    bubble_id: &str,
    message_type: &str,
    ciphertext: &str,
) {
    let client_message_id = Uuid::new_v4().to_string();
    let (status, sent) = request_json(
        app.clone(),
        Method::POST,
        "/v1/messages",
        Some(sender.token),
        Some(json!({
            "bubble_id": bubble_id,
            "sender_device_id": sender.device_id,
            "recipient_device_id": recipient.device_id,
            "client_message_id": client_message_id,
            "message_type": message_type,
            "ciphertext": ciphertext
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let message_id = sent["id"].as_str().expect("message id");
    assert_eq!(sent["bubble_id"], bubble_id);

    let (status, pending) = request_json(
        app.clone(),
        Method::GET,
        &format!("/v1/messages/pending?device_id={}", recipient.device_id),
        Some(recipient.token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let pending_message = pending["messages"]
        .as_array()
        .expect("pending messages")
        .iter()
        .find(|message| message["id"].as_str() == Some(message_id))
        .expect("pending message for tested message_type");
    assert_eq!(pending_message["bubble_id"], bubble_id);
    assert_eq!(pending_message["message_type"], message_type);

    let (status, receipt) = request_json(
        app,
        Method::POST,
        &format!("/v1/messages/{message_id}/receipt"),
        Some(recipient.token),
        Some(json!({"device_id": recipient.device_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
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
