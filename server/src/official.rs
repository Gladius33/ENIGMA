use crate::{auth::AuthUser, error::AppError, push::PushNotification, AppState};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
pub fn user_router() -> Router<AppState> {
    Router::new()
        .route("/account", get(account))
        .route("/announcements/pending", get(pending))
        .route("/announcements/:id/read", post(read))
        .route("/announcements/:id/dismiss", post(dismiss))
}
pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/announcements", get(list).post(create))
        .route("/announcements/:id/publish", post(publish))
        .route("/announcements/:id/broadcast", post(broadcast))
        .route("/announcements/:id/send-test", post(send_test))
}
fn enabled(s: &AppState) -> Result<(), AppError> {
    if s.config.business.official_relay_mode {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}
fn admin(s: &AppState, h: &HeaderMap) -> Result<(), AppError> {
    enabled(s)?;
    let supplied = h
        .get("x-enigma-admin-token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            h.get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });
    if supplied.is_some() && supplied == s.config.business.admin_token.as_deref() {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}
#[derive(Serialize)]
struct Account {
    id: &'static str,
    display_name_fr: &'static str,
    display_name_en: &'static str,
    verified: bool,
}
async fn account(State(s): State<AppState>) -> Result<Json<Account>, AppError> {
    enabled(&s)?;
    Ok(Json(Account {
        id: "official-enigma",
        display_name_fr: "Enigma Officiel",
        display_name_en: "Enigma Official",
        verified: true,
    }))
}
#[derive(Deserialize)]
pub struct Create {
    kind: String,
    title_fr: String,
    body_fr: String,
    title_en: Option<String>,
    body_en: Option<String>,
    cta_label_fr: Option<String>,
    cta_label_en: Option<String>,
    cta_url_fr: Option<String>,
    cta_url_en: Option<String>,
    audience: Option<String>,
    priority: Option<String>,
    starts_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}
#[derive(Serialize, FromRow)]
struct Row {
    id: Uuid,
    kind: String,
    title_fr: String,
    body_fr: String,
    title_en: Option<String>,
    body_en: Option<String>,
    cta_label_fr: Option<String>,
    cta_label_en: Option<String>,
    cta_url_fr: Option<String>,
    cta_url_en: Option<String>,
    audience: String,
    priority: String,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}
async fn create(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(p): Json<Create>,
) -> Result<Json<Row>, AppError> {
    admin(&s, &h)?;
    if !matches!(
        p.audience.as_deref().unwrap_or("all"),
        "all" | "free" | "premium"
    ) {
        return Err(AppError::BadRequest("INVALID_ANNOUNCEMENT_AUDIENCE".into()));
    }
    let r=sqlx::query_as("INSERT INTO official_announcements(kind,title_fr,body_fr,title_en,body_en,cta_label_fr,cta_label_en,cta_url_fr,cta_url_en,audience,priority,starts_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id,kind,title_fr,body_fr,title_en,body_en,cta_label_fr,cta_label_en,cta_url_fr,cta_url_en,audience,priority,status,created_at,expires_at").bind(p.kind).bind(p.title_fr).bind(p.body_fr).bind(p.title_en).bind(p.body_en).bind(p.cta_label_fr).bind(p.cta_label_en).bind(p.cta_url_fr).bind(p.cta_url_en).bind(p.audience.unwrap_or_else(||"all".into())).bind(p.priority.unwrap_or_else(||"normal".into())).bind(p.starts_at).bind(p.expires_at).fetch_one(&s.pg).await?;
    Ok(Json(r))
}
async fn list(State(s): State<AppState>, h: HeaderMap) -> Result<Json<Vec<Row>>, AppError> {
    admin(&s, &h)?;
    Ok(Json(sqlx::query_as("SELECT id,kind,title_fr,body_fr,title_en,body_en,cta_label_fr,cta_label_en,cta_url_fr,cta_url_en,audience,priority,status,created_at,expires_at FROM official_announcements ORDER BY created_at DESC").fetch_all(&s.pg).await?))
}
async fn publish(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    admin(&s, &h)?;
    let n = sqlx::query(
        "UPDATE official_announcements SET status='published',updated_at=now() WHERE id=$1",
    )
    .bind(id)
    .execute(&s.pg)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"status":"published"})))
}
async fn broadcast(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    admin(&s, &h)?;
    let a: Option<(String, String)> =
        sqlx::query_as("SELECT audience,status FROM official_announcements WHERE id=$1")
            .bind(id)
            .fetch_optional(&s.pg)
            .await?;
    let (aud, status) = a.ok_or(AppError::NotFound)?;
    if status != "published" {
        return Err(AppError::Conflict("ANNOUNCEMENT_NOT_PUBLISHED".into()));
    }
    let q="INSERT INTO official_announcement_deliveries(announcement_id,identity_id,delivered_at) SELECT $1,u.id,now() FROM users u WHERE u.disabled_at IS NULL AND ($2='all' OR ($2='free' AND NOT EXISTS(SELECT 1 FROM subscriptions s WHERE s.identity_id=u.id AND s.status='active')) OR ($2='premium' AND EXISTS(SELECT 1 FROM subscriptions s WHERE s.identity_id=u.id AND s.status='active' AND s.plan_code<>'free'))) ON CONFLICT DO NOTHING";
    let count = sqlx::query(q)
        .bind(id)
        .bind(aud)
        .execute(&s.pg)
        .await?
        .rows_affected();
    let tokens:Vec<String>=sqlx::query_scalar("SELECT DISTINCT d.fcm_token FROM devices d JOIN official_announcement_deliveries x ON x.identity_id=d.user_id WHERE x.announcement_id=$1 AND d.revoked_at IS NULL AND d.push_enabled=TRUE AND d.fcm_token IS NOT NULL").bind(id).fetch_all(&s.pg).await?;
    for token in tokens {
        let _ = s
            .push
            .send(&token, &PushNotification::official_sync_hint())
            .await;
    }
    Ok(Json(serde_json::json!({"deliveries_created":count})))
}
#[derive(Deserialize)]
struct TestTarget {
    identity_id: Uuid,
}
async fn send_test(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(t): Json<TestTarget>,
) -> Result<Json<serde_json::Value>, AppError> {
    admin(&s, &h)?;
    sqlx::query("INSERT INTO official_announcement_deliveries(announcement_id,identity_id,delivered_at) VALUES($1,$2,now()) ON CONFLICT DO NOTHING").bind(id).bind(t.identity_id).execute(&s.pg).await?;
    Ok(Json(serde_json::json!({"status":"queued"})))
}
#[derive(Serialize)]
struct Pending {
    announcements: Vec<Localized>,
}
#[derive(Serialize, FromRow)]
struct Localized {
    id: Uuid,
    kind: String,
    priority: String,
    title: String,
    body: String,
    cta_label: Option<String>,
    cta_url: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}
async fn pending(State(s): State<AppState>, a: AuthUser) -> Result<Json<Pending>, AppError> {
    enabled(&s)?;
    let rows=sqlx::query_as("SELECT n.id,n.kind,n.priority,COALESCE(n.title_en,n.title_fr) title,COALESCE(n.body_en,n.body_fr) body,COALESCE(n.cta_label_en,n.cta_label_fr) cta_label,COALESCE(n.cta_url_en,n.cta_url_fr) cta_url,n.created_at,n.expires_at FROM official_announcements n JOIN official_announcement_deliveries d ON d.announcement_id=n.id WHERE d.identity_id=$1 AND d.opened_at IS NULL AND d.dismissed_at IS NULL AND n.status='published' AND (n.starts_at IS NULL OR n.starts_at<=now()) AND (n.expires_at IS NULL OR n.expires_at>now()) ORDER BY n.created_at DESC").bind(a.user_id).fetch_all(&s.pg).await?;
    Ok(Json(Pending {
        announcements: rows,
    }))
}
async fn read(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    mark(&s, a.user_id, id, "opened_at").await
}
async fn dismiss(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    mark(&s, a.user_id, id, "dismissed_at").await
}
async fn mark(
    s: &AppState,
    u: Uuid,
    id: Uuid,
    column: &str,
) -> Result<Json<serde_json::Value>, AppError> {
    enabled(s)?;
    let rows_affected = match column {
        "opened_at" => sqlx::query(
            "UPDATE official_announcement_deliveries
             SET opened_at=now()
             WHERE announcement_id=$1 AND identity_id=$2",
        )
        .bind(id)
        .bind(u)
        .execute(&s.pg)
        .await?
        .rows_affected(),
        "dismissed_at" => sqlx::query(
            "UPDATE official_announcement_deliveries
             SET dismissed_at=now()
             WHERE announcement_id=$1 AND identity_id=$2",
        )
        .bind(id)
        .bind(u)
        .execute(&s.pg)
        .await?
        .rows_affected(),
        _ => return Err(AppError::BadRequest("INVALID_ANNOUNCEMENT_MARK".into())),
    };
    if rows_affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"status":"ok"})))
}
