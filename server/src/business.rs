use crate::{auth::AuthUser, error::AppError, AppState};
use axum::{routing::get, Json, Router};
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

pub fn me_router() -> Router<AppState> {
    Router::new()
        .route("/plan", get(my_plan))
        .route("/usage", get(my_usage))
}
pub fn support_router() -> Router<AppState> {
    Router::new().route("/config", get(support_config))
}

#[derive(Debug, Clone, FromRow)]
pub struct Plan {
    pub code: String,
    pub name_fr: String,
    pub name_en: String,
    pub storage_quota_bytes: i64,
    pub pending_storage_quota_bytes: i64,
    pub max_attachment_bytes: i64,
    pub attachment_retention_seconds: i64,
    pub max_devices: i32,
    pub max_groups: Option<i32>,
    pub max_group_members: Option<i32>,
    pub max_channels: Option<i32>,
    pub max_channel_subscribers: Option<i32>,
    pub turn_monthly_seconds: Option<i32>,
}
#[derive(FromRow)]
pub struct Usage {
    pub storage_verified_bytes: i64,
    pub storage_pending_bytes: i64,
    pub uploads_today_bytes: i64,
    pub uploads_today_count: i32,
}

const ACTIVE_PLAN_SQL: &str = "SELECT p.code,p.name_fr,p.name_en,p.storage_quota_bytes,p.pending_storage_quota_bytes,p.max_attachment_bytes,p.attachment_retention_seconds,p.max_devices,p.max_groups,p.max_group_members,p.max_channels,p.max_channel_subscribers,p.turn_monthly_seconds FROM plans p LEFT JOIN subscriptions s ON s.plan_code=p.code AND s.identity_id=$1 AND s.status='active' AND (s.current_period_end IS NULL OR s.current_period_end>now()) WHERE p.code=COALESCE(s.plan_code,'free') ORDER BY (s.plan_code IS NOT NULL) DESC LIMIT 1";

pub async fn active_plan(state: &AppState, identity_id: Uuid) -> Result<Plan, AppError> {
    sqlx::query_as(ACTIVE_PLAN_SQL)
        .bind(identity_id)
        .fetch_one(&state.pg)
        .await
        .map_err(Into::into)
}

pub async fn active_plan_tx(
    tx: &mut Transaction<'_, Postgres>,
    identity_id: Uuid,
) -> Result<Plan, AppError> {
    sqlx::query_as(ACTIVE_PLAN_SQL)
        .bind(identity_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(Into::into)
}

pub fn optional_limit_reached(current: i64, limit: Option<i32>) -> bool {
    limit.is_some_and(|limit| current >= i64::from(limit.max(0)))
}

pub async fn usage(state: &AppState, id: Uuid) -> Result<Usage, AppError> {
    sqlx::query(
        "INSERT INTO identity_usage_counters(identity_id) VALUES($1) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&state.pg)
    .await?;
    Ok(sqlx::query_as("SELECT storage_verified_bytes,storage_pending_bytes,uploads_today_bytes,uploads_today_count FROM identity_usage_counters WHERE identity_id=$1").bind(id).fetch_one(&state.pg).await?)
}
#[derive(Serialize)]
struct PlanResponse {
    plan_code: String,
    plan_name: String,
    status: &'static str,
    storage_quota_bytes: i64,
    max_attachment_bytes: i64,
    attachment_retention_seconds: i64,
    max_devices: i32,
    max_groups: Option<i32>,
    max_group_members: Option<i32>,
    max_channels: Option<i32>,
    max_channel_subscribers: Option<i32>,
    turn_monthly_seconds: Option<i32>,
    premium_url: Option<String>,
}
async fn my_plan(
    axum::extract::State(s): axum::extract::State<AppState>,
    a: AuthUser,
) -> Result<Json<PlanResponse>, AppError> {
    let p = active_plan(&s, a.user_id).await?;
    Ok(Json(PlanResponse {
        plan_code: p.code,
        plan_name: p.name_en,
        status: "active",
        storage_quota_bytes: p.storage_quota_bytes,
        max_attachment_bytes: p.max_attachment_bytes,
        attachment_retention_seconds: p.attachment_retention_seconds,
        max_devices: p.max_devices,
        max_groups: p.max_groups,
        max_group_members: p.max_group_members,
        max_channels: p.max_channels,
        max_channel_subscribers: p.max_channel_subscribers,
        turn_monthly_seconds: p.turn_monthly_seconds,
        premium_url: s.config.business.premium_urls[2].clone(),
    }))
}
#[derive(Serialize)]
struct UsageResponse {
    storage_verified_bytes: i64,
    storage_pending_bytes: i64,
    storage_quota_bytes: i64,
    storage_used_percent: f64,
    uploads_today_bytes: i64,
    uploads_today_count: i32,
}
async fn my_usage(
    axum::extract::State(s): axum::extract::State<AppState>,
    a: AuthUser,
) -> Result<Json<UsageResponse>, AppError> {
    let p = active_plan(&s, a.user_id).await?;
    let u = usage(&s, a.user_id).await?;
    let used = u.storage_verified_bytes + u.storage_pending_bytes;
    Ok(Json(UsageResponse {
        storage_verified_bytes: u.storage_verified_bytes,
        storage_pending_bytes: u.storage_pending_bytes,
        storage_quota_bytes: p.storage_quota_bytes,
        storage_used_percent: (used as f64 / p.storage_quota_bytes as f64) * 100.0,
        uploads_today_bytes: u.uploads_today_bytes,
        uploads_today_count: u.uploads_today_count,
    }))
}
#[derive(Serialize)]
struct SupportResponse {
    support_enabled: bool,
    donations_enabled: bool,
    donation_url_fr: Option<String>,
    donation_url_en: Option<String>,
    donation_url_default: Option<String>,
    premium_enabled: bool,
    premium_url_fr: Option<String>,
    premium_url_en: Option<String>,
    premium_url_default: Option<String>,
}
async fn support_config(
    axum::extract::State(s): axum::extract::State<AppState>,
) -> Json<SupportResponse> {
    let b = &s.config.business;
    let enabled = b.support_enabled;
    Json(SupportResponse {
        support_enabled: enabled,
        donations_enabled: enabled && b.donation_urls.iter().any(Option::is_some),
        donation_url_fr: b.donation_urls[0].clone(),
        donation_url_en: b.donation_urls[1].clone(),
        donation_url_default: b.donation_urls[2].clone(),
        premium_enabled: enabled && b.premium_urls.iter().any(Option::is_some),
        premium_url_fr: b.premium_urls[0].clone(),
        premium_url_en: b.premium_urls[1].clone(),
        premium_url_default: b.premium_urls[2].clone(),
    })
}

pub async fn recalculate_usage_for_identity(state: &AppState, id: Uuid) -> Result<(), AppError> {
    sqlx::query("INSERT INTO identity_usage_counters(identity_id,storage_verified_bytes,storage_pending_bytes) SELECT $1,COALESCE(sum(size_bytes) FILTER(WHERE status='verified'),0),COALESCE(sum(size_bytes) FILTER(WHERE status='pending'),0) FROM attachments WHERE owner_id=$1 ON CONFLICT(identity_id) DO UPDATE SET storage_verified_bytes=EXCLUDED.storage_verified_bytes,storage_pending_bytes=EXCLUDED.storage_pending_bytes,updated_at=now()").bind(id).execute(&state.pg).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::optional_limit_reached;

    #[test]
    fn optional_limits_are_unlimited_when_null() {
        assert!(!optional_limit_reached(1_000_000, None));
    }

    #[test]
    fn optional_limits_block_at_the_boundary() {
        assert!(!optional_limit_reached(4, Some(5)));
        assert!(optional_limit_reached(5, Some(5)));
        assert!(optional_limit_reached(6, Some(5)));
    }
}
