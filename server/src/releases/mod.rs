use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{error::AppError, AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/android", get(android_release))
}

#[derive(Debug, Deserialize)]
struct ReleaseQuery {
    #[serde(default = "default_channel")]
    channel: String,
}

#[derive(Debug, Serialize)]
struct AndroidReleaseResponse {
    platform: &'static str,
    channel: String,
    latest_version_name: String,
    latest_version_code: i64,
    apk_url: String,
    sha256: String,
    signature: Option<String>,
    mandatory: bool,
    release_notes: ReleaseNotes,
}

#[derive(Debug, Serialize)]
struct ReleaseNotes {
    fr: String,
    en: String,
}

async fn android_release(
    State(state): State<AppState>,
    Query(query): Query<ReleaseQuery>,
) -> Result<Json<AndroidReleaseResponse>, AppError> {
    let release = state
        .config
        .releases
        .android
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("RELEASE_NOT_CONFIGURED".into()))?;
    if release.channel != query.channel {
        return Err(AppError::NotFound);
    }

    Ok(Json(AndroidReleaseResponse {
        platform: "android",
        channel: release.channel.clone(),
        latest_version_name: release.latest_version_name.clone(),
        latest_version_code: release.latest_version_code,
        apk_url: release.apk_url.clone(),
        sha256: release.sha256.clone(),
        signature: release.signature.clone(),
        mandatory: release.mandatory,
        release_notes: ReleaseNotes {
            fr: release.release_notes_fr.clone(),
            en: release.release_notes_en.clone(),
        },
    }))
}

fn default_channel() -> String {
    "stable".into()
}
