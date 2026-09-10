use axum::{
    extract::{DefaultBodyLimit, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    middleware,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::{
    auth, bubbles, calls, channels, contacts, devices,
    error::AppError,
    groups, identities, keys, messages, relays, releases,
    security::{headers::apply_security_headers, rate_limit::redis_rate_limit},
    turn, users, ws, AppState,
};

pub fn router(state: AppState) -> Router {
    let max_body = state.config.limits.max_json_body_bytes;
    let cors = cors_layer(&state);

    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/v1/health", get(health))
        .route("/v1/ws", get(ws::handler))
        .nest("/v1/auth", auth::router())
        .nest("/v1/bubbles", bubbles::router())
        .nest("/v1/calls", calls::router())
        .nest("/v1/channels", channels::router())
        .nest("/v1/contacts", contacts::router())
        .nest("/v1/devices", devices::router())
        .nest("/v1/groups", groups::router())
        .nest("/v1/identities", identities::router())
        .nest("/v1/keys", keys::router())
        .nest("/v1/users", users::router())
        .nest("/v1/messages", messages::router())
        .nest("/v1/attachments", crate::attachments::router())
        .nest("/v1/me", crate::business::me_router())
        .nest("/v1/support", crate::business::support_router())
        .nest("/v1/official", crate::official::user_router())
        .nest("/v1/admin/official", crate::official::admin_router())
        .nest("/v1/releases", releases::router())
        .nest("/v1/relays", relays::router())
        .nest("/v1/turn", turn::router())
        .layer(middleware::from_fn(apply_security_headers))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            redis_rate_limit,
        ))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::extract::Request| {
                    tracing::span!(
                        Level::INFO,
                        "http_request",
                        method = %request.method(),
                        path = %request.uri().path()
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
}

#[derive(Serialize)]
struct VersionResponse<'a> {
    name: &'a str,
    version: &'a str,
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse<'static>>, AppError> {
    let _: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&state.pg).await?;
    let mut conn = state.redis.get_multiplexed_async_connection().await?;
    let _: String = redis::cmd("PING").query_async(&mut conn).await?;
    Ok(Json(HealthResponse { status: "ok" }))
}

async fn version() -> Json<VersionResponse<'static>> {
    Json(VersionResponse {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(600));

    if state
        .config
        .cors
        .allowed_origins
        .iter()
        .any(|origin| origin == "*")
    {
        layer.allow_origin(Any)
    } else {
        let origins = state
            .config
            .cors
            .allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect::<Vec<_>>();
        layer.allow_origin(AllowOrigin::list(origins))
    }
}
