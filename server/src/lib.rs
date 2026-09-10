pub mod attachments;
pub mod auth;
pub mod bubbles;
pub mod business;
pub mod calls;
pub mod channels;
pub mod config;
pub mod contacts;
pub mod db;
pub mod devices;
pub mod error;
pub mod groups;
pub mod http;
pub mod identities;
pub mod keys;
pub mod maintenance;
pub mod messages;
pub mod official;
pub mod push;
pub mod relay_constants;
pub mod relays;
pub mod releases;
pub mod security;
pub mod turn;
pub mod users;
pub mod ws;

use std::sync::Arc;

use attachments::s3::build_s3_client;
use aws_sdk_s3::Client as S3Client;
use config::{Config, PushProvider};
use error::AppError;
use redis::Client as RedisClient;
use sqlx::{postgres::PgPoolOptions, PgPool};
use ws::hub::WsHub;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pg: PgPool,
    pub redis: RedisClient,
    pub s3: S3Client,
    pub ws: WsHub,
    pub push: Arc<dyn push::PushSender>,
}

pub async fn build_state(config: Config) -> Result<AppState, AppError> {
    let pg = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    let redis = RedisClient::open(config.redis.url.clone())?;
    let s3 = build_s3_client(&config.s3).await;

    let push: Arc<dyn push::PushSender> = match &config.push.provider {
        PushProvider::Noop => Arc::new(push::NoopPushSender),
        PushProvider::Fcm(fcm) => Arc::new(push::FcmPushSender::new(fcm)?),
    };

    Ok(AppState {
        config: Arc::new(config),
        pg,
        redis,
        s3,
        ws: WsHub::default(),
        push,
    })
}
