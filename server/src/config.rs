use std::{
    env,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub environment: Environment,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub proxy: ProxyConfig,
    pub cors: CorsConfig,
    pub limits: LimitsConfig,
    pub s3: S3Config,
    pub turn: TurnConfig,
    pub push: PushConfig,
    pub releases: ReleasesConfig,
    pub business: BusinessConfig,
}

#[derive(Debug, Clone)]
pub struct BusinessConfig {
    pub official_relay_mode: bool,
    pub admin_token: Option<String>,
    pub support_enabled: bool,
    pub donation_urls: [Option<String>; 3],
    pub premium_urls: [Option<String>; 3],
    pub attachment_pending_ttl: Duration,
    pub attachment_unattached_ttl: Duration,
    pub attachment_purge_batch_size: i64,
    pub free_upload_daily_bytes: i64,
    pub free_upload_daily_count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_ttl: Duration,
    pub issuer: String,
    pub audience: String,
    pub accept_legacy_tokens: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub trusted_proxies: Vec<TrustedProxy>,
    pub public_client_ip_header: PublicClientIpHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicClientIpHeader {
    None,
    XForwardedFor,
    XRealIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_json_body_bytes: usize,
    pub max_ciphertext_bytes: usize,
    pub rate_limit_window: Duration,
    pub rate_limit_max_requests: u32,
    pub message_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket: String,
    pub force_path_style: bool,
    pub upload_presign_ttl: Duration,
    pub download_presign_ttl: Duration,
    pub attachment_ttl: Duration,
    pub max_attachment_bytes: i64,
}

#[derive(Debug, Clone)]
pub struct TurnConfig {
    pub secret: String,
    pub realm: String,
    pub ttl: Duration,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub provider: PushProvider,
}

#[derive(Debug, Clone)]
pub enum PushProvider {
    Noop,
    Fcm(FcmConfig),
}

#[derive(Debug, Clone)]
pub struct FcmConfig {
    pub project_id: String,
    pub service_account_json: String,
}

#[derive(Debug, Clone)]
pub struct ReleasesConfig {
    pub android: Option<AndroidReleaseConfig>,
}

#[derive(Debug, Clone)]
pub struct AndroidReleaseConfig {
    pub channel: String,
    pub latest_version_name: String,
    pub latest_version_code: i64,
    pub apk_url: String,
    pub sha256: String,
    pub signature: Option<String>,
    pub mandatory: bool,
    pub release_notes_fr: String,
    pub release_notes_en: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable {0}")]
    Missing(&'static str),
    #[error("invalid environment variable {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let jwt_secret = required("JWT_SECRET")?;
        if jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid {
                name: "JWT_SECRET",
                reason: "must be at least 32 bytes".into(),
            });
        }
        let environment = environment()?;
        let cors_allowed_origins = csv("CORS_ALLOWED_ORIGINS", "*")?;
        if environment == Environment::Production
            && cors_allowed_origins.iter().any(|origin| origin == "*")
        {
            return Err(ConfigError::Invalid {
                name: "CORS_ALLOWED_ORIGINS",
                reason: "must not be '*' in production".into(),
            });
        }

        let bind_addr =
            var("BIND_ADDR", "0.0.0.0:8080")
                .parse()
                .map_err(|err| ConfigError::Invalid {
                    name: "BIND_ADDR",
                    reason: format!("invalid socket address: {err}"),
                })?;

        let official_relay_mode = parse("OFFICIAL_RELAY_MODE", false)?;
        let admin_token = optional("ENIGMA_ADMIN_TOKEN");
        if environment == Environment::Production
            && official_relay_mode
            && admin_token.as_ref().is_none_or(|token| token.len() < 32)
        {
            return Err(ConfigError::Invalid {
                name: "ENIGMA_ADMIN_TOKEN",
                reason: "must be at least 32 bytes for an official production relay".into(),
            });
        }
        Ok(Self {
            server: ServerConfig { bind_addr },
            environment,
            database: DatabaseConfig {
                url: required("DATABASE_URL")?,
                max_connections: parse("DATABASE_MAX_CONNECTIONS", 10)?,
            },
            redis: RedisConfig {
                url: required("REDIS_URL")?,
            },
            jwt: JwtConfig {
                secret: jwt_secret,
                access_ttl: seconds("JWT_ACCESS_TTL_SECONDS", 3600)?,
                issuer: var("JWT_ISSUER", "enigma-v1"),
                audience: var("JWT_AUDIENCE", "enigma-api"),
                accept_legacy_tokens: parse("JWT_ACCEPT_LEGACY_TOKENS", true)?,
            },
            proxy: ProxyConfig {
                trusted_proxies: trusted_proxies("TRUSTED_PROXIES")?,
                public_client_ip_header: public_client_ip_header("PUBLIC_CLIENT_IP_HEADER")?,
            },
            cors: CorsConfig {
                allowed_origins: cors_allowed_origins,
            },
            limits: LimitsConfig {
                max_json_body_bytes: parse("MAX_JSON_BODY_BYTES", 1_048_576)?,
                max_ciphertext_bytes: parse("MAX_CIPHERTEXT_BYTES", 262_144)?,
                rate_limit_window: seconds("RATE_LIMIT_WINDOW_SECONDS", 60)?,
                rate_limit_max_requests: parse("RATE_LIMIT_MAX_REQUESTS", 120)?,
                message_ttl: seconds("MESSAGE_TTL_SECONDS", 604_800)?,
            },
            s3: S3Config {
                endpoint: required("S3_ENDPOINT")?,
                region: var("S3_REGION", "us-east-1"),
                access_key_id: required("S3_ACCESS_KEY_ID")?,
                secret_access_key: required("S3_SECRET_ACCESS_KEY")?,
                bucket: required("S3_BUCKET")?,
                force_path_style: parse("S3_FORCE_PATH_STYLE", true)?,
                upload_presign_ttl: seconds("S3_UPLOAD_PRESIGN_TTL_SECONDS", 900)?,
                download_presign_ttl: seconds("S3_DOWNLOAD_PRESIGN_TTL_SECONDS", 900)?,
                attachment_ttl: seconds("ATTACHMENT_TTL_SECONDS", 604_800)?,
                max_attachment_bytes: parse("MAX_ATTACHMENT_BYTES", 104_857_600)?,
            },
            turn: TurnConfig {
                secret: var("TURN_SHARED_SECRET", ""),
                realm: var("TURN_REALM", "enigma.local"),
                ttl: seconds("TURN_CREDENTIAL_TTL_SECONDS", 600)?,
                uris: csv("TURN_URIS", "turn:localhost:3478?transport=udp")?,
            },
            push: PushConfig {
                provider: push_provider(environment)?,
            },
            releases: ReleasesConfig {
                android: android_release_config()?,
            },
            business: BusinessConfig {
                official_relay_mode,
                admin_token,
                support_enabled: parse("SUPPORT_ENABLED", false)?,
                donation_urls: [
                    optional("DONATION_URL_FR"),
                    optional("DONATION_URL_EN"),
                    optional("DONATION_URL_DEFAULT"),
                ],
                premium_urls: [
                    optional("PREMIUM_URL_FR"),
                    optional("PREMIUM_URL_EN"),
                    optional("PREMIUM_URL_DEFAULT"),
                ],
                attachment_pending_ttl: seconds("ATTACHMENT_PENDING_TTL_SECONDS", 3600)?,
                attachment_unattached_ttl: seconds("ATTACHMENT_UNATTACHED_TTL_SECONDS", 86400)?,
                attachment_purge_batch_size: parse("ATTACHMENT_PURGE_BATCH_SIZE", 500)?,
                free_upload_daily_bytes: parse("FREE_UPLOAD_DAILY_BYTES", 262_144_000)?,
                free_upload_daily_count: parse("FREE_UPLOAD_DAILY_COUNT", 100)?,
            },
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .map(|value| value.trim().to_owned())
        .map_err(|_| ConfigError::Missing(name))
        .and_then(|value| {
            if value.is_empty() {
                Err(ConfigError::Missing(name))
            } else {
                Ok(value)
            }
        })
}

fn var(name: &'static str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn optional(name: &'static str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value.parse::<T>().map_err(|err| ConfigError::Invalid {
            name,
            reason: err.to_string(),
        }),
        Err(_) => Ok(default),
    }
}

fn seconds(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    let value = parse(name, default)?;
    Ok(Duration::from_secs(value))
}

fn csv(name: &'static str, default: &str) -> Result<Vec<String>, ConfigError> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_owned());
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return Err(ConfigError::Invalid {
            name,
            reason: "must contain at least one origin".into(),
        });
    }

    Ok(values)
}

fn trusted_proxies(name: &'static str) -> Result<Vec<TrustedProxy>, ConfigError> {
    let raw = env::var(name).unwrap_or_default();
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    values
        .into_iter()
        .map(|value| {
            TrustedProxy::parse(&value).map_err(|reason| ConfigError::Invalid { name, reason })
        })
        .collect()
}

fn public_client_ip_header(name: &'static str) -> Result<PublicClientIpHeader, ConfigError> {
    match var(name, "none").to_ascii_lowercase().as_str() {
        "none" | "" => Ok(PublicClientIpHeader::None),
        "x-forwarded-for" => Ok(PublicClientIpHeader::XForwardedFor),
        "x-real-ip" => Ok(PublicClientIpHeader::XRealIp),
        other => Err(ConfigError::Invalid {
            name,
            reason: format!("unsupported client IP header: {other}"),
        }),
    }
}

impl TrustedProxy {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (addr, prefix) = if let Some((addr, prefix)) = value.split_once('/') {
            let addr = addr
                .parse::<IpAddr>()
                .map_err(|err| format!("invalid trusted proxy address: {err}"))?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|err| format!("invalid trusted proxy prefix: {err}"))?;
            (addr, prefix)
        } else {
            let addr = value
                .parse::<IpAddr>()
                .map_err(|err| format!("invalid trusted proxy address: {err}"))?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            (addr, prefix)
        };

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(format!("trusted proxy prefix must be <= {max_prefix}"));
        }

        Ok(Self {
            network: addr,
            prefix,
        })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(network) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(network) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

fn environment() -> Result<Environment, ConfigError> {
    match var("APP_ENV", "development").as_str() {
        "development" | "dev" => Ok(Environment::Development),
        "test" => Ok(Environment::Test),
        "production" | "prod" => Ok(Environment::Production),
        other => Err(ConfigError::Invalid {
            name: "APP_ENV",
            reason: format!("unsupported environment '{other}'"),
        }),
    }
}

fn push_provider(environment: Environment) -> Result<PushProvider, ConfigError> {
    match var("PUSH_PROVIDER", "noop").as_str() {
        "noop" => {
            if environment == Environment::Production {
                return Err(ConfigError::Invalid {
                    name: "PUSH_PROVIDER",
                    reason: "must be 'fcm' in production".into(),
                });
            }
            Ok(PushProvider::Noop)
        }
        "fcm" => Ok(PushProvider::Fcm(FcmConfig {
            project_id: required("FCM_PROJECT_ID")?,
            service_account_json: fcm_service_account_json()?,
        })),
        other => Err(ConfigError::Invalid {
            name: "PUSH_PROVIDER",
            reason: format!("unsupported provider '{other}'"),
        }),
    }
}

fn fcm_service_account_json() -> Result<String, ConfigError> {
    if let Some(json) = optional("FCM_SERVICE_ACCOUNT_JSON") {
        return Ok(json);
    }
    let path = required("FCM_SERVICE_ACCOUNT_JSON_PATH")?;
    std::fs::read_to_string(&path).map_err(|err| ConfigError::Invalid {
        name: "FCM_SERVICE_ACCOUNT_JSON_PATH",
        reason: format!("cannot read service account JSON: {err}"),
    })
}

fn android_release_config() -> Result<Option<AndroidReleaseConfig>, ConfigError> {
    let Some(apk_url) = optional("ANDROID_APK_URL") else {
        return Ok(None);
    };

    Ok(Some(AndroidReleaseConfig {
        channel: var("ANDROID_RELEASE_CHANNEL", "stable"),
        latest_version_name: required("ANDROID_LATEST_VERSION_NAME")?,
        latest_version_code: parse("ANDROID_LATEST_VERSION_CODE", 1)?,
        apk_url,
        sha256: required("ANDROID_APK_SHA256")?,
        signature: optional("ANDROID_APK_SIGNATURE"),
        mandatory: parse("ANDROID_UPDATE_MANDATORY", false)?,
        release_notes_fr: var("ANDROID_RELEASE_NOTES_FR", ""),
        release_notes_en: var("ANDROID_RELEASE_NOTES_EN", ""),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, sync::Mutex};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const CONFIG_ENV_KEYS: &[&str] = &[
        "APP_ENV",
        "BIND_ADDR",
        "CORS_ALLOWED_ORIGINS",
        "DATABASE_MAX_CONNECTIONS",
        "DATABASE_URL",
        "FCM_PROJECT_ID",
        "FCM_SERVICE_ACCOUNT_JSON",
        "FCM_SERVICE_ACCOUNT_JSON_PATH",
        "JWT_ACCESS_TTL_SECONDS",
        "JWT_SECRET",
        "PUSH_PROVIDER",
        "REDIS_URL",
        "S3_ACCESS_KEY_ID",
        "S3_BUCKET",
        "S3_ENDPOINT",
        "S3_FORCE_PATH_STYLE",
        "S3_SECRET_ACCESS_KEY",
        "TURN_CREDENTIAL_TTL_SECONDS",
        "TURN_REALM",
        "TURN_SHARED_SECRET",
        "TURN_URIS",
        "ANDROID_APK_URL",
    ];

    struct EnvSnapshot(Vec<(&'static str, Option<String>)>);

    impl EnvSnapshot {
        fn capture() -> Self {
            Self(
                CONFIG_ENV_KEYS
                    .iter()
                    .map(|key| (*key, env::var(key).ok()))
                    .collect(),
            )
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }

    fn clear_config_env() {
        for key in CONFIG_ENV_KEYS {
            env::remove_var(key);
        }
    }

    fn set_base_env() {
        clear_config_env();
        env::set_var("JWT_SECRET", "01234567890123456789012345678901");
        env::set_var("DATABASE_URL", "postgres://enigma:enigma@localhost/enigma");
        env::set_var("REDIS_URL", "redis://localhost:6379");
        env::set_var("S3_ENDPOINT", "http://localhost:9000");
        env::set_var("S3_ACCESS_KEY_ID", "minioadmin");
        env::set_var("S3_SECRET_ACCESS_KEY", "minioadmin123");
        env::set_var("S3_BUCKET", "enigma-attachments");
    }

    #[test]
    fn production_rejects_wildcard_cors() {
        let _lock = ENV_LOCK.lock().expect("env lock poisoned");
        let _snapshot = EnvSnapshot::capture();
        set_base_env();
        env::set_var("APP_ENV", "production");
        env::set_var("CORS_ALLOWED_ORIGINS", "*");
        env::set_var("PUSH_PROVIDER", "fcm");
        env::set_var("FCM_PROJECT_ID", "enigma-prod");
        env::set_var("FCM_SERVICE_ACCOUNT_JSON", "{}");

        let error = Config::from_env().expect_err("wildcard CORS must be rejected in production");

        match error {
            ConfigError::Invalid { name, reason } => {
                assert_eq!(name, "CORS_ALLOWED_ORIGINS");
                assert!(reason.contains("production"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn production_rejects_noop_push_provider() {
        let _lock = ENV_LOCK.lock().expect("env lock poisoned");
        let _snapshot = EnvSnapshot::capture();
        set_base_env();
        env::set_var("APP_ENV", "production");
        env::set_var("CORS_ALLOWED_ORIGINS", "https://app.example.com");
        env::set_var("PUSH_PROVIDER", "noop");

        let error = Config::from_env().expect_err("noop push must be rejected in production");

        match error {
            ConfigError::Invalid { name, reason } => {
                assert_eq!(name, "PUSH_PROVIDER");
                assert!(reason.contains("production"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn production_accepts_fcm_push_provider_with_inline_service_account() {
        let _lock = ENV_LOCK.lock().expect("env lock poisoned");
        let _snapshot = EnvSnapshot::capture();
        set_base_env();
        env::set_var("APP_ENV", "production");
        env::set_var("CORS_ALLOWED_ORIGINS", "https://app.example.com");
        env::set_var("PUSH_PROVIDER", "fcm");
        env::set_var("FCM_PROJECT_ID", "enigma-prod");
        env::set_var("FCM_SERVICE_ACCOUNT_JSON", "{}");

        let config = Config::from_env().expect("valid production fcm config");

        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.cors.allowed_origins, vec!["https://app.example.com"]);
        match config.push.provider {
            PushProvider::Fcm(fcm) => {
                assert_eq!(fcm.project_id, "enigma-prod");
                assert_eq!(fcm.service_account_json, "{}");
            }
            PushProvider::Noop => panic!("expected FCM push provider"),
        }
    }
}
