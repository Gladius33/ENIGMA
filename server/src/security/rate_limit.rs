use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;

use crate::{
    auth,
    config::{ProxyConfig, PublicClientIpHeader},
    error::AppError,
    security::jwt,
    AppState,
};

pub async fn redis_rate_limit(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let path = request.uri().path();
    if path == "/v1/health" {
        return Ok(next.run(request).await);
    }

    let socket_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let client_ip = resolve_client_ip(socket_ip, request.headers(), &state.config.proxy);
    let mut dimensions = rate_limit_dimensions(path, request.headers(), &state, client_ip);

    let window = state.config.limits.rate_limit_window.as_secs();
    let mut conn = state.redis.get_multiplexed_async_connection().await?;
    for dimension in dimensions.drain(..) {
        let redis_key = format!("rl:v1:{dimension}");
        let count: u32 = conn.incr(&redis_key, 1_u32).await?;
        if count == 1 {
            let _: () = conn.expire(&redis_key, window as i64).await?;
        }
        if count > state.config.limits.rate_limit_max_requests {
            return Err(AppError::RateLimited);
        }
    }

    Ok(next.run(request).await)
}

fn rate_limit_dimensions(
    path: &str,
    headers: &HeaderMap,
    state: &AppState,
    client_ip: String,
) -> Vec<String> {
    let endpoint = endpoint_bucket(path);
    let mut dimensions = vec![format!("ip:{client_ip}:{endpoint}")];

    if let Ok(token) = auth::bearer_token(headers) {
        if let Ok(claims) = jwt::verify_token(&state.config.jwt, token) {
            dimensions.push(format!("user:{}:{endpoint}", claims.sub));
            if let Some(device_id) = claims.did {
                dimensions.push(format!("device:{device_id}:{endpoint}"));
            }
        }
    }

    if let Some(target) = target_bucket(path) {
        dimensions.push(format!("target:{target}:{endpoint}"));
    }

    dimensions
}

pub fn resolve_client_ip(
    socket_ip: Option<IpAddr>,
    headers: &HeaderMap,
    proxy: &ProxyConfig,
) -> String {
    let socket_ip = match socket_ip {
        Some(ip) => ip,
        None => return "unknown-socket".to_owned(),
    };

    if !proxy
        .trusted_proxies
        .iter()
        .any(|trusted| trusted.contains(socket_ip))
    {
        return socket_ip.to_string();
    }

    let forwarded = match proxy.public_client_ip_header {
        PublicClientIpHeader::None => None,
        PublicClientIpHeader::XForwardedFor => headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim),
        PublicClientIpHeader::XRealIp => headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .map(str::trim),
    };

    forwarded
        .filter(|value| !value.is_empty())
        .and_then(|value| IpAddr::from_str(value).ok())
        .unwrap_or(socket_ip)
        .to_string()
}

fn endpoint_bucket(path: &str) -> String {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() >= 3 && parts[0] == "v1" && matches!(parts[1], "keys" | "groups" | "channels") {
        return format!("{}/{}/{}", parts[0], parts[1], "{id}");
    }
    if parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        path.to_owned()
    }
}

fn target_bucket(path: &str) -> Option<String> {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        ["v1", "keys", user_id] => Some(format!("keys-user:{user_id}")),
        ["v1", "keys", user_id, "devices"] => Some(format!("keys-user:{user_id}")),
        ["v1", "keys", user_id, "devices", device_id, "claim-prekey"] => {
            Some(format!("keys-device:{user_id}:{device_id}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, TrustedProxy};
    use axum::http::HeaderValue;

    #[test]
    fn ignores_forwarded_for_without_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let proxy = ProxyConfig {
            trusted_proxies: vec![],
            public_client_ip_header: PublicClientIpHeader::XForwardedFor,
        };

        assert_eq!(
            resolve_client_ip(Some("198.51.100.20".parse().unwrap()), &headers, &proxy),
            "198.51.100.20"
        );
    }

    #[test]
    fn accepts_forwarded_for_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let proxy = ProxyConfig {
            trusted_proxies: vec![TrustedProxy::parse("198.51.100.0/24").unwrap()],
            public_client_ip_header: PublicClientIpHeader::XForwardedFor,
        };

        assert_eq!(
            resolve_client_ip(Some("198.51.100.20".parse().unwrap()), &headers, &proxy),
            "203.0.113.10"
        );
    }
}
