use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, auth::jwt, db::users};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_in: u64,
    pub role: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Rate limiting: prevent brute force attacks
    let client_ip = extract_client_ip(peer, &headers);

    if !state
        .login_rate_limiter
        .check_user(&client_ip, &payload.username)
        .await
    {
        tracing::warn!(
            "Login rate limit exceeded for IP: {} (user: {})",
            client_ip,
            payload.username
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many login attempts. Please try again later.".to_string(),
        ));
    }

    let pool = &state.db_pool;
    let user = users::verify_password(pool, &payload.username, &payload.password)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(user) = user {
        if !user.is_active {
            return Err((StatusCode::FORBIDDEN, "Account is disabled".to_string()));
        }
        let config = state.config.load();
        let secret = &config.authentication.jwt_secret;
        let expiration = config.authentication.jwt_expiration;
        let token = jwt::create_jwt(user.id, &user.username, &user.role, secret, expiration)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = users::update_last_login(pool, user.id).await;
        Ok(Json(LoginResponse {
            token,
            expires_in: expiration,
            role: user.role,
        })
        .into_response())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))
    }
}

/// Resolve the client IP used for login rate limiting.
///
/// The socket peer is the source of truth. `X-Real-IP` / `X-Forwarded-For` are
/// client-controlled and were previously trusted unconditionally, so an
/// attacker could rotate the header per request to mint a fresh rate-limit
/// bucket and brute-force logins. We now honor forwarded headers ONLY when the
/// immediate peer is loopback — i.e. a reverse proxy on the same host (the
/// bundled nginx). A remote peer's forged header is ignored.
fn extract_client_ip(peer: SocketAddr, headers: &HeaderMap) -> String {
    let peer_ip = peer.ip();
    if peer_ip.is_loopback() {
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let ip = real_ip.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
        if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = fwd.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    peer_ip.to_string()
}
