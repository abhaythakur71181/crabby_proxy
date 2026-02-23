use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, auth::jwt, db::users};

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
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Response, (StatusCode, String)> {
    // Rate limiting: prevent brute force attacks
    let client_ip = extract_client_ip(&headers);

    if !state.login_rate_limiter.check(&client_ip).await {
        tracing::warn!("Login rate limit exceeded for IP: {}", client_ip);
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
        let config = state.config.read().await;
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

/// Extract client IP from request headers
/// Checks X-Forwarded-For and X-Real-IP headers, falls back to localhost
/// S5: Prefer socket peer address. X-Forwarded-For is untrusted by default.
/// Only trust forwarded headers in production behind a known reverse proxy.
fn extract_client_ip(headers: &HeaderMap) -> String {
    // Try socket peer address first via X-Real-IP (set by reverse proxies)
    // In production, this should be the only trusted source
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    // Fallback: X-Forwarded-For (less trusted, can be spoofed)
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    "127.0.0.1".to_string()
}
