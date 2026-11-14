use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::admin::auth::{AuthSession, CurrentUser};
use crate::{
    app_state::AppState,
    auth::jwt,
    db::{sessions, users},
};
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
        let (secret, expiration) = {
            let config = state.config.load();
            (
                config.authentication.jwt_secret.clone(),
                config.authentication.jwt_expiration,
            )
        };
        let (token, claims) =
            jwt::issue_jwt(user.id, &user.username, &user.role, &secret, expiration)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Every token is backed by a session row keyed by its jti; the auth
        // middleware rejects tokens whose session is gone (logout / revoke).
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(256).collect::<String>());
        // Opportunistic cleanup keeps the table bounded without a timer.
        let _ = sessions::cleanup_expired_sessions(pool).await;
        sessions::create_session(
            pool,
            user.id,
            &claims.jti,
            claims.exp as i64,
            Some(&client_ip),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to persist session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session".to_string(),
            )
        })?;
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

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    /// Unix seconds when the current token expires (absent for Basic auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// GET /api/session — who am I, according to the presented credentials.
pub async fn current_session(
    user: CurrentUser,
    session: Option<Extension<AuthSession>>,
) -> Json<SessionResponse> {
    Json(SessionResponse {
        user_id: user.id,
        username: user.username,
        role: user.role,
        expires_at: session.map(|s| s.expires_at),
    })
}

/// POST /api/logout — revoke the session behind the presented token.
///
/// Public route and idempotent: an invalid, expired or already-revoked token
/// still gets 204, so a client can always clear its local state. A valid
/// token's session row is deleted, which makes the token unusable at once.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> StatusCode {
    let secret = state.config.load().authentication.jwt_secret.clone();
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    if let Some(token) = token {
        if let Ok(claims) = jwt::validate_jwt(token, &secret) {
            if let Err(e) = sessions::delete_session_by_token(&state.db_pool, &claims.jti).await {
                tracing::error!("Logout: failed to delete session: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
    }
    StatusCode::NO_CONTENT
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
