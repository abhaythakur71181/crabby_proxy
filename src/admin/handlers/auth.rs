use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::admin::auth::{self as admin_auth, AuthSession, CurrentUser};
use crate::{
    app_state::AppState,
    auth::jwt,
    db::{sessions, users},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Browser clients (webv2) set this to receive the session as an
    /// HttpOnly cookie instead of a token in the body. API/CLI clients omit
    /// it and keep getting a bearer token, unchanged.
    #[serde(default)]
    pub use_cookie: bool,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Bearer token. Omitted in cookie mode so the browser-side script never
    /// sees a credential it could leak.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub expires_in: u64,
    pub role: String,
    pub user_id: i64,
    pub username: String,
    /// Unix seconds when the session expires.
    pub expires_at: i64,
    /// Cookie mode only: value to send in `X-CSRF-Token` on unsafe requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
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
        .check_user(client_ip, &payload.username)
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
        let (secret, expiration, cookie_secure) = {
            let config = state.config.load();
            (
                config.authentication.jwt_secret.clone(),
                config.authentication.jwt_expiration,
                config.admin.session_cookie_secure,
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
            Some(&client_ip.to_string()),
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
        let mut body = LoginResponse {
            token: None,
            expires_in: expiration,
            role: user.role,
            user_id: user.id,
            username: user.username,
            expires_at: claims.exp as i64,
            csrf_token: None,
        };
        if payload.use_cookie {
            body.csrf_token = Some(admin_auth::csrf_token(&secret, &claims.jti));
            let cookie = admin_auth::session_cookie_header(&token, expiration, cookie_secure);
            Ok(([(header::SET_COOKIE, cookie), no_store()], Json(body)).into_response())
        } else {
            body.token = Some(token);
            Ok(([no_store()], Json(body)).into_response())
        }
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
    /// Cookie sessions only: the CSRF token for this session, so a reloaded
    /// tab (which lost its in-memory copy) can recover it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
}

/// GET /api/session — who am I, according to the presented credentials.
pub async fn current_session(
    State(state): State<Arc<AppState>>,
    user: CurrentUser,
    session: Option<Extension<AuthSession>>,
) -> impl IntoResponse {
    let csrf_token = session.as_ref().filter(|s| s.via_cookie).map(|s| {
        let secret = state.config.load().authentication.jwt_secret.clone();
        admin_auth::csrf_token(&secret, &s.jti)
    });
    (
        [no_store()],
        Json(SessionResponse {
            user_id: user.id,
            username: user.username,
            role: user.role,
            expires_at: session.map(|s| s.expires_at),
            csrf_token,
        }),
    )
}

fn no_store() -> (header::HeaderName, String) {
    (header::CACHE_CONTROL, "no-store".to_string())
}

/// POST /api/logout — revoke the session behind the presented token (bearer
/// header, or the browser session cookie) and clear the cookie.
///
/// Public route and idempotent: an invalid, expired or already-revoked token
/// still gets 204, so a client can always clear its local state. A valid
/// token's session row is deleted, which makes the token unusable at once.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (secret, cookie_secure) = {
        let config = state.config.load();
        (
            config.authentication.jwt_secret.clone(),
            config.admin.session_cookie_secure,
        )
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| admin_auth::session_cookie(&headers));
    if let Some(token) = token {
        if let Ok(claims) = jwt::validate_jwt(&token, &secret) {
            if let Err(e) = sessions::delete_session_by_token(&state.db_pool, &claims.jti).await {
                tracing::error!("Logout: failed to delete session: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            admin_auth::clear_session_cookie_header(cookie_secure),
        )],
    )
        .into_response()
}

/// Resolve the client IP used for login rate limiting.
///
/// The socket peer is the source of truth. `X-Real-IP` / `X-Forwarded-For` are
/// client-controlled and were previously trusted unconditionally, so an
/// attacker could rotate the header per request to mint a fresh rate-limit
/// bucket and brute-force logins. We now honor forwarded headers ONLY when the
/// immediate peer is loopback — i.e. a reverse proxy on the same host (the
/// bundled nginx). A remote peer's forged header is ignored.
///
/// Returns a typed `IpAddr`: a forwarded value that does not parse as an IP is
/// ignored (we fall back to the peer address) rather than handed to the
/// limiter as an opaque string, which used to fail open.
pub(crate) fn extract_client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    if peer_ip.is_loopback() {
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn remote_peer_ignores_forwarded_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        let peer: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        assert_eq!(
            extract_client_ip(peer, &h),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn loopback_peer_honors_forwarded_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 10.0.0.1"),
        );
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        assert_eq!(
            extract_client_ip(peer, &h),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn unparseable_forwarded_value_falls_back_to_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.7:8080"));
        h.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        assert_eq!(
            extract_client_ip(peer, &h),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
