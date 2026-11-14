use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose, Engine};
use std::sync::Arc;

use crate::app_state::AppState;
use crate::auth::jwt;
use crate::db::models::Role;
use crate::db::users;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (auth_enabled, jwt_secret) = {
        let config = state.config.load();
        (
            config.admin.auth_enabled,
            config.authentication.jwt_secret.clone(),
        )
    };
    if !auth_enabled {
        return Ok(next.run(request).await);
    }
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    // Browser (webv2) sessions: no Authorization header, HttpOnly cookie.
    // An explicit Authorization header always wins, so API/CLI clients are
    // unaffected by any cookie the same browser profile may also hold.
    if auth_header.is_none() {
        if let Some(token) = session_cookie(request.headers()) {
            let (user_id, mut session) = authenticate_token(&state, &token, &jwt_secret).await?;
            session.via_cookie = true;
            // Cookies are attached by the browser automatically, so every
            // state-changing request must also prove it came from our UI by
            // echoing the per-session CSRF token in a header.
            if !request.method().is_safe() {
                let presented = request
                    .headers()
                    .get(CSRF_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !csrf_token_matches(&jwt_secret, &session.jti, presented) {
                    tracing::warn!("Rejecting cookie-authenticated request: bad CSRF token");
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            request.extensions_mut().insert(user_id);
            request.extensions_mut().insert(session);
            if let Err(e) = check_user_rate_limit(&state, user_id).await {
                tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            return Ok(next.run(request).await);
        }
    }
    match auth_header {
        Some(auth) if auth.starts_with("Bearer ") => {
            let token = auth.trim_start_matches("Bearer ");
            let (user_id, session) = authenticate_token(&state, token, &jwt_secret).await?;
            request.extensions_mut().insert(user_id);
            request.extensions_mut().insert(session);
            if let Err(e) = check_user_rate_limit(&state, user_id).await {
                tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            return Ok(next.run(request).await);
        }
        Some(auth) if auth.starts_with("Basic ") => {
            let encoded = auth.trim_start_matches("Basic ");
            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                let credentials = String::from_utf8_lossy(&decoded);
                let parts: Vec<&str> = credentials.splitn(2, ':').collect();

                if parts.len() == 2 {
                    let (username, password) = (parts[0], parts[1]);
                    match users::verify_password(&state.db_pool, username, password).await {
                        Ok(Some(user)) => {
                            // Attach user_id to request extensions
                            let user_id = user.id;
                            request.extensions_mut().insert(user_id);
                            if let Err(e) = check_user_rate_limit(&state, user_id).await {
                                tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                                return Err(StatusCode::TOO_MANY_REQUESTS);
                            }

                            return Ok(next.run(request).await);
                        }
                        _ => {
                            // Fallback to Config credentials
                            let config = state.config.load();
                            if username == config.admin.admin_username
                                && password == config.admin.admin_password
                            {
                                // Look up root admin user from DB for an accurate
                                // user_id. We refuse to fall back to a sentinel — a
                                // negative id can confuse downstream code that does
                                // `user_id > 0` checks and may quietly bypass per-user
                                // accounting (quotas, audit logs, rate limits).
                                match crate::db::users::get_user_by_username(
                                    &state.db_pool,
                                    "root_admin",
                                )
                                .await
                                {
                                    Ok(Some(user)) => {
                                        request.extensions_mut().insert(user.id);
                                        // Root admin bypasses rate limiting.
                                        return Ok(next.run(request).await);
                                    }
                                    Ok(None) => {
                                        tracing::error!(
                                            "Config admin login succeeded but root_admin user is missing from database; rejecting to avoid sentinel user_id"
                                        );
                                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Config admin login: failed to look up root_admin: {}",
                                            e
                                        );
                                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// The server-side session behind an authenticated JWT request. Inserted into
/// request extensions by `auth_middleware` (absent for Basic-auth requests and
/// when admin auth is disabled).
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// JWT id; the key of the backing `sessions` row.
    pub jti: String,
    /// Unix seconds when the token expires.
    pub expires_at: i64,
    /// Authenticated via the browser session cookie (vs. Authorization header).
    pub via_cookie: bool,
}

/// Name of the browser session cookie (HttpOnly; holds the session JWT).
pub const SESSION_COOKIE: &str = "cbpx_session";
/// Header carrying the CSRF token on cookie-authenticated unsafe requests.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Extract the session JWT from the `Cookie` header(s), if present.
pub fn session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, value)| *name == SESSION_COOKIE && !value.is_empty())
        .map(|(_, value)| value.to_string())
}

/// `Set-Cookie` value establishing the browser session.
pub fn session_cookie_header(token: &str, max_age_secs: u64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age_secs}; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

/// `Set-Cookie` value deleting the browser session cookie.
pub fn clear_session_cookie_header(secure: bool) -> String {
    session_cookie_header("", 0, secure)
}

/// CSRF token for a cookie session: HMAC-SHA256(jwt_secret, "csrf:" + jti),
/// hex encoded. Bound to the session (a new login gets a new token) and
/// stateless (recomputed per request, nothing stored). It is handed to the UI
/// in the login / session response bodies, never in a cookie, so a cross-site
/// page can neither read nor forge it.
pub fn csrf_token(jwt_secret: &str, jti: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(jwt_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(b"csrf:");
    mac.update(jti.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Constant-time comparison of a presented CSRF token with the expected one.
pub fn csrf_token_matches(jwt_secret: &str, jti: &str, presented: &str) -> bool {
    let expected = csrf_token(jwt_secret, jti);
    let (a, b) = (expected.as_bytes(), presented.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Validate an admin JWT and its backing session.
///
/// A valid signature is not enough:
/// - the token's `jti` must still have a live row in `sessions`, so logout,
///   "sign out everywhere" and credential resets revoke it immediately;
/// - the account must still exist and be active (re-checked per request via
///   the role cache) rather than keeping a token working until expiry.
pub(crate) async fn authenticate_token(
    state: &AppState,
    token: &str,
    jwt_secret: &str,
) -> Result<(i64, AuthSession), StatusCode> {
    let claims = jwt::validate_jwt(token, jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_id = claims.user_id;
    match crate::db::sessions::get_session_by_token(&state.db_pool, &claims.jti).await {
        Ok(Some(s)) if s.user_id == user_id => {}
        Ok(_) => {
            tracing::debug!("Rejecting revoked or unknown session for user {}", user_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            tracing::error!("Session lookup failed: {}", e);
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    match state.cached_user_role(user_id).await {
        Some(u) if u.is_active => {}
        Some(_) => {
            tracing::warn!("Rejecting token for disabled user {}", user_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
        None => {
            tracing::warn!("Rejecting token for unknown user {}", user_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok((
        user_id,
        AuthSession {
            jti: claims.jti,
            expires_at: claims.exp as i64,
            via_cookie: false,
        },
    ))
}

/// Check if user has exceeded their rate limit (optimized with cache)
async fn check_user_rate_limit(state: &AppState, user_id: i64) -> Result<(), &'static str> {
    if let Some(cached_config) = state.user_rate_limiter.get_cached_config(user_id).await {
        let allowed = state
            .user_rate_limiter
            .check_user_cached(user_id, cached_config)
            .await;

        return if allowed {
            Ok(())
        } else {
            Err("Rate limit exceeded")
        };
    }
    let user = users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|_| "Failed to fetch user")?
        .ok_or("User not found")?;
    state
        .user_rate_limiter
        .cache_config(
            user_id,
            user.rate_limit_rps as u32,
            user.rate_limit_burst as u32,
            user.rate_limit_enabled,
            user.max_connections,
        )
        .await;
    // Check if rate limiting is enabled for this user
    if !user.rate_limit_enabled {
        return Ok(());
    }
    let allowed = state
        .user_rate_limiter
        .check_user(
            user_id,
            user.rate_limit_rps as u32,
            user.rate_limit_burst as u32,
        )
        .await;
    if allowed {
        Ok(())
    } else {
        Err("Rate limit exceeded")
    }
}

/// Public endpoints
#[allow(dead_code)]
pub fn is_public_endpoint(path: &str) -> bool {
    matches!(path, "/health" | "/metrics" | "/api/login")
}

/// Current authenticated user (extracted from JWT in middleware)
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

/// Authorize `caller` acting on credentials / sessions of another account
/// (`target_id` with `target_role`). This is the single gate for any action
/// that would let the caller obtain or control a credential for the target
/// (API keys, sessions):
///
/// - anyone may act on themselves;
/// - root_admin may act on anyone;
/// - admin may act only on regular users (never on another admin or on
///   root_admin, otherwise an admin could mint a key for root_admin and
///   impersonate it);
/// - a regular user may not act on anyone else.
pub fn authorize_admin_target(
    caller_id: i64,
    caller_role: &Role,
    target_id: i64,
    target_role: &Role,
) -> Result<(), String> {
    if caller_id == target_id {
        return Ok(());
    }
    match caller_role {
        Role::RootAdmin => Ok(()),
        Role::Admin if *target_role == Role::User => Ok(()),
        Role::Admin => Err("Admins can only manage regular users".to_string()),
        Role::User => Err("Cannot manage other users".to_string()),
    }
}

fn parse_role(role: &str) -> Role {
    match role {
        "root_admin" => Role::RootAdmin,
        "admin" => Role::Admin,
        _ => Role::User,
    }
}

impl CurrentUser {
    /// Parsed role. Unknown role strings degrade to the least-privileged role.
    pub fn role_enum(&self) -> Role {
        parse_role(&self.role)
    }

    /// Resolve `target_id` and apply [`authorize_admin_target`]. Returns 404
    /// for an unknown target, 403 when the caller may not manage it.
    pub async fn authorize_target(
        &self,
        state: &AppState,
        target_id: i64,
    ) -> Result<(), super::handlers::models::ApiError> {
        use super::handlers::models::ApiError;
        if target_id == self.id {
            return Ok(());
        }
        let target = state
            .cached_user_role(target_id)
            .await
            .ok_or_else(|| ApiError::not_found(format!("User {} not found", target_id)))?;
        authorize_admin_target(
            self.id,
            &self.role_enum(),
            target_id,
            &parse_role(&target.role),
        )
        .map_err(ApiError::forbidden)
    }

    /// Check if user can access another user's data
    pub fn can_access_user(&self, target_user_id: i64) -> bool {
        // Admins can access all users
        if self.role == "root_admin" || self.role == "admin" {
            return true;
        }
        // Regular users can only access their own data
        self.id == target_user_id
    }

    /// Require admin role
    pub fn require_admin(&self) -> Result<(), super::handlers::models::ApiError> {
        if self.role == "root_admin" || self.role == "admin" {
            Ok(())
        } else {
            Err(super::handlers::models::ApiError::forbidden(
                "Admin access required",
            ))
        }
    }

    /// Extract from request extensions (set by auth middleware).
    /// Uses Redis -> DB cache-aside via `cached_user_role`.
    pub async fn from_request_extensions(
        state: &AppState,
        user_id: i64,
    ) -> Result<Self, super::handlers::models::ApiError> {
        let cached = state
            .cached_user_role(user_id)
            .await
            .ok_or_else(|| super::handlers::models::ApiError::unauthorized("Invalid session"))?;

        if !cached.is_active {
            return Err(super::handlers::models::ApiError::unauthorized(
                "Account is disabled",
            ));
        }

        Ok(CurrentUser {
            id: cached.id,
            username: cached.username,
            role: cached.role,
        })
    }
}

/// Axum extractor: any authenticated user.
///
/// Resolves the `user_id` attached to request extensions by `auth_middleware`
/// into a `CurrentUser` (which re-checks `is_active` via the role cache).
#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<AppState>> for CurrentUser {
    type Rejection = super::handlers::models::ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user_id =
            parts.extensions.get::<i64>().copied().ok_or_else(|| {
                super::handlers::models::ApiError::unauthorized("Not authenticated")
            })?;
        CurrentUser::from_request_extensions(state, user_id).await
    }
}

/// Axum extractor: authenticated user that must be an admin (`admin` or
/// `root_admin`). Resolution + the role check happen in the extractor, so a
/// handler that takes `AdminUser` cannot run for a non-admin caller — there is
/// no way to forget the guard inside the handler body.
pub struct AdminUser(#[allow(dead_code)] pub CurrentUser);

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = super::handlers::models::ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        user.require_admin()?;
        Ok(AdminUser(user))
    }
}

/// Axum extractor: authenticated user that must be `root_admin`.
pub struct RootAdminUser(pub CurrentUser);

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<AppState>> for RootAdminUser {
    type Rejection = super::handlers::models::ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.role_enum() != Role::RootAdmin {
            return Err(super::handlers::models::ApiError::forbidden(
                "root_admin access required",
            ));
        }
        Ok(RootAdminUser(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_admin_user() -> CurrentUser {
        CurrentUser {
            id: 1,
            username: "root".to_string(),
            role: "root_admin".to_string(),
        }
    }

    fn admin_user() -> CurrentUser {
        CurrentUser {
            id: 2,
            username: "admin1".to_string(),
            role: "admin".to_string(),
        }
    }

    fn regular_user(id: i64) -> CurrentUser {
        CurrentUser {
            id,
            username: format!("user{}", id),
            role: "user".to_string(),
        }
    }

    // === can_access_user Tests ===

    #[test]
    fn test_root_admin_can_access_any_user() {
        let user = root_admin_user();
        assert!(user.can_access_user(1));
        assert!(user.can_access_user(2));
        assert!(user.can_access_user(999));
    }

    #[test]
    fn test_admin_can_access_any_user() {
        let user = admin_user();
        assert!(user.can_access_user(1));
        assert!(user.can_access_user(2));
        assert!(user.can_access_user(999));
    }

    #[test]
    fn test_regular_user_can_access_own_data() {
        let user = regular_user(10);
        assert!(user.can_access_user(10));
    }

    #[test]
    fn test_regular_user_cannot_access_other_users() {
        let user = regular_user(10);
        assert!(!user.can_access_user(1));
        assert!(!user.can_access_user(11));
        assert!(!user.can_access_user(999));
    }

    // === authorize_admin_target (privilege-escalation gate, #16) ===

    #[test]
    fn test_admin_target_matrix() {
        use Role::*;
        // self is always allowed
        for r in [RootAdmin, Admin, User] {
            assert!(authorize_admin_target(5, &r, 5, &r).is_ok());
        }
        // root_admin may target anyone
        for t in [RootAdmin, Admin, User] {
            assert!(authorize_admin_target(1, &RootAdmin, 2, &t).is_ok());
        }
        // admin may target only regular users
        assert!(authorize_admin_target(2, &Admin, 3, &User).is_ok());
        assert!(authorize_admin_target(2, &Admin, 1, &RootAdmin).is_err());
        assert!(authorize_admin_target(2, &Admin, 4, &Admin).is_err());
        // a regular user may not target anyone else
        for t in [RootAdmin, Admin, User] {
            assert!(authorize_admin_target(3, &User, 9, &t).is_err());
        }
    }

    #[test]
    fn test_role_enum_parsing() {
        assert_eq!(root_admin_user().role_enum(), Role::RootAdmin);
        assert_eq!(admin_user().role_enum(), Role::Admin);
        assert_eq!(regular_user(3).role_enum(), Role::User);
        let odd = CurrentUser {
            id: 1,
            username: "x".into(),
            role: "superuser".into(),
        };
        assert_eq!(odd.role_enum(), Role::User);
    }

    // === Session cookie / CSRF helpers ===

    #[test]
    fn test_session_cookie_parsing() {
        let mut h = axum::http::HeaderMap::new();
        assert_eq!(session_cookie(&h), None);
        h.insert(
            header::COOKIE,
            "theme=dark; cbpx_session=abc.def.ghi; other=1"
                .parse()
                .unwrap(),
        );
        assert_eq!(session_cookie(&h).as_deref(), Some("abc.def.ghi"));
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::COOKIE, "cbpx_session=".parse().unwrap());
        assert_eq!(session_cookie(&h), None, "empty (cleared) cookie ignored");
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::COOKIE, "xcbpx_session=evil".parse().unwrap());
        assert_eq!(session_cookie(&h), None, "name must match exactly");
    }

    #[test]
    fn test_session_cookie_attributes() {
        let c = session_cookie_header("tok", 3600, true);
        for attr in [
            "cbpx_session=tok",
            "HttpOnly",
            "SameSite=Strict",
            "Secure",
            "Path=/",
            "Max-Age=3600",
        ] {
            assert!(c.contains(attr), "missing {attr} in {c}");
        }
        assert!(!session_cookie_header("tok", 1, false).contains("Secure"));
        assert!(clear_session_cookie_header(true).contains("Max-Age=0"));
    }

    #[test]
    fn test_csrf_token_bound_to_session_and_secret() {
        let s = "secret_key_at_least_32_bytes_long_xxxxxx";
        let t = csrf_token(s, "jti-1");
        assert_eq!(t.len(), 64);
        assert!(csrf_token_matches(s, "jti-1", &t));
        assert!(!csrf_token_matches(s, "jti-2", &t));
        assert!(!csrf_token_matches(
            "another_secret_key_32_bytes_long_xxxxx",
            "jti-1",
            &t
        ));
        assert!(!csrf_token_matches(s, "jti-1", ""));
        assert!(!csrf_token_matches(s, "jti-1", &t[..63]));
    }

    // === require_admin Tests ===

    #[test]
    fn test_root_admin_passes_require_admin() {
        let user = root_admin_user();
        assert!(user.require_admin().is_ok());
    }

    #[test]
    fn test_admin_passes_require_admin() {
        let user = admin_user();
        assert!(user.require_admin().is_ok());
    }

    #[test]
    fn test_regular_user_fails_require_admin() {
        let user = regular_user(10);
        let result = user.require_admin();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_unknown_role_fails_require_admin() {
        let user = CurrentUser {
            id: 99,
            username: "custom".to_string(),
            role: "moderator".to_string(),
        };
        assert!(user.require_admin().is_err());
    }

    // === is_public_endpoint Tests ===

    #[test]
    fn test_health_is_public() {
        assert!(is_public_endpoint("/health"));
    }

    #[test]
    fn test_metrics_is_public() {
        assert!(is_public_endpoint("/metrics"));
    }

    #[test]
    fn test_login_is_public() {
        assert!(is_public_endpoint("/api/login"));
    }

    #[test]
    fn test_users_is_not_public() {
        assert!(!is_public_endpoint("/api/users"));
    }

    #[test]
    fn test_connections_is_not_public() {
        assert!(!is_public_endpoint("/api/connections"));
    }

    #[test]
    fn test_config_is_not_public() {
        assert!(!is_public_endpoint("/api/config"));
    }

    #[test]
    fn test_empty_path_is_not_public() {
        assert!(!is_public_endpoint(""));
    }

    #[test]
    fn test_root_path_is_not_public() {
        assert!(!is_public_endpoint("/"));
    }

    // === CurrentUser Debug/Clone ===

    #[test]
    fn test_current_user_clone() {
        let user = root_admin_user();
        let cloned = user.clone();
        assert_eq!(cloned.id, user.id);
        assert_eq!(cloned.username, user.username);
        assert_eq!(cloned.role, user.role);
    }

    #[test]
    fn test_current_user_debug() {
        let user = admin_user();
        let debug = format!("{:?}", user);
        assert!(debug.contains("admin1"));
        assert!(debug.contains("admin"));
    }
}
