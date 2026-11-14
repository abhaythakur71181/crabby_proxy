use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose, Engine};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::admin::handlers::auth::extract_client_ip;
use crate::app_state::AppState;
use crate::auth::jwt;
use crate::auth_cache::{credential_key, CredentialDomain};
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
    match auth_header {
        Some(auth) if auth.starts_with("Bearer ") => {
            let token = auth.trim_start_matches("Bearer ");
            match jwt::validate_jwt(token, &jwt_secret) {
                Ok(claims) => {
                    let user_id = claims.user_id;
                    // Re-validate the account on every request (cache-aside, cheap).
                    // A valid signature is not enough: a disabled or deleted user
                    // must lose access immediately rather than keep a 24h token
                    // working until natural expiry.
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
                    request.extensions_mut().insert(user_id);
                    if let Err(e) = check_user_rate_limit(&state, user_id).await {
                        tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                        return Err(StatusCode::TOO_MANY_REQUESTS);
                    }
                    return Ok(next.run(request).await);
                }
                Err(_) => {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
        Some(auth) if auth.starts_with("Basic ") => {
            let encoded = auth.trim_start_matches("Basic ");
            let Ok(decoded) = general_purpose::STANDARD.decode(encoded) else {
                return Err(StatusCode::UNAUTHORIZED);
            };
            let credentials = String::from_utf8_lossy(&decoded);
            let Some((username, password)) = credentials.split_once(':') else {
                return Err(StatusCode::UNAUTHORIZED);
            };
            let client_ip = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| extract_client_ip(ci.0, request.headers()))
                // No peer address (only possible outside axum::serve): share
                // one strictly limited bucket rather than skip throttling.
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let user_id = match authenticate_basic(&state, client_ip, username, password).await {
                Ok(uid) => uid,
                Err(status) => return Err(status),
            };
            request.extensions_mut().insert(user_id);
            if let Err(e) = check_user_rate_limit(&state, user_id).await {
                tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            return Ok(next.run(request).await);
        }
        _ => {}
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Authenticate an admin-API `Authorization: Basic` credential.
///
/// Every protected endpoint accepts Basic, so without throttling each one is
/// an unthrottled password oracle, and each guess forces a memory-hard Argon2
/// hash (a cheap request buying expensive server work). So:
///
/// 1. A recently verified credential is served from the auth cache (no
///    Argon2, no limiter), so legitimate clients that send Basic on every
///    request pay for one hash per cache TTL.
/// 2. Otherwise the attempt must pass the same per-IP and per-(IP, username)
///    login limiter as `/api/login` BEFORE any hashing happens.
/// 3. Then the DB user is checked (active accounts only), then the static
///    config credential (constant-time, optionally an Argon2 hash), which now
///    goes through the same limiter instead of bypassing it.
async fn authenticate_basic(
    state: &AppState,
    client_ip: IpAddr,
    username: &str,
    password: &str,
) -> Result<i64, StatusCode> {
    let cache_key = credential_key(CredentialDomain::AdminBasic, username, password);
    if let Some(uid) = state.auth_cache.get(&cache_key) {
        // Same per-request account re-validation as the Bearer path.
        if matches!(state.cached_user_role(uid).await, Some(u) if u.is_active) {
            return Ok(uid);
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !state
        .login_rate_limiter
        .check_user(client_ip, username)
        .await
    {
        tracing::warn!(
            "Admin Basic-auth rate limit exceeded for IP {} (user: {})",
            client_ip,
            username
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    match users::verify_password(&state.db_pool, username, password).await {
        Ok(Some(user)) if user.is_active => {
            state.auth_cache.insert(cache_key, user.id);
            return Ok(user.id);
        }
        Ok(Some(user)) => {
            tracing::warn!("Rejecting Basic auth for disabled user {}", user.id);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("Admin Basic auth: user lookup failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let (expected_user, expected_secret) = {
        let config = state.config.load();
        (
            config.admin.admin_username.clone(),
            config.admin.admin_password.clone(),
        )
    };
    if !crate::credentials::config_credential_matches(
        &expected_user,
        &expected_secret,
        username,
        password,
    )
    .await
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // The config credential maps to the real root_admin account. We refuse
    // to fall back to a sentinel id: a negative id can confuse downstream
    // code that does `user_id > 0` checks and quietly bypass per-user
    // accounting (quotas, audit logs, rate limits).
    match users::get_root_admin(&state.db_pool).await {
        Ok(Some(user)) => {
            state.auth_cache.insert(cache_key, user.id);
            Ok(user.id)
        }
        Ok(None) => {
            tracing::error!(
                "Config admin credential matched but no active root_admin user exists; rejecting to avoid a sentinel user_id"
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(e) => {
            tracing::error!(
                "Config admin credential: failed to look up root_admin: {}",
                e
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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

impl CurrentUser {
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

#[cfg(test)]
mod basic_auth_tests {
    use super::*;
    use crate::db::models::{CreateUserRequest, Role};

    async fn test_state(admin_password: &str) -> AppState {
        let mut config = crate::config::Config::default();
        config.admin.admin_password = admin_password.to_string();
        // Point Redis at a closed port so the test never shares state with
        // a developer's local Redis.
        config.state.redis_url = "redis://127.0.0.1:1".to_string();
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        users::ensure_root_admin(&pool).await.unwrap();
        AppState::new(config, None, pool).await.unwrap()
    }

    async fn add_user(state: &AppState, name: &str, password: &str) -> i64 {
        users::create_user(
            &state.db_pool,
            &CreateUserRequest {
                username: name.to_string(),
                password: password.to_string(),
                role: Role::User,
                max_connections: None,
                bandwidth_limit_mb: None,
                rate_limit_enabled: Some(false),
                rate_limit_rps: None,
                allowed_protocols: None,
                notes: None,
            },
            None,
        )
        .await
        .unwrap()
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    #[tokio::test]
    async fn failed_basic_attempts_are_throttled_before_hashing() {
        let state = test_state("config-admin-password-123").await;
        add_user(&state, "alice", "alice-password-1").await;

        let mut statuses = Vec::new();
        for _ in 0..8 {
            statuses.push(
                authenticate_basic(&state, ip(1), "alice", "wrong")
                    .await
                    .unwrap_err(),
            );
        }
        // Per-(ip, username) burst is 5: then every attempt is refused
        // without reaching Argon2.
        assert!(statuses[..5].iter().all(|s| *s == StatusCode::UNAUTHORIZED));
        assert!(statuses[5..]
            .iter()
            .all(|s| *s == StatusCode::TOO_MANY_REQUESTS));
        // Even the right password is refused while throttled.
        assert_eq!(
            authenticate_basic(&state, ip(1), "alice", "alice-password-1").await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
        // A different client IP is unaffected.
        assert!(
            authenticate_basic(&state, ip(2), "alice", "alice-password-1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn verified_basic_credential_is_cached() {
        let state = test_state("config-admin-password-123").await;
        let uid = add_user(&state, "bob", "bob-password-12").await;
        // Many requests with a correct credential: only the first one is a
        // limiter attempt; the rest are cache hits and never throttled.
        for _ in 0..50 {
            assert_eq!(
                authenticate_basic(&state, ip(3), "bob", "bob-password-12").await,
                Ok(uid)
            );
        }
    }

    #[tokio::test]
    async fn config_admin_credential_resolves_to_root_and_is_throttled() {
        let state = test_state("config-admin-password-123").await;
        let root = users::get_root_admin(&state.db_pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            authenticate_basic(&state, ip(4), "admin", "config-admin-password-123").await,
            Ok(root.id)
        );
        // The config credential no longer bypasses the limiter.
        let mut last = Ok(0);
        for _ in 0..8 {
            last = authenticate_basic(&state, ip(5), "admin", "guess").await;
        }
        assert_eq!(last, Err(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn config_admin_credential_accepts_argon2_hash() {
        let hash = users::hash_password("hashed-admin-secret").await.unwrap();
        let state = test_state(&hash).await;
        assert!(
            authenticate_basic(&state, ip(6), "admin", "hashed-admin-secret")
                .await
                .is_ok()
        );
        assert_eq!(
            authenticate_basic(&state, ip(7), "admin", &hash).await,
            Err(StatusCode::UNAUTHORIZED)
        );
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
