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
                    // Use user_id directly from JWT claims (avoids DB lookup)
                    let user_id = claims.user_id;
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
            match general_purpose::STANDARD.decode(encoded) {
                Ok(decoded) => {
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
                                    tracing::warn!(
                                        "Rate limit exceeded for user {}: {}",
                                        user_id,
                                        e
                                    );
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
                Err(_) => {}
            }
        }
        _ => {}
    }

    Err(StatusCode::UNAUTHORIZED)
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
            Err(super::handlers::models::ApiError::forbidden("Admin access required"))
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
            return Err(super::handlers::models::ApiError::unauthorized("Account is disabled"));
        }

        Ok(CurrentUser {
            id: cached.id,
            username: cached.username,
            role: cached.role,
        })
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
