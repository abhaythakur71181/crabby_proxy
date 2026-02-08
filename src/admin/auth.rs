use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::{engine::general_purpose, Engine};

use crate::app_state::AppState;
use crate::auth::jwt;
use crate::db::users;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (auth_enabled, jwt_secret) = {
        let config = state.config.read().await;
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
                    // JWT claims.sub contains username, need to fetch user_id
                    let username = claims.sub;
                    match users::get_user_by_username(&state.db_pool, &username).await {
                        Ok(Some(user)) => {
                            let user_id = user.id;
                            request.extensions_mut().insert(user_id);
                            if let Err(e) = check_user_rate_limit(&state, user_id).await {
                                tracing::warn!("Rate limit exceeded for user {}: {}", user_id, e);
                                return Err(StatusCode::TOO_MANY_REQUESTS);
                            }
                            return Ok(next.run(request).await);
                        }
                        _ => {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                    }
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
                                let config = state.config.read().await;
                                if username == config.admin.admin_username
                                    && password == config.admin.admin_password
                                {
                                    // For config auth, use root user ID (1)
                                    let user_id = 1i64;
                                    request.extensions_mut().insert(user_id);

                                    // Root admin bypasses rate limiting
                                    return Ok(next.run(request).await);
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
pub fn is_public_endpoint(path: &str) -> bool {
    matches!(path, "/health" | "/metrics" | "/api/login")
}
