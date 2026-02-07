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
                    // Attach user_id to request extensions
                    request.extensions_mut().insert(claims.sub);
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
                                request.extensions_mut().insert(user.id);
                                return Ok(next.run(request).await);
                            }
                            _ => {
                                // Fallback to Config credentials
                                let config = state.config.read().await;
                                if username == config.admin.admin_username
                                    && password == config.admin.admin_password
                                {
                                    // For config auth, use root user ID (1)
                                    request.extensions_mut().insert(1i64);
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

/// Public endpoints
pub fn is_public_endpoint(path: &str) -> bool {
    matches!(path, "/health" | "/metrics" | "/api/login")
}
