use axum::{
    extract::State,
    http::StatusCode,
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
    Json(payload): Json<LoginRequest>,
) -> Result<Response, (StatusCode, String)> {
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
