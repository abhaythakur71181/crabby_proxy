use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;

#[derive(Debug, Serialize)]
pub struct QuotaResponse {
    pub user_id: i64,
    pub quota_bytes: Option<i64>,
    pub used_bytes: i64,
    pub remaining_bytes: Option<i64>,
    pub percentage_used: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateQuotaRequest {
    pub quota_bytes: Option<i64>,
}

/// GET /api/users/:id/quota - Get user's quota usage stats
pub async fn get_user_quota(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<QuotaResponse>, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    // Authorization check: only admins or the user themselves can view quota
    if !current_user.can_access_user(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let user = crate::db::users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if user.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    let stats = crate::db::quota::get_quota_stats(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(QuotaResponse {
        user_id,
        quota_bytes: stats.quota_bytes,
        used_bytes: stats.used_bytes,
        remaining_bytes: stats.remaining_bytes,
        percentage_used: stats.percentage_used,
    }))
}

/// PUT /api/users/:id/quota - Update user's quota
pub async fn update_user_quota(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<UpdateQuotaRequest>,
) -> Result<Json<QuotaResponse>, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    // Only admins can update quotas
    current_user.require_admin()?;
    let user = crate::db::users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if user.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    crate::db::quota::update_quota(&state.db_pool, user_id, payload.quota_bytes)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stats = crate::db::quota::get_quota_stats(&state.db_pool, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(QuotaResponse {
        user_id,
        quota_bytes: stats.quota_bytes,
        used_bytes: stats.used_bytes,
        remaining_bytes: stats.remaining_bytes,
        percentage_used: stats.percentage_used,
    }))
}
