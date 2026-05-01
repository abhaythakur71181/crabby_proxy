use super::models::ApiError;
use axum::{extract::Path, Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::app_state::AppState;
use std::sync::Arc;

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
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<QuotaResponse>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(ApiError::forbidden("Cannot access other users' quota"));
    }
    let user = crate::db::users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            ApiError::internal("Database error")
        })?;
    if user.is_none() {
        return Err(ApiError::not_found(format!("User {} not found", user_id)));
    }
    let stats = crate::db::quota::get_quota_stats(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get quota stats: {}", e);
            ApiError::internal("Failed to retrieve quota stats")
        })?;
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
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Json(payload): Json<UpdateQuotaRequest>,
) -> Result<Json<QuotaResponse>, ApiError> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;
    let user = crate::db::users::get_user_by_id(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            ApiError::internal("Database error")
        })?;
    if user.is_none() {
        return Err(ApiError::not_found(format!("User {} not found", user_id)));
    }
    crate::db::quota::update_quota(&state.db_pool, user_id, payload.quota_bytes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update quota: {}", e);
            ApiError::internal("Failed to update quota")
        })?;

    // Invalidate cached quota so proxy picks up the new limit immediately
    state.invalidate_quota_cache(user_id).await;

    let stats = crate::db::quota::get_quota_stats(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get quota stats: {}", e);
            ApiError::internal("Failed to retrieve quota stats")
        })?;
    Ok(Json(QuotaResponse {
        user_id,
        quota_bytes: stats.quota_bytes,
        used_bytes: stats.used_bytes,
        remaining_bytes: stats.remaining_bytes,
        percentage_used: stats.percentage_used,
    }))
}
