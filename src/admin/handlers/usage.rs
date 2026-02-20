use crate::app_state::AppState;
use crate::db::usage;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct UsageQuery {
    /// Number of days to query (default: 30)
    pub days: Option<i32>,
    /// Number of recent records to return (default: 100)
    pub limit: Option<i32>,
}

#[derive(Serialize)]
pub struct UsageStatsResponse {
    pub user_id: i64,
    pub period_days: i32,
    pub connection_count: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub total_bandwidth: i64,
}

#[derive(Serialize)]
pub struct UsageRecordResponse {
    pub id: i64,
    pub connection_id: String,
    pub client_ip: String,
    pub target_host: String,
    pub protocol: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub duration_seconds: Option<i32>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub status: String,
}

/// GET /api/users/:id/usage - Get user usage statistics
pub async fn get_user_usage_stats(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Query(params): Query<UsageQuery>,
) -> Result<Json<UsageStatsResponse>, StatusCode> {
    // Extract current user and check authorization
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let days = params.days.unwrap_or(30);
    let stats = usage::get_user_usage(&state.db_pool, user_id, days)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user usage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(UsageStatsResponse {
        user_id,
        period_days: days,
        connection_count: stats.connection_count,
        bytes_sent: stats.total_bytes_sent,
        bytes_received: stats.total_bytes_received,
        total_bandwidth: stats.total_bandwidth,
    }))
}

/// GET /api/users/:id/usage/recent - Get recent usage records
pub async fn get_recent_usage(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Query(params): Query<UsageQuery>,
) -> Result<Json<Vec<UsageRecordResponse>>, StatusCode> {
    // Extract current user and check authorization
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let limit = params.limit.unwrap_or(100);

    let records = usage::get_recent_usage_records(&state.db_pool, user_id, limit)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get recent usage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response = records
        .into_iter()
        .map(|r| UsageRecordResponse {
            id: r.id,
            connection_id: r.connection_id,
            client_ip: r.client_ip,
            target_host: r.target_host,
            protocol: r.protocol,
            started_at: r.started_at,
            ended_at: r.ended_at,
            duration_seconds: r.duration_seconds,
            bytes_sent: r.bytes_sent,
            bytes_received: r.bytes_received,
            status: r.status,
        })
        .collect();

    Ok(Json(response))
}

/// GET /api/users/:id/usage/all-time - Get all-time usage statistics
pub async fn get_all_time_usage(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    axum::Extension(current_user_id): axum::Extension<i64>,
) -> Result<Json<UsageStatsResponse>, StatusCode> {
    // Extract current user and check authorization
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    if !current_user.can_access_user(user_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let stats = usage::get_all_time_usage(&state.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get all-time usage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(UsageStatsResponse {
        user_id,
        period_days: -1, // Indicates all-time
        connection_count: stats.connection_count,
        bytes_sent: stats.total_bytes_sent,
        bytes_received: stats.total_bytes_received,
        total_bandwidth: stats.total_bandwidth,
    }))
}

// --- System-wide usage ---

#[derive(Serialize)]
pub struct SystemUsageSummaryResponse {
    pub period_days: i32,
    pub total_connections: i64,
    pub total_bytes_sent: i64,
    pub total_bytes_received: i64,
    pub total_bandwidth: i64,
    pub unique_users: i64,
    pub top_users: Vec<TopUserResponse>,
}

#[derive(Serialize)]
pub struct TopUserResponse {
    pub user_id: i64,
    pub total_bandwidth: i64,
    pub connection_count: i64,
}

/// GET /api/usage/summary - System-wide usage dashboard (admin only)
pub async fn get_system_usage_summary(
    State(state): State<AppState>,
    axum::Extension(current_user_id): axum::Extension<i64>,
    Query(params): Query<UsageQuery>,
) -> Result<Json<SystemUsageSummaryResponse>, StatusCode> {
    let current_user =
        crate::admin::auth::CurrentUser::from_request_extensions(&state, current_user_id).await?;
    current_user.require_admin()?;

    let days = params.days.unwrap_or(30);
    let top_limit = params.limit.unwrap_or(10);

    let stats = usage::get_system_usage_stats(&state.db_pool, days)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get system usage stats: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let top_users = usage::get_top_users_by_bandwidth(&state.db_pool, days, top_limit)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top users: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(SystemUsageSummaryResponse {
        period_days: days,
        total_connections: stats.total_connections,
        total_bytes_sent: stats.total_bytes_sent,
        total_bytes_received: stats.total_bytes_received,
        total_bandwidth: stats.total_bandwidth,
        unique_users: stats.unique_users,
        top_users: top_users
            .into_iter()
            .map(|u| TopUserResponse {
                user_id: u.user_id,
                total_bandwidth: u.total_bandwidth,
                connection_count: u.connection_count,
            })
            .collect(),
    }))
}
