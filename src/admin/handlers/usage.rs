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
    Query(params): Query<UsageQuery>,
) -> Result<Json<UsageStatsResponse>, StatusCode> {
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
    Query(params): Query<UsageQuery>,
) -> Result<Json<Vec<UsageRecordResponse>>, StatusCode> {
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
) -> Result<Json<UsageStatsResponse>, StatusCode> {
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
