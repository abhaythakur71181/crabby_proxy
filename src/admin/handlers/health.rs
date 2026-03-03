use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app_state::AppState;

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct StatsResponse {
    pub uptime_seconds: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_bandwidth: u64,
}

pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Server statistics endpoint
pub async fn stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);

    // Read bandwidth from Prometheus counters
    let bytes_sent = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["sent"])
        .get() as u64;
    let bytes_received = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["received"])
        .get() as u64;

    Json(StatsResponse {
        uptime_seconds: state.uptime().as_secs(),
        active_connections: active_count,
        total_connections: total_count,
        total_bytes_sent: bytes_sent,
        total_bytes_received: bytes_received,
        total_bandwidth: bytes_sent + bytes_received,
    })
}

/// Aggregate dashboard response
#[derive(Serialize)]
pub struct DashboardResponse {
    // System
    pub uptime_seconds: u64,
    pub version: String,
    pub status: String,
    // Connections
    pub active_connections: usize,
    pub total_connections: u64,
    // Bandwidth
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bandwidth: u64,
    // Usage (last 24h)
    pub bandwidth_24h: Option<i64>,
    pub connections_24h: Option<i64>,
    // Users
    pub total_users: i64,
    pub top_users_24h: Vec<TopUserDashboard>,
    // Tunnels
    pub active_tunnels: usize,
}

#[derive(Serialize)]
pub struct TopUserDashboard {
    pub user_id: i64,
    pub bandwidth: i64,
    pub connections: i64,
}

/// GET /api/dashboard — Aggregate dashboard data in a single call
pub async fn dashboard(State(state): State<Arc<AppState>>) -> Json<DashboardResponse> {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);
    let bytes_sent = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["sent"])
        .get() as u64;
    let bytes_received = crate::metrics::BYTES_TRANSFERRED
        .with_label_values(&["received"])
        .get() as u64;
    // 24h usage stats
    let (bandwidth_24h, connections_24h) =
        match crate::db::usage::get_system_usage_stats(&state.db_pool, 1).await {
            Ok(stats) => (Some(stats.total_bandwidth), Some(stats.total_connections)),
            Err(_) => (None, None),
        };
    // Top users by bandwidth (24h, top 5)
    let top_users_24h =
        match crate::db::usage::get_top_users_by_bandwidth(&state.db_pool, 1, 5).await {
            Ok(users) => users
                .into_iter()
                .map(|u| TopUserDashboard {
                    user_id: u.user_id,
                    bandwidth: u.total_bandwidth,
                    connections: u.connection_count,
                })
                .collect(),
            Err(_) => vec![],
        };
    // Total users
    let total_users = match crate::db::users::count_users(&state.db_pool).await {
        Ok(count) => count,
        Err(_) => 0,
    };
    // Active tunnels
    let active_tunnels = state.tunnels.read().await.count_active();
    Json(DashboardResponse {
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "healthy".to_string(),
        active_connections: active_count,
        total_connections: total_count,
        bytes_sent,
        bytes_received,
        total_bandwidth: bytes_sent + bytes_received,
        bandwidth_24h,
        connections_24h,
        total_users,
        top_users_24h,
        active_tunnels,
    })
}
