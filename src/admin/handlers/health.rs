use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

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
}

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        uptime_seconds: state.uptime().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Server statistics endpoint
pub async fn stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);
    Json(StatsResponse {
        uptime_seconds: state.uptime().as_secs(),
        active_connections: active_count,
        total_connections: total_count,
    })
}
