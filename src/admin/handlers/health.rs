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
