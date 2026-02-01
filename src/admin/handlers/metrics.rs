use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::app_state::AppState;

/// Prometheus metrics endpoint
pub async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let active_count = state.state.count_connections().await.unwrap_or(0);
    let total_count = state
        .state
        .get_counter("total_connections")
        .await
        .unwrap_or(0);
    let uptime = state.uptime().as_secs();
    let metrics = format!(
        "# HELP proxy_uptime_seconds Server uptime in seconds\n\
         # TYPE proxy_uptime_seconds gauge\n\
         proxy_uptime_seconds {}\n\
         \n\
         # HELP proxy_active_connections Current number of active connections\n\
         # TYPE proxy_active_connections gauge\n\
         proxy_active_connections {}\n\
         \n\
         # HELP proxy_total_connections_total Total connections since start\n\
         # TYPE proxy_total_connections_total counter\n\
         proxy_total_connections_total {}\n",
        uptime, active_count, total_count
    );
    (StatusCode::OK, metrics)
}
