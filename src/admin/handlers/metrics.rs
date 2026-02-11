use crate::app_state::AppState;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
};

/// Prometheus metrics endpoint
pub async fn prometheus_metrics(State(_state): State<AppState>) -> impl IntoResponse {
    let metrics_output = crate::metrics::export_metrics();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics_output,
    )
}
