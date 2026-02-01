use axum::{routing::get, Router};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

use super::handlers;
use crate::app_state::AppState;

pub async fn run_admin_server(state: AppState, addr: SocketAddr) -> Result<(), std::io::Error> {
    tracing::info!("Starting admin API server on {}", addr);
    let app = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/stats", get(handlers::health::stats))
        .route(
            "/api/connections",
            get(handlers::connections::list_connections),
        )
        .route(
            "/api/connections/count",
            get(handlers::connections::count_connections),
        )
        .route("/metrics", get(handlers::metrics::prometheus_metrics))
        .layer(CorsLayer::permissive())
        .with_state(state);
    tracing::info!("Admin API routes configured");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
