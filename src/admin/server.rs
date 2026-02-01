use axum::{
    routing::{delete, get, post},
    Router,
};
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
        .route("/api/tunnels", get(handlers::tunnels::list_tunnels))
        .route("/api/tunnels", post(handlers::tunnels::create_tunnel))
        .route(
            "/api/tunnels/:port",
            delete(handlers::tunnels::close_tunnel),
        )
        .route("/api/config", get(handlers::config::get_config))
        .route("/api/config/reload", post(handlers::config::reload_config))
        .route("/metrics", get(handlers::metrics::prometheus_metrics))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("Admin API routes configured");
    tracing::info!("  GET /health - Health check");
    tracing::info!("  GET /stats - Server statistics");
    tracing::info!("  GET /api/connections - List connections");
    tracing::info!("  GET /api/tunnels - List tunnels");
    tracing::info!("  POST /api/tunnels - Create tunnel");
    tracing::info!("  DELETE /api/tunnels/:port - Close tunnel");
    tracing::info!("  GET /api/config - View configuration");
    tracing::info!("  POST /api/config/reload - Reload configuration");
    tracing::info!("  GET /metrics - Prometheus metrics");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
