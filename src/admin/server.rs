use axum::http::Method;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

use super::handlers;
use crate::app_state::AppState;

pub async fn run_admin_server(state: AppState, addr: SocketAddr) -> Result<(), std::io::Error> {
    tracing::info!("Starting admin API server on {}", addr);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/metrics", get(handlers::metrics::prometheus_metrics))
        .route("/api/login", post(handlers::auth::login));

    // Protected routes (auth required)
    let protected_routes = Router::new()
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
        // User management routes
        .route("/api/users", post(handlers::users::create_user))
        .route("/api/users", get(handlers::users::list_users))
        .route("/api/users/:id", get(handlers::users::get_user))
        .route(
            "/api/users/:id",
            axum::routing::put(handlers::users::update_user),
        )
        .route("/api/users/:id", delete(handlers::users::delete_user))
        // Usage tracking routes
        .route(
            "/api/users/:id/usage",
            get(handlers::usage::get_user_usage_stats),
        )
        .route(
            "/api/users/:id/usage/recent",
            get(handlers::usage::get_recent_usage),
        )
        .route(
            "/api/users/:id/usage/all-time",
            get(handlers::usage::get_all_time_usage),
        )
        // System-wide usage dashboard
        .route(
            "/api/usage/summary",
            get(handlers::usage::get_system_usage_summary),
        )
        // Quota management routes
        .route(
            "/api/users/:id/quota",
            get(handlers::quotas::get_user_quota),
        )
        .route(
            "/api/users/:id/quota",
            axum::routing::put(handlers::quotas::update_user_quota),
        )
        // API key management routes
        .route(
            "/api/users/:id/api-keys",
            post(handlers::users::create_api_key),
        )
        .route(
            "/api/users/:id/api-keys",
            get(handlers::users::list_api_keys),
        )
        .route(
            "/api/users/:id/api-keys/:key_id",
            delete(handlers::users::revoke_api_key),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::auth_middleware,
        ))
        // Limit request body to 1MB to prevent OOM from large payloads
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any)
        .allow_origin(Any); // TODO: restrict to admin UI origin
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors)
        .with_state(state.clone());

    tracing::info!(
        "Admin API listening on {} with {} routes (health, metrics, login, stats, connections, tunnels, users, quota, config)",
        addr,
        "public + protected"
    );
    tracing::info!("Admin API routes configured");
    tracing::info!("  GET /health - Health check");
    tracing::info!("  GET /metrics - Prometheus metrics");
    tracing::info!("  POST /api/login - Admin login");
    tracing::info!("  GET /stats - Server statistics");
    tracing::info!("  GET /api/connections - List connections");
    tracing::info!("  GET /api/tunnels - List tunnels");
    tracing::info!("  POST /api/tunnels - Create tunnel");
    tracing::info!("  DELETE /api/tunnels/:port - Close tunnel");
    tracing::info!("  GET /api/config - View configuration");
    tracing::info!("  POST /api/config/reload - Reload configuration");

    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Admin API shutting down gracefully");
        })
        .await?;
    Ok(())
}
