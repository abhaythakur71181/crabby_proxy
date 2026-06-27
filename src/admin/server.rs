use axum::http::Method;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use super::handlers;
use crate::app_state::AppState;

pub async fn run_admin_server(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> Result<(), std::io::Error> {
    tracing::info!("Starting admin API server on {}", addr);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health::health_check))
        .route("/health/deep", get(handlers::health::deep_health_check))
        .route("/metrics", get(handlers::metrics::prometheus_metrics))
        .route("/api/login", post(handlers::auth::login))
        // Authorized by a one-time ticket (minted at /api/connections/live-ticket),
        // since a browser can't put a bearer on the WS handshake.
        .route(
            "/api/connections/live",
            get(handlers::connections::live_connections),
        );

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/stats", get(handlers::health::stats))
        .route("/api/dashboard", get(handlers::health::dashboard))
        .route("/api/metrics", get(handlers::health::json_metrics))
        .route(
            "/api/connections",
            get(handlers::connections::list_connections),
        )
        .route(
            "/api/connections/count",
            get(handlers::connections::count_connections),
        )
        .route(
            "/api/connections/:id",
            delete(handlers::connections::terminate_connection),
        )
        .route(
            "/api/connections/live-ticket",
            post(handlers::connections::issue_live_ticket),
        )
        .route("/api/tunnels", get(handlers::tunnels::list_tunnels))
        .route("/api/tunnels", post(handlers::tunnels::create_tunnel))
        .route(
            "/api/tunnels/:port",
            delete(handlers::tunnels::close_tunnel),
        )
        .route("/api/config", get(handlers::config::get_config))
        .route(
            "/api/config",
            axum::routing::put(handlers::config::update_config),
        )
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
        .route(
            "/api/usage/timeseries",
            get(handlers::usage::get_usage_timeseries),
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
        // Approval management routes
        .route("/api/approvals", post(handlers::approvals::create_approval))
        .route("/api/approvals", get(handlers::approvals::list_approvals))
        .route(
            "/api/approvals/:id",
            delete(handlers::approvals::terminate_approval),
        )
        .route(
            "/api/users/:id/approvals",
            get(handlers::approvals::list_user_approvals),
        )
        // Approval request workflow routes
        .route(
            "/api/approval-requests",
            post(handlers::approval_requests::create_request),
        )
        .route(
            "/api/approval-requests",
            get(handlers::approval_requests::list_requests),
        )
        .route(
            "/api/approval-requests/:id/approve",
            post(handlers::approval_requests::approve_request),
        )
        .route(
            "/api/approval-requests/:id/reject",
            post(handlers::approval_requests::reject_request),
        )
        // Audit log routes
        .route("/api/audit-log", get(handlers::audit::list_audit_log))
        // Session management routes
        .route(
            "/api/users/:id/sessions",
            get(handlers::audit::list_user_sessions),
        )
        .route(
            "/api/users/:id/sessions",
            delete(handlers::audit::delete_user_sessions),
        )
        // User group routes
        .route("/api/groups", post(handlers::groups::create_group))
        .route("/api/groups", get(handlers::groups::list_groups))
        .route("/api/groups/:id", get(handlers::groups::get_group))
        .route("/api/groups/:id", delete(handlers::groups::delete_group))
        .route(
            "/api/groups/:id/members",
            post(handlers::groups::add_member),
        )
        .route(
            "/api/groups/:id/members",
            get(handlers::groups::list_members),
        )
        .route(
            "/api/groups/:id/members/:user_id",
            delete(handlers::groups::remove_member),
        )
        .route(
            "/api/users/:id/groups",
            get(handlers::groups::list_user_groups),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::auth::auth_middleware,
        ))
        // Limit request body to 1MB to prevent OOM from large payloads
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));

    // S3: Use configured CORS origins instead of allow_origin(Any)
    let cors_origins = state.config.load().admin.cors_origins.clone();
    // R2-18: never combine `allow_origin(Any)` with `allow_credentials(true)`.
    // The admin API uses bearer-token auth, so credentialed requests are the
    // norm — wide-open CORS is a CSRF/exfiltration risk. Empty config now
    // means "no cross-origin access", not "everyone allowed".
    let cors = if cors_origins.is_empty() {
        tracing::warn!(
            "No CORS origins configured — admin API will only accept same-origin requests. \
             Set [admin] cors_origins = [\"https://your.dashboard\"] to allow a UI."
        );
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
    } else if cors_origins.iter().any(|o| o == "*") {
        // Explicit "*" still works but only without credentials, and we
        // refuse to also allow Authorization headers since they wouldn't
        // be honored cross-origin anyway.
        tracing::warn!(
            "CORS configured with '*' — credentialed requests will not be honored. \
             Configure explicit origins to allow the admin UI to call the API."
        );
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([axum::http::header::CONTENT_TYPE])
            .allow_origin(Any)
    } else {
        // Parse each origin; log loudly on a malformed entry instead of silently
        // dropping it (a silent drop manifests later as a confusing "CORS broke"
        // with no clue which entry was bad).
        let origins: Vec<_> = cors_origins
            .iter()
            .filter_map(|o| match o.parse::<axum::http::HeaderValue>() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::error!("Ignoring invalid CORS origin '{}': {}", o, e);
                    None
                }
            })
            .collect();
        if origins.is_empty() {
            tracing::error!(
                "All configured CORS origins were invalid — admin API will reject cross-origin requests"
            );
        }
        tracing::info!("CORS allowed origins: {:?}", cors_origins);
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
            .allow_credentials(true)
            .allow_origin(origins)
    };
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.recv().await;
        tracing::info!("Admin API shutting down gracefully");
    })
    .await?;
    Ok(())
}
