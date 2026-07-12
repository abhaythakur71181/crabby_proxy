mod admin;
mod app_state;
mod auth;
mod bandwidth;
mod cache;
mod config;
mod config_env;
#[allow(dead_code)]
mod connection;
mod connection_pool;
#[allow(dead_code)]
mod constants;
mod db;
mod dns_cache;
#[allow(dead_code)]
mod error;
mod event_bus;
mod geo_filter;
mod ip_filter;
mod ip_pattern;
mod metrics;
pub mod middleware;
mod proxy;
mod proxy_protocol;
mod quota_tracker;
#[allow(dead_code)]
mod rate_limit;
mod self_loop;
mod state;
#[allow(dead_code)]
mod stream;
mod target_filter;
#[allow(dead_code)]
mod tunnel;
mod usage_writer;
#[allow(dead_code)]
mod utils;
#[allow(dead_code)]
mod validation;
#[allow(dead_code)]
mod webhook;

use crate::app_state::AppState;
use crate::config::Config;
use crate::config_env::ConfigEnvExt;
use crate::proxy::listener::run_proxy_server;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "crabby-proxy.toml")]
    config: PathBuf,

    /// Override proxy bind address
    #[arg(long)]
    proxy_bind: Option<String>,

    /// Override admin bind address
    #[arg(long)]
    admin_bind: Option<String>,

    /// Log format: "text" (default) or "json" for structured JSON logs
    #[arg(long, default_value = "text")]
    log_format: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Install the process-level rustls crypto provider before any TLS use
    // (Redis rediss://, etc.). rustls 0.23 requires this when multiple or no
    // provider features are auto-selected.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");

    // Honor RUST_LOG (e.g. "info", "crabby_proxy=debug,warn"); default to info.
    // Previously the level was hardcoded to TRACE, which ignored RUST_LOG and
    // flooded production logs (and could leak sensitive request data).
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match args.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    let mut config = if args.config.exists() {
        tracing::info!("Loading configuration from: {}", args.config.display());
        Config::from_file(&args.config)?
    } else {
        tracing::warn!("Configuration file not found, using defaults");
        Config::default()
    };

    // Apply CLI overrides
    if let Some(proxy_bind) = args.proxy_bind {
        config.server.proxy_bind = proxy_bind;
    }
    if let Some(admin_bind) = args.admin_bind {
        config.server.admin_bind = admin_bind;
    }

    // Apply environment variable overrides for secrets
    config.apply_env_overrides();

    tracing::info!("Configuration loaded successfully");
    tracing::info!("  Proxy: {}", config.server.proxy_bind);
    tracing::info!("  Admin: {}", config.server.admin_bind);
    tracing::info!("  State backend: {}", config.state.backend);
    tracing::info!("  Auth enabled: {}", config.authentication.enabled);

    // Initialize database
    tracing::info!("Initializing database...");
    let db_pool = db::create_pool(&config.database.path, config.database.max_connections).await?;

    // Run migrations
    tracing::info!("Running database migrations...");
    db::run_migrations(&db_pool).await?;

    // Ensure root admin exists
    if db::users::ensure_root_admin(&db_pool).await? {
        tracing::info!("Root admin account created");
    }

    let config_path = if args.config.exists() {
        Some(args.config.to_string_lossy().to_string())
    } else {
        None
    };
    let state = Arc::new(AppState::new(config.clone(), config_path, db_pool).await?);

    // Parse socket addresses
    let proxy_addr = config.server.proxy_bind.parse()?;
    let admin_addr = config.server.admin_bind.parse()?;

    tracing::info!("🚀 Starting Crabby Proxy");
    tracing::info!("  Proxy server: {}", proxy_addr);
    tracing::info!("  Admin API: {}", admin_addr);
    tracing::info!("  Protocols: HTTP/HTTPS, SOCKS4/5");

    let proxy_state = state.clone();
    let admin_state = state.clone();
    let proxy_handle = tokio::spawn(async move {
        run_proxy_server(proxy_state, proxy_addr).await;
    });
    let admin_handle =
        tokio::spawn(async move { admin::run_admin_server(admin_state, admin_addr).await });

    // Background: Event bus subscriber (cross-instance coordination)
    {
        let redis_url = config.state.redis_url.clone();
        let prefix = config.state.redis_key_prefix.clone();
        let sub_state = state.clone();
        tokio::spawn(async move {
            event_bus::start_subscriber(&redis_url, &prefix, sub_state).await;
        });
    }

    // Background: DNS cache cleanup (every 60s)
    {
        let dns_state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(constants::DNS_CLEANUP_INTERVAL).await;
                dns_state.dns_cache.cleanup_expired();
            }
        });
    }

    // Background: Connection pool cleanup (every 30s, if pooling enabled)
    if let Some(ref pool) = state.connection_pool {
        let pool_ref = pool.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(constants::POOL_CLEANUP_INTERVAL).await;
                pool_ref.cleanup_expired();
            }
        });
    }

    // Wait for EITHER shutdown signal OR server crash
    tokio::select! {
        _ = shutdown_signal() => {
            tracing::info!("Shutdown signal received");
        }
        result = proxy_handle => {
            tracing::error!("Proxy server exited unexpectedly: {:?}", result);
        }
        result = admin_handle => {
            tracing::error!("Admin server exited unexpectedly: {:?}", result);
        }
    }

    // Signal shutdown to all servers (stops accepting new connections)
    tracing::info!("Initiating graceful shutdown...");
    let _ = state.shutdown_tx.send(());
    crate::metrics::DRAINING.set(1);

    // Poll active connections until drained or timeout
    let drain_start = std::time::Instant::now();
    let drain_timeout = constants::SHUTDOWN_DRAIN_TIMEOUT;
    loop {
        let active_count = state
            .state
            .list_connections()
            .await
            .map(|c| c.len())
            .unwrap_or(0);
        crate::metrics::DRAINING_CONNECTIONS.set(active_count as i64);
        if active_count == 0 {
            tracing::info!("All connections drained");
            break;
        }
        if drain_start.elapsed() >= drain_timeout {
            tracing::warn!(
                "Shutdown drain timeout reached with {} connections still active — forcing close",
                active_count
            );
            break;
        }
        tracing::info!(
            "Waiting for {} active connections to drain ({:.0}s remaining)...",
            active_count,
            (drain_timeout - drain_start.elapsed()).as_secs_f64()
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Tear down reverse tunnels: abort their listener tasks and release the
    // allocated ports. Without this, tunnel listeners kept accepting/forwarding
    // past "drain complete" and were only killed abruptly at process exit.
    state.shutdown().await;

    tracing::info!("Graceful shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (SIGTERM or Ctrl+C)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal");
        },
    }
}
