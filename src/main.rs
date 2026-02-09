mod admin;
mod app_state;
mod auth;
mod config;
mod connection;
mod db;
mod error;
mod proxy;
mod rate_limit;
mod state;
mod stream;
mod tunnel;
mod utils;
mod validation;

use crate::app_state::AppState;
use crate::config::Config;
use crate::proxy::listener::run_proxy_server;
use clap::Parser;
use std::path::PathBuf;
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    let args = Args::parse();
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

    tracing::info!("Configuration loaded successfully");
    tracing::info!("  Proxy: {}", config.server.proxy_bind);
    tracing::info!("  Admin: {}", config.server.admin_bind);
    tracing::info!("  State backend: {}", config.state.backend);
    tracing::info!("  Auth enabled: {}", config.authentication.enabled);

    // Initialize database
    tracing::info!("Initializing database...");
    let db_pool = db::create_pool(&config.database.path).await?;

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
    let state = AppState::new(config.clone(), config_path, db_pool).await?;

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

    // Signal shutdown to all servers
    tracing::info!("Initiating graceful shutdown...");
    let _ = state.shutdown_tx.send(());
    tracing::info!("Waiting for active connections to drain (max 30s)...");
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
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
