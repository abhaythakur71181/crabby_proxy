mod admin;
mod app_state;
mod config;
mod connection;
mod error;
mod proxy;
mod state;
mod stream;
mod tunnel;
mod utils;

use crate::app_state::AppState;
use crate::config::Config;
use crate::proxy::listener::run_proxy_server;
use clap::Parser;
use std::path::PathBuf;

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

    // Create application state
    let state = AppState::new(config.clone()).await?;

    // Parse socket addresses
    let proxy_addr = config.server.proxy_bind.parse()?;
    let admin_addr = config.server.admin_bind.parse()?;

    tracing::info!("🚀 Starting Crabby Proxy");
    tracing::info!("  Proxy server: {}", proxy_addr);
    tracing::info!("  Admin API: {}", admin_addr);
    tracing::info!("  Protocols: HTTP/HTTPS, SOCKS4/5");

    // graceful shutdown
    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        tracing::info!("Received shutdown signal");
        state_clone.shutdown().await;
        std::process::exit(0);
    });

    let proxy_handle = tokio::spawn(run_proxy_server(state.clone(), proxy_addr));
    let admin_handle = tokio::spawn(admin::run_admin_server(state.clone(), admin_addr));
    let _ = tokio::join!(proxy_handle, admin_handle);

    Ok(())
}
