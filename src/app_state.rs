use crate::config::Config;
use crate::state::{MemoryBackend, StateBackend};
use crate::tunnel::manager::TunnelManager;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

/// Events that can be published through the notification system
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    NewConnection(Uuid),
    ConnectionApproved(Uuid),
    ConnectionRejected(Uuid),
    ConnectionClosed(Uuid),
    TunnelCreated(u16),
    TunnelClosed(u16),
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    // Configuration (hot reload 😉)
    pub config: Arc<RwLock<Config>>,

    // Pluggable state (memory or Redis)
    pub state: Arc<dyn StateBackend>,

    // Tunnel manager for reverse tunnels
    pub tunnels: Arc<RwLock<TunnelManager>>,

    // Notification channel for events
    pub notify_tx: mpsc::Sender<ConnectionEvent>,

    // Optional TLS acceptor
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,

    // Runtime start time
    pub start_time: Instant,

    // Authentication credentials (cached from config)
    pub username: Option<String>,
    pub password: Option<String>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let state: Arc<dyn StateBackend> = match config.state.backend.as_str() {
            "redis" => {
                tracing::info!(
                    "Redis backend configured but not yet implemented, falling back to memory"
                );
                // TODO: Implement Redis backend
                // Arc::new(RedisBackend::new(&config.state.redis_url, config.state.redis_key_prefix.clone())?)
                Arc::new(MemoryBackend::new())
            }
            "memory" | _ => {
                tracing::info!("Using in-memory state backend");
                Arc::new(MemoryBackend::new())
            }
        };

        // Create notification channel
        let (notify_tx, notify_rx) = mpsc::channel(1000);

        // Spawn event processor
        tokio::spawn(process_events(notify_rx, state.clone()));
        let tls_acceptor = if config.server.tls_enabled {
            if config.server.tls_cert_path.is_empty() || config.server.tls_key_path.is_empty() {
                tracing::warn!("TLS enabled but certificate paths not configured");
                None
            } else {
                Some(Arc::new(crate::utils::create_tls_acceptor(
                    &config.server.tls_cert_path,
                    &config.server.tls_key_path,
                )?))
            }
        } else {
            None
        };

        // Cache authentication credentials
        let username = if config.authentication.enabled {
            Some(config.authentication.username.clone())
        } else {
            None
        };
        let password = if config.authentication.enabled {
            Some(config.authentication.password.clone())
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            state,
            tunnels: Arc::new(RwLock::new(TunnelManager::new(
                config.features.tunnel_port_start,
                config.features.tunnel_port_end,
            ))),
            notify_tx,
            tls_acceptor,
            start_time: Instant::now(),
            username,
            password,
        })
    }

    /// Get application uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Hot-Reload configuration from file
    pub async fn reload_config(&self, new_config: Config) {
        tracing::info!("Reloading configuration");
        let mut config = self.config.write().await;
        *config = new_config;
        // NOTE: Some config changes may require restart (like state backend change)
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down application");
        // Close all tunnels
        self.tunnels.write().await.shutdown().await;
    }
}

/// Process connection events from the notification channel
async fn process_events(mut rx: mpsc::Receiver<ConnectionEvent>, state: Arc<dyn StateBackend>) {
    while let Some(event) = rx.recv().await {
        match event {
            ConnectionEvent::NewConnection(id) => {
                tracing::debug!("New connection: {}", id);
                let _ = state.increment_counter("total_connections", 1).await;
                let _ = state
                    .publish_event("connection", &format!("new:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionClosed(id) => {
                tracing::debug!("Connection closed: {}", id);
                let _ = state.delete_connection(id).await;
                let _ = state
                    .publish_event("connection", &format!("closed:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionApproved(id) => {
                tracing::info!("Connection approved: {}", id);
                let _ = state.remove_pending(id).await;
                let _ = state
                    .publish_event("approval", &format!("approved:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionRejected(id) => {
                tracing::info!("Connection rejected: {}", id);
                let _ = state.remove_pending(id).await;
                let _ = state
                    .publish_event("approval", &format!("rejected:{}", id))
                    .await;
            }
            ConnectionEvent::TunnelCreated(port) => {
                tracing::info!("Tunnel created on port: {}", port);
                let _ = state
                    .publish_event("tunnel", &format!("created:{}", port))
                    .await;
            }
            ConnectionEvent::TunnelClosed(port) => {
                tracing::info!("Tunnel closed on port: {}", port);
                let _ = state
                    .publish_event("tunnel", &format!("closed:{}", port))
                    .await;
            }
        }
    }
}
