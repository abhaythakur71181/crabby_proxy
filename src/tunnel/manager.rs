use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::{io, net::TcpStream};
use uuid::Uuid;

use crate::connection::ServiceType;

use super::{error::TunnelError, port_allocator::PortAllocator};

/// Live per-tunnel counters, shared with the tunnel's listener task.
#[derive(Debug, Default)]
pub struct TunnelMetrics {
    /// Total bytes relayed in both directions across all connections.
    pub bytes_transferred: AtomicU64,
    /// Connections accepted over the tunnel's lifetime.
    pub total_connections: AtomicU64,
    /// Connections currently being relayed.
    pub active_connections: AtomicU64,
}

/// Public tunnel info for admin API responses
#[derive(Debug, Clone, serde::Serialize)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub listen_port: u16,
    pub target_addr: String,
    pub service_type: String,
    pub created_at: i64,
    /// "active" — the tunnel's listener is accepting (always true while listed).
    pub status: String,
    pub bytes_transferred: u64,
    pub total_connections: u64,
    pub active_connections: u64,
}

pub struct TunnelManager {
    active_tunnels: HashMap<u16, ActiveTunnel>,
    port_allocator: PortAllocator,
    tasks: HashMap<u16, Vec<JoinHandle<()>>>,
}

struct ActiveTunnel {
    tunnel_id: Uuid,
    client_id: Uuid,
    listen_port: u16,
    target_addr: SocketAddr,
    service_type: ServiceType,
    created_at: chrono::DateTime<Utc>,
    metrics: Arc<TunnelMetrics>,
}

impl ActiveTunnel {
    fn to_info(&self) -> TunnelInfo {
        TunnelInfo {
            tunnel_id: self.tunnel_id.to_string(),
            listen_port: self.listen_port,
            target_addr: self.target_addr.to_string(),
            service_type: format!("{:?}", self.service_type),
            created_at: self.created_at.timestamp(),
            status: "active".to_string(),
            bytes_transferred: self.metrics.bytes_transferred.load(Ordering::Relaxed),
            total_connections: self.metrics.total_connections.load(Ordering::Relaxed),
            active_connections: self.metrics.active_connections.load(Ordering::Relaxed),
        }
    }
}

impl TunnelManager {
    pub fn new(start_port: u16, end_port: u16) -> Self {
        Self {
            active_tunnels: HashMap::new(),
            port_allocator: PortAllocator::new(start_port, end_port),
            tasks: HashMap::new(),
        }
    }

    pub async fn create_reverse_tunnel(
        &mut self,
        service_type: ServiceType,
        preferred_port: Option<u16>,
        client_addr: SocketAddr,
    ) -> Result<u16, TunnelError> {
        // Allocate port
        let port = self.port_allocator.allocate_port(preferred_port)?;

        // INFO: Bind eagerly so we can release port on failure
        let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
            Ok(l) => l,
            Err(e) => {
                // Release port back since bind failed
                let _ = self.port_allocator.release_port(port);
                return Err(TunnelError::BindError(port, e.to_string()));
            }
        };

        // Create tunnel
        let metrics = Arc::new(TunnelMetrics::default());
        let tunnel = ActiveTunnel {
            tunnel_id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            listen_port: port,
            target_addr: client_addr,
            service_type: service_type.clone(),
            created_at: Utc::now(),
            metrics: metrics.clone(),
        };

        let handle = tokio::spawn(tunnel_listener_task_with_listener(
            listener,
            port,
            client_addr,
            metrics,
        ));
        self.tasks.entry(port).or_default().push(handle);

        // Store tunnel
        self.active_tunnels.insert(port, tunnel);
        Ok(port)
    }

    pub async fn close_tunnel(&mut self, port: u16) -> Result<(), TunnelError> {
        // Remove tunnel metadata first
        self.active_tunnels
            .remove(&port)
            .ok_or(TunnelError::TunnelNotFound(port))?;

        // Release port
        self.port_allocator
            .release_port(port)
            .map_err(|e| TunnelError::PortReleaseError(port, e.to_string()))?;

        // Abort tasks associated with this port only
        if let Some(handles) = self.tasks.remove(&port) {
            for handle in handles {
                handle.abort();
                // optionally: let _ = handle.await; // would yield JoinError::is_cancelled()
            }
        }

        Ok(())
    }

    pub async fn shutdown(&mut self) {
        // INFO: Release all ports before clearing
        for &port in self.active_tunnels.keys() {
            let _ = self.port_allocator.release_port(port);
        }
        for (_, handles) in self.tasks.drain() {
            for h in handles {
                h.abort();
            }
        }
        self.active_tunnels.clear();
    }

    /// List all active tunnels (for admin API)
    pub fn list_active(&self) -> Vec<TunnelInfo> {
        self.active_tunnels.values().map(|t| t.to_info()).collect()
    }

    /// Count active tunnels
    pub fn count_active(&self) -> usize {
        self.active_tunnels.len()
    }

    /// Create a tunnel from admin API (no client connection needed)
    pub async fn create_tunnel_admin(
        &mut self,
        service_type: ServiceType,
        preferred_port: Option<u16>,
        target_addr: SocketAddr,
    ) -> Result<TunnelInfo, TunnelError> {
        let port = self
            .create_reverse_tunnel(service_type, preferred_port, target_addr)
            .await?;
        // Build the response from the just-inserted entry. Avoid `.unwrap()`:
        // although the entry exists under the current `&mut self` lock, an
        // unwrap would panic the admin request task on any future refactor that
        // released the lock or removed the tunnel early.
        let tunnel = self.active_tunnels.get(&port).ok_or_else(|| {
            TunnelError::AllocationError(format!(
                "tunnel on port {port} vanished immediately after creation"
            ))
        })?;
        Ok(tunnel.to_info())
    }
}

async fn tunnel_listener_task(port: u16, target_addr: SocketAddr) {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind tunnel port {port}: {e}");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                tokio::spawn(handle_tunnel_connection(inbound, target_addr));
            }
            Err(e) => {
                tracing::error!("Accept error on port {port}: {e}");
            }
        }
    }
}

/// INFO: Tunnel listener task with pre-bound listener (bind failure handled by caller)
async fn tunnel_listener_task_with_listener(
    listener: tokio::net::TcpListener,
    port: u16,
    target_addr: SocketAddr,
    metrics: Arc<TunnelMetrics>,
) {
    loop {
        match listener.accept().await {
            Ok((inbound, _)) => {
                metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                let m = metrics.clone();
                tokio::spawn(async move {
                    let bytes = handle_tunnel_connection(inbound, target_addr).await;
                    m.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
                    m.active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                tracing::error!("Accept error on port {port}: {e}");
            }
        }
    }
}

/// Relay one tunnel connection; returns total bytes moved in both directions.
async fn handle_tunnel_connection(
    mut inbound: tokio::net::TcpStream,
    target_addr: SocketAddr,
) -> u64 {
    let mut outbound = match TcpStream::connect(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to connect to client {target_addr}: {e}");
            return 0;
        }
    };

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        let n = io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await?;
        io::Result::Ok(n)
    };

    let server_to_client = async {
        let n = io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await?;
        io::Result::Ok(n)
    };

    match tokio::try_join!(client_to_server, server_to_client) {
        Ok((a, b)) => a + b,
        Err(e) => {
            tracing::error!("Tunnel error: {e}");
            0
        }
    }
}
