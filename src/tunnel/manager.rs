use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
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

/// Runtime limits applied to every connection relayed by a tunnel.
#[derive(Debug, Clone, Copy)]
pub struct TunnelLimits {
    /// Tear a relayed connection down after this long with no traffic in
    /// either direction (`None` = no idle timeout).
    pub idle_timeout: Option<Duration>,
    /// Max concurrent relayed connections for the tunnel (0 = unlimited).
    pub max_connections: usize,
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

    /// Reserve a listen port. Synchronous so callers can hold the manager
    /// lock only for the reservation, then bind with the lock released.
    pub fn reserve_port(&mut self, preferred_port: Option<u16>) -> Result<u16, TunnelError> {
        Ok(self.port_allocator.allocate_port(preferred_port)?)
    }

    /// Give back a port reserved with [`reserve_port`] whose bind failed.
    pub fn release_reserved_port(&mut self, port: u16) {
        let _ = self.port_allocator.release_port(port);
    }

    /// Register a tunnel on a port reserved with [`reserve_port`] and an
    /// already-bound listener, and start relaying.
    pub fn register_tunnel(
        &mut self,
        service_type: ServiceType,
        listener: TcpListener,
        target_addr: SocketAddr,
        limits: TunnelLimits,
    ) -> Result<TunnelInfo, TunnelError> {
        let port = listener
            .local_addr()
            .map_err(|e| TunnelError::AllocationError(e.to_string()))?
            .port();
        let metrics = Arc::new(TunnelMetrics::default());
        let tunnel = ActiveTunnel {
            tunnel_id: Uuid::new_v4(),
            listen_port: port,
            target_addr,
            service_type,
            created_at: Utc::now(),
            metrics: metrics.clone(),
        };
        let info = tunnel.to_info();

        let handle = tokio::spawn(tunnel_listener_task(
            listener,
            port,
            target_addr,
            metrics,
            limits,
        ));
        self.tasks.entry(port).or_default().push(handle);
        self.active_tunnels.insert(port, tunnel);
        Ok(info)
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
}

/// Accept loop for one tunnel. Aborting the task drops the listener; relayed
/// connections run in their own tasks and end via EOF or the idle timeout.
async fn tunnel_listener_task(
    listener: TcpListener,
    port: u16,
    target_addr: SocketAddr,
    metrics: Arc<TunnelMetrics>,
    limits: TunnelLimits,
) {
    let slots = (limits.max_connections > 0)
        .then(|| Arc::new(tokio::sync::Semaphore::new(limits.max_connections)));
    loop {
        match listener.accept().await {
            Ok((inbound, peer)) => {
                let slot = match &slots {
                    Some(sem) => match sem.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            tracing::warn!(
                                "tunnel {port}: connection limit ({}) reached, rejecting {peer}",
                                limits.max_connections
                            );
                            continue; // drops `inbound`
                        }
                    },
                    None => None,
                };
                metrics.total_connections.fetch_add(1, Ordering::Relaxed);
                metrics.active_connections.fetch_add(1, Ordering::Relaxed);
                let m = metrics.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let bytes =
                        handle_tunnel_connection(inbound, target_addr, limits.idle_timeout).await;
                    m.bytes_transferred.fetch_add(bytes, Ordering::Relaxed);
                    m.active_connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                // Typically EMFILE/ENFILE; back off instead of spinning.
                tracing::error!("Accept error on tunnel port {port}: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Relay one tunnel connection; returns total bytes moved in both directions.
async fn handle_tunnel_connection(
    inbound: TcpStream,
    target_addr: SocketAddr,
    idle_timeout: Option<Duration>,
) -> u64 {
    let outbound = match tokio::time::timeout(
        crate::constants::UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(target_addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("Failed to connect to tunnel target {target_addr}: {e}");
            return 0;
        }
        Err(_) => {
            tracing::error!("Timed out connecting to tunnel target {target_addr}");
            return 0;
        }
    };
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    crate::utils::enable_tcp_keepalive(&inbound);

    // Same relay as the proxy paths: shared idle clock reaps half-open
    // connections whose peer vanished without FIN/RST.
    match crate::stream::create_throttled_tunnel(
        inbound.into_split(),
        outbound.into_split(),
        "tunnel-in",
        "tunnel-out",
        None,
        None,
        false,
        idle_timeout,
    )
    .await
    {
        Ok((a, b)) => a + b,
        Err(e) => {
            tracing::error!("Tunnel error: {e}");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tunnel_relays_and_enforces_connection_limit() {
        let target = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut mgr = TunnelManager::new(port, port);
        mgr.reserve_port(Some(port)).unwrap();
        let info = mgr
            .register_tunnel(
                ServiceType::WebService,
                listener,
                target,
                TunnelLimits {
                    idle_timeout: Some(Duration::from_secs(5)),
                    max_connections: 1,
                },
            )
            .unwrap();
        assert_eq!(info.listen_port, port);

        let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        first.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        first.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");

        // Second concurrent connection is over the limit and gets closed.
        let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), second.read(&mut b))
            .await
            .expect("over-limit connection should be closed")
            .unwrap_or(0);
        assert_eq!(n, 0);

        mgr.close_tunnel(port).await.unwrap();
    }

    #[tokio::test]
    async fn idle_tunnel_connection_is_reaped() {
        let target = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut mgr = TunnelManager::new(port, port);
        mgr.reserve_port(Some(port)).unwrap();
        mgr.register_tunnel(
            ServiceType::WebService,
            listener,
            target,
            TunnelLimits {
                idle_timeout: Some(Duration::from_millis(200)),
                max_connections: 0,
            },
        )
        .unwrap();

        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut b))
            .await
            .expect("idle tunnel connection was not reaped")
            .unwrap_or(0);
        assert_eq!(n, 0);
    }
}
