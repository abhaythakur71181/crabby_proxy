//! Upstream connection pool — reuses idle TCP connections to the same host:port.
//!
//! Gated by `advanced.connection_pooling` (default: false).
//! After a tunnel closes cleanly, the upstream `TcpStream` is returned to the pool.
//! Before reuse, a zero-byte peek validates the connection is still alive.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Metadata for a pooled connection.
struct PooledConnection {
    stream: TcpStream,
    created_at: Instant,
    last_used: Instant,
}

/// Connection pool statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolStats {
    pub total_hosts: usize,
    pub total_idle: usize,
    pub hits: u64,
    pub misses: u64,
}

/// Per-host idle connection pool.
pub struct ConnectionPool {
    pools: DashMap<String, VecDeque<PooledConnection>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
    max_lifetime: Duration,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ConnectionPool {
    /// Create a new pool.
    /// - `max_idle_per_host`: max idle connections to keep per target
    /// - `idle_timeout_secs`: evict idle connections after this many seconds
    pub fn new(max_idle_per_host: usize, idle_timeout_secs: u64) -> Self {
        Self {
            pools: DashMap::new(),
            max_idle_per_host,
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            max_lifetime: Duration::from_secs(300), // 5 min max lifetime
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Try to get an idle connection from the pool.
    /// Validates the connection is still alive with a zero-byte peek.
    /// Returns `None` if no valid idle connection is available.
    pub async fn try_get(&self, addr: &str) -> Option<TcpStream> {
        let mut entry = self.pools.get_mut(addr)?;
        let queue = entry.value_mut();

        while let Some(pooled) = queue.pop_front() {
            // Check expiry
            if pooled.last_used.elapsed() > self.idle_timeout
                || pooled.created_at.elapsed() > self.max_lifetime
            {
                // Expired — drop and try next
                continue;
            }

            // Validate with zero-byte peek (non-blocking check if connection is still open)
            let mut buf = [0u8; 1];
            match timeout(Duration::from_millis(10), pooled.stream.peek(&mut buf)).await {
                Ok(Ok(0)) => {
                    // Peer closed the connection
                    continue;
                }
                Ok(Err(_)) => {
                    // I/O error — connection is dead
                    continue;
                }
                // Ok(Ok(n)) where n > 0 means there's unexpected data — don't reuse
                Ok(Ok(_)) => {
                    continue;
                }
                // Timeout means no data and no error — connection is idle and healthy
                Err(_) => {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!("Reusing pooled connection to {}", addr);
                    return Some(pooled.stream);
                }
            }
        }

        None
    }

    /// Get a connection from the pool, or create a new one.
    pub async fn get_or_connect(
        &self,
        addr: &str,
        resolved: std::net::SocketAddr,
        connect_timeout: Duration,
    ) -> std::io::Result<TcpStream> {
        // Try pool first
        if let Some(stream) = self.try_get(addr).await {
            return Ok(stream);
        }

        // Pool miss — create new connection
        self.misses.fetch_add(1, Ordering::Relaxed);
        let stream = timeout(connect_timeout, TcpStream::connect(resolved))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout")
            })??;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// Return a connection to the pool for future reuse.
    /// Only call this if the connection closed cleanly (no errors).
    pub fn return_connection(&self, addr: &str, stream: TcpStream) {
        let mut entry = self
            .pools
            .entry(addr.to_string())
            .or_insert_with(VecDeque::new);
        let queue = entry.value_mut();

        // Don't exceed max idle connections per host
        if queue.len() >= self.max_idle_per_host {
            // Drop the oldest idle connection
            queue.pop_front();
        }

        queue.push_back(PooledConnection {
            stream,
            created_at: Instant::now(),
            last_used: Instant::now(),
        });
    }

    /// Evict all expired idle connections. Call periodically.
    pub fn cleanup_expired(&self) {
        let idle_timeout = self.idle_timeout;
        let max_lifetime = self.max_lifetime;
        self.pools.alter_all(|_, mut queue| {
            queue.retain(|conn| {
                conn.last_used.elapsed() < idle_timeout && conn.created_at.elapsed() < max_lifetime
            });
            queue
        });
        // Remove empty entries
        self.pools.retain(|_, queue| !queue.is_empty());
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        let total_hosts = self.pools.len();
        let total_idle: usize = self.pools.iter().map(|e| e.value().len()).sum();
        PoolStats {
            total_hosts,
            total_idle,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}
