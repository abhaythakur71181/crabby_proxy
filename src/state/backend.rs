use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;

use crate::connection::{ConnectionRequest, ConnectionState};
use crate::proxy::protocol::ProxyProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub id: Uuid,
    pub client_addr: SocketAddr,
    pub target_addr: String,
    pub protocol: ProxyProtocol,
    pub state: ConnectionState,
    pub user_id: Option<i64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub created_at: i64,
}

#[derive(Debug)]
pub enum StateBackendError {
    NotFound,
    ConnectionFailed(String),
    SerializationError(String),
    Other(String),
}

impl std::fmt::Display for StateBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateBackendError::NotFound => write!(f, "Item not found"),
            StateBackendError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            StateBackendError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            StateBackendError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for StateBackendError {}

pub type StateResult<T> = Result<T, StateBackendError>;

/// Trait for pluggable state backends (memory, Redis, etc.)
#[async_trait]
pub trait StateBackend: Send + Sync {
    // Connection management
    async fn get_connection(&self, id: Uuid) -> StateResult<ConnectionInfo>;
    async fn set_connection(&self, id: Uuid, conn: ConnectionInfo) -> StateResult<()>;
    async fn delete_connection(&self, id: Uuid) -> StateResult<()>;
    async fn list_connections(&self) -> StateResult<Vec<ConnectionInfo>>;
    async fn count_connections(&self) -> StateResult<usize>;
    async fn count_user_connections(&self, user_id: i64) -> StateResult<usize>;

    /// How long a connection record lives without a refresh, for backends
    /// whose records expire (Redis). `None` means records live until deleted.
    fn connection_record_ttl(&self) -> Option<Duration> {
        None
    }

    /// Push back the expiry of a live connection's record and its index
    /// entries. A no-op for backends whose records do not expire.
    async fn refresh_connection(&self, _id: Uuid) -> StateResult<()> {
        Ok(())
    }

    // Pending connections (for approval workflow)
    async fn get_pending(&self, id: Uuid) -> StateResult<ConnectionRequest>;
    async fn add_pending(&self, req: ConnectionRequest) -> StateResult<()>;
    async fn remove_pending(&self, id: Uuid) -> StateResult<()>;
    async fn list_pending(&self) -> StateResult<Vec<ConnectionRequest>>;

    // Metrics tracking (Not yet planned)
    async fn increment_counter(&self, key: &str, value: u64) -> StateResult<()>;
    async fn get_counter(&self, key: &str) -> StateResult<u64>;

    // Events (for cross-instance communication)
    async fn publish_event(&self, event: &str, data: &str) -> StateResult<()>;
}

/// Run `fut` (a live connection's relay) while keeping its connection record
/// from expiring.
///
/// Records in an expiring backend (Redis, 1h) used to lapse under a tunnel
/// that outlived the TTL. The per-user count then pruned them and admitted
/// connections past `max_connections` (#46). The record is refreshed every
/// third of its TTL for as long as the connection runs. Untracked connections
/// (`tracked == false`) have no record to refresh.
pub async fn keep_record_alive<F: Future>(
    backend: &dyn StateBackend,
    id: Uuid,
    tracked: bool,
    fut: F,
) -> F::Output {
    let period = if tracked {
        backend.connection_record_ttl().map(|ttl| ttl / 3)
    } else {
        None
    };
    refresh_periodically(
        period,
        || async move {
            match backend.refresh_connection(id).await {
                // Already deleted (admin terminate) or never stored.
                Ok(()) | Err(StateBackendError::NotFound) => {}
                Err(e) => {
                    tracing::warn!("state backend: refresh_connection({}) failed: {}", id, e);
                    crate::metrics::STATE_BACKEND_ERRORS
                        .with_label_values(&["refresh_connection"])
                        .inc();
                }
            }
        },
        fut,
    )
    .await
}

/// Drive `fut` to completion, calling `refresh` every `period` meanwhile.
async fn refresh_periodically<F, R, RF>(
    period: Option<Duration>,
    mut refresh: R,
    fut: F,
) -> F::Output
where
    F: Future,
    R: FnMut() -> RF,
    RF: Future<Output = ()>,
{
    let Some(period) = period.filter(|p| !p.is_zero()) else {
        return fut.await;
    };
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            out = &mut fut => return out,
            _ = ticker.tick() => refresh().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn refreshes_while_running_and_stops_after() {
        let calls = AtomicUsize::new(0);
        let out = refresh_periodically(
            Some(Duration::from_secs(1200)),
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
            },
            async {
                tokio::time::sleep(Duration::from_secs(3 * 3600 - 1)).await;
                42
            },
        )
        .await;
        assert_eq!(out, 42);
        // ~3h run, 20 min period: refreshed at 20, 40, ... 160 min.
        assert_eq!(calls.load(Ordering::SeqCst), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn no_period_means_no_refresh() {
        let calls = AtomicUsize::new(0);
        refresh_periodically(
            None,
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
            },
            tokio::time::sleep(Duration::from_secs(10 * 3600)),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
