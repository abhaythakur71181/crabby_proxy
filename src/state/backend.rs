use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
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

    // Pending connections (TODO: for approval workflow)
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
