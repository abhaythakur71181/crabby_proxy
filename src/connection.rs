use std::{collections::HashMap, net::SocketAddr, time::Instant};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::proxy::protocol::{ProxyProtocol, ProxyTarget};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConnectionState {
    Pending,
    Approved,
    Rejected,
    Active,
    Closed,
}

// ConnectionType enum
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConnectionType {
    /// Forward proxy (client -> proxy -> target server)
    Forward {
        target: ProxyTarget,
        protocol: ProxyProtocol,
    },
    /// Reverse tunnel (client requests proxy to expose a local service)
    ReverseTunnel {
        service_type: ServiceType,
        listen_port: Option<u16>, // None = auto-assign port
    },
}

// Service types for reverse tunnels
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ServiceType {
    Database(DbType),
    WebService,
    SshService,
    Custom(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DbType {
    Postgres,
    MySQL,
    Redis,
    MongoDB,
    Custom(String),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ConnectionRequest {
    pub id: Uuid,
    pub client_addr: SocketAddr,
    pub connection_type: ConnectionType,
    #[serde(skip, default = "Instant::now")]
    pub requested_at: Instant,
    #[serde(skip)]
    pub response_tx: Option<oneshot::Sender<bool>>,
}

// Expanded approval response
#[derive(Debug)]
pub enum ConnectionApproval {
    Approved,
    ApprovedWithPort(u16), // For reverse tunnels
    Rejected(String),      // Rejection reason
}

#[derive(Debug)]
pub struct ConnectionManager {
    pending: HashMap<Uuid, ConnectionRequest>,
    active: HashMap<Uuid, Instant>,
}

#[derive(Debug)]
pub enum ConnectionError {
    NotFound,
    InvalidState,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            active: HashMap::new(),
        }
    }

    pub fn new_connection(
        &mut self,
        client_addr: SocketAddr,
        connection_type: ConnectionType,
    ) -> (Uuid, oneshot::Receiver<bool>) {
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();

        let request = ConnectionRequest {
            id,
            client_addr,
            connection_type,
            requested_at: Instant::now(),
            response_tx: Some(tx),
        };

        self.pending.insert(id, request);
        (id, rx)
    }

    pub fn add_pending(&mut self, request: ConnectionRequest) {
        self.pending.insert(request.id, request);
    }

    pub fn approve_connection(&mut self, id: Uuid) -> bool {
        if let Some(mut request) = self.pending.remove(&id) {
            // Notify the waiting task
            if let Some(tx) = request.response_tx.take() {
                let _ = tx.send(true);
            }

            // Mark as active
            self.active.insert(id, Instant::now());
            true
        } else {
            false
        }
    }

    pub fn reject_connection(&mut self, id: Uuid, _reason: String) -> bool {
        if let Some(mut request) = self.pending.remove(&id) {
            // Notify the waiting task
            if let Some(tx) = request.response_tx.take() {
                let _ = tx.send(false);
            }
            true
        } else {
            false
        }
    }

    pub fn close_connection(&mut self, id: Uuid) -> Result<(), ConnectionError> {
        if self.active.remove(&id).is_some() {
            Ok(())
        } else {
            Err(ConnectionError::NotFound)
        }
    }
}
