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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
    }

    fn test_connection_type() -> ConnectionType {
        ConnectionType::Forward {
            target: ProxyTarget {
                host: "example.com".to_string(),
                port: 443,
            },
            protocol: ProxyProtocol::HTTPS,
        }
    }

    // === ConnectionManager::new Tests ===

    #[test]
    fn test_new_connection_manager_is_empty() {
        let cm = ConnectionManager::new();
        assert!(cm.pending.is_empty());
        assert!(cm.active.is_empty());
    }

    // === new_connection Tests ===

    #[test]
    fn test_new_connection_creates_pending_entry() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());

        assert!(cm.pending.contains_key(&id));
        assert_eq!(cm.pending.len(), 1);
        assert!(cm.active.is_empty());
    }

    #[test]
    fn test_new_connection_returns_unique_ids() {
        let mut cm = ConnectionManager::new();
        let (id1, _rx1) = cm.new_connection(test_addr(), test_connection_type());
        let (id2, _rx2) = cm.new_connection(test_addr(), test_connection_type());

        assert_ne!(id1, id2);
        assert_eq!(cm.pending.len(), 2);
    }

    #[test]
    fn test_new_connection_stores_client_addr() {
        let mut cm = ConnectionManager::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321);
        let (id, _rx) = cm.new_connection(addr, test_connection_type());

        assert_eq!(cm.pending[&id].client_addr, addr);
    }

    // === approve_connection Tests ===

    #[tokio::test]
    async fn test_approve_connection_moves_to_active() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());

        let result = cm.approve_connection(id);
        assert!(result);
        assert!(!cm.pending.contains_key(&id));
        assert!(cm.active.contains_key(&id));
    }

    #[tokio::test]
    async fn test_approve_connection_sends_true_to_receiver() {
        let mut cm = ConnectionManager::new();
        let (id, rx) = cm.new_connection(test_addr(), test_connection_type());

        cm.approve_connection(id);
        let result = rx.await.unwrap();
        assert!(result);
    }

    #[test]
    fn test_approve_nonexistent_connection_returns_false() {
        let mut cm = ConnectionManager::new();
        let fake_id = Uuid::new_v4();

        let result = cm.approve_connection(fake_id);
        assert!(!result);
    }

    #[test]
    fn test_approve_already_approved_connection_returns_false() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());

        assert!(cm.approve_connection(id));
        // Second approval should fail (no longer pending)
        assert!(!cm.approve_connection(id));
    }

    // === reject_connection Tests ===

    #[tokio::test]
    async fn test_reject_connection_removes_from_pending() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());

        let result = cm.reject_connection(id, "denied".to_string());
        assert!(result);
        assert!(!cm.pending.contains_key(&id));
        assert!(!cm.active.contains_key(&id)); // Should NOT be in active
    }

    #[tokio::test]
    async fn test_reject_connection_sends_false_to_receiver() {
        let mut cm = ConnectionManager::new();
        let (id, rx) = cm.new_connection(test_addr(), test_connection_type());

        cm.reject_connection(id, "denied".to_string());
        let result = rx.await.unwrap();
        assert!(!result);
    }

    #[test]
    fn test_reject_nonexistent_connection_returns_false() {
        let mut cm = ConnectionManager::new();
        let fake_id = Uuid::new_v4();

        let result = cm.reject_connection(fake_id, "not found".to_string());
        assert!(!result);
    }

    // === close_connection Tests ===

    #[test]
    fn test_close_active_connection_succeeds() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());
        cm.approve_connection(id);

        let result = cm.close_connection(id);
        assert!(result.is_ok());
        assert!(!cm.active.contains_key(&id));
    }

    #[test]
    fn test_close_nonexistent_connection_returns_not_found() {
        let mut cm = ConnectionManager::new();
        let fake_id = Uuid::new_v4();

        let result = cm.close_connection(fake_id);
        assert!(matches!(result, Err(ConnectionError::NotFound)));
    }

    #[test]
    fn test_close_pending_connection_returns_not_found() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());

        // Pending connections can't be closed (they're not active)
        let result = cm.close_connection(id);
        assert!(matches!(result, Err(ConnectionError::NotFound)));
    }

    #[test]
    fn test_double_close_returns_not_found() {
        let mut cm = ConnectionManager::new();
        let (id, _rx) = cm.new_connection(test_addr(), test_connection_type());
        cm.approve_connection(id);

        assert!(cm.close_connection(id).is_ok());
        assert!(matches!(
            cm.close_connection(id),
            Err(ConnectionError::NotFound)
        ));
    }

    // === add_pending Tests ===

    #[test]
    fn test_add_pending_inserts_request() {
        let mut cm = ConnectionManager::new();
        let id = Uuid::new_v4();
        let request = ConnectionRequest {
            id,
            client_addr: test_addr(),
            connection_type: test_connection_type(),
            requested_at: Instant::now(),
            response_tx: None,
        };

        cm.add_pending(request);
        assert!(cm.pending.contains_key(&id));
    }

    // === Full lifecycle test ===

    #[tokio::test]
    async fn test_full_connection_lifecycle() {
        let mut cm = ConnectionManager::new();

        // Create
        let (id, rx) = cm.new_connection(test_addr(), test_connection_type());
        assert_eq!(cm.pending.len(), 1);
        assert_eq!(cm.active.len(), 0);

        // Approve
        cm.approve_connection(id);
        assert_eq!(cm.pending.len(), 0);
        assert_eq!(cm.active.len(), 1);

        // Verify receiver got true
        assert!(rx.await.unwrap());

        // Close
        cm.close_connection(id).unwrap();
        assert_eq!(cm.pending.len(), 0);
        assert_eq!(cm.active.len(), 0);
    }

    // === ConnectionState serialization ===

    #[test]
    fn test_connection_state_variants() {
        // Ensure all variants exist and can be created
        let _pending = ConnectionState::Pending;
        let _approved = ConnectionState::Approved;
        let _rejected = ConnectionState::Rejected;
        let _active = ConnectionState::Active;
        let _closed = ConnectionState::Closed;
    }

    // === ConnectionType variants ===

    #[test]
    fn test_connection_type_forward() {
        let ct = ConnectionType::Forward {
            target: ProxyTarget {
                host: "example.com".to_string(),
                port: 80,
            },
            protocol: ProxyProtocol::HTTP,
        };
        // Should be Debug-printable
        let debug = format!("{:?}", ct);
        assert!(debug.contains("Forward"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn test_connection_type_reverse_tunnel() {
        let ct = ConnectionType::ReverseTunnel {
            service_type: ServiceType::WebService,
            listen_port: Some(8080),
        };
        let debug = format!("{:?}", ct);
        assert!(debug.contains("ReverseTunnel"));
    }

    #[test]
    fn test_connection_type_reverse_tunnel_auto_port() {
        let ct = ConnectionType::ReverseTunnel {
            service_type: ServiceType::Database(DbType::Postgres),
            listen_port: None,
        };
        let debug = format!("{:?}", ct);
        assert!(debug.contains("Postgres"));
    }

    // === ServiceType and DbType variants ===

    #[test]
    fn test_service_type_variants() {
        let _db = ServiceType::Database(DbType::MySQL);
        let _web = ServiceType::WebService;
        let _ssh = ServiceType::SshService;
        let _custom = ServiceType::Custom("my-service".to_string());
    }

    #[test]
    fn test_db_type_variants() {
        let _pg = DbType::Postgres;
        let _mysql = DbType::MySQL;
        let _redis = DbType::Redis;
        let _mongo = DbType::MongoDB;
        let _custom = DbType::Custom("cockroachdb".to_string());
    }
}
