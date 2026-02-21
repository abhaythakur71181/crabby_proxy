use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::backend::*;
use crate::connection::ConnectionRequest;

/// In-memory state backend for single-instance deployments
pub struct MemoryBackend {
    connections: Arc<RwLock<HashMap<Uuid, ConnectionInfo>>>,
    pending: Arc<RwLock<HashMap<Uuid, ConnectionRequest>>>,
    counters: Arc<RwLock<HashMap<String, u64>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StateBackend for MemoryBackend {
    async fn get_connection(&self, id: Uuid) -> StateResult<ConnectionInfo> {
        self.connections
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or(StateBackendError::NotFound)
    }

    async fn set_connection(&self, id: Uuid, conn: ConnectionInfo) -> StateResult<()> {
        self.connections.write().await.insert(id, conn);
        Ok(())
    }

    async fn delete_connection(&self, id: Uuid) -> StateResult<()> {
        self.connections
            .write()
            .await
            .remove(&id)
            .ok_or(StateBackendError::NotFound)?;
        Ok(())
    }

    async fn list_connections(&self) -> StateResult<Vec<ConnectionInfo>> {
        Ok(self.connections.read().await.values().cloned().collect())
    }

    async fn count_connections(&self) -> StateResult<usize> {
        Ok(self.connections.read().await.len())
    }

    async fn count_user_connections(&self, user_id: i64) -> StateResult<usize> {
        let connections = self.connections.read().await;
        let count = connections
            .values()
            .filter(|c| c.user_id == Some(user_id))
            .count();
        Ok(count)
    }

    async fn get_pending(&self, _id: Uuid) -> StateResult<ConnectionRequest> {
        // Can't return because ConnectionRequest doesn't implement Clone
        // This is a limitation of the in-memory backend
        Err(StateBackendError::Other(
            "get_pending not supported in memory backend".to_string(),
        ))
    }

    async fn add_pending(&self, req: ConnectionRequest) -> StateResult<()> {
        self.pending.write().await.insert(req.id, req);
        Ok(())
    }

    async fn remove_pending(&self, id: Uuid) -> StateResult<()> {
        self.pending
            .write()
            .await
            .remove(&id)
            .ok_or(StateBackendError::NotFound)?;
        Ok(())
    }

    async fn list_pending(&self) -> StateResult<Vec<ConnectionRequest>> {
        // Can't clone ConnectionRequest, not supported in memory backend
        Err(StateBackendError::Other(
            "list_pending not supported in memory backend".to_string(),
        ))
    }

    async fn increment_counter(&self, key: &str, value: u64) -> StateResult<()> {
        let mut counters = self.counters.write().await;
        *counters.entry(key.to_string()).or_insert(0) += value;
        Ok(())
    }

    async fn get_counter(&self, key: &str) -> StateResult<u64> {
        Ok(*self.counters.read().await.get(key).unwrap_or(&0))
    }

    async fn publish_event(&self, _event: &str, _data: &str) -> StateResult<()> {
        // No-op for in-memory backend (single instance only)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{ConnectionState, ConnectionType, ServiceType};
    use crate::proxy::protocol::{ProxyProtocol, ProxyTarget};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    fn test_connection_info(id: Uuid) -> ConnectionInfo {
        ConnectionInfo {
            id,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            target_addr: "example.com:443".to_string(),
            protocol: ProxyProtocol::HTTPS,
            state: ConnectionState::Active,
            user_id: Some(1),
            bytes_sent: 1024,
            bytes_received: 2048,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    // === Connection CRUD Tests ===

    #[tokio::test]
    async fn test_set_and_get_connection() {
        let backend = MemoryBackend::new();
        let id = Uuid::new_v4();
        let conn = test_connection_info(id);

        backend.set_connection(id, conn.clone()).await.unwrap();
        let retrieved = backend.get_connection(id).await.unwrap();

        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.target_addr, "example.com:443");
        assert_eq!(retrieved.bytes_sent, 1024);
    }

    #[tokio::test]
    async fn test_get_connection_not_found() {
        let backend = MemoryBackend::new();
        let result = backend.get_connection(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StateBackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_connection() {
        let backend = MemoryBackend::new();
        let id = Uuid::new_v4();
        backend
            .set_connection(id, test_connection_info(id))
            .await
            .unwrap();

        backend.delete_connection(id).await.unwrap();
        let result = backend.get_connection(id).await;
        assert!(matches!(result, Err(StateBackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_connection_not_found() {
        let backend = MemoryBackend::new();
        let result = backend.delete_connection(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StateBackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_list_connections_empty() {
        let backend = MemoryBackend::new();
        let conns = backend.list_connections().await.unwrap();
        assert!(conns.is_empty());
    }

    #[tokio::test]
    async fn test_list_connections_multiple() {
        let backend = MemoryBackend::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        backend
            .set_connection(id1, test_connection_info(id1))
            .await
            .unwrap();
        backend
            .set_connection(id2, test_connection_info(id2))
            .await
            .unwrap();

        let conns = backend.list_connections().await.unwrap();
        assert_eq!(conns.len(), 2);
    }

    #[tokio::test]
    async fn test_count_connections() {
        let backend = MemoryBackend::new();
        assert_eq!(backend.count_connections().await.unwrap(), 0);

        let id = Uuid::new_v4();
        backend
            .set_connection(id, test_connection_info(id))
            .await
            .unwrap();
        assert_eq!(backend.count_connections().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_count_user_connections() {
        let backend = MemoryBackend::new();

        let id1 = Uuid::new_v4();
        let mut conn1 = test_connection_info(id1);
        conn1.user_id = Some(1);
        backend.set_connection(id1, conn1).await.unwrap();

        let id2 = Uuid::new_v4();
        let mut conn2 = test_connection_info(id2);
        conn2.user_id = Some(1);
        backend.set_connection(id2, conn2).await.unwrap();

        let id3 = Uuid::new_v4();
        let mut conn3 = test_connection_info(id3);
        conn3.user_id = Some(2);
        backend.set_connection(id3, conn3).await.unwrap();

        assert_eq!(backend.count_user_connections(1).await.unwrap(), 2);
        assert_eq!(backend.count_user_connections(2).await.unwrap(), 1);
        assert_eq!(backend.count_user_connections(99).await.unwrap(), 0);
    }

    // === Pending connection Tests ===

    #[tokio::test]
    async fn test_add_pending() {
        let backend = MemoryBackend::new();
        let id = Uuid::new_v4();
        let req = ConnectionRequest {
            id,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000),
            connection_type: ConnectionType::Forward {
                target: ProxyTarget {
                    host: "test.com".to_string(),
                    port: 80,
                },
                protocol: ProxyProtocol::HTTP,
            },
            requested_at: Instant::now(),
            response_tx: None,
        };

        backend.add_pending(req).await.unwrap();
        // Can't verify directly since get_pending returns error
    }

    #[tokio::test]
    async fn test_remove_pending() {
        let backend = MemoryBackend::new();
        let id = Uuid::new_v4();
        let req = ConnectionRequest {
            id,
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000),
            connection_type: ConnectionType::ReverseTunnel {
                service_type: ServiceType::WebService,
                listen_port: None,
            },
            requested_at: Instant::now(),
            response_tx: None,
        };

        backend.add_pending(req).await.unwrap();
        backend.remove_pending(id).await.unwrap();
    }

    #[tokio::test]
    async fn test_remove_pending_not_found() {
        let backend = MemoryBackend::new();
        let result = backend.remove_pending(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StateBackendError::NotFound)));
    }

    #[tokio::test]
    async fn test_get_pending_not_supported() {
        let backend = MemoryBackend::new();
        let result = backend.get_pending(Uuid::new_v4()).await;
        assert!(matches!(result, Err(StateBackendError::Other(_))));
    }

    #[tokio::test]
    async fn test_list_pending_not_supported() {
        let backend = MemoryBackend::new();
        let result = backend.list_pending().await;
        assert!(matches!(result, Err(StateBackendError::Other(_))));
    }

    // === Counter Tests ===

    #[tokio::test]
    async fn test_increment_and_get_counter() {
        let backend = MemoryBackend::new();

        backend.increment_counter("requests", 1).await.unwrap();
        assert_eq!(backend.get_counter("requests").await.unwrap(), 1);

        backend.increment_counter("requests", 5).await.unwrap();
        assert_eq!(backend.get_counter("requests").await.unwrap(), 6);
    }

    #[tokio::test]
    async fn test_get_counter_nonexistent_returns_zero() {
        let backend = MemoryBackend::new();
        assert_eq!(backend.get_counter("nonexistent").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_multiple_independent_counters() {
        let backend = MemoryBackend::new();

        backend.increment_counter("bytes_sent", 100).await.unwrap();
        backend
            .increment_counter("bytes_received", 200)
            .await
            .unwrap();

        assert_eq!(backend.get_counter("bytes_sent").await.unwrap(), 100);
        assert_eq!(backend.get_counter("bytes_received").await.unwrap(), 200);
    }

    // === Event Tests ===

    #[tokio::test]
    async fn test_publish_event_no_op() {
        let backend = MemoryBackend::new();
        // Should succeed (no-op)
        backend.publish_event("connection.new", "{}").await.unwrap();
    }

    // === Default trait ===

    #[tokio::test]
    async fn test_default_creates_empty_backend() {
        let backend = MemoryBackend::default();
        assert_eq!(backend.count_connections().await.unwrap(), 0);
        assert_eq!(backend.get_counter("any").await.unwrap(), 0);
    }

    // === Overwrite connection ===

    #[tokio::test]
    async fn test_set_connection_overwrites_existing() {
        let backend = MemoryBackend::new();
        let id = Uuid::new_v4();

        let mut conn1 = test_connection_info(id);
        conn1.bytes_sent = 100;
        backend.set_connection(id, conn1).await.unwrap();

        let mut conn2 = test_connection_info(id);
        conn2.bytes_sent = 999;
        backend.set_connection(id, conn2).await.unwrap();

        let retrieved = backend.get_connection(id).await.unwrap();
        assert_eq!(retrieved.bytes_sent, 999);
        assert_eq!(backend.count_connections().await.unwrap(), 1);
    }
}
