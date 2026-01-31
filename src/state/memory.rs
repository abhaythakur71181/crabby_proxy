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
