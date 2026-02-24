use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use uuid::Uuid;

use super::backend::*;
use crate::connection::ConnectionRequest;

/// Redis state backend for multi-instance deployments
pub struct RedisBackend {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisBackend {
    pub async fn new(redis_url: &str, prefix: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        tracing::info!("Redis state backend connected to {}", redis_url);
        Ok(Self { conn, prefix })
    }

    fn key(&self, suffix: &str) -> String {
        format!("{}:{}", self.prefix, suffix)
    }

    fn conn_key(&self, id: Uuid) -> String {
        self.key(&format!("conn:{}", id))
    }

    fn pending_key(&self, id: Uuid) -> String {
        self.key(&format!("pending:{}", id))
    }

    fn counter_key(&self, name: &str) -> String {
        self.key(&format!("counter:{}", name))
    }
}

#[async_trait]
impl StateBackend for RedisBackend {
    async fn get_connection(&self, id: Uuid) -> StateResult<ConnectionInfo> {
        let mut conn = self.conn.clone();
        let data: Option<String> = conn
            .get(self.conn_key(id))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| StateBackendError::SerializationError(e.to_string())),
            None => Err(StateBackendError::NotFound),
        }
    }

    async fn set_connection(&self, id: Uuid, conn_info: ConnectionInfo) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let json = serde_json::to_string(&conn_info)
            .map_err(|e| StateBackendError::SerializationError(e.to_string()))?;
        // Store connection info with 1-hour TTL
        let _: () = conn
            .set_ex(self.conn_key(id), &json, 3600)
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        // Add to connections set for listing
        let _: () = conn
            .sadd(self.key("connections"), id.to_string())
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        // Track per-user connections
        if let Some(user_id) = conn_info.user_id {
            let _: () = conn
                .sadd(self.key(&format!("user_conns:{}", user_id)), id.to_string())
                .await
                .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete_connection(&self, id: Uuid) -> StateResult<()> {
        let mut conn = self.conn.clone();
        // Get connection info first to clean up user tracking
        if let Ok(info) = self.get_connection(id).await {
            if let Some(user_id) = info.user_id {
                let _: () = conn
                    .srem(self.key(&format!("user_conns:{}", user_id)), id.to_string())
                    .await
                    .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
            }
        }
        let _: () = conn
            .del(self.conn_key(id))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        let _: () = conn
            .srem(self.key("connections"), id.to_string())
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }

    async fn list_connections(&self) -> StateResult<Vec<ConnectionInfo>> {
        let mut conn = self.conn.clone();
        let ids: Vec<String> = conn
            .smembers(self.key("connections"))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        let mut connections = Vec::new();
        for id_str in ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Ok(info) = self.get_connection(id).await {
                    connections.push(info);
                } else {
                    // Stale entry — remove from set
                    let _: Result<(), _> = conn.srem(self.key("connections"), &id_str).await;
                }
            }
        }
        Ok(connections)
    }

    async fn count_connections(&self) -> StateResult<usize> {
        let mut conn = self.conn.clone();
        let count: usize = conn
            .scard(self.key("connections"))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(count)
    }

    async fn count_user_connections(&self, user_id: i64) -> StateResult<usize> {
        let mut conn = self.conn.clone();
        let count: usize = conn
            .scard(self.key(&format!("user_conns:{}", user_id)))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(count)
    }

    async fn get_pending(&self, id: Uuid) -> StateResult<ConnectionRequest> {
        let mut conn = self.conn.clone();
        let data: Option<String> = conn
            .get(self.pending_key(id))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        match data {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| StateBackendError::SerializationError(e.to_string())),
            None => Err(StateBackendError::NotFound),
        }
    }

    async fn add_pending(&self, req: ConnectionRequest) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let json = serde_json::to_string(&req)
            .map_err(|e| StateBackendError::SerializationError(e.to_string()))?;
        // Store with 5-minute TTL for pending requests
        let _: () = conn
            .set_ex(self.pending_key(req.id), &json, 300)
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        let _: () = conn
            .sadd(self.key("pending"), req.id.to_string())
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }

    async fn remove_pending(&self, id: Uuid) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .del(self.pending_key(id))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        let _: () = conn
            .srem(self.key("pending"), id.to_string())
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }

    async fn list_pending(&self) -> StateResult<Vec<ConnectionRequest>> {
        let mut conn = self.conn.clone();
        let ids: Vec<String> = conn
            .smembers(self.key("pending"))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;

        let mut pending = Vec::new();
        for id_str in ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Ok(req) = self.get_pending(id).await {
                    pending.push(req);
                } else {
                    let _: Result<(), _> = conn.srem(self.key("pending"), &id_str).await;
                }
            }
        }
        Ok(pending)
    }

    async fn increment_counter(&self, key: &str, value: u64) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .incr(self.counter_key(key), value)
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }

    async fn get_counter(&self, key: &str) -> StateResult<u64> {
        let mut conn = self.conn.clone();
        let val: Option<u64> = conn
            .get(self.counter_key(key))
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(val.unwrap_or(0))
    }

    async fn publish_event(&self, event: &str, data: &str) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .publish(self.key(&format!("events:{}", event)), data)
            .await
            .map_err(|e| StateBackendError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }
}
