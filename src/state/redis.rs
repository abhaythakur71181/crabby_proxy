use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use uuid::Uuid;

use super::backend::*;
use crate::connection::ConnectionRequest;

/// TTL of a `conn:<id>` record.
const CONN_TTL_SECS: u64 = 3600;
/// TTL of a `pending:<id>` record.
const PENDING_TTL_SECS: u64 = 300;
/// TTL of the index sets (`connections`, `user_conns:<uid>`, `pending`). Every
/// write refreshes it, so an active set never expires, while a set left holding
/// only orphans (e.g. after a crash skipped the delete) self-expires instead of
/// lingering forever. It is longer than the record TTL, so no live record can
/// outlive its index entry.
const CONN_INDEX_TTL_SECS: i64 = (CONN_TTL_SECS * 2) as i64;
const PENDING_INDEX_TTL_SECS: i64 = (PENDING_TTL_SECS * 2) as i64;

fn redis_err(e: redis::RedisError) -> StateBackendError {
    StateBackendError::ConnectionFailed(e.to_string())
}

/// Key naming and the multi-key write pipelines. Kept separate from the
/// connection so the command sequences can be unit-tested without a server.
struct KeySpace {
    prefix: String,
}

impl KeySpace {
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

    fn connections_set(&self) -> String {
        self.key("connections")
    }

    fn user_conns_set(&self, user_id: i64) -> String {
        self.key(&format!("user_conns:{}", user_id))
    }

    fn pending_set(&self) -> String {
        self.key("pending")
    }

    /// Store a connection record and index it, all-or-nothing (MULTI/EXEC), so
    /// a failure part-way can no longer leave a record without its index entry
    /// or an index entry without its record.
    fn set_connection_pipe(&self, id: Uuid, user_id: Option<i64>, json: &str) -> redis::Pipeline {
        let id_str = id.to_string();
        let all = self.connections_set();
        let mut pipe = redis::pipe();
        pipe.atomic()
            .set_ex(self.conn_key(id), json, CONN_TTL_SECS)
            .ignore()
            .sadd(&all, &id_str)
            .ignore()
            .expire(&all, CONN_INDEX_TTL_SECS)
            .ignore();
        if let Some(uid) = user_id {
            let user_set = self.user_conns_set(uid);
            pipe.sadd(&user_set, &id_str)
                .ignore()
                .expire(&user_set, CONN_INDEX_TTL_SECS)
                .ignore();
        }
        pipe
    }

    /// Push back the expiry of a live record and its index sets (#46).
    fn refresh_connection_pipe(&self, id: Uuid, user_id: Option<i64>) -> redis::Pipeline {
        let mut pipe = redis::pipe();
        pipe.atomic()
            .expire(self.conn_key(id), CONN_TTL_SECS as i64)
            .ignore()
            .expire(self.connections_set(), CONN_INDEX_TTL_SECS)
            .ignore();
        if let Some(uid) = user_id {
            pipe.expire(self.user_conns_set(uid), CONN_INDEX_TTL_SECS)
                .ignore();
        }
        pipe
    }

    /// Remove a connection record and its index entries, all-or-nothing.
    fn delete_connection_pipe(&self, id: Uuid, user_id: Option<i64>) -> redis::Pipeline {
        let id_str = id.to_string();
        let mut pipe = redis::pipe();
        pipe.atomic();
        if let Some(uid) = user_id {
            pipe.srem(self.user_conns_set(uid), &id_str).ignore();
        }
        pipe.del(self.conn_key(id))
            .ignore()
            .srem(self.connections_set(), &id_str)
            .ignore();
        pipe
    }

    fn add_pending_pipe(&self, id: Uuid, json: &str) -> redis::Pipeline {
        let set = self.pending_set();
        let mut pipe = redis::pipe();
        pipe.atomic()
            .set_ex(self.pending_key(id), json, PENDING_TTL_SECS)
            .ignore()
            .sadd(&set, id.to_string())
            .ignore()
            .expire(&set, PENDING_INDEX_TTL_SECS)
            .ignore();
        pipe
    }

    fn remove_pending_pipe(&self, id: Uuid) -> redis::Pipeline {
        let mut pipe = redis::pipe();
        pipe.atomic()
            .del(self.pending_key(id))
            .ignore()
            .srem(self.pending_set(), id.to_string())
            .ignore();
        pipe
    }
}

/// Redis state backend for multi-instance deployments
pub struct RedisBackend {
    conn: ConnectionManager,
    keys: KeySpace,
}

impl RedisBackend {
    pub async fn new(redis_url: &str, prefix: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        tracing::info!("Redis state backend connected to {}", redis_url);
        Ok(Self {
            conn,
            keys: KeySpace { prefix },
        })
    }

    /// Count live members of a connection index set, removing any whose backing
    /// `conn:<id>` key no longer exists (crash orphans / TTL expiry). Bounded by
    /// the set size, which for per-user sets is at most that user's connection
    /// limit.
    async fn prune_and_count(&self, set_key: &str) -> StateResult<usize> {
        let mut conn = self.conn.clone();
        let ids: Vec<String> = conn.smembers(set_key).await.map_err(redis_err)?;
        let mut live = 0usize;
        for id_str in ids {
            let key = match Uuid::parse_str(&id_str) {
                Ok(id) => self.keys.conn_key(id),
                Err(_) => {
                    let _: Result<(), _> = conn.srem(set_key, &id_str).await;
                    continue;
                }
            };
            // On a transient EXISTS error, assume live (don't under-count and
            // wrongly allow past a limit).
            let exists: bool = conn.exists(&key).await.unwrap_or(true);
            if exists {
                live += 1;
            } else {
                let _: Result<(), _> = conn.srem(set_key, &id_str).await;
            }
        }
        Ok(live)
    }
}

#[async_trait]
impl StateBackend for RedisBackend {
    async fn get_connection(&self, id: Uuid) -> StateResult<ConnectionInfo> {
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(self.keys.conn_key(id)).await.map_err(redis_err)?;
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
        let _: () = self
            .keys
            .set_connection_pipe(id, conn_info.user_id, &json)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn delete_connection(&self, id: Uuid) -> StateResult<()> {
        let mut conn = self.conn.clone();
        // Look up the owner first so the per-user index is cleaned in the same
        // transaction. If the record already expired, any per-user entry is an
        // orphan that prune_and_count removes on the next count.
        let user_id = self.get_connection(id).await.ok().and_then(|i| i.user_id);
        let _: () = self
            .keys
            .delete_connection_pipe(id, user_id)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn list_connections(&self) -> StateResult<Vec<ConnectionInfo>> {
        let mut conn = self.conn.clone();
        let set = self.keys.connections_set();
        let ids: Vec<String> = conn.smembers(&set).await.map_err(redis_err)?;
        let mut connections = Vec::new();
        for id_str in ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Ok(info) = self.get_connection(id).await {
                    connections.push(info);
                } else {
                    // Stale entry — remove from set
                    let _: Result<(), _> = conn.srem(&set, &id_str).await;
                }
            }
        }
        Ok(connections)
    }

    async fn count_connections(&self) -> StateResult<usize> {
        // Prune-and-count rather than a raw SCARD: a crash (or expiry of the 1h
        // conn key) that skips delete_connection leaves orphaned members that
        // would otherwise inflate the count until the set's own TTL lapses.
        self.prune_and_count(&self.keys.connections_set()).await
    }

    async fn count_user_connections(&self, user_id: i64) -> StateResult<usize> {
        // Accuracy matters here — this drives the per-user connection limit, so
        // an over-count would wrongly deny legitimate connections.
        self.prune_and_count(&self.keys.user_conns_set(user_id))
            .await
    }

    fn connection_record_ttl(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(CONN_TTL_SECS))
    }

    async fn refresh_connection(&self, id: Uuid) -> StateResult<()> {
        // NotFound here means the record is already gone (deleted by an admin
        // terminate, or expired during a long Redis outage); nothing to extend.
        let user_id = self.get_connection(id).await?.user_id;
        let mut conn = self.conn.clone();
        let _: () = self
            .keys
            .refresh_connection_pipe(id, user_id)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn get_pending(&self, id: Uuid) -> StateResult<ConnectionRequest> {
        let mut conn = self.conn.clone();
        let data: Option<String> = conn
            .get(self.keys.pending_key(id))
            .await
            .map_err(redis_err)?;
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
        let _: () = self
            .keys
            .add_pending_pipe(req.id, &json)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn remove_pending(&self, id: Uuid) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = self
            .keys
            .remove_pending_pipe(id)
            .query_async(&mut conn)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn list_pending(&self) -> StateResult<Vec<ConnectionRequest>> {
        let mut conn = self.conn.clone();
        let set = self.keys.pending_set();
        let ids: Vec<String> = conn.smembers(&set).await.map_err(redis_err)?;

        let mut pending = Vec::new();
        for id_str in ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Ok(req) = self.get_pending(id).await {
                    pending.push(req);
                } else {
                    let _: Result<(), _> = conn.srem(&set, &id_str).await;
                }
            }
        }
        Ok(pending)
    }

    async fn increment_counter(&self, key: &str, value: u64) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .incr(self.keys.counter_key(key), value)
            .await
            .map_err(redis_err)?;
        Ok(())
    }

    async fn get_counter(&self, key: &str) -> StateResult<u64> {
        let mut conn = self.conn.clone();
        let val: Option<u64> = conn
            .get(self.keys.counter_key(key))
            .await
            .map_err(redis_err)?;
        Ok(val.unwrap_or(0))
    }

    async fn publish_event(&self, event: &str, data: &str) -> StateResult<()> {
        let mut conn = self.conn.clone();
        let _: () = conn
            .publish(self.keys.key(&format!("events:{}", event)), data)
            .await
            .map_err(redis_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Command names of a packed pipeline, in order (RESP: each command is
    /// `*N`, then `$len`, then the command name).
    fn cmds(pipe: &redis::Pipeline) -> Vec<String> {
        let packed = String::from_utf8_lossy(&pipe.get_packed_pipeline()).into_owned();
        let parts: Vec<&str> = packed.split("\r\n").collect();
        parts
            .iter()
            .enumerate()
            .filter(|(i, p)| p.starts_with('*') && i + 2 < parts.len())
            .map(|(i, _)| parts[i + 2].to_uppercase())
            .collect()
    }

    fn packed(pipe: &redis::Pipeline) -> String {
        String::from_utf8_lossy(&pipe.get_packed_pipeline()).into_owned()
    }

    #[test]
    fn writes_are_atomic_and_index_sets_get_ttl() {
        let ks = KeySpace { prefix: "t".into() };
        let id = Uuid::nil();

        let set = ks.set_connection_pipe(id, Some(7), "{}");
        assert_eq!(
            cmds(&set),
            vec!["MULTI", "SETEX", "SADD", "EXPIRE", "SADD", "EXPIRE", "EXEC"]
        );
        assert!(packed(&set).contains("t:user_conns:7"));
        assert_eq!(
            cmds(&ks.set_connection_pipe(id, None, "{}")),
            vec!["MULTI", "SETEX", "SADD", "EXPIRE", "EXEC"]
        );

        assert_eq!(
            cmds(&ks.refresh_connection_pipe(id, Some(7))),
            vec!["MULTI", "EXPIRE", "EXPIRE", "EXPIRE", "EXEC"]
        );
        assert!(packed(&ks.refresh_connection_pipe(id, Some(7))).contains("t:user_conns:7"));
        assert_eq!(
            cmds(&ks.delete_connection_pipe(id, Some(7))),
            vec!["MULTI", "SREM", "DEL", "SREM", "EXEC"]
        );
        assert_eq!(
            cmds(&ks.add_pending_pipe(id, "{}")),
            vec!["MULTI", "SETEX", "SADD", "EXPIRE", "EXEC"]
        );
        assert_eq!(
            cmds(&ks.remove_pending_pipe(id)),
            vec!["MULTI", "DEL", "SREM", "EXEC"]
        );
    }

    /// Round-trip against a real server when `CRABBY_TEST_REDIS_URL` is set
    /// (skipped otherwise, so CI without Redis still passes).
    #[tokio::test]
    async fn live_round_trip_when_redis_available() {
        let Ok(url) = std::env::var("CRABBY_TEST_REDIS_URL") else {
            return;
        };
        let prefix = format!("crabby-test-{}", Uuid::new_v4());
        let backend = RedisBackend::new(&url, prefix).await.unwrap();
        let id = Uuid::new_v4();
        let info = ConnectionInfo {
            id,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            target_addr: "example.com:443".into(),
            protocol: crate::proxy::protocol::ProxyProtocol::HTTP,
            state: crate::connection::ConnectionState::Active,
            user_id: Some(9),
            bytes_sent: 0,
            bytes_received: 0,
            created_at: 0,
        };
        backend.set_connection(id, info).await.unwrap();
        assert_eq!(backend.count_connections().await.unwrap(), 1);
        assert_eq!(backend.count_user_connections(9).await.unwrap(), 1);
        let mut conn = backend.conn.clone();
        let ttl: i64 = conn.ttl(backend.keys.user_conns_set(9)).await.unwrap();
        assert!(ttl > 0 && ttl <= CONN_INDEX_TTL_SECS);

        // A refresh pushes the record's expiry back to the full TTL (#46).
        let _: () = conn.expire(backend.keys.conn_key(id), 5).await.unwrap();
        backend.refresh_connection(id).await.unwrap();
        let ttl: i64 = conn.ttl(backend.keys.conn_key(id)).await.unwrap();
        assert!(ttl > 5 && ttl <= CONN_TTL_SECS as i64);

        backend.delete_connection(id).await.unwrap();
        assert_eq!(backend.count_connections().await.unwrap(), 0);
        assert_eq!(backend.count_user_connections(9).await.unwrap(), 0);
        assert!(backend.get_connection(id).await.is_err());
    }

    /// #46 against a real server: reserve-then-count never admits more than
    /// `max` concurrent connections for one user (skipped without Redis).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reserve_then_count_never_overshoots_on_redis() {
        use crate::proxy::validators::exceeds_connection_limit;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let Ok(url) = std::env::var("CRABBY_TEST_REDIS_URL") else {
            return;
        };
        const MAX: usize = 3;
        let prefix = format!("crabby-test-{}", Uuid::new_v4());
        let backend = Arc::new(RedisBackend::new(&url, prefix).await.unwrap());
        let admitted_now = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..60u16 {
            let (backend, admitted_now, peak) =
                (backend.clone(), admitted_now.clone(), peak.clone());
            tasks.push(tokio::spawn(async move {
                let id = Uuid::new_v4();
                let info = ConnectionInfo {
                    id,
                    client_addr: ([127, 0, 0, 1], 2000 + i).into(),
                    target_addr: "example.com:443".into(),
                    protocol: crate::proxy::protocol::ProxyProtocol::SOCKS5,
                    state: crate::connection::ConnectionState::Active,
                    user_id: Some(11),
                    bytes_sent: 0,
                    bytes_received: 0,
                    created_at: 0,
                };
                backend.set_connection(id, info).await.unwrap();
                let count = backend.count_user_connections(11).await.unwrap();
                if !exceeds_connection_limit(count, MAX) {
                    let now = admitted_now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    admitted_now.fetch_sub(1, Ordering::SeqCst);
                }
                backend.delete_connection(id).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= MAX);
        assert_eq!(backend.count_user_connections(11).await.unwrap(), 0);
    }

    #[test]
    fn index_ttl_outlives_record_ttl() {
        assert!(CONN_INDEX_TTL_SECS as u64 > CONN_TTL_SECS);
        assert!(PENDING_INDEX_TTL_SECS as u64 > PENDING_TTL_SECS);
    }
}
