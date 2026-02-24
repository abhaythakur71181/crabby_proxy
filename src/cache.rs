use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

use crate::db::models::User;

/// TTL constants (in seconds)
pub(crate) const USER_TTL: u64 = 300; // 5 minutes
pub(crate) const API_KEY_TTL: u64 = 300; // 5 minutes
pub(crate) const QUOTA_TTL: u64 = 30; // 30 seconds (matches existing DashMap TTL)
pub(crate) const APPROVAL_TTL: u64 = 120; // 2 minutes
pub(crate) const USER_ROLE_TTL: u64 = 300; // 5 minutes

/// Redis-backed cache layer for frequently accessed data.
/// Falls back gracefully to DB queries if Redis is unavailable.
#[derive(Clone)]
pub struct CacheLayer {
    conn: ConnectionManager,
    prefix: String,
}

impl CacheLayer {
    pub async fn new(redis_url: &str, prefix: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        tracing::info!("Cache layer connected to Redis at {}", redis_url);
        Ok(Self { conn, prefix })
    }

    pub(crate) fn key(&self, suffix: &str) -> String {
        format!("{}cache:{}", self.prefix, suffix)
    }

    // ─── Generic helpers ───────────────────────────────────────────────

    async fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let mut conn = self.conn.clone();
        let data: Option<String> = conn.get(key).await.ok()?;
        data.and_then(|json| serde_json::from_str(&json).ok())
    }

    async fn set_json<T: Serialize>(&self, key: &str, value: &T, ttl: u64) {
        let mut conn = self.conn.clone();
        if let Ok(json) = serde_json::to_string(value) {
            let _: Result<(), _> = conn.set_ex(key, &json, ttl).await;
        }
    }

    async fn del(&self, key: &str) {
        let mut conn = self.conn.clone();
        let _: Result<(), _> = conn.del(key).await;
    }

    // ─── Cache-aside generic ──────────────────────────────────────────
    //
    // Rust equivalent of the Java `withCache(key, function)` pattern:
    //   1. Check Redis for `suffix`
    //   2. On miss, call `fetch()` (the DB fallback)
    //   3. If fetch returns Some, populate Redis and return it
    //   4. If fetch returns None, return None (don't cache absence)

    pub async fn get_or_set<T, F, Fut>(&self, suffix: &str, ttl: u64, fetch: F) -> Option<T>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let full_key = self.key(suffix);
        if let Some(cached) = self.get_json::<T>(&full_key).await {
            return Some(cached);
        }
        let value = fetch().await?;
        self.set_json(&full_key, &value, ttl).await;
        Some(value)
    }

    // ─── User cache (kept for direct set/invalidate) ──────────────────

    pub async fn set_user_by_id(&self, user_id: i64, user: &CachedUser) {
        let key = self.key(&format!("user:id:{}", user_id));
        self.set_json(&key, user, USER_TTL).await;
    }

    pub async fn set_user_by_username(&self, username: &str, user: &CachedUser) {
        let key = self.key(&format!("user:name:{}", username));
        self.set_json(&key, user, USER_TTL).await;
    }

    /// Invalidate all cache entries for a user
    pub async fn invalidate_user(&self, user_id: i64, username: &str) {
        self.del(&self.key(&format!("user:id:{}", user_id))).await;
        self.del(&self.key(&format!("user:name:{}", username)))
            .await;
        self.del(&self.key(&format!("user:role:{}", user_id))).await;
    }

    // ─── User role cache ──────────────────────────────────────────────

    pub async fn set_user_role(&self, user_id: i64, role: &CachedUserRole) {
        let key = self.key(&format!("user:role:{}", user_id));
        self.set_json(&key, role, USER_ROLE_TTL).await;
    }

    // ─── API key verification cache ────────────────────────────────────

    pub async fn get_api_key_verified(&self, user_id: i64, key_value: &str) -> Option<bool> {
        let digest = simple_hash(key_value);
        let key = self.key(&format!("apikey:{}:{}", user_id, digest));
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(&key).await.ok()?;
        val.map(|v| v == "1")
    }

    pub async fn set_api_key_verified(&self, user_id: i64, key_value: &str, verified: bool) {
        let digest = simple_hash(key_value);
        let key = self.key(&format!("apikey:{}:{}", user_id, digest));
        let mut conn = self.conn.clone();
        let val = if verified { "1" } else { "0" };
        let _: Result<(), _> = conn.set_ex(&key, val, API_KEY_TTL).await;
    }

    pub async fn invalidate_api_keys_for_user(&self, user_id: i64) {
        let pattern = self.key(&format!("apikey:{}:*", user_id));
        let mut conn = self.conn.clone();
        let keys: Vec<String> = match redis::cmd("KEYS")
            .arg(&pattern)
            .query_async::<Vec<String>>(&mut conn)
            .await
        {
            Ok(keys) => keys,
            Err(_) => return,
        };
        for key in keys {
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    // ─── Quota cache ───────────────────────────────────────────────────

    pub async fn get_quota_allowed(&self, user_id: i64) -> Option<bool> {
        let key = self.key(&format!("quota:{}", user_id));
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(&key).await.ok()?;
        val.map(|v| v == "1")
    }

    pub async fn set_quota_allowed(&self, user_id: i64, allowed: bool) {
        let key = self.key(&format!("quota:{}", user_id));
        let mut conn = self.conn.clone();
        let val = if allowed { "1" } else { "0" };
        let _: Result<(), _> = conn.set_ex(&key, val, QUOTA_TTL).await;
    }

    pub async fn invalidate_quota(&self, user_id: i64) {
        self.del(&self.key(&format!("quota:{}", user_id))).await;
    }

    // ─── IP approval cache ─────────────────────────────────────────────

    pub async fn get_ip_approved(&self, user_id: i64, client_ip: &str) -> Option<bool> {
        let key = self.key(&format!("approval:{}:{}", user_id, client_ip));
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(&key).await.ok()?;
        val.map(|v| v == "1")
    }

    pub async fn set_ip_approved(&self, user_id: i64, client_ip: &str, approved: bool) {
        let key = self.key(&format!("approval:{}:{}", user_id, client_ip));
        let mut conn = self.conn.clone();
        let val = if approved { "1" } else { "0" };
        let _: Result<(), _> = conn.set_ex(&key, val, APPROVAL_TTL).await;
    }

    pub async fn invalidate_approvals_for_user(&self, user_id: i64) {
        let pattern = self.key(&format!("approval:{}:*", user_id));
        let mut conn = self.conn.clone();
        let keys: Vec<String> = match redis::cmd("KEYS")
            .arg(&pattern)
            .query_async::<Vec<String>>(&mut conn)
            .await
        {
            Ok(keys) => keys,
            Err(_) => return,
        };
        for key in keys {
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    // ─── Bandwidth usage counter ───────────────────────────────────────

    pub async fn incr_bandwidth(&self, user_id: i64, bytes: i64) {
        let month_key = current_month_key();
        let key = self.key(&format!("bw:{}:{}", user_id, month_key));
        let mut conn = self.conn.clone();
        let _: Result<(), _> = conn.incr(&key, bytes).await;
        let _: Result<(), _> = conn.expire(&key, 35 * 86400).await;
    }

    pub async fn get_bandwidth(&self, user_id: i64) -> Option<i64> {
        let month_key = current_month_key();
        let key = self.key(&format!("bw:{}:{}", user_id, month_key));
        let mut conn = self.conn.clone();
        conn.get(&key).await.ok()
    }
}

// ─── Cached data structures ────────────────────────────────────────────

/// Lightweight cached user (excludes password_hash for security)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedUser {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub max_connections: i32,
    pub bandwidth_limit_mb: i64,
    pub rate_limit_enabled: bool,
    pub rate_limit_rps: i32,
    pub rate_limit_burst: i32,
    pub allowed_protocols: Option<String>,
    pub ip_whitelist: Option<String>,
    pub monthly_bandwidth_quota: Option<i64>,
}

impl From<User> for CachedUser {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            is_active: u.is_active,
            max_connections: u.max_connections,
            bandwidth_limit_mb: u.bandwidth_limit_mb,
            rate_limit_enabled: u.rate_limit_enabled,
            rate_limit_rps: u.rate_limit_rps,
            rate_limit_burst: u.rate_limit_burst,
            allowed_protocols: u.allowed_protocols,
            ip_whitelist: u.ip_whitelist,
            monthly_bandwidth_quota: None,
        }
    }
}

/// Minimal role info for admin middleware
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedUserRole {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_active: bool,
}

impl From<User> for CachedUserRole {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role: u.role,
            is_active: u.is_active,
        }
    }
}

impl From<&CachedUser> for CachedUserRole {
    fn from(u: &CachedUser) -> Self {
        Self {
            id: u.id,
            username: u.username.clone(),
            role: u.role.clone(),
            is_active: u.is_active,
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────

/// Simple FNV-1a hash for cache keys (NOT cryptographic — just for key uniqueness)
fn simple_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

/// Get current month key like "2026-02"
fn current_month_key() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}
