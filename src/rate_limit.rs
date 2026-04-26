use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use nonzero_ext::nonzero;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Normalize IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to IPv4
/// Prevents bypass where same IP tracked as two different entries
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                ip
            }
        }
        _ => ip,
    }
}

/// Rate limiter for IP addresses (proxy layer)
/// Uses DashMap for lock-free per-key access (no global write lock)
#[derive(Clone)]
pub struct IpRateLimiter {
    limiters: Arc<DashMap<IpAddr, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    quota: Quota,
}

impl IpRateLimiter {
    /// Create new IP rate limiter
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        let quota = Quota::per_second(
            std::num::NonZeroU32::new(requests_per_second).unwrap_or(nonzero!(10u32)),
        )
        .allow_burst(std::num::NonZeroU32::new(burst_size).unwrap_or(nonzero!(20u32)));

        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
        }
    }

    /// Check if IP is allowed to make a request
    /// Uses DashMap entry API — only locks the shard containing this IP
    pub async fn check_ip(&self, ip: IpAddr) -> bool {
        // INFO: Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to IPv4
        let ip = normalize_ip(ip);
        let limiter = self
            .limiters
            .entry(ip)
            .or_insert_with(|| GovernorRateLimiter::direct(self.quota));
        limiter.check().is_ok()
    }

    /// Get number of tracked IPs
    pub async fn count(&self) -> usize {
        self.limiters.len()
    }

    /// Clear all rate limiters (for testing)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.limiters.clear();
    }
}

/// Rate limiter for authenticated users
/// Uses DashMap for lock-free per-user access
#[derive(Clone)]
pub struct UserRateLimiter {
    limiters: Arc<DashMap<i64, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    // Cache user rate limit configs (user_id -> config)
    user_configs: Arc<DashMap<i64, UserRateLimitConfig>>,
    cache_ttl: std::time::Duration,
}

#[derive(Clone, Debug)]
pub struct UserRateLimitConfig {
    pub rps: u32,
    pub burst: u32,
    pub enabled: bool,
    pub max_connections: i32,
    pub cached_at: std::time::Instant,
}

impl UserRateLimiter {
    /// Create new user rate limiter with 60-second cache TTL
    pub fn new() -> Self {
        Self::with_ttl(std::time::Duration::from_secs(60))
    }

    /// Create new user rate limiter with custom cache TTL
    pub fn with_ttl(cache_ttl: std::time::Duration) -> Self {
        Self {
            limiters: Arc::new(DashMap::new()),
            user_configs: Arc::new(DashMap::new()),
            cache_ttl,
        }
    }

    /// Check if user is allowed to make a request (uses cached config)
    pub async fn check_user_cached(&self, user_id: i64, config: UserRateLimitConfig) -> bool {
        if !config.enabled {
            return true;
        }
        let quota =
            Quota::per_second(std::num::NonZeroU32::new(config.rps).unwrap_or(nonzero!(5u32)))
                .allow_burst(std::num::NonZeroU32::new(config.burst).unwrap_or(nonzero!(10u32)));
        let limiter = self
            .limiters
            .entry(user_id)
            .or_insert_with(|| GovernorRateLimiter::direct(quota));
        limiter.check().is_ok()
    }

    /// Check if user is allowed (legacy method)
    pub async fn check_user(&self, user_id: i64, rps: u32, burst: u32) -> bool {
        let quota = Quota::per_second(std::num::NonZeroU32::new(rps).unwrap_or(nonzero!(5u32)))
            .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(nonzero!(10u32)));
        let limiter = self
            .limiters
            .entry(user_id)
            .or_insert_with(|| GovernorRateLimiter::direct(quota));
        limiter.check().is_ok()
    }

    /// Get cached user config or return None if expired/missing
    pub async fn get_cached_config(&self, user_id: i64) -> Option<UserRateLimitConfig> {
        if let Some(config) = self.user_configs.get(&user_id) {
            if config.cached_at.elapsed() < self.cache_ttl {
                return Some(config.clone());
            }
        }
        None
    }

    /// Cache user rate limit configuration (includes max_connections)
    pub async fn cache_config(
        &self,
        user_id: i64,
        rps: u32,
        burst: u32,
        enabled: bool,
        max_connections: i32,
    ) {
        let config = UserRateLimitConfig {
            rps,
            burst,
            enabled,
            max_connections,
            cached_at: std::time::Instant::now(),
        };
        self.user_configs.insert(user_id, config);
    }

    /// Get cached max_connections for a user (returns None if cache miss)
    pub async fn get_cached_max_connections(&self, user_id: i64) -> Option<i32> {
        self.get_cached_config(user_id)
            .await
            .map(|c| c.max_connections)
    }

    /// Invalidate cache for specific user (call when user settings change)
    pub async fn invalidate_user(&self, user_id: i64) {
        self.user_configs.remove(&user_id);
        self.limiters.remove(&user_id);
    }

    /// Clear all cached configs
    pub async fn clear_cache(&self) {
        self.user_configs.clear();
    }

    /// Get number of tracked users
    pub async fn count(&self) -> usize {
        self.limiters.len()
    }

    /// Clear all rate limiters (for testing)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.limiters.clear();
        self.user_configs.clear();
    }
}

impl Default for UserRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for login attempts (prevents brute force)
/// Uses RwLock<LruCache> since LRU eviction needs global ordering
#[derive(Clone)]
pub struct LoginRateLimiter {
    limiters: Arc<
        RwLock<lru::LruCache<IpAddr, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    >,
    quota: Quota,
}

impl LoginRateLimiter {
    /// Create new login rate limiter
    /// Default: 5 attempts per minute per IP, max 10,000 tracked IPs
    pub fn new() -> Self {
        Self::with_limits(5, 10, 10_000)
    }

    /// Create login rate limiter with custom limits
    pub fn with_limits(attempts_per_minute: u32, burst: u32, max_ips: usize) -> Self {
        let quota = Quota::per_minute(
            std::num::NonZeroU32::new(attempts_per_minute).unwrap_or(nonzero!(5u32)),
        )
        .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(nonzero!(10u32)));
        Self {
            limiters: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(max_ips).unwrap(),
            ))),
            quota,
        }
    }

    /// Check if IP is allowed to attempt login (B15: use IpAddr to prevent string-key bypass)
    pub async fn check(&self, ip: &str) -> bool {
        // Parse to IpAddr for consistent keying; fall back to allow if unparseable
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => normalize_ip(addr), // normalize IPv4-mapped IPv6
            Err(_) => return true,
        };
        let mut limiters = self.limiters.write().await;
        let limiter = limiters.get_or_insert(ip_addr, || GovernorRateLimiter::direct(self.quota));
        limiter.check().is_ok()
    }

    /// Get number of tracked IPs
    pub async fn count(&self) -> usize {
        self.limiters.read().await.len()
    }

    /// Clear all rate limiters (for testing)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.limiters.write().await.clear();
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Redis-backed distributed rate limiter using fixed window counters.
/// Suitable for multi-instance deployments where in-process rate limiters
/// don't share state.
///
/// Uses INCR + EXPIRE for atomic increment-and-expire in a single round trip.
#[derive(Clone)]
#[allow(dead_code)]
pub struct RedisRateLimiter {
    conn: redis::aio::ConnectionManager,
    key_prefix: String,
    window_secs: u64,
    max_requests: u64,
}

impl RedisRateLimiter {
    /// Create a new Redis-backed rate limiter.
    ///
    /// - `key_prefix`: e.g. "rl:ip:" or "rl:user:"
    /// - `window_secs`: time window in seconds (e.g. 1 for per-second)
    /// - `max_requests`: max allowed requests in the window
    pub fn new(
        conn: redis::aio::ConnectionManager,
        key_prefix: &str,
        window_secs: u64,
        max_requests: u64,
    ) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
            window_secs,
            max_requests,
        }
    }

    /// Check if a key (IP or user ID) is within the rate limit.
    /// Returns true if allowed, false if rate limited.
    ///
    /// Uses a Lua script for atomic INCR + EXPIRE to avoid race conditions.
    pub async fn check(&self, key: &str) -> bool {
        let full_key = format!("{}{}", self.key_prefix, key);
        let mut conn = self.conn.clone();

        // Lua script: atomically increment counter and set expiry if new
        let script = redis::Script::new(
            r#"
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            "#,
        );

        match script
            .key(&full_key)
            .arg(self.window_secs)
            .invoke_async::<i64>(&mut conn)
            .await
        {
            Ok(count) => count <= self.max_requests as i64,
            Err(e) => {
                tracing::warn!("Redis rate limit check failed (allowing): {}", e);
                true // Fail open on Redis errors
            }
        }
    }

    /// Get the current count for a key.
    pub async fn get_count(&self, key: &str) -> u64 {
        let full_key = format!("{}{}", self.key_prefix, key);
        let mut conn = self.conn.clone();
        redis::cmd("GET")
            .arg(&full_key)
            .query_async::<Option<u64>>(&mut conn)
            .await
            .unwrap_or(Some(0))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // === IpRateLimiter Tests ===

    #[tokio::test]
    async fn test_ip_rate_limiter_allows_within_limit() {
        let limiter = IpRateLimiter::new(10, 20);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow first 20 requests (burst)
        for _ in 0..20 {
            assert!(limiter.check_ip(ip).await);
        }
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_blocks_over_limit() {
        let limiter = IpRateLimiter::new(10, 20);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Exhaust burst
        for _ in 0..20 {
            limiter.check_ip(ip).await;
        }

        // Next request should be blocked
        assert!(!limiter.check_ip(ip).await);
    }

    #[tokio::test]
    async fn test_user_rate_limiter() {
        let limiter = UserRateLimiter::new();
        let user_id = 1;

        // Should allow first 10 requests (burst = 2x rps = 10)
        for _ in 0..10 {
            assert!(limiter.check_user(user_id, 5, 10).await);
        }

        // Next should be blocked
        assert!(!limiter.check_user(user_id, 5, 10).await);
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let limiter = IpRateLimiter::new(10, 20);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Exhaust ip1
        for _ in 0..20 {
            limiter.check_ip(ip1).await;
        }
        assert!(!limiter.check_ip(ip1).await);

        // ip2 should still work
        assert!(limiter.check_ip(ip2).await);
    }

    // === New IpRateLimiter Tests ===

    #[tokio::test]
    async fn test_ip_rate_limiter_count() {
        let limiter = IpRateLimiter::new(10, 20);
        assert_eq!(limiter.count().await, 0);

        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        limiter.check_ip(ip1).await;
        assert_eq!(limiter.count().await, 1);

        limiter.check_ip(ip2).await;
        assert_eq!(limiter.count().await, 2);
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_clear() {
        let limiter = IpRateLimiter::new(10, 20);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        limiter.check_ip(ip).await;
        assert_eq!(limiter.count().await, 1);

        limiter.clear().await;
        assert_eq!(limiter.count().await, 0);
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_ipv6() {
        let limiter = IpRateLimiter::new(5, 5);
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        for _ in 0..5 {
            assert!(limiter.check_ip(ip).await);
        }
        assert!(!limiter.check_ip(ip).await);
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_ipv4_ipv6_independent() {
        let limiter = IpRateLimiter::new(5, 5);
        let ipv4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        // Exhaust IPv4
        for _ in 0..5 {
            limiter.check_ip(ipv4).await;
        }
        assert!(!limiter.check_ip(ipv4).await);

        // IPv6 should still work
        assert!(limiter.check_ip(ipv6).await);
    }

    // === New UserRateLimiter Tests ===

    #[tokio::test]
    async fn test_user_rate_limiter_different_users_independent() {
        let limiter = UserRateLimiter::new();

        // Exhaust user 1
        for _ in 0..5 {
            limiter.check_user(1, 5, 5).await;
        }
        assert!(!limiter.check_user(1, 5, 5).await);

        // User 2 should still work
        assert!(limiter.check_user(2, 5, 5).await);
    }

    #[tokio::test]
    async fn test_user_rate_limiter_count() {
        let limiter = UserRateLimiter::new();
        assert_eq!(limiter.count().await, 0);

        limiter.check_user(1, 10, 20).await;
        assert_eq!(limiter.count().await, 1);

        limiter.check_user(2, 10, 20).await;
        assert_eq!(limiter.count().await, 2);
    }

    #[tokio::test]
    async fn test_user_rate_limiter_clear() {
        let limiter = UserRateLimiter::new();
        limiter.check_user(1, 10, 20).await;
        limiter.check_user(2, 10, 20).await;

        limiter.clear().await;
        assert_eq!(limiter.count().await, 0);
    }

    #[tokio::test]
    async fn test_user_rate_limiter_default() {
        let limiter = UserRateLimiter::default();
        assert_eq!(limiter.count().await, 0);
    }

    // === Cache Tests ===

    #[tokio::test]
    async fn test_cache_config_and_get() {
        let limiter = UserRateLimiter::new();

        limiter.cache_config(1, 100, 200, true, 50).await;

        let config = limiter.get_cached_config(1).await;
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.rps, 100);
        assert_eq!(config.burst, 200);
        assert!(config.enabled);
        assert_eq!(config.max_connections, 50);
    }

    #[tokio::test]
    async fn test_cache_miss_returns_none() {
        let limiter = UserRateLimiter::new();
        let config = limiter.get_cached_config(999).await;
        assert!(config.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let limiter = UserRateLimiter::with_ttl(std::time::Duration::from_millis(50));

        limiter.cache_config(1, 10, 20, true, 5).await;
        assert!(limiter.get_cached_config(1).await.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(limiter.get_cached_config(1).await.is_none());
    }

    #[tokio::test]
    async fn test_invalidate_user() {
        let limiter = UserRateLimiter::new();

        limiter.cache_config(1, 10, 20, true, 5).await;
        limiter.check_user(1, 10, 20).await;

        limiter.invalidate_user(1).await;

        assert!(limiter.get_cached_config(1).await.is_none());
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let limiter = UserRateLimiter::new();

        limiter.cache_config(1, 10, 20, true, 5).await;
        limiter.cache_config(2, 10, 20, true, 5).await;

        limiter.clear_cache().await;

        assert!(limiter.get_cached_config(1).await.is_none());
        assert!(limiter.get_cached_config(2).await.is_none());
    }

    #[tokio::test]
    async fn test_get_cached_max_connections() {
        let limiter = UserRateLimiter::new();

        limiter.cache_config(1, 10, 20, true, 42).await;
        assert_eq!(limiter.get_cached_max_connections(1).await, Some(42));
        assert_eq!(limiter.get_cached_max_connections(999).await, None);
    }

    #[tokio::test]
    async fn test_check_user_cached_disabled() {
        let limiter = UserRateLimiter::new();

        let config = UserRateLimitConfig {
            rps: 1,
            burst: 1,
            enabled: false, // Rate limiting disabled
            max_connections: 10,
            cached_at: std::time::Instant::now(),
        };

        // Even though burst is 1, disabled should always allow
        for _ in 0..100 {
            assert!(limiter.check_user_cached(1, config.clone()).await);
        }
    }

    #[tokio::test]
    async fn test_check_user_cached_enabled_blocks() {
        let limiter = UserRateLimiter::new();

        let config = UserRateLimitConfig {
            rps: 5,
            burst: 3,
            enabled: true,
            max_connections: 10,
            cached_at: std::time::Instant::now(),
        };

        // Exhaust burst
        for _ in 0..3 {
            limiter.check_user_cached(1, config.clone()).await;
        }
        assert!(!limiter.check_user_cached(1, config.clone()).await);
    }

    // === LoginRateLimiter Tests ===

    #[tokio::test]
    async fn test_login_rate_limiter_allows_initial_attempts() {
        let limiter = LoginRateLimiter::new();
        // Default: 5 per minute, burst 10
        for _ in 0..10 {
            assert!(limiter.check("192.168.1.1").await);
        }
    }

    #[tokio::test]
    async fn test_login_rate_limiter_blocks_after_burst() {
        let limiter = LoginRateLimiter::with_limits(5, 5, 1000);
        let ip = "10.0.0.1";

        for _ in 0..5 {
            limiter.check(ip).await;
        }
        assert!(!limiter.check(ip).await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_different_ips_independent() {
        let limiter = LoginRateLimiter::with_limits(5, 3, 1000);

        // Exhaust ip1
        for _ in 0..3 {
            limiter.check("1.1.1.1").await;
        }
        assert!(!limiter.check("1.1.1.1").await);

        // ip2 should still work
        assert!(limiter.check("2.2.2.2").await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_count() {
        let limiter = LoginRateLimiter::new();
        assert_eq!(limiter.count().await, 0);

        limiter.check("1.1.1.1").await;
        assert_eq!(limiter.count().await, 1);

        limiter.check("2.2.2.2").await;
        assert_eq!(limiter.count().await, 2);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_clear() {
        let limiter = LoginRateLimiter::new();
        limiter.check("1.1.1.1").await;
        limiter.check("2.2.2.2").await;

        limiter.clear().await;
        assert_eq!(limiter.count().await, 0);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_default() {
        let limiter = LoginRateLimiter::default();
        assert_eq!(limiter.count().await, 0);
        assert!(limiter.check("test-ip").await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_string_ip_formats() {
        let limiter = LoginRateLimiter::new();
        // Should work with various string formats
        assert!(limiter.check("127.0.0.1").await);
        assert!(limiter.check("::1").await);
        assert!(limiter.check("10.0.0.1:8080").await); // With port as string
    }
}
