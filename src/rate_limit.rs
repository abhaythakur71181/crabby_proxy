use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use nonzero_ext::nonzero;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// One tracked IP: its token bucket plus when it was last used, so eviction
/// can prefer entries that carry no state worth keeping.
struct IpEntry {
    limiter: GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    /// Milliseconds since `IpRateLimiter::epoch` of the last check.
    last_seen_ms: AtomicU64,
    /// Logical use counter (from `IpRateLimiter::seq`) for LRU ordering;
    /// unlike the millisecond clock it never ties.
    last_use: AtomicU64,
}

/// Rate limiter for IP addresses (proxy layer)
/// Uses DashMap for lock-free per-key access (no global write lock)
#[derive(Clone)]
pub struct IpRateLimiter {
    limiters: Arc<DashMap<IpAddr, IpEntry>>,
    quota: Quota,
    /// Maximum number of tracked IPs before eviction kicks in.
    /// Bounds memory so an attacker cannot exhaust RAM by spraying source IPs.
    max_entries: usize,
    /// An entry untouched for this long has a fully refilled bucket, so it is
    /// indistinguishable from a fresh limiter and can be dropped losslessly.
    idle_after_ms: u64,
    epoch: std::time::Instant,
    /// Last idle sweep (ms since `epoch`), `u64::MAX` = never.
    last_sweep_ms: Arc<AtomicU64>,
    /// Last time a "lossy eviction" warning was logged (ms since `epoch`).
    last_warn_ms: Arc<AtomicU64>,
    /// Monotonic counter bumped on every check, used for LRU ordering.
    seq: Arc<AtomicU64>,
    /// Raw (rps, burst), for the Redis limiter.
    limits: (u32, u32),
    /// Shared bucket across instances (state backend = redis).
    distributed: Option<RedisRateLimiter>,
}

/// Default cap on tracked IPs. ~100k entries × ~200 bytes ≈ 20 MB upper bound.
pub const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Minimum spacing between full idle sweeps when the map is at its cap.
const IP_SWEEP_INTERVAL_MS: u64 = 1_000;
/// How many entries to sample when picking least-recently-used victims.
const IP_EVICT_SAMPLE: usize = 64;
/// How many of the sampled entries to evict per lossy eviction round.
const IP_EVICT_BATCH: usize = 8;

impl IpRateLimiter {
    /// Create new IP rate limiter with the default tracked-IP cap.
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        Self::with_max_entries(requests_per_second, burst_size, DEFAULT_MAX_TRACKED_IPS)
    }

    /// Create new IP rate limiter with an explicit cap on tracked IPs.
    pub fn with_max_entries(requests_per_second: u32, burst_size: u32, max_entries: usize) -> Self {
        let rps = std::num::NonZeroU32::new(requests_per_second).unwrap_or(nonzero!(10u32));
        let burst = std::num::NonZeroU32::new(burst_size).unwrap_or(nonzero!(20u32));
        let quota = Quota::per_second(rps).allow_burst(burst);
        // Time for an empty bucket to refill completely: burst / rps seconds.
        let idle_after_ms = (u64::from(burst.get()) * 1000).div_ceil(u64::from(rps.get()));

        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
            max_entries: max_entries.max(1),
            idle_after_ms: idle_after_ms.max(1),
            epoch: std::time::Instant::now(),
            last_sweep_ms: Arc::new(AtomicU64::new(u64::MAX)),
            last_warn_ms: Arc::new(AtomicU64::new(u64::MAX)),
            seq: Arc::new(AtomicU64::new(0)),
            limits: (rps.get(), burst.get()),
            distributed: None,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Check if IP is allowed to make a request
    /// Uses DashMap entry API — only locks the shard containing this IP
    pub async fn check_ip(&self, ip: IpAddr) -> bool {
        // INFO: Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to IPv4
        let ip = normalize_ip(ip);
        let now = self.now_ms();
        let use_seq = self.seq.fetch_add(1, Ordering::Relaxed);

        // If we're at the cap and this IP is new, make room first. We check
        // `contains_key` to avoid evicting on the hot path for IPs that
        // already have a limiter.
        if self.limiters.len() >= self.max_entries && !self.limiters.contains_key(&ip) {
            self.make_room(now);
        }

        let local_ok = {
            let entry = self.limiters.entry(ip).or_insert_with(|| IpEntry {
                limiter: GovernorRateLimiter::direct(self.quota),
                last_seen_ms: AtomicU64::new(now),
                last_use: AtomicU64::new(use_seq),
            });
            entry.last_seen_ms.store(now, Ordering::Relaxed);
            entry.last_use.store(use_seq, Ordering::Relaxed);
            entry.limiter.check().is_ok()
        };
        if !local_ok {
            return false;
        }
        let (rps, burst) = self.limits;
        distributed_allows(
            &self.distributed,
            &format!("ip:{}", ip),
            per_second_emission_us(rps),
            burst,
        )
        .await
    }

    /// Also enforce the per-IP limit in a bucket shared by every instance.
    pub fn with_distributed(mut self, redis: RedisRateLimiter) -> Self {
        self.distributed = Some(redis);
        self
    }

    /// Free space for a new IP.
    ///
    /// The old policy evicted 8 arbitrary entries, which let an IP-spraying
    /// attacker both push out legitimate clients' state and reset its own
    /// buckets (an evicted IP got a fresh full burst on reinsertion). Now:
    ///
    /// 1. Drop entries idle long enough that their bucket has fully refilled.
    ///    Those are equivalent to a fresh limiter, so evicting them loses no
    ///    rate-limit state at all.
    /// 2. Only if that frees nothing, evict the least-recently-used entries
    ///    from a sample. A client that is actively being throttled keeps
    ///    touching its entry, so it is the last thing to go. These lossy
    ///    evictions are what `IP_RATE_LIMIT_EVICTIONS` counts; a sustained
    ///    non-zero rate means `max_tracked_ips` is too small for the traffic.
    fn make_room(&self, now: u64) {
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if last == u64::MAX || now.saturating_sub(last) >= IP_SWEEP_INTERVAL_MS {
            self.last_sweep_ms.store(now, Ordering::Relaxed);
            let idle_after = self.idle_after_ms;
            self.limiters.retain(|_, e| {
                now.saturating_sub(e.last_seen_ms.load(Ordering::Relaxed)) < idle_after
            });
            if self.limiters.len() < self.max_entries {
                return;
            }
        }

        let mut sample: Vec<(u64, IpAddr)> = self
            .limiters
            .iter()
            .take(IP_EVICT_SAMPLE)
            .map(|e| (e.last_use.load(Ordering::Relaxed), *e.key()))
            .collect();
        sample.sort_unstable_by_key(|(used, _)| *used);
        for (_, ip) in sample.into_iter().take(IP_EVICT_BATCH) {
            if self.limiters.remove(&ip).is_some() {
                crate::metrics::IP_RATE_LIMIT_EVICTIONS.inc();
            }
        }

        let last_warn = self.last_warn_ms.load(Ordering::Relaxed);
        if last_warn == u64::MAX || now.saturating_sub(last_warn) >= 60_000 {
            self.last_warn_ms.store(now, Ordering::Relaxed);
            tracing::warn!(
                "IP rate limiter is full ({} active IPs); evicting least-recently-used entries. \
                 Possible IP-spray attack, or rate_limiting.max_tracked_ips is too small.",
                self.max_entries
            );
        }
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
    /// Shared bucket across instances (state backend = redis).
    distributed: Option<RedisRateLimiter>,
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
            distributed: None,
        }
    }

    /// Also enforce per-user limits in a bucket shared by every instance.
    pub fn with_distributed(mut self, redis: RedisRateLimiter) -> Self {
        self.distributed = Some(redis);
        self
    }

    /// Check if user is allowed to make a request (uses cached config)
    pub async fn check_user_cached(&self, user_id: i64, config: UserRateLimitConfig) -> bool {
        if !config.enabled {
            return true;
        }
        self.check_user(user_id, config.rps, config.burst).await
    }

    /// Check if user is allowed (legacy method)
    pub async fn check_user(&self, user_id: i64, rps: u32, burst: u32) -> bool {
        let rps = std::num::NonZeroU32::new(rps).unwrap_or(nonzero!(5u32));
        let burst = std::num::NonZeroU32::new(burst).unwrap_or(nonzero!(10u32));
        let local_ok = {
            let quota = Quota::per_second(rps).allow_burst(burst);
            let limiter = self
                .limiters
                .entry(user_id)
                .or_insert_with(|| GovernorRateLimiter::direct(quota));
            limiter.check().is_ok()
        };
        if !local_ok {
            return false;
        }
        distributed_allows(
            &self.distributed,
            &format!("user:{}", user_id),
            per_second_emission_us(rps.get()),
            burst.get(),
        )
        .await
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
/// Uses RwLock<LruCache> since LRU eviction needs global ordering.
///
/// Two independent dimensions:
///   1. per-IP — caps total attempts from a single client IP
///   2. per-(IP, username) — caps targeted enumeration of a specific user
///      from a specific IP. Stops a single attacker from burning the per-IP
///      budget while still trying many users.
#[allow(clippy::type_complexity)] // the governor LRU cache type is inherently verbose
#[derive(Clone)]
pub struct LoginRateLimiter {
    limiters: Arc<
        RwLock<lru::LruCache<IpAddr, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    >,
    user_limiters: Arc<
        RwLock<
            lru::LruCache<
                (IpAddr, String),
                GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>,
            >,
        >,
    >,
    quota: Quota,
    user_quota: Quota,
    /// Raw (per-minute, burst) for the per-IP bucket, for the Redis limiter.
    ip_limits: (u32, u32),
    /// Shared bucket across instances (state backend = redis).
    distributed: Option<RedisRateLimiter>,
}

/// Per-(ip, username) login limit: 3 per minute, burst 5.
const LOGIN_USER_PER_MINUTE: u32 = 3;
const LOGIN_USER_BURST: u32 = 5;

impl LoginRateLimiter {
    /// Create new login rate limiter
    /// Default: 5 attempts per minute per IP, max 10,000 tracked IPs
    pub fn new() -> Self {
        Self::with_limits(5, 10, 10_000)
    }

    /// Create login rate limiter with custom limits
    pub fn with_limits(attempts_per_minute: u32, burst: u32, max_ips: usize) -> Self {
        let per_minute = std::num::NonZeroU32::new(attempts_per_minute).unwrap_or(nonzero!(5u32));
        let burst = std::num::NonZeroU32::new(burst).unwrap_or(nonzero!(10u32));
        let quota = Quota::per_minute(per_minute).allow_burst(burst);
        // Per-(ip, username) is tighter — repeated targeted attempts for a
        // single user from one IP are almost always brute force.
        let user_quota = Quota::per_minute(nonzero!(LOGIN_USER_PER_MINUTE))
            .allow_burst(nonzero!(LOGIN_USER_BURST));
        let max_ips = std::num::NonZeroUsize::new(max_ips).unwrap_or(nonzero!(1usize));
        Self {
            limiters: Arc::new(RwLock::new(lru::LruCache::new(max_ips))),
            user_limiters: Arc::new(RwLock::new(lru::LruCache::new(max_ips))),
            quota,
            user_quota,
            ip_limits: (per_minute.get(), burst.get()),
            distributed: None,
        }
    }

    /// Also enforce the limits in a bucket shared by every instance.
    pub fn with_distributed(mut self, redis: RedisRateLimiter) -> Self {
        self.distributed = Some(redis);
        self
    }

    /// Check if IP is allowed to attempt login.
    ///
    /// Takes a typed `IpAddr` rather than a string so there is no "unparseable
    /// input" branch: the old `&str` API failed OPEN (returned `true`) on any
    /// value that did not parse, so a caller passing e.g. `"ip:port"` would
    /// have silently disabled login throttling.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let ip_addr = normalize_ip(ip);
        let local_ok = {
            let mut limiters = self.limiters.write().await;
            let limiter =
                limiters.get_or_insert(ip_addr, || GovernorRateLimiter::direct(self.quota));
            limiter.check().is_ok()
        };
        if !local_ok {
            return false;
        }
        let (per_minute, burst) = self.ip_limits;
        distributed_allows(
            &self.distributed,
            &format!("login:ip:{}", ip_addr),
            per_minute_emission_us(per_minute),
            burst,
        )
        .await
    }

    /// Check both the per-IP and per-(IP, username) buckets. Both must
    /// allow the attempt. Use this on the login path so a single client
    /// can't enumerate users without burning its overall budget.
    pub async fn check_user(&self, ip: IpAddr, username: &str) -> bool {
        if !self.check(ip).await {
            return false;
        }
        let ip_addr = normalize_ip(ip);
        let local_ok = {
            let key = (ip_addr, username.to_string());
            let mut limiters = self.user_limiters.write().await;
            let limiter =
                limiters.get_or_insert(key, || GovernorRateLimiter::direct(self.user_quota));
            limiter.check().is_ok()
        };
        if !local_ok {
            return false;
        }
        distributed_allows(
            &self.distributed,
            &format!("login:ipuser:{}:{}", ip_addr, username_bucket_id(username)),
            per_minute_emission_us(LOGIN_USER_PER_MINUTE),
            LOGIN_USER_BURST,
        )
        .await
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

/// GCRA (generic cell rate algorithm) in Lua. Equivalent to a token bucket of
/// size `burst` refilled every `emission` microseconds, i.e. the same model as
/// the in-process `governor` limiters, so a config value means the same thing
/// in both backends. Unlike a fixed-window counter there is no 2x burst at
/// window edges. Time comes from the Redis server clock so instances with
/// skewed clocks still agree.
const GCRA_SCRIPT: &str = r#"
if redis.replicate_commands then pcall(redis.replicate_commands) end
local emission = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local tat = tonumber(redis.call('GET', KEYS[1]))
if (not tat) or tat < now then tat = now end
local new_tat = tat + emission
if new_tat - now > emission * burst then
  return 0
end
local ttl_ms = math.ceil((new_tat - now) / 1000)
if ttl_ms < 1 then ttl_ms = 1 end
redis.call('SET', KEYS[1], string.format('%d', new_tat), 'PX', ttl_ms)
return 1
"#;

/// Redis-backed distributed rate limiter (GCRA / token bucket).
///
/// In-process limiters only see the traffic that reaches their own instance,
/// so with N instances behind a load balancer every per-IP / per-user /
/// login limit is effectively N times larger. When the state backend is
/// Redis, the IP, user and login limiters consult this shared bucket in
/// addition to their local one.
#[derive(Clone)]
pub struct RedisRateLimiter {
    conn: redis::aio::ConnectionManager,
    key_prefix: String,
    script: Arc<redis::Script>,
}

impl RedisRateLimiter {
    /// `key_prefix` is prepended to every bucket key, e.g. `"crabby_proxy:"`.
    pub fn new(conn: redis::aio::ConnectionManager, key_prefix: &str) -> Self {
        Self {
            conn,
            key_prefix: key_prefix.to_string(),
            script: Arc::new(redis::Script::new(GCRA_SCRIPT)),
        }
    }

    /// Take one token from the bucket `key`. `emission_us` is the refill
    /// interval per token in microseconds and `burst` the bucket size.
    pub async fn check(
        &self,
        key: &str,
        emission_us: u64,
        burst: u32,
    ) -> Result<bool, redis::RedisError> {
        let full_key = format!("{}rl:{}", self.key_prefix, key);
        let mut conn = self.conn.clone();
        let allowed: i64 = self
            .script
            .key(&full_key)
            .arg(emission_us.max(1))
            .arg(burst.max(1))
            .invoke_async(&mut conn)
            .await?;
        Ok(allowed == 1)
    }
}

/// Microseconds per token for an N-per-second quota.
fn per_second_emission_us(rps: u32) -> u64 {
    1_000_000 / u64::from(rps.max(1))
}

/// Microseconds per token for an N-per-minute quota.
fn per_minute_emission_us(per_minute: u32) -> u64 {
    60_000_000 / u64::from(per_minute.max(1))
}

/// Consult the shared Redis bucket, if one is configured.
///
/// On a Redis error this returns `true`, leaving the local verdict (which the
/// caller has already enforced) in charge, rather than failing closed: failing
/// closed would turn any Redis blip into a full proxy / admin outage, while
/// this still keeps the per-instance limit in force. Errors are logged at most
/// once every 30 seconds.
async fn distributed_allows(
    redis: &Option<RedisRateLimiter>,
    key: &str,
    emission_us: u64,
    burst: u32,
) -> bool {
    let Some(redis) = redis else {
        return true;
    };
    match redis.check(key, emission_us, burst).await {
        Ok(allowed) => allowed,
        Err(e) => {
            static LAST_WARN: AtomicU64 = AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now.saturating_sub(LAST_WARN.load(Ordering::Relaxed)) >= 30 {
                LAST_WARN.store(now, Ordering::Relaxed);
                tracing::warn!(
                    "Distributed rate limit check failed, using the per-instance limit only: {}",
                    e
                );
            }
            true
        }
    }
}

/// Stable, non-reversible bucket id for a username (usernames can contain
/// any character, including the `:` used as a key separator).
fn username_bucket_id(username: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(username.as_bytes())[..16]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
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

    #[tokio::test]
    async fn test_ip_rate_limiter_evicts_when_full() {
        // Tiny cap so we can prove eviction without inserting 100k entries.
        let limiter = IpRateLimiter::with_max_entries(100, 100, 16);

        // Insert past the cap.
        for i in 0..64u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
            limiter.check_ip(ip).await;
        }

        // The map must remain bounded near `max_entries` (eviction batches
        // of 8 mean we may temporarily sit slightly above, but never far above).
        assert!(
            limiter.count().await <= 16,
            "expected <=16 entries after eviction, got {}",
            limiter.count().await
        );
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_prefers_idle_entries() {
        // 1000 rps, burst 1: a bucket refills in 1 ms, so entries go idle fast.
        let limiter = IpRateLimiter::with_max_entries(1000, 1, 16);
        for i in 0..16u8 {
            limiter
                .check_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 0, i)))
                .await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let before = crate::metrics::IP_RATE_LIMIT_EVICTIONS.get();
        limiter
            .check_ip(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)))
            .await;
        // All 16 idle entries were swept losslessly; only the new IP remains.
        assert_eq!(limiter.count().await, 1);
        assert_eq!(crate::metrics::IP_RATE_LIMIT_EVICTIONS.get(), before);
    }

    #[tokio::test]
    async fn test_ip_rate_limiter_spray_does_not_reset_active_offender() {
        // 1 rps, burst 1: once limited, an IP stays limited for ~1s.
        let limiter = IpRateLimiter::with_max_entries(1, 1, 16);
        let offender = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(limiter.check_ip(offender).await);
        assert!(!limiter.check_ip(offender).await);

        // Spray far more IPs than the cap. The offender keeps retrying, so it
        // is always the most recently used entry and must never be evicted
        // (which would hand it a fresh burst).
        for i in 0..200u32 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 3, (i / 256) as u8, (i % 256) as u8));
            limiter.check_ip(ip).await;
            assert!(
                !limiter.check_ip(offender).await,
                "offender bucket was reset after {} sprayed IPs",
                i + 1
            );
        }
        assert!(limiter.count().await <= 16);
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
            assert!(limiter.check(v4(192, 168, 1, 1)).await);
        }
    }

    #[tokio::test]
    async fn test_login_rate_limiter_blocks_after_burst() {
        let limiter = LoginRateLimiter::with_limits(5, 5, 1000);
        let ip = v4(10, 0, 0, 1);

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
            limiter.check(v4(1, 1, 1, 1)).await;
        }
        assert!(!limiter.check(v4(1, 1, 1, 1)).await);

        // ip2 should still work
        assert!(limiter.check(v4(2, 2, 2, 2)).await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_count() {
        let limiter = LoginRateLimiter::new();
        assert_eq!(limiter.count().await, 0);

        limiter.check(v4(1, 1, 1, 1)).await;
        assert_eq!(limiter.count().await, 1);

        limiter.check(v4(2, 2, 2, 2)).await;
        assert_eq!(limiter.count().await, 2);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_clear() {
        let limiter = LoginRateLimiter::new();
        limiter.check(v4(1, 1, 1, 1)).await;
        limiter.check(v4(2, 2, 2, 2)).await;

        limiter.clear().await;
        assert_eq!(limiter.count().await, 0);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_default() {
        let limiter = LoginRateLimiter::default();
        assert_eq!(limiter.count().await, 0);
        assert!(limiter.check(v4(127, 0, 0, 1)).await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_ipv4_mapped_shares_bucket() {
        // ::ffff:10.0.0.9 and 10.0.0.9 are the same client and must share
        // one bucket, otherwise the mapped form is a free second budget.
        let limiter = LoginRateLimiter::with_limits(5, 2, 1000);
        let mapped: IpAddr = "::ffff:10.0.0.9".parse().unwrap();
        assert!(limiter.check(v4(10, 0, 0, 9)).await);
        assert!(limiter.check(mapped).await);
        assert!(!limiter.check(v4(10, 0, 0, 9)).await);
        assert!(!limiter.check(mapped).await);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_per_user_bucket() {
        let limiter = LoginRateLimiter::with_limits(1000, 1000, 1000);
        let ip = v4(10, 0, 0, 1);
        // Per-(ip, user) burst is 5.
        for _ in 0..5 {
            assert!(limiter.check_user(ip, "alice").await);
        }
        assert!(!limiter.check_user(ip, "alice").await);
        // A different username from the same IP has its own bucket.
        assert!(limiter.check_user(ip, "bob").await);
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_emission_intervals() {
        assert_eq!(per_second_emission_us(10), 100_000);
        assert_eq!(per_second_emission_us(0), 1_000_000);
        assert_eq!(per_minute_emission_us(3), 20_000_000);
    }

    #[test]
    fn test_username_bucket_id_is_opaque_and_stable() {
        let a = username_bucket_id("alice:with:colons");
        assert_eq!(a, username_bucket_id("alice:with:colons"));
        assert_ne!(a, username_bucket_id("bob"));
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // === RedisRateLimiter (needs a live Redis) ===
    //
    // Skipped unless CRABBY_TEST_REDIS_URL is set, e.g.
    //   CRABBY_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test rate_limit

    async fn test_redis() -> Option<RedisRateLimiter> {
        let url = std::env::var("CRABBY_TEST_REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        let conn = redis::aio::ConnectionManager::new(client).await.ok()?;
        let prefix = format!("crabby_test:{}:", uuid::Uuid::new_v4());
        Some(RedisRateLimiter::new(conn, &prefix))
    }

    #[tokio::test]
    async fn test_redis_gcra_allows_burst_then_blocks() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // 1 token per minute, burst 3.
        for _ in 0..3 {
            assert!(redis.check("k", 60_000_000, 3).await.unwrap());
        }
        assert!(!redis.check("k", 60_000_000, 3).await.unwrap());
        // Independent key is unaffected.
        assert!(redis.check("other", 60_000_000, 3).await.unwrap());
    }

    #[tokio::test]
    async fn test_redis_gcra_refills() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // 50 ms per token, burst 1.
        assert!(redis.check("r", 50_000, 1).await.unwrap());
        assert!(!redis.check("r", 50_000, 1).await.unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(redis.check("r", 50_000, 1).await.unwrap());
    }

    #[tokio::test]
    async fn test_login_limiter_shared_across_instances() {
        let Some(redis) = test_redis().await else {
            return;
        };
        // Two "instances" with their own local state but one shared bucket:
        // together they must not exceed the single-instance burst.
        let a = LoginRateLimiter::with_limits(5, 4, 100).with_distributed(redis.clone());
        let b = LoginRateLimiter::with_limits(5, 4, 100).with_distributed(redis);
        let ip = v4(198, 51, 100, 1);
        let mut allowed = 0;
        for i in 0..8 {
            let l = if i % 2 == 0 { &a } else { &b };
            if l.check(ip).await {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 4);
    }
}
