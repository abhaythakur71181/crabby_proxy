use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use nonzero_ext::nonzero;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Rate limiter for IP addresses (proxy layer)
#[derive(Clone)]
pub struct IpRateLimiter {
    limiters:
        Arc<RwLock<HashMap<IpAddr, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
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
            limiters: Arc::new(RwLock::new(HashMap::new())),
            quota,
        }
    }

    /// Check if IP is allowed to make a request
    pub async fn check_ip(&self, ip: IpAddr) -> bool {
        let mut limiters = self.limiters.write().await;
        let limiter = limiters
            .entry(ip)
            .or_insert_with(|| GovernorRateLimiter::direct(self.quota));

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

/// Rate limiter for authenticated users
#[derive(Clone)]
pub struct UserRateLimiter {
    limiters: Arc<RwLock<HashMap<i64, GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    // Cache user rate limit configs (user_id -> (rps, burst, enabled, last_updated))
    user_configs: Arc<RwLock<HashMap<i64, UserRateLimitConfig>>>,
    cache_ttl: std::time::Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct UserRateLimitConfig {
    rps: u32,
    burst: u32,
    enabled: bool,
    cached_at: std::time::Instant,
}

impl UserRateLimiter {
    /// Create new user rate limiter with 60-second cache TTL
    pub fn new() -> Self {
        Self::with_ttl(std::time::Duration::from_secs(60))
    }

    /// Create new user rate limiter with custom cache TTL
    pub fn with_ttl(cache_ttl: std::time::Duration) -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
            user_configs: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
        }
    }

    /// Check if user is allowed to make a request (uses cached config)
    pub async fn check_user_cached(&self, user_id: i64, config: UserRateLimitConfig) -> bool {
        // Check if rate limiting is disabled for this user
        if !config.enabled {
            return true;
        }
        // Create quota for this specific user
        let quota =
            Quota::per_second(std::num::NonZeroU32::new(config.rps).unwrap_or(nonzero!(5u32)))
                .allow_burst(std::num::NonZeroU32::new(config.burst).unwrap_or(nonzero!(10u32)));
        let mut limiters = self.limiters.write().await;
        // Get or create limiter for this user
        let limiter = limiters
            .entry(user_id)
            .or_insert_with(|| GovernorRateLimiter::direct(quota));
        limiter.check().is_ok()
    }

    /// Check if user is allowed (legacy method - still requires DB query)
    pub async fn check_user(&self, user_id: i64, rps: u32, burst: u32) -> bool {
        // Create quota for this specific user
        let quota = Quota::per_second(std::num::NonZeroU32::new(rps).unwrap_or(nonzero!(5u32)))
            .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(nonzero!(10u32)));
        let mut limiters = self.limiters.write().await;
        // Get or create limiter for this user
        // Note: This creates a new limiter each time which resets the quota
        // TODO: we'd want to cache limiters with their quotas
        let limiter = limiters
            .entry(user_id)
            .or_insert_with(|| GovernorRateLimiter::direct(quota));
        limiter.check().is_ok()
    }

    /// Get cached user config or return None if expired/missing
    pub async fn get_cached_config(&self, user_id: i64) -> Option<UserRateLimitConfig> {
        let configs = self.user_configs.read().await;
        if let Some(config) = configs.get(&user_id) {
            // Check if cache is still valid
            if config.cached_at.elapsed() < self.cache_ttl {
                return Some(config.clone());
            }
        }
        None
    }

    /// Cache user rate limit configuration
    pub async fn cache_config(&self, user_id: i64, rps: u32, burst: u32, enabled: bool) {
        let config = UserRateLimitConfig {
            rps,
            burst,
            enabled,
            cached_at: std::time::Instant::now(),
        };
        self.user_configs.write().await.insert(user_id, config);
    }

    /// Invalidate cache for specific user (call when user settings change)
    pub async fn invalidate_user(&self, user_id: i64) {
        self.user_configs.write().await.remove(&user_id);
        // Also remove their rate limiter to reset quota
        self.limiters.write().await.remove(&user_id);
    }

    /// Clear all cached configs
    pub async fn clear_cache(&self) {
        self.user_configs.write().await.clear();
    }

    /// Get number of tracked users
    pub async fn count(&self) -> usize {
        self.limiters.read().await.len()
    }

    /// Clear all rate limiters (for testing)
    #[allow(dead_code)]
    pub async fn clear(&self) {
        self.limiters.write().await.clear();
        self.user_configs.write().await.clear();
    }
}

impl Default for UserRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
}
