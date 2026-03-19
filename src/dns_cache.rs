//! DNS resolution cache with configurable TTL.
//!
//! Uses `DashMap` for lock-free concurrent reads and `tokio::net::lookup_host`
//! for async DNS resolution. On cache hit, returns a round-robin selected address
//! from the cached list. On miss or expired entry, resolves fresh and caches.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io;
use tokio::net::lookup_host;

/// A cached DNS entry: resolved addresses + time of resolution.
struct DnsEntry {
    addrs: Vec<SocketAddr>,
    cached_at: Instant,
    /// Round-robin counter for distributing across resolved addresses
    counter: AtomicU64,
}

/// Async DNS cache backed by `DashMap`.
pub struct DnsCache {
    cache: DashMap<String, DnsEntry>,
    ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache with the given TTL in seconds.
    /// A TTL of 0 effectively disables caching (every lookup is fresh).
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Resolve a hostname:port, returning a single `SocketAddr`.
    ///
    /// - On cache hit (within TTL): returns round-robin selected address.
    /// - On cache miss or expired: performs async DNS resolution, caches all
    ///   addresses, and returns the first.
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let key = format!("{}:{}", host, port);

        // Fast path: check cache
        if let Some(entry) = self.cache.get(&key) {
            if entry.cached_at.elapsed() < self.ttl && !entry.addrs.is_empty() {
                let idx = entry.counter.fetch_add(1, Ordering::Relaxed) as usize;
                let addr = entry.addrs[idx % entry.addrs.len()];
                return Ok(addr);
            }
        }

        // Slow path: resolve and cache
        let addrs: Vec<SocketAddr> = lookup_host(&key).await?.collect();
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("DNS resolution returned no addresses for {}", key),
            ));
        }

        let first = addrs[0];
        self.cache.insert(
            key,
            DnsEntry {
                addrs,
                cached_at: Instant::now(),
                counter: AtomicU64::new(1), // first addr already used
            },
        );

        Ok(first)
    }

    /// Remove a cached entry (e.g., after a connection failure to that host).
    pub fn invalidate(&self, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        self.cache.remove(&key);
    }

    /// Return current cache statistics: (total_entries, total_cached_addresses).
    pub fn stats(&self) -> (usize, usize) {
        let entries = self.cache.len();
        let total_addrs: usize = self.cache.iter().map(|e| e.addrs.len()).sum();
        (entries, total_addrs)
    }

    /// Evict all expired entries. Call periodically from a background task.
    pub fn cleanup_expired(&self) {
        self.cache
            .retain(|_, entry| entry.cached_at.elapsed() < self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_localhost() {
        let cache = DnsCache::new(300);
        let addr = cache.resolve("127.0.0.1", 80).await.unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(addr.port(), 80);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache = DnsCache::new(300);
        // First resolve (cache miss)
        let addr1 = cache.resolve("127.0.0.1", 8080).await.unwrap();
        // Second resolve (cache hit)
        let addr2 = cache.resolve("127.0.0.1", 8080).await.unwrap();
        assert_eq!(addr1, addr2);
        assert_eq!(cache.stats().0, 1); // one entry
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = DnsCache::new(300);
        cache.resolve("127.0.0.1", 9090).await.unwrap();
        assert_eq!(cache.stats().0, 1);
        cache.invalidate("127.0.0.1", 9090);
        assert_eq!(cache.stats().0, 0);
    }

    #[tokio::test]
    async fn test_expired_entry() {
        let cache = DnsCache::new(0); // 0s TTL = always expired
        cache.resolve("127.0.0.1", 7070).await.unwrap();
        // With 0 TTL, next resolve should re-resolve (still works, just not cached effectively)
        let addr = cache.resolve("127.0.0.1", 7070).await.unwrap();
        assert_eq!(addr.port(), 7070);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let cache = DnsCache::new(0); // everything expires immediately
        cache.resolve("127.0.0.1", 1111).await.unwrap();
        cache.resolve("127.0.0.1", 2222).await.unwrap();
        // Small delay to ensure entries are expired
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache.cleanup_expired();
        assert_eq!(cache.stats().0, 0);
    }

    #[tokio::test]
    async fn test_resolution_failure() {
        let cache = DnsCache::new(300);
        let result = cache
            .resolve("this-host-definitely-does-not-exist.invalid", 80)
            .await;
        assert!(result.is_err());
    }
}
