//! DNS resolution cache with configurable TTL and LRU eviction.
//!
//! Resolution uses `tokio::net::lookup_host` (the system resolver via
//! `getaddrinfo`). On a hit the cache returns a round-robin address from the
//! cached list; on a miss or expired entry it resolves fresh and caches.
//!
//! TTL: `getaddrinfo` does not expose the DNS record TTL, so entries live for
//! the configured `advanced.dns_cache_ttl` (an upper bound). Honouring the
//! real record TTL needs a DNS-speaking resolver (e.g. hickory-resolver); the
//! SSRF egress guard runs on the resolved IP, so a stale entry cannot be used
//! to reach a blocked range.
//!
//! Eviction: entries sit in an LRU, so inserting at capacity drops the least
//! recently used entry in O(1). The previous design collected and sorted the
//! whole map on the resolve hot path once the cap was reached (#50).

use lru::LruCache;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io;
use tokio::net::lookup_host;

/// A cached DNS entry: resolved addresses + time of resolution.
struct DnsEntry {
    addrs: Arc<[SocketAddr]>,
    cached_at: Instant,
    /// Round-robin counter for distributing across resolved addresses.
    counter: usize,
}

/// Default maximum number of cached DNS entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Async DNS cache with TTL expiry and bounded LRU size.
pub struct DnsCache {
    cache: Mutex<LruCache<String, DnsEntry>>,
    ttl: Duration,
}

impl DnsCache {
    /// Create a new DNS cache with the given TTL in seconds.
    /// A TTL of 0 disables caching (every lookup is fresh).
    pub fn new(ttl_secs: u64) -> Self {
        Self::with_max_entries(ttl_secs, DEFAULT_MAX_ENTRIES)
    }

    /// Create a new DNS cache with a custom max entries limit (min 1).
    pub fn with_max_entries(ttl_secs: u64, max_entries: usize) -> Self {
        let cap = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<String, DnsEntry>> {
        // A panic while holding this short, non-reentrant lock cannot leave
        // the map logically inconsistent; keep serving.
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Resolve a hostname:port, returning a single `SocketAddr`.
    ///
    /// - On cache hit (within TTL): returns round-robin selected address.
    /// - On cache miss or expired: performs async DNS resolution, caches all
    ///   addresses, and returns the first.
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let key = format!("{}:{}", host, port);

        // Fast path: check cache (the lock is never held across an await).
        {
            let mut cache = self.lock();
            if let Some(entry) = cache.get_mut(&key) {
                if entry.cached_at.elapsed() < self.ttl && !entry.addrs.is_empty() {
                    let idx = entry.counter;
                    entry.counter = entry.counter.wrapping_add(1);
                    return Ok(entry.addrs[idx % entry.addrs.len()]);
                }
                cache.pop(&key);
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
        if !self.ttl.is_zero() {
            // `put` evicts the least recently used entry when full: O(1).
            self.lock().put(
                key,
                DnsEntry {
                    addrs: addrs.into(),
                    cached_at: Instant::now(),
                    counter: 1, // first addr already used
                },
            );
        }

        Ok(first)
    }

    /// Remove a cached entry (e.g., after a connection failure to that host).
    pub fn invalidate(&self, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        self.lock().pop(&key);
    }

    /// Return current cache statistics: (total_entries, total_cached_addresses).
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.lock();
        let total_addrs: usize = cache.iter().map(|(_, e)| e.addrs.len()).sum();
        (cache.len(), total_addrs)
    }

    /// Evict all expired entries. Called periodically from a background task
    /// (not on the resolve path).
    pub fn cleanup_expired(&self) {
        let mut cache = self.lock();
        let expired: Vec<String> = cache
            .iter()
            .filter(|(_, e)| e.cached_at.elapsed() >= self.ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            cache.pop(&k);
        }
    }

    #[cfg(test)]
    fn insert_for_test(&self, key: &str, addr: SocketAddr) {
        self.lock().put(
            key.to_string(),
            DnsEntry {
                addrs: vec![addr].into(),
                cached_at: Instant::now(),
                counter: 0,
            },
        );
    }

    #[cfg(test)]
    fn contains_for_test(&self, key: &str) -> bool {
        self.lock().contains(key)
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

    /// #50: at capacity the least recently *used* entry is evicted, in O(1),
    /// and a recently read entry survives.
    #[tokio::test]
    async fn test_lru_eviction_keeps_recently_used() {
        let cache = DnsCache::with_max_entries(300, 2);
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        cache.insert_for_test("a:1", a);
        cache.insert_for_test("b:1", "10.0.0.2:1".parse().unwrap());
        // Touch "a" through the real hit path so "b" becomes the LRU entry.
        assert_eq!(cache.resolve("a", 1).await.unwrap(), a);
        cache.resolve("127.0.0.1", 3).await.unwrap(); // insert at capacity
        assert_eq!(cache.stats().0, 2);
        assert!(cache.contains_for_test("a:1"));
        assert!(!cache.contains_for_test("b:1"));
        assert!(cache.contains_for_test("127.0.0.1:3"));
    }

    #[tokio::test]
    async fn test_zero_ttl_does_not_cache() {
        let cache = DnsCache::new(0);
        cache.resolve("127.0.0.1", 4444).await.unwrap();
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
