//! DNS resolution cache that honours record TTLs, with LRU eviction.
//!
//! Resolution uses `hickory-resolver` configured from the system
//! (`/etc/resolv.conf` nameservers, `search`/`ndots`/`timeout`/`attempts`
//! options, and `/etc/hosts`), so the real record TTL is known (#50). Each
//! answer is cached for that TTL, clamped to `[min_ttl, max_ttl]`
//! (`advanced.dns_cache_min_ttl` / `advanced.dns_cache_ttl`). NXDOMAIN and
//! "no records" answers are cached for the zone's negative TTL, capped at
//! `advanced.dns_negative_cache_ttl`, so a burst of requests for a dead name
//! doesn't hammer the upstream resolver.
//!
//! Fallback to the libc resolver (`getaddrinfo`): if no system DNS config can
//! be read, or a hickory lookup fails for a transport reason (timeout,
//! unreachable nameserver), the name is resolved via `getaddrinfo` instead.
//! That keeps NSS-only sources (mDNS, LDAP, systemd-resolved stubs) working
//! as before. Those answers carry no TTL and are cached for `max_ttl`.
//!
//! Safety: the cache only maps names to addresses. The SSRF egress guard and
//! self-loop check run on the address returned here, on every connection, so
//! no cached or rebinding answer can reach a blocked range.
//!
//! Eviction: entries sit in an LRU keyed by host, so inserting at capacity
//! drops the least recently used entry in O(1). Expired entries are dropped on
//! access and by the periodic `cleanup_expired` sweep.

use async_trait::async_trait;
use lru::LruCache;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io;

/// Default maximum number of cached DNS entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// TTL bounds for cached answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsTtlPolicy {
    /// Floor for positive answers (a 0s record is still cached this long).
    pub min_ttl: Duration,
    /// Ceiling for positive answers. Zero disables caching entirely.
    pub max_ttl: Duration,
    /// Ceiling for negative answers (NXDOMAIN / no records). Zero disables
    /// negative caching.
    pub negative_ttl: Duration,
}

impl DnsTtlPolicy {
    pub fn from_secs(min_ttl: u64, max_ttl: u64, negative_ttl: u64) -> Self {
        Self {
            min_ttl: Duration::from_secs(min_ttl),
            max_ttl: Duration::from_secs(max_ttl),
            negative_ttl: Duration::from_secs(negative_ttl),
        }
    }

    /// How long to cache a positive answer whose record TTL is `ttl`
    /// (`None` = unknown, e.g. a `getaddrinfo` answer).
    fn positive(&self, ttl: Option<Duration>) -> Duration {
        if self.max_ttl.is_zero() {
            return Duration::ZERO;
        }
        let floor = self.min_ttl.min(self.max_ttl);
        ttl.unwrap_or(self.max_ttl).clamp(floor, self.max_ttl)
    }

    /// How long to cache a negative answer whose zone negative TTL is `ttl`.
    fn negative(&self, ttl: Option<Duration>) -> Duration {
        if self.max_ttl.is_zero() {
            return Duration::ZERO;
        }
        ttl.unwrap_or(self.negative_ttl).min(self.negative_ttl)
    }
}

/// A successful lookup: addresses plus the record TTL, if known.
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    ips: Vec<IpAddr>,
    ttl: Option<Duration>,
}

/// A failed lookup.
#[derive(Debug)]
pub(crate) enum LookupError {
    /// Authoritative "no such name / no address records", with the zone's
    /// negative TTL when the response carried an SOA.
    Negative { ttl: Option<Duration> },
    /// Anything else (transport failure, malformed name): never cached.
    Other(io::Error),
}

/// Name → addresses. Abstracted so tests can drive the cache without network.
#[async_trait]
pub(crate) trait HostLookup: Send + Sync {
    async fn lookup(&self, host: &str) -> Result<Answer, LookupError>;
}

/// `getaddrinfo` via tokio. Answers carry no TTL.
struct SystemLookup;

#[async_trait]
impl HostLookup for SystemLookup {
    async fn lookup(&self, host: &str) -> Result<Answer, LookupError> {
        let ips: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
            .await
            .map_err(LookupError::Other)?
            .map(|a| a.ip())
            .collect();
        Ok(Answer { ips, ttl: None })
    }
}

/// hickory stub resolver built from the system config, with `getaddrinfo` as
/// the fallback for transport failures.
struct HickoryLookup {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryLookup {
    fn from_system_conf() -> Result<Self, String> {
        let mut builder =
            hickory_resolver::TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
        let opts = builder.options_mut();
        // Our LRU is the only cache: a second cache inside hickory would
        // defeat `invalidate()` after a failed connect and double the memory.
        opts.cache_size = 0;
        opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Always;
        let resolver = builder.build().map_err(|e| e.to_string())?;
        Ok(Self { resolver })
    }
}

#[async_trait]
impl HostLookup for HickoryLookup {
    async fn lookup(&self, host: &str) -> Result<Answer, LookupError> {
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => {
                let ttl = lookup
                    .valid_until()
                    .saturating_duration_since(Instant::now());
                Ok(Answer {
                    ips: lookup.iter().collect(),
                    ttl: Some(ttl),
                })
            }
            Err(e) if e.is_no_records_found() => {
                let ttl = match &e {
                    hickory_resolver::net::NetError::Dns(
                        hickory_resolver::net::DnsError::NoRecordsFound(nr),
                    ) => nr.negative_ttl.map(|s| Duration::from_secs(s as u64)),
                    _ => None,
                };
                Err(LookupError::Negative { ttl })
            }
            Err(e) => {
                tracing::debug!(
                    "hickory lookup for {} failed ({}); falling back to getaddrinfo",
                    host,
                    e
                );
                SystemLookup.lookup(host).await
            }
        }
    }
}

enum Cached {
    Positive {
        ips: Arc<[IpAddr]>,
        /// Round-robin counter for distributing across resolved addresses.
        counter: usize,
    },
    Negative,
}

struct DnsEntry {
    value: Cached,
    expires_at: Instant,
}

/// Async DNS cache with per-record TTL expiry and bounded LRU size.
pub struct DnsCache {
    cache: Mutex<LruCache<String, DnsEntry>>,
    policy: DnsTtlPolicy,
    lookup: Box<dyn HostLookup>,
}

impl DnsCache {
    /// Create a cache backed by the system DNS configuration.
    pub fn new(policy: DnsTtlPolicy) -> Self {
        let lookup: Box<dyn HostLookup> = match HickoryLookup::from_system_conf() {
            Ok(h) => Box::new(h),
            Err(e) => {
                tracing::warn!(
                    "DNS: cannot load system resolver config ({}); using getaddrinfo \
                     (record TTLs unknown, answers cached for dns_cache_ttl)",
                    e
                );
                Box::new(SystemLookup)
            }
        };
        Self::with_lookup(policy, DEFAULT_MAX_ENTRIES, lookup)
    }

    pub(crate) fn with_lookup(
        policy: DnsTtlPolicy,
        max_entries: usize,
        lookup: Box<dyn HostLookup>,
    ) -> Self {
        let cap = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            policy,
            lookup,
        }
    }

    fn lock(&self) -> MutexGuard<'_, LruCache<String, DnsEntry>> {
        // A panic while holding this short, non-reentrant lock cannot leave
        // the map logically inconsistent; keep serving.
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn not_found(host: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS resolution returned no addresses for {}", host),
        )
    }

    /// Resolve `host` and pair it with `port`.
    ///
    /// - IP literals are returned directly.
    /// - On a live cache hit: a round-robin address, or the cached negative
    ///   answer.
    /// - Otherwise: a fresh lookup, cached per [`DnsTtlPolicy`].
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let key = host.to_ascii_lowercase();

        // Fast path (the lock is never held across an await).
        {
            let mut cache = self.lock();
            if let Some(entry) = cache.get_mut(&key) {
                if Instant::now() < entry.expires_at {
                    match &mut entry.value {
                        Cached::Positive { ips, counter } => {
                            let idx = *counter;
                            *counter = counter.wrapping_add(1);
                            return Ok(SocketAddr::new(ips[idx % ips.len()], port));
                        }
                        Cached::Negative => return Err(Self::not_found(host)),
                    }
                }
                cache.pop(&key);
            }
        }

        // Slow path: resolve and cache.
        match self.lookup.lookup(host).await {
            Ok(answer) if !answer.ips.is_empty() => {
                let first = answer.ips[0];
                let ttl = self.policy.positive(answer.ttl);
                self.store(
                    key,
                    Cached::Positive {
                        ips: answer.ips.into(),
                        counter: 1, // first addr already used
                    },
                    ttl,
                );
                Ok(SocketAddr::new(first, port))
            }
            Ok(_) => {
                self.store(key, Cached::Negative, self.policy.negative(None));
                Err(Self::not_found(host))
            }
            Err(LookupError::Negative { ttl }) => {
                self.store(key, Cached::Negative, self.policy.negative(ttl));
                Err(Self::not_found(host))
            }
            Err(LookupError::Other(e)) => Err(e),
        }
    }

    fn store(&self, key: String, value: Cached, ttl: Duration) {
        if ttl.is_zero() {
            return;
        }
        // `put` evicts the least recently used entry when full: O(1).
        self.lock().put(
            key,
            DnsEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Remove a cached entry (e.g., after a connection failure to that host).
    pub fn invalidate(&self, host: &str, _port: u16) {
        self.lock().pop(&host.to_ascii_lowercase());
    }

    /// Return current cache statistics: (total_entries, total_cached_addresses).
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.lock();
        let total_addrs: usize = cache
            .iter()
            .map(|(_, e)| match &e.value {
                Cached::Positive { ips, .. } => ips.len(),
                Cached::Negative => 0,
            })
            .sum();
        (cache.len(), total_addrs)
    }

    /// Evict all expired entries. Called periodically from a background task
    /// (not on the resolve path).
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut cache = self.lock();
        let expired: Vec<String> = cache
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            cache.pop(&k);
        }
    }

    #[cfg(test)]
    fn ttl_left_for_test(&self, host: &str) -> Option<Duration> {
        self.lock()
            .peek(host)
            .map(|e| e.expires_at.saturating_duration_since(Instant::now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Scripted lookup: host → result, counting calls.
    #[derive(Default)]
    struct FakeLookup {
        answers: HashMap<String, (Vec<IpAddr>, Option<u64>)>,
        negative: HashMap<String, Option<u64>>,
        calls: Arc<AtomicUsize>,
    }

    impl FakeLookup {
        fn answer(mut self, host: &str, ips: &[&str], ttl: Option<u64>) -> Self {
            let ips = ips.iter().map(|s| s.parse().unwrap()).collect();
            self.answers.insert(host.to_string(), (ips, ttl));
            self
        }
        fn nxdomain(mut self, host: &str, ttl: Option<u64>) -> Self {
            self.negative.insert(host.to_string(), ttl);
            self
        }
    }

    #[async_trait]
    impl HostLookup for FakeLookup {
        async fn lookup(&self, host: &str) -> Result<Answer, LookupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some((ips, ttl)) = self.answers.get(host) {
                return Ok(Answer {
                    ips: ips.clone(),
                    ttl: ttl.map(Duration::from_secs),
                });
            }
            if let Some(ttl) = self.negative.get(host) {
                return Err(LookupError::Negative {
                    ttl: ttl.map(Duration::from_secs),
                });
            }
            Err(LookupError::Other(io::Error::other("unreachable")))
        }
    }

    fn cache(policy: DnsTtlPolicy, max: usize, fake: FakeLookup) -> (DnsCache, Arc<AtomicUsize>) {
        let calls = fake.calls.clone();
        (DnsCache::with_lookup(policy, max, Box::new(fake)), calls)
    }

    fn policy() -> DnsTtlPolicy {
        DnsTtlPolicy::from_secs(5, 300, 10)
    }

    fn near(d: Option<Duration>, secs: u64) -> bool {
        let d = d.expect("entry cached").as_secs_f64();
        (secs as f64 - d).abs() < 2.0
    }

    #[test]
    fn ttl_clamp() {
        let p = policy();
        assert_eq!(
            p.positive(Some(Duration::from_secs(60))),
            Duration::from_secs(60)
        );
        assert_eq!(p.positive(Some(Duration::ZERO)), Duration::from_secs(5));
        assert_eq!(
            p.positive(Some(Duration::from_secs(86400))),
            Duration::from_secs(300)
        );
        assert_eq!(p.positive(None), Duration::from_secs(300));
        assert_eq!(
            p.negative(Some(Duration::from_secs(3600))),
            Duration::from_secs(10)
        );
        assert_eq!(
            p.negative(Some(Duration::from_secs(2))),
            Duration::from_secs(2)
        );
        assert_eq!(p.negative(None), Duration::from_secs(10));
        // min above max: max wins.
        let p = DnsTtlPolicy::from_secs(600, 300, 10);
        assert_eq!(
            p.positive(Some(Duration::from_secs(1))),
            Duration::from_secs(300)
        );
        // max 0 disables caching altogether.
        let p = DnsTtlPolicy::from_secs(5, 0, 10);
        assert!(p.positive(Some(Duration::from_secs(60))).is_zero());
        assert!(p.negative(None).is_zero());
    }

    #[tokio::test]
    async fn record_ttl_is_honoured_and_clamped() {
        let fake = FakeLookup::default()
            .answer("short.test", &["192.0.2.1"], Some(30))
            .answer("zero.test", &["192.0.2.2"], Some(0))
            .answer("long.test", &["192.0.2.3"], Some(86_400));
        let (c, _) = cache(policy(), 100, fake);
        for h in ["short.test", "zero.test", "long.test"] {
            c.resolve(h, 443).await.unwrap();
        }
        assert!(near(c.ttl_left_for_test("short.test"), 30));
        assert!(near(c.ttl_left_for_test("zero.test"), 5));
        assert!(near(c.ttl_left_for_test("long.test"), 300));
    }

    #[tokio::test]
    async fn hit_round_robins_and_skips_lookup() {
        let fake = FakeLookup::default().answer("rr.test", &["192.0.2.1", "192.0.2.2"], Some(60));
        let (c, calls) = cache(policy(), 100, fake);
        let a = c.resolve("rr.test", 80).await.unwrap();
        let b = c.resolve("rr.test", 8080).await.unwrap();
        let d = c.resolve("RR.test", 80).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_ne!(a.ip(), b.ip());
        assert_eq!(a.ip(), d.ip());
        assert_eq!(b.port(), 8080);
    }

    #[tokio::test]
    async fn negative_answers_are_cached_briefly() {
        let fake = FakeLookup::default().nxdomain("gone.test", Some(3600));
        let (c, calls) = cache(policy(), 100, fake);
        assert!(c.resolve("gone.test", 80).await.is_err());
        assert!(c.resolve("gone.test", 80).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(near(c.ttl_left_for_test("gone.test"), 10));
    }

    #[tokio::test]
    async fn transport_errors_are_not_cached() {
        let (c, calls) = cache(policy(), 100, FakeLookup::default());
        assert!(c.resolve("flaky.test", 80).await.is_err());
        assert!(c.resolve("flaky.test", 80).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(c.stats().0, 0);
    }

    #[tokio::test]
    async fn ip_literals_bypass_lookup() {
        let (c, calls) = cache(policy(), 100, FakeLookup::default());
        assert_eq!(
            c.resolve("127.0.0.1", 80).await.unwrap(),
            "127.0.0.1:80".parse().unwrap()
        );
        assert_eq!(
            c.resolve("[::1]", 443).await.unwrap(),
            "[::1]:443".parse().unwrap()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalidate_forces_fresh_lookup() {
        let fake = FakeLookup::default().answer("a.test", &["192.0.2.1"], Some(60));
        let (c, calls) = cache(policy(), 100, fake);
        c.resolve("a.test", 80).await.unwrap();
        c.invalidate("a.test", 80);
        assert_eq!(c.stats().0, 0);
        c.resolve("a.test", 80).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_max_ttl_does_not_cache() {
        let fake = FakeLookup::default()
            .answer("a.test", &["192.0.2.1"], Some(60))
            .nxdomain("gone.test", None);
        let (c, calls) = cache(DnsTtlPolicy::from_secs(5, 0, 10), 100, fake);
        c.resolve("a.test", 80).await.unwrap();
        let _ = c.resolve("gone.test", 80).await;
        assert_eq!(c.stats().0, 0);
        c.resolve("a.test", 80).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cleanup_drops_expired_entries() {
        let fake = FakeLookup::default()
            .answer("a.test", &["192.0.2.1"], Some(60))
            .nxdomain("gone.test", Some(1));
        // Negative ceiling of 1s so the negative entry expires quickly.
        let (c, _) = cache(DnsTtlPolicy::from_secs(1, 300, 1), 100, fake);
        c.resolve("a.test", 80).await.unwrap();
        let _ = c.resolve("gone.test", 80).await;
        assert_eq!(c.stats(), (2, 1));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        c.cleanup_expired();
        assert_eq!(c.stats(), (1, 1));
    }

    /// #50: at capacity the least recently *used* entry is evicted, in O(1),
    /// and a recently read entry survives.
    #[tokio::test]
    async fn lru_eviction_keeps_recently_used() {
        let fake = FakeLookup::default()
            .answer("a.test", &["192.0.2.1"], Some(60))
            .answer("b.test", &["192.0.2.2"], Some(60))
            .answer("c.test", &["192.0.2.3"], Some(60));
        let (c, _) = cache(policy(), 2, fake);
        c.resolve("a.test", 1).await.unwrap();
        c.resolve("b.test", 1).await.unwrap();
        // Touch "a" through the hit path so "b" becomes the LRU entry.
        c.resolve("a.test", 1).await.unwrap();
        c.resolve("c.test", 1).await.unwrap(); // insert at capacity
        assert_eq!(c.stats().0, 2);
        assert!(c.ttl_left_for_test("a.test").is_some());
        assert!(c.ttl_left_for_test("b.test").is_none());
        assert!(c.ttl_left_for_test("c.test").is_some());
    }

    /// The real resolver: system config + hosts file. `localhost` resolves
    /// through /etc/hosts without any network.
    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let c = DnsCache::new(policy());
        let addr = c.resolve("localhost", 80).await.unwrap();
        assert!(addr.ip().is_loopback(), "got {}", addr);
    }

    #[tokio::test]
    async fn system_resolver_fails_for_invalid_tld() {
        let c = DnsCache::new(policy());
        assert!(c
            .resolve("this-host-definitely-does-not-exist.invalid", 80)
            .await
            .is_err());
    }
}
