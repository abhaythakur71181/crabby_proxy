//! Bounded, TTL-evicted cache of successful credential checks.
//!
//! Proxy connections (and admin API requests using HTTP Basic) would
//! otherwise run a database lookup plus an Argon2 verify on every request.
//! This cache maps an HMAC of the presented credentials to the user id they
//! authenticated as.
//!
//! Properties:
//! - Keys are HMAC-SHA256 under a process-random key, so plaintext
//!   credentials never live in memory as map keys and keys are collision-safe.
//! - Keys are domain-separated (`CredentialDomain`), so a credential accepted
//!   on one surface (e.g. the proxy's config credential) is never a cache hit
//!   on another (the admin API).
//! - Entries expire after `ttl`; expired entries are swept at most once per
//!   `ttl` on insert, and the map is hard-capped at `capacity` entries.
//! - Entries remember their user id, so a revoked API key, changed password or
//!   disabled account can be evicted for that user alone.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Default positive-cache TTL.
pub const AUTH_CACHE_TTL: Duration = Duration::from_secs(60);
/// Default cap on cached credential entries.
pub const AUTH_CACHE_CAPACITY: usize = 10_000;

/// When the cache is full and nothing has expired, evict this many of the
/// oldest entries from a sample of `EVICT_SAMPLE`.
const EVICT_SAMPLE: usize = 64;
const EVICT_BATCH: usize = 8;

/// Which surface a credential was presented on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialDomain {
    /// Proxy authentication (Basic / SOCKS5 user-pass / API key).
    Proxy,
    /// `Authorization: Basic` on the admin API.
    #[allow(dead_code)]
    AdminBasic,
}

impl CredentialDomain {
    fn tag(self) -> &'static [u8] {
        match self {
            CredentialDomain::Proxy => b"proxy",
            CredentialDomain::AdminBasic => b"admin-basic",
        }
    }
}

/// Process-random HMAC key for cache keys. Generated once per process so keys
/// are unforgeable and never stable across restarts.
static CACHE_HMAC_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// Derive the opaque cache key for a credential pair.
pub fn credential_key(domain: CredentialDomain, username: &str, password: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use sha2::Sha256;

    let key = CACHE_HMAC_KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    });
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(domain.tag());
    mac.update(&[0u8]);
    mac.update(username.as_bytes());
    mac.update(&[0u8]); // separator so (a, b) != (ab, "")
    mac.update(password.as_bytes());
    mac.finalize().into_bytes().into()
}

struct Entry {
    user_id: i64,
    inserted: Instant,
}

/// See the module docs.
pub struct AuthCache {
    map: DashMap<[u8; 32], Entry>,
    ttl: Duration,
    capacity: usize,
    epoch: Instant,
    /// Last expiry sweep, in ms since `epoch`.
    last_sweep_ms: AtomicU64,
}

impl AuthCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            capacity: capacity.max(1),
            epoch: Instant::now(),
            last_sweep_ms: AtomicU64::new(0),
        }
    }

    /// The user id cached for `key`, if present and not expired.
    pub fn get(&self, key: &[u8; 32]) -> Option<i64> {
        let hit = {
            let entry = self.map.get(key)?;
            (entry.inserted.elapsed() < self.ttl).then_some(entry.user_id)
        };
        if hit.is_none() {
            self.map
                .remove_if(key, |_, e| e.inserted.elapsed() >= self.ttl);
        }
        hit
    }

    /// Record that `key` authenticated as `user_id`.
    pub fn insert(&self, key: [u8; 32], user_id: i64) {
        self.maybe_sweep();
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            self.sweep_expired();
            if self.map.len() >= self.capacity {
                self.evict_oldest();
            }
        }
        self.map.insert(
            key,
            Entry {
                user_id,
                inserted: Instant::now(),
            },
        );
    }

    /// Drop every cached credential for `user_id`. Call when a user's
    /// password changes, an API key is revoked, or the account is disabled
    /// or deleted.
    pub fn invalidate_user(&self, user_id: i64) {
        self.map.retain(|_, e| e.user_id != user_id);
    }

    /// Drop everything (e.g. after a config reload changed a username).
    pub fn clear(&self) {
        self.map.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Sweep expired entries at most once per TTL so the cache does not hold
    /// stale entries indefinitely between lookups.
    fn maybe_sweep(&self) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= self.ttl.as_millis() as u64 {
            self.last_sweep_ms.store(now_ms, Ordering::Relaxed);
            self.sweep_expired();
        }
    }

    fn sweep_expired(&self) {
        let ttl = self.ttl;
        self.map.retain(|_, e| e.inserted.elapsed() < ttl);
    }

    fn evict_oldest(&self) {
        let mut sample: Vec<(Instant, [u8; 32])> = self
            .map
            .iter()
            .take(EVICT_SAMPLE)
            .map(|e| (e.inserted, *e.key()))
            .collect();
        sample.sort_unstable_by_key(|(t, _)| *t);
        for (_, key) in sample.into_iter().take(EVICT_BATCH) {
            self.map.remove(&key);
        }
    }
}

impl Default for AuthCache {
    fn default() -> Self {
        Self::new(AUTH_CACHE_TTL, AUTH_CACHE_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u32) -> [u8; 32] {
        credential_key(CredentialDomain::Proxy, &format!("u{}", n), "pw")
    }

    #[test]
    fn domains_are_separated() {
        assert_ne!(
            credential_key(CredentialDomain::Proxy, "admin", "pw"),
            credential_key(CredentialDomain::AdminBasic, "admin", "pw")
        );
        assert_ne!(
            credential_key(CredentialDomain::Proxy, "ab", ""),
            credential_key(CredentialDomain::Proxy, "a", "b")
        );
    }

    #[test]
    fn get_returns_inserted_user() {
        let c = AuthCache::default();
        c.insert(k(1), 42);
        assert_eq!(c.get(&k(1)), Some(42));
        assert_eq!(c.get(&k(2)), None);
    }

    #[test]
    fn entries_expire() {
        let c = AuthCache::new(Duration::from_millis(20), 100);
        c.insert(k(1), 1);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(c.get(&k(1)), None);
        assert_eq!(c.len(), 0, "expired entry is removed on lookup");
    }

    #[test]
    fn expired_entries_are_swept_on_insert() {
        let c = AuthCache::new(Duration::from_millis(20), 100);
        for i in 0..10 {
            c.insert(k(i), 1);
        }
        std::thread::sleep(Duration::from_millis(40));
        c.insert(k(100), 2);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn capacity_is_enforced() {
        let c = AuthCache::new(Duration::from_secs(60), 16);
        for i in 0..200 {
            c.insert(k(i), i as i64);
        }
        assert!(c.len() <= 16, "cache grew to {}", c.len());
        // The most recent insert is always present.
        assert_eq!(c.get(&k(199)), Some(199));
    }

    #[test]
    fn invalidate_user_only_drops_that_user() {
        let c = AuthCache::default();
        c.insert(k(1), 7);
        c.insert(k(2), 7);
        c.insert(k(3), 8);
        c.invalidate_user(7);
        assert_eq!(c.get(&k(1)), None);
        assert_eq!(c.get(&k(2)), None);
        assert_eq!(c.get(&k(3)), Some(8));
    }
}
