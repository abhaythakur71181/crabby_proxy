//! In-process bandwidth quota tracker.
//!
//! Provides per-user atomic byte counters that are seeded from the database
//! on first use and then mutated on the hot path of the relay loop. The
//! tracker is the single source of truth for both admission checks
//! (`validate_quota`) and in-flight enforcement (the relay loop), so a
//! connection that crosses the limit mid-stream is torn down within one
//! buffer iteration.
//!
//! Design notes:
//! - Lock-free reads/writes via `AtomicI64`. No `await`s on the hot path.
//! - The window (monthly) is recorded per-entry; on access we lazily reseed
//!   from the database when the window has rolled over.
//! - A `limit` of `NO_LIMIT` (`i64::MAX`) disables enforcement for that user.
//! - Admin updates to a user's quota fire through the existing event bus and
//!   call `invalidate`/`update_limit` to reseed on the next access.
//! - Entries are bounded: `evict_idle` (run periodically) drops trackers that no
//!   live connection holds and that have not been looked up recently. The
//!   evicted counter is kept as a compact per-window "floor" so a later reseed
//!   from the (possibly lagging) `usage` table can never under-count (#30).
//! - Concurrent first-use seeds race only on the database read; the map insert
//!   is first-writer-wins, so every connection for a user shares one counter.
//!
//! Known limits (#30): enforcement is per process. Admission (`is_over`) and
//! accounting (`add_and_over`) are separate steps, so N connections admitted
//! together can overshoot by at most about one relay buffer each before the
//! relay loop tears them down. A hard global quota across replicas needs a
//! shared counter (e.g. Redis INCRBY + limit check) and is not implemented.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// Sentinel value meaning "no quota configured" (effectively unlimited).
pub const NO_LIMIT: i64 = i64::MAX;

/// A tracker no connection holds is evicted after this long without a lookup.
pub const IDLE_EVICT_SECS: i64 = 600;
/// How often the background sweep calls [`QuotaTrackerRegistry::evict_idle`].
pub const EVICT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Per-user live bandwidth counter for the current quota window.
///
/// Also stashes the resolved bandwidth throttler (if any) the first time
/// the relay path needs it, so subsequent connections in the same window
/// skip a `bandwidth_throttlers.get_or_create` lookup. The cell stores
/// `Option<Arc<...>>` so "user has no throttle" is a hit too, not a re-check.
pub struct UserQuotaTracker {
    used: AtomicI64,
    limit: AtomicI64,
    window_start: AtomicI64,
    /// Unix seconds of the last registry lookup (not touched on the relay hot
    /// path; a held `Arc` already pins the entry against eviction).
    last_access: AtomicI64,
    throttler: std::sync::OnceLock<Option<crate::bandwidth::BandwidthThrottler>>,
}

impl UserQuotaTracker {
    pub fn new(used: i64, limit: Option<i64>, window_start: i64) -> Self {
        Self {
            used: AtomicI64::new(used),
            limit: AtomicI64::new(limit.unwrap_or(NO_LIMIT)),
            window_start: AtomicI64::new(window_start),
            last_access: AtomicI64::new(now_secs()),
            throttler: std::sync::OnceLock::new(),
        }
    }

    /// Resolve the per-user throttler, populating the once-cell on first
    /// call. `init` is invoked at most once per tracker (i.e. at most once
    /// per quota window per user). `BandwidthThrottler` is internally
    /// `Arc`-shared so this clone is cheap.
    pub fn throttler_or_init<F>(&self, init: F) -> Option<crate::bandwidth::BandwidthThrottler>
    where
        F: FnOnce() -> Option<crate::bandwidth::BandwidthThrottler>,
    {
        self.throttler.get_or_init(init).clone()
    }

    /// Non-blocking peek at the cached throttler. Returns `Some(value)` only
    /// when the cell has already been initialized (so the caller can avoid
    /// running their async resolution work on the hot path).
    pub fn throttler_cached(&self) -> Option<Option<crate::bandwidth::BandwidthThrottler>> {
        self.throttler.get().cloned()
    }

    /// True if the user is currently at or above the configured limit.
    /// `NO_LIMIT` always returns false.
    pub fn is_over(&self) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        if limit == NO_LIMIT {
            return false;
        }
        self.used.load(Ordering::Relaxed) >= limit
    }

    /// Atomically add `bytes` to the live counter and return true if the
    /// user is now at or above the limit. Always returns false when the
    /// user has no configured limit.
    ///
    /// Called from the relay hot path — must remain allocation-free and
    /// lock-free.
    pub fn add_and_over(&self, bytes: i64) -> bool {
        if bytes <= 0 {
            return self.is_over();
        }
        let limit = self.limit.load(Ordering::Relaxed);
        let prev = self.used.fetch_add(bytes, Ordering::Relaxed);
        limit != NO_LIMIT && (prev + bytes) >= limit
    }

    pub fn used(&self) -> i64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> i64 {
        self.limit.load(Ordering::Relaxed)
    }

    pub fn window_start(&self) -> i64 {
        self.window_start.load(Ordering::Relaxed)
    }

    fn touch(&self) {
        self.last_access.store(now_secs(), Ordering::Relaxed);
    }

    fn last_access(&self) -> i64 {
        self.last_access.load(Ordering::Relaxed)
    }

    fn set_limit(&self, limit: Option<i64>) {
        self.limit
            .store(limit.unwrap_or(NO_LIMIT), Ordering::Relaxed);
    }
}

/// Process-wide registry of per-user quota trackers.
pub struct QuotaTrackerRegistry {
    entries: DashMap<i64, Arc<UserQuotaTracker>>,
    /// `user_id -> (window_start, used)` remembered from evicted trackers, so a
    /// reseed in the same window starts from at least what was counted live.
    floors: DashMap<i64, (i64, i64)>,
}

impl QuotaTrackerRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            floors: DashMap::new(),
        }
    }

    /// Number of live tracker entries (for tests / metrics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Insert a freshly seeded tracker unless another task won the race, in
    /// which case the existing current-window tracker is returned instead. A
    /// stale-window entry is replaced.
    fn install(&self, user_id: i64, fresh: Arc<UserQuotaTracker>) -> Arc<UserQuotaTracker> {
        let window = fresh.window_start();
        let tracker = match self.entries.entry(user_id) {
            Entry::Occupied(mut o) => {
                if o.get().window_start() == window {
                    o.get().clone()
                } else {
                    o.insert(fresh.clone());
                    fresh
                }
            }
            Entry::Vacant(v) => {
                v.insert(fresh.clone());
                fresh
            }
        };
        self.floors.remove(&user_id);
        tracker.touch();
        tracker
    }

    /// Drop trackers that no connection currently holds and that have not been
    /// looked up for `idle_secs`. Their counters are kept as per-window floors
    /// (cheap `(i64, i64)` pairs, cleared when the window rolls over) so the
    /// next reseed cannot fall below what was already counted. Returns the
    /// number of trackers evicted.
    pub fn evict_idle(&self, idle_secs: i64) -> usize {
        let now = now_secs();
        let window = crate::db::quota::QuotaPeriod::Monthly.window_start();
        let mut evicted = 0usize;
        self.entries.retain(|uid, t| {
            // strong_count == 1 means only the map holds it: no live relay or
            // in-progress admission check. Checked under the shard write lock,
            // so no lookup can clone it concurrently.
            let keep = Arc::strong_count(t) > 1 || now - t.last_access() < idle_secs;
            if !keep {
                evicted += 1;
                if t.window_start() == window && t.used() > 0 {
                    self.floors.insert(*uid, (window, t.used()));
                }
            }
            keep
        });
        self.floors.retain(|_, (w, _)| *w == window);
        evicted
    }

    /// Get the tracker for `user_id`, seeding it from the database if
    /// missing or if the quota window has rolled over since it was last
    /// seeded.
    pub async fn get_or_seed(
        &self,
        pool: &SqlitePool,
        user_id: i64,
    ) -> Result<Arc<UserQuotaTracker>, sqlx::Error> {
        let current_window = crate::db::quota::QuotaPeriod::Monthly.window_start();

        if let Some(entry) = self.entries.get(&user_id) {
            if entry.window_start() == current_window {
                entry.touch();
                return Ok(entry.clone());
            }
            // Window rolled over — reseed below; `install` replaces it.
        }

        let stats = crate::db::quota::get_quota_stats(pool, user_id).await?;
        let floor = self
            .floors
            .get(&user_id)
            .filter(|f| f.0 == current_window)
            .map(|f| f.1)
            .unwrap_or(0);
        let fresh = Arc::new(UserQuotaTracker::new(
            stats.used_bytes.max(floor),
            stats.quota_bytes,
            current_window,
        ));
        Ok(self.install(user_id, fresh))
    }

    /// Drop the cached tracker for a user. The next access will reseed
    /// from the database. Use this when admin actions change the user's
    /// `monthly_bandwidth_quota` or zero out their usage.
    pub fn invalidate(&self, user_id: i64) {
        self.entries.remove(&user_id);
        self.floors.remove(&user_id);
    }

    /// Update only the limit on an existing tracker, without touching
    /// `used`. Falls back to invalidation if the user has no live entry.
    pub fn update_limit(&self, user_id: i64, limit: Option<i64>) {
        if let Some(entry) = self.entries.get(&user_id) {
            entry.set_limit(limit);
        }
    }
}

impl Default for QuotaTrackerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_never_over() {
        let t = UserQuotaTracker::new(0, None, 0);
        assert!(!t.is_over());
        assert!(!t.add_and_over(1_000_000_000));
        assert!(!t.is_over());
    }

    #[test]
    fn add_and_over_crosses_threshold() {
        let t = UserQuotaTracker::new(0, Some(1_048_576), 0);
        assert!(!t.add_and_over(500_000));
        assert!(!t.is_over());
        assert!(t.add_and_over(600_000));
        assert!(t.is_over());
    }

    fn current_window() -> i64 {
        crate::db::quota::QuotaPeriod::Monthly.window_start()
    }

    #[test]
    fn install_is_first_writer_wins() {
        let reg = QuotaTrackerRegistry::new();
        let w = current_window();
        let a = reg.install(1, Arc::new(UserQuotaTracker::new(0, Some(100), w)));
        let b = reg.install(1, Arc::new(UserQuotaTracker::new(0, Some(100), w)));
        assert!(
            Arc::ptr_eq(&a, &b),
            "concurrent seeds must share one counter"
        );
        // A stale-window entry is replaced.
        let reg2 = QuotaTrackerRegistry::new();
        let old = reg2.install(1, Arc::new(UserQuotaTracker::new(5, None, w - 1)));
        let new = reg2.install(1, Arc::new(UserQuotaTracker::new(0, None, w)));
        assert!(!Arc::ptr_eq(&old, &new));
    }

    #[test]
    fn evict_idle_skips_held_and_recent_entries_and_keeps_floor() {
        let reg = QuotaTrackerRegistry::new();
        let w = current_window();
        let held = reg.install(1, Arc::new(UserQuotaTracker::new(0, None, w)));
        let idle = reg.install(2, Arc::new(UserQuotaTracker::new(0, None, w)));
        idle.add_and_over(4242);
        drop(idle);
        reg.install(3, Arc::new(UserQuotaTracker::new(0, None, w)));

        // Nothing is idle long enough yet.
        assert_eq!(reg.evict_idle(IDLE_EVICT_SECS), 0);
        assert_eq!(reg.len(), 3);

        // With a zero idle threshold, only the held entry survives.
        assert_eq!(reg.evict_idle(0), 2);
        assert_eq!(reg.len(), 1);
        assert!(reg.entries.contains_key(&1));
        drop(held);

        // The evicted counter is remembered as a floor for this window.
        assert_eq!(reg.floors.get(&2).map(|f| *f), Some((w, 4242)));
        assert!(!reg.floors.contains_key(&3), "zero usage needs no floor");
    }

    /// Reseeding after eviction never drops below the live count, even when
    /// the usage table lags (rows still queued or dropped by the writer).
    #[tokio::test]
    async fn reseed_after_eviction_uses_floor() {
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, monthly_bandwidth_quota) VALUES (1,'u','h','user',0,0,10000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let reg = QuotaTrackerRegistry::new();
        let t = reg.get_or_seed(&pool, 1).await.unwrap();
        assert_eq!(t.used(), 0);
        t.add_and_over(700); // live bytes not (yet) in the usage table
        drop(t);
        assert_eq!(reg.evict_idle(0), 1);

        let t = reg.get_or_seed(&pool, 1).await.unwrap();
        assert_eq!(t.used(), 700);
        assert_eq!(t.limit(), 10000);
        assert!(reg.floors.is_empty(), "floor is consumed on reseed");
    }

    #[test]
    fn update_limit_in_place() {
        let t = UserQuotaTracker::new(500, Some(1000), 0);
        assert!(!t.is_over());
        t.set_limit(Some(400));
        assert!(t.is_over());
        t.set_limit(None);
        assert!(!t.is_over());
    }
}
