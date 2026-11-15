//! Bandwidth quota tracker.
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
//! # Shared (Redis) mode, for more than one replica (#30)
//!
//! With `[state] backend = "redis"` the registry is built with
//! [`QuotaTrackerRegistry::with_redis`] and the authoritative per-user count
//! for the window lives in Redis under `{prefix}quota:{user_id}:{window_start}`.
//! The relay hot path stays synchronous: each chunk is added to the local
//! counter and to a local `pending` delta. The delta is pushed with one atomic
//! Lua call (`INCRBY` plus floor and expiry) by
//! - the background sync loop every [`SHARED_SYNC_INTERVAL`] for every tracker
//!   with unpushed bytes or a live connection, and
//! - every admission check ([`QuotaTrackerRegistry::get_for_admission`]),
//!
//! and the local counter is then reset to `global + still-pending`, so a long
//! tunnel on one replica also sees bytes counted by the others.
//!
//! Seeding never lowers the shared counter: the script sets the key to
//! `max(existing, seed)`, where the seed is the `usage` table SUM (or the
//! local floor, whichever is larger). A replica that restarts, or a lagging
//! `usage` table, therefore cannot under-count. Every call refreshes an
//! `EXPIREAT` one week after the window ends, so old windows clean themselves
//! up. A key that vanished (Redis restarted without persistence) is restored
//! to at least the last global value this replica saw before the delta is
//! added.
//!
//! Overshoot bound: a replica learns about the others' traffic at most one
//! sync interval late, so a user can exceed the quota by roughly what all
//! replicas relay for them in that interval, plus about one relay buffer per
//! connection admitted at the same instant. That is the price of keeping
//! Redis off the per-chunk path.
//!
//! Redis unavailable: like the rate limiter (`rate_limit::distributed_allows`)
//! this fails *open to local enforcement*, not closed. A failed sync puts the
//! delta back into `pending`, increments `proxy_quota_sync_errors_total` and
//! logs at most every 30 s; admission and in-flight checks keep using this
//! replica's last known global count plus everything it relayed since. When
//! Redis returns, the retained deltas are pushed and the replicas converge.
//! During the outage each replica may admit up to the remaining quota on its
//! own, so the worst-case overshoot is (replicas - 1) x the remaining quota.
//!
//! With the memory backend nothing of this applies: the counter is
//! per-process, which is correct for the single-instance topology.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

/// Sentinel value meaning "no quota configured" (effectively unlimited).
pub const NO_LIMIT: i64 = i64::MAX;

/// A tracker no connection holds is evicted after this long without a lookup.
pub const IDLE_EVICT_SECS: i64 = 600;
/// How often the background sweep calls [`QuotaTrackerRegistry::evict_idle`].
pub const EVICT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// How often, in shared mode, local deltas are pushed to Redis and the global
/// count pulled back.
pub const SHARED_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
/// Upper bound on one Redis round trip for a quota sync; past it the local
/// view is used (see "Redis unavailable" above).
const SHARED_SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// Shared counters expire this long after their window ends.
const SHARED_KEY_GRACE_SECS: i64 = 7 * 86_400;

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Start of the monthly window after the one starting at `window_start`.
fn next_window_start(window_start: i64) -> i64 {
    use chrono::Datelike;
    let d = chrono::DateTime::from_timestamp(window_start, 0)
        .unwrap_or_default()
        .date_naive();
    let (y, m) = if d.month() == 12 {
        (d.year() + 1, 1)
    } else {
        (d.year(), d.month() + 1)
    };
    chrono::NaiveDate::from_ymd_opt(y, m, 1)
        .and_then(|n| n.and_hms_opt(0, 0, 0))
        .map(|n| n.and_utc().timestamp())
        .unwrap_or(window_start + 31 * 86_400)
}

/// Per-user live bandwidth counter for the current quota window.
///
/// Also stashes the resolved bandwidth throttler (if any) the first time
/// the relay path needs it, so subsequent connections in the same window
/// skip a `bandwidth_throttlers.get_or_create` lookup. The cell stores
/// `Option<Arc<...>>` so "user has no throttle" is a hit too, not a re-check.
pub struct UserQuotaTracker {
    user_id: i64,
    used: AtomicI64,
    limit: AtomicI64,
    window_start: AtomicI64,
    /// Unix seconds of the last registry lookup (not touched on the relay hot
    /// path; a held `Arc` already pins the entry against eviction).
    last_access: AtomicI64,
    /// Shared mode only: bytes counted here but not yet pushed to Redis.
    pending: AtomicI64,
    /// Shared mode only: the last global count read back from Redis (or the
    /// seed). A lower bound for the shared counter, used to restore a lost key.
    synced: AtomicI64,
    shared: bool,
    throttler: std::sync::OnceLock<Option<crate::bandwidth::BandwidthThrottler>>,
}

impl UserQuotaTracker {
    pub fn new(used: i64, limit: Option<i64>, window_start: i64) -> Self {
        Self::build(0, used, limit, window_start, false)
    }

    fn build(user_id: i64, used: i64, limit: Option<i64>, window_start: i64, shared: bool) -> Self {
        Self {
            user_id,
            used: AtomicI64::new(used),
            limit: AtomicI64::new(limit.unwrap_or(NO_LIMIT)),
            window_start: AtomicI64::new(window_start),
            last_access: AtomicI64::new(now_secs()),
            pending: AtomicI64::new(0),
            synced: AtomicI64::new(used),
            shared,
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
        // `pending` first: a concurrent `apply_global` may then count these
        // bytes twice until the next sync (safe), but never drops them.
        if self.shared {
            self.pending.fetch_add(bytes, Ordering::Relaxed);
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

    fn pending(&self) -> i64 {
        self.pending.load(Ordering::Relaxed)
    }

    /// Take the unpushed delta for a sync.
    fn take_pending(&self) -> i64 {
        self.pending.swap(0, Ordering::Relaxed)
    }

    /// A sync failed: keep the delta for the next attempt.
    fn restore_pending(&self, delta: i64) {
        if delta != 0 {
            self.pending.fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// Adopt the global count returned by Redis. The local view becomes
    /// `global + bytes relayed since the delta was taken`. `synced` only moves
    /// forward, so an older reply racing a newer one cannot lower it.
    fn apply_global(&self, global: i64) {
        let prev = self.synced.fetch_max(global, Ordering::Relaxed);
        let global = prev.max(global);
        // CAS so a relay increment landing between the two loads is retried
        // instead of being overwritten.
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let target = global + self.pending.load(Ordering::Relaxed);
            match self
                .used
                .compare_exchange_weak(cur, target, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Atomically: restore a missing or low counter to `floor`, add `delta`,
/// refresh the expiry, return the new total. With `delta = 0` this is the
/// seed operation (`max(existing, seed)`), so a reseed never lowers the count.
const SYNC_SCRIPT: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]))
local floor = tonumber(ARGV[2])
if (not cur) or cur < floor then
  redis.call('SET', KEYS[1], floor)
end
local n = redis.call('INCRBY', KEYS[1], ARGV[1])
redis.call('EXPIREAT', KEYS[1], ARGV[3])
return n
"#;

/// Redis-backed shared quota counters (see the module docs).
#[derive(Clone)]
pub struct SharedQuotaStore {
    conn: redis::aio::ConnectionManager,
    prefix: String,
    script: Arc<redis::Script>,
}

impl SharedQuotaStore {
    pub fn new(conn: redis::aio::ConnectionManager, key_prefix: &str) -> Self {
        Self {
            conn,
            prefix: key_prefix.to_string(),
            script: Arc::new(redis::Script::new(SYNC_SCRIPT)),
        }
    }

    fn key(&self, user_id: i64, window_start: i64) -> String {
        format!("{}quota:{}:{}", self.prefix, user_id, window_start)
    }

    /// Push `delta` for the user's window (restoring the key to at least
    /// `floor` first) and return the global total.
    pub async fn sync(
        &self,
        user_id: i64,
        window_start: i64,
        delta: i64,
        floor: i64,
    ) -> Result<i64, redis::RedisError> {
        let mut conn = self.conn.clone();
        let mut invocation = self.script.key(self.key(user_id, window_start));
        invocation
            .arg(delta)
            .arg(floor.max(0))
            .arg(next_window_start(window_start) + SHARED_KEY_GRACE_SECS);
        let call = invocation.invoke_async(&mut conn);
        // Admission waits on this; a hung Redis must not stall connections.
        match tokio::time::timeout(SHARED_SYNC_TIMEOUT, call).await {
            Ok(r) => r,
            Err(_) => Err(redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shared quota sync timed out",
            ))),
        }
    }
}

/// Log a shared-counter failure at most once every 30 seconds.
fn warn_sync_failure(e: &redis::RedisError) {
    static LAST_WARN: AtomicU64 = AtomicU64::new(0);
    crate::metrics::QUOTA_SYNC_ERRORS.inc();
    let now = now_secs() as u64;
    if now.saturating_sub(LAST_WARN.load(Ordering::Relaxed)) >= 30 {
        LAST_WARN.store(now, Ordering::Relaxed);
        tracing::warn!(
            "Shared quota counter sync failed, enforcing quotas from this instance's view only: {}",
            e
        );
    }
}

/// Process-wide registry of per-user quota trackers.
pub struct QuotaTrackerRegistry {
    entries: DashMap<i64, Arc<UserQuotaTracker>>,
    /// `user_id -> (window_start, used)` remembered from evicted trackers, so a
    /// reseed in the same window starts from at least what was counted live.
    floors: DashMap<i64, (i64, i64)>,
    /// Shared mode: the Redis counters. `None` = per-process (memory backend).
    shared: Option<SharedQuotaStore>,
    /// Shared mode: trackers dropped from `entries` (window rollover or
    /// invalidation) that live relays may still be adding to. They keep being
    /// synced until nothing holds them and nothing is pending.
    retired: std::sync::Mutex<Vec<Arc<UserQuotaTracker>>>,
}

impl QuotaTrackerRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            floors: DashMap::new(),
            shared: None,
            retired: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A registry whose counts are shared with other replicas through Redis.
    pub fn with_redis(store: SharedQuotaStore) -> Self {
        Self {
            shared: Some(store),
            ..Self::new()
        }
    }

    /// True when counts are shared through Redis.
    pub fn is_shared(&self) -> bool {
        self.shared.is_some()
    }

    /// Number of live tracker entries (for tests / metrics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn retire(&self, old: Arc<UserQuotaTracker>) {
        // Memory mode needs no retirement: closed connections reach SQLite
        // through the usage writer, which is what the next seed reads.
        if self.shared.is_some() && (old.pending() != 0 || Arc::strong_count(&old) > 1) {
            if let Ok(mut r) = self.retired.lock() {
                r.push(old);
            }
        }
    }

    /// Insert a freshly seeded tracker unless another task won the race, in
    /// which case the existing current-window tracker is returned instead. A
    /// stale-window entry is replaced.
    fn install(&self, user_id: i64, fresh: Arc<UserQuotaTracker>) -> Arc<UserQuotaTracker> {
        let window = fresh.window_start();
        let mut replaced = None;
        let tracker = match self.entries.entry(user_id) {
            Entry::Occupied(mut o) => {
                if o.get().window_start() == window {
                    o.get().clone()
                } else {
                    replaced = Some(o.insert(fresh.clone()));
                    fresh
                }
            }
            Entry::Vacant(v) => {
                v.insert(fresh.clone());
                fresh
            }
        };
        if let Some(old) = replaced {
            self.retire(old);
        }
        self.floors.remove(&user_id);
        tracker.touch();
        tracker
    }

    /// Drop trackers that no connection currently holds and that have not been
    /// looked up for `idle_secs`. Their counters are kept as per-window floors
    /// (cheap `(i64, i64)` pairs, cleared when the window rolls over) so the
    /// next reseed cannot fall below what was already counted. In shared mode
    /// a tracker with unpushed bytes is kept until a sync succeeds. Returns the
    /// number of trackers evicted.
    pub fn evict_idle(&self, idle_secs: i64) -> usize {
        let now = now_secs();
        let window = crate::db::quota::QuotaPeriod::Monthly.window_start();
        let mut evicted = 0usize;
        self.entries.retain(|uid, t| {
            // strong_count == 1 means only the map holds it: no live relay or
            // in-progress admission check. Checked under the shard write lock,
            // so no lookup can clone it concurrently.
            let keep =
                Arc::strong_count(t) > 1 || now - t.last_access() < idle_secs || t.pending() != 0;
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

    /// Seed a tracker for `user_id` in the current window from the `usage`
    /// table (and, in shared mode, from the Redis counter).
    async fn seed(
        &self,
        pool: &SqlitePool,
        user_id: i64,
        window: i64,
    ) -> Result<Arc<UserQuotaTracker>, sqlx::Error> {
        let stats = crate::db::quota::get_quota_stats(pool, user_id).await?;
        let floor = self
            .floors
            .get(&user_id)
            .filter(|f| f.0 == window)
            .map(|f| f.1)
            .unwrap_or(0);
        let mut used = stats.used_bytes.max(floor);
        if let Some(store) = &self.shared {
            // max(existing shared count, local seed): never lowers it.
            match store.sync(user_id, window, 0, used).await {
                Ok(global) => used = global.max(used),
                Err(e) => warn_sync_failure(&e),
            }
        }
        Ok(Arc::new(UserQuotaTracker::build(
            user_id,
            used,
            stats.quota_bytes,
            window,
            self.shared.is_some(),
        )))
    }

    /// Get the tracker for `user_id`, seeding it from the database if
    /// missing or if the quota window has rolled over since it was last
    /// seeded. Does not talk to Redis for an existing tracker; admission
    /// checks use [`Self::get_for_admission`].
    pub async fn get_or_seed(
        &self,
        pool: &SqlitePool,
        user_id: i64,
    ) -> Result<Arc<UserQuotaTracker>, sqlx::Error> {
        Ok(self.get_or_seed_inner(pool, user_id).await?.0)
    }

    /// Returns the tracker and whether it was freshly seeded (and so already
    /// carries the current global count).
    async fn get_or_seed_inner(
        &self,
        pool: &SqlitePool,
        user_id: i64,
    ) -> Result<(Arc<UserQuotaTracker>, bool), sqlx::Error> {
        let current_window = crate::db::quota::QuotaPeriod::Monthly.window_start();

        if let Some(entry) = self.entries.get(&user_id) {
            if entry.window_start() == current_window {
                entry.touch();
                return Ok((entry.clone(), false));
            }
            // Window rolled over — reseed below; `install` replaces it.
        }

        let fresh = self.seed(pool, user_id, current_window).await?;
        let installed = self.install(user_id, fresh.clone());
        let is_fresh = Arc::ptr_eq(&installed, &fresh);
        Ok((installed, is_fresh))
    }

    /// Like [`Self::get_or_seed`], but in shared mode also pushes this
    /// replica's pending bytes and pulls the global count first, so the
    /// admission decision sees every replica's usage. On a Redis error the
    /// local view is used (see the module docs).
    pub async fn get_for_admission(
        &self,
        pool: &SqlitePool,
        user_id: i64,
    ) -> Result<Arc<UserQuotaTracker>, sqlx::Error> {
        let (tracker, fresh) = self.get_or_seed_inner(pool, user_id).await?;
        if !fresh {
            self.sync_tracker(&tracker).await;
        }
        Ok(tracker)
    }

    /// Shared mode: push one tracker's pending delta and adopt the global
    /// count. Returns false if Redis could not be reached. No-op (true) in
    /// memory mode.
    async fn sync_tracker(&self, t: &UserQuotaTracker) -> bool {
        let Some(store) = &self.shared else {
            return true;
        };
        let delta = t.take_pending();
        let floor = t.synced.load(Ordering::Relaxed);
        match store.sync(t.user_id, t.window_start(), delta, floor).await {
            Ok(global) => {
                t.apply_global(global);
                true
            }
            Err(e) => {
                t.restore_pending(delta);
                warn_sync_failure(&e);
                false
            }
        }
    }

    /// Shared mode: sync every tracker that has unpushed bytes or is held by
    /// a live connection (so long tunnels see other replicas' usage), plus
    /// retired trackers. Run every [`SHARED_SYNC_INTERVAL`]. Stops early on
    /// the first Redis error; the deltas stay pending for the next round.
    pub async fn sync_all(&self) {
        if self.shared.is_none() {
            return;
        }
        let mut batch: Vec<Arc<UserQuotaTracker>> = self
            .entries
            .iter()
            .filter(|e| e.value().pending() != 0 || Arc::strong_count(e.value()) > 1)
            .map(|e| e.value().clone())
            .collect();
        if let Ok(mut retired) = self.retired.lock() {
            // Done once nothing holds it (only the list) and nothing is left.
            retired.retain(|t| Arc::strong_count(t) > 1 || t.pending() != 0);
            batch.extend(retired.iter().cloned());
        }
        for t in batch {
            if !self.sync_tracker(&t).await {
                break;
            }
        }
    }

    /// Drop the cached tracker for a user. The next access will reseed
    /// from the database. Use this when admin actions change the user's
    /// `monthly_bandwidth_quota` or zero out their usage.
    pub fn invalidate(&self, user_id: i64) {
        if let Some((_, old)) = self.entries.remove(&user_id) {
            self.retire(old);
        }
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

    #[test]
    fn next_window_rolls_months_and_years() {
        let jan = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let dec = chrono::NaiveDate::from_ymd_opt(2025, 12, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(next_window_start(dec), jan);
        assert_eq!(next_window_start(jan) - jan, 31 * 86_400);
    }

    /// Memory-mode trackers never accumulate a pending delta.
    #[test]
    fn memory_tracker_has_no_pending() {
        let t = UserQuotaTracker::new(0, Some(100), 0);
        t.add_and_over(40);
        assert_eq!(t.pending(), 0);
        assert_eq!(t.used(), 40);
    }

    /// The sync bookkeeping: a pushed delta is folded into the global count,
    /// bytes relayed meanwhile stay pending and counted, a failed push keeps
    /// its delta, and a stale (smaller) reply cannot lower the view.
    #[test]
    fn shared_tracker_sync_bookkeeping() {
        let t = UserQuotaTracker::build(7, 1000, Some(5000), 0, true);
        t.add_and_over(100);
        assert_eq!((t.used(), t.pending()), (1100, 100));

        let delta = t.take_pending();
        assert_eq!(delta, 100);
        t.add_and_over(5); // relayed while the sync is in flight
        t.apply_global(1600); // other replicas added 500
        assert_eq!((t.used(), t.pending()), (1605, 5));

        // Failed sync: the delta goes back.
        let d = t.take_pending();
        t.restore_pending(d);
        assert_eq!(t.pending(), 5);

        // An older reply arriving late does not move the view backwards.
        t.apply_global(1200);
        assert_eq!(t.used(), 1605);
        assert_eq!(t.synced.load(Ordering::Relaxed), 1600);
    }

    #[test]
    fn evict_idle_keeps_trackers_with_unpushed_bytes() {
        let reg = QuotaTrackerRegistry::new();
        let w = current_window();
        let t = reg.install(1, Arc::new(UserQuotaTracker::build(1, 0, None, w, true)));
        t.add_and_over(10);
        drop(t);
        assert_eq!(reg.evict_idle(0), 0, "pending bytes pin the entry");
        reg.entries.get(&1).unwrap().take_pending();
        assert_eq!(reg.evict_idle(0), 1);
    }

    // === Shared (Redis) mode, needs a live Redis ===
    //
    // Skipped unless CRABBY_TEST_REDIS_URL is set, e.g.
    //   CRABBY_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test quota_tracker

    async fn test_store() -> Option<SharedQuotaStore> {
        let url = std::env::var("CRABBY_TEST_REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        let conn = redis::aio::ConnectionManager::new(client).await.ok()?;
        let prefix = format!("crabby_test:{}:", uuid::Uuid::new_v4());
        Some(SharedQuotaStore::new(conn, &prefix))
    }

    async fn pool_with_user(quota: i64) -> SqlitePool {
        let pool = crate::db::create_pool("sqlite::memory:", 1).await.unwrap();
        crate::db::run_migrations(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at, monthly_bandwidth_quota) VALUES (1,'u','h','user',0,0,?)",
        )
        .bind(quota)
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    /// Two replicas share one quota: bytes counted on either are enforced on
    /// both after a sync.
    #[tokio::test]
    async fn redis_quota_is_global_across_replicas() {
        let Some(store) = test_store().await else {
            return;
        };
        let pool = pool_with_user(1000).await;
        let a = QuotaTrackerRegistry::with_redis(store.clone());
        let b = QuotaTrackerRegistry::with_redis(store);

        let ta = a.get_for_admission(&pool, 1).await.unwrap();
        assert!(!ta.add_and_over(600));
        a.sync_all().await;

        let tb = b.get_for_admission(&pool, 1).await.unwrap();
        assert_eq!(tb.used(), 600, "replica B sees A's usage on admission");
        assert!(tb.add_and_over(500), "B's local view crosses the limit");
        assert!(!ta.is_over(), "A has not synced yet");

        b.sync_all().await;
        a.sync_all().await;
        assert_eq!(ta.used(), 1100);
        assert!(ta.is_over(), "A tears down after the next sync");

        // A third replica starting now is refused at admission.
        let c = QuotaTrackerRegistry::with_redis(test_store_same(&a));
        let tc = c.get_for_admission(&pool, 1).await.unwrap();
        assert!(tc.is_over());
    }

    fn test_store_same(reg: &QuotaTrackerRegistry) -> SharedQuotaStore {
        reg.shared.clone().unwrap()
    }

    /// Seeding is max(existing, seed): a replica reseeding from a lagging
    /// `usage` table cannot lower the shared count, and a lost key is
    /// restored to the caller's floor before the delta is added.
    #[tokio::test]
    async fn redis_seed_never_lowers_and_lost_key_restores_floor() {
        let Some(store) = test_store().await else {
            return;
        };
        let w = current_window();
        assert_eq!(store.sync(9, w, 0, 700).await.unwrap(), 700);
        assert_eq!(store.sync(9, w, 0, 100).await.unwrap(), 700);
        assert_eq!(store.sync(9, w, 0, 900).await.unwrap(), 900);
        assert_eq!(store.sync(9, w, 50, 0).await.unwrap(), 950);

        let mut conn = store.conn.clone();
        let key = store.key(9, w);
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(ttl > 0, "monthly keys must expire");
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(store.sync(9, w, 10, 950).await.unwrap(), 960);
    }

    /// A restarted replica (empty registry, `usage` table still behind)
    /// seeds from the shared counter instead of the database.
    #[tokio::test]
    async fn redis_reseed_after_restart_uses_shared_count() {
        let Some(store) = test_store().await else {
            return;
        };
        let pool = pool_with_user(10_000).await;
        let a = QuotaTrackerRegistry::with_redis(store.clone());
        let t = a.get_or_seed(&pool, 1).await.unwrap();
        t.add_and_over(700); // not in the usage table yet
        a.sync_all().await;
        drop(t);
        drop(a);

        let restarted = QuotaTrackerRegistry::with_redis(store);
        let t = restarted.get_or_seed(&pool, 1).await.unwrap();
        assert_eq!(t.used(), 700);
    }

    /// Bytes a live relay adds to a tracker after it was dropped from the
    /// registry are still pushed by the sync loop.
    #[tokio::test]
    async fn redis_retired_tracker_is_still_synced() {
        let Some(store) = test_store().await else {
            return;
        };
        let pool = pool_with_user(10_000).await;
        let a = QuotaTrackerRegistry::with_redis(store.clone());
        let held = a.get_or_seed(&pool, 1).await.unwrap();
        a.invalidate(1);
        held.add_and_over(300);
        a.sync_all().await;
        assert_eq!(held.pending(), 0);
        let w = current_window();
        assert_eq!(store.sync(1, w, 0, 0).await.unwrap(), 300);
    }
}
