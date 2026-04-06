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

use dashmap::DashMap;
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// Sentinel value meaning "no quota configured" (effectively unlimited).
pub const NO_LIMIT: i64 = i64::MAX;

/// Per-user live bandwidth counter for the current quota window.
pub struct UserQuotaTracker {
    used: AtomicI64,
    limit: AtomicI64,
    window_start: AtomicI64,
}

impl UserQuotaTracker {
    pub fn new(used: i64, limit: Option<i64>, window_start: i64) -> Self {
        Self {
            used: AtomicI64::new(used),
            limit: AtomicI64::new(limit.unwrap_or(NO_LIMIT)),
            window_start: AtomicI64::new(window_start),
        }
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

    fn set_limit(&self, limit: Option<i64>) {
        self.limit
            .store(limit.unwrap_or(NO_LIMIT), Ordering::Relaxed);
    }
}

/// Process-wide registry of per-user quota trackers.
pub struct QuotaTrackerRegistry {
    entries: DashMap<i64, Arc<UserQuotaTracker>>,
}

impl QuotaTrackerRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
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
                return Ok(entry.clone());
            }
            // Window rolled over — drop the stale entry and reseed below.
            drop(entry);
            self.entries.remove(&user_id);
        }

        let stats = crate::db::quota::get_quota_stats(pool, user_id).await?;
        let tracker = Arc::new(UserQuotaTracker::new(
            stats.used_bytes,
            stats.quota_bytes,
            current_window,
        ));
        self.entries.insert(user_id, tracker.clone());
        Ok(tracker)
    }

    /// Drop the cached tracker for a user. The next access will reseed
    /// from the database. Use this when admin actions change the user's
    /// `monthly_bandwidth_quota` or zero out their usage.
    pub fn invalidate(&self, user_id: i64) {
        self.entries.remove(&user_id);
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
