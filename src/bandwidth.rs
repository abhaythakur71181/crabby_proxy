//! Per-user bandwidth throttling using a token bucket algorithm.
//!
//! Each user can be assigned a maximum bytes-per-second rate. The throttler
//! sleeps between writes to enforce the limit, spreading data evenly across
//! the time window instead of bursting and pausing.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A token bucket bandwidth throttler.
///
/// Tokens represent bytes. Tokens are added at `rate_bytes_per_sec` and
/// the bucket holds at most `burst_bytes` tokens (defaults to 2x the rate
/// for a 2-second burst allowance).
#[derive(Clone)]
pub struct BandwidthThrottler {
    inner: Arc<Mutex<ThrottlerState>>,
}

struct ThrottlerState {
    /// Bytes allowed per second.
    rate: f64,
    /// Maximum burst size in bytes.
    burst: f64,
    /// Current available tokens (bytes).
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl BandwidthThrottler {
    /// Create a new throttler with the given bytes-per-second rate.
    /// Burst is set to 2x the rate (2-second burst window).
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec as f64;
        let burst = rate * 2.0;
        Self {
            inner: Arc::new(Mutex::new(ThrottlerState {
                rate,
                burst,
                tokens: burst, // Start full
                last_refill: Instant::now(),
            })),
        }
    }

    /// Create a throttler with custom burst size.
    pub fn with_burst(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        let rate = rate_bytes_per_sec as f64;
        let burst = burst_bytes as f64;
        Self {
            inner: Arc::new(Mutex::new(ThrottlerState {
                rate,
                burst,
                tokens: burst,
                last_refill: Instant::now(),
            })),
        }
    }

    /// Consume `bytes` worth of tokens. If not enough tokens are available,
    /// sleeps until enough have accumulated. Returns immediately if the
    /// throttler has capacity.
    pub async fn consume(&self, bytes: usize) {
        let bytes = bytes as f64;

        loop {
            let sleep_duration = {
                let mut state = self.inner.lock().await;

                // Refill tokens based on elapsed time
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.tokens = (state.tokens + elapsed * state.rate).min(state.burst);
                state.last_refill = now;

                if state.tokens >= bytes {
                    state.tokens -= bytes;
                    return; // Enough tokens, proceed immediately
                }

                // Not enough tokens — calculate sleep time
                let deficit = bytes - state.tokens;
                Duration::from_secs_f64(deficit / state.rate)
            };

            tokio::time::sleep(sleep_duration).await;
        }
    }

    /// Get the current rate in bytes per second.
    pub async fn rate_bytes_per_sec(&self) -> u64 {
        let state = self.inner.lock().await;
        state.rate as u64
    }
}

/// Registry for per-user bandwidth throttlers.
/// Lazily creates throttlers when a user first transfers data.
pub struct ThrottlerRegistry {
    throttlers: dashmap::DashMap<i64, BandwidthThrottler>,
}

impl Default for ThrottlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ThrottlerRegistry {
    pub fn new() -> Self {
        Self {
            throttlers: dashmap::DashMap::new(),
        }
    }

    /// Get or create a throttler for the given user ID.
    /// Returns None if `rate_bytes_per_sec` is 0 (unlimited).
    pub fn get_or_create(
        &self,
        user_id: i64,
        rate_bytes_per_sec: u64,
    ) -> Option<BandwidthThrottler> {
        if rate_bytes_per_sec == 0 {
            return None;
        }
        self.throttlers
            .entry(user_id)
            .or_insert_with(|| BandwidthThrottler::new(rate_bytes_per_sec))
            .clone()
            .into()
    }

    /// Remove a user's throttler (e.g., on user deletion).
    pub fn remove(&self, user_id: i64) {
        self.throttlers.remove(&user_id);
    }

    /// Number of active throttlers.
    pub fn len(&self) -> usize {
        self.throttlers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_throttler_allows_within_rate() {
        // 1 MB/s rate
        let throttler = BandwidthThrottler::new(1_000_000);
        let start = Instant::now();

        // Consume 500KB — should be instant (within burst)
        throttler.consume(500_000).await;
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_throttler_delays_over_burst() {
        // 10KB/s rate, 10KB burst
        let throttler = BandwidthThrottler::with_burst(10_000, 10_000);

        // Consume entire burst
        throttler.consume(10_000).await;

        // Next consume should be delayed (~1 second for 10KB at 10KB/s)
        let start = Instant::now();
        throttler.consume(10_000).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(800),
            "Expected ~1s delay, got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_registry_returns_none_for_zero_rate() {
        let registry = ThrottlerRegistry::new();
        assert!(registry.get_or_create(1, 0).is_none());
    }

    #[tokio::test]
    async fn test_registry_creates_throttler() {
        let registry = ThrottlerRegistry::new();
        let t = registry.get_or_create(1, 1_000_000);
        assert!(t.is_some());
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test]
    async fn test_registry_reuses_throttler() {
        let registry = ThrottlerRegistry::new();
        let _t1 = registry.get_or_create(1, 1_000_000);
        let _t2 = registry.get_or_create(1, 1_000_000);
        assert_eq!(registry.len(), 1);
    }
}
