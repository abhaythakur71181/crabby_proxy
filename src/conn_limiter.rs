//! Global connection cap that can be resized at runtime (#51).
//!
//! `server.max_connections` used to be snapshotted into a plain `Semaphore`
//! at startup, so a config reload or an admin update changed the config value
//! but never the enforced limit.

use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

pub struct ConnLimiter {
    sem: Arc<Semaphore>,
    /// The capacity the semaphore is converging to. Guarded so concurrent
    /// resizes are applied one at a time.
    capacity: Mutex<usize>,
}

impl ConnLimiter {
    pub fn new(capacity: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(capacity)),
            capacity: Mutex::new(capacity),
        }
    }

    /// The underlying semaphore; acquire one permit per connection/stream.
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.sem.clone()
    }

    /// The configured capacity (the limit the semaphore enforces once any
    /// pending shrink has drained).
    pub fn capacity(&self) -> usize {
        *self.capacity.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Change the capacity. Growing adds permits immediately. Shrinking
    /// forgets idle permits right away; any shortfall (permits held by live
    /// connections) is reclaimed by a background task as those connections
    /// close. Live connections are never cut. The semaphore is fair, so the
    /// reclaim task is served before new connections are admitted.
    pub fn resize(&self, new_capacity: usize) {
        let mut cap = self.capacity.lock().unwrap_or_else(|e| e.into_inner());
        let old = *cap;
        if new_capacity == old {
            return;
        }
        *cap = new_capacity;
        if new_capacity > old {
            self.sem.add_permits(new_capacity - old);
        } else {
            let shrink = old - new_capacity;
            let forgotten = self.sem.forget_permits(shrink);
            let remaining = shrink - forgotten;
            if remaining > 0 {
                let sem = self.sem.clone();
                tokio::spawn(async move {
                    // acquire_many takes a u32; a shrink that large is not
                    // realistic, but loop to stay correct.
                    let mut left = remaining;
                    while left > 0 {
                        let n = left.min(u32::MAX as usize) as u32;
                        match sem.acquire_many(n).await {
                            Ok(p) => p.forget(),
                            Err(_) => return, // semaphore closed
                        }
                        left -= n as usize;
                    }
                });
            }
        }
        tracing::info!(
            "global connection limit changed: {} -> {}",
            old,
            new_capacity
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn grow_adds_permits() {
        let l = ConnLimiter::new(2);
        l.resize(5);
        assert_eq!(l.semaphore().available_permits(), 5);
        assert_eq!(l.capacity(), 5);
    }

    #[tokio::test]
    async fn shrink_idle_is_immediate() {
        let l = ConnLimiter::new(5);
        l.resize(2);
        assert_eq!(l.semaphore().available_permits(), 2);
    }

    #[tokio::test]
    async fn shrink_below_in_use_drains_as_connections_close() {
        let l = ConnLimiter::new(4);
        let sem = l.semaphore();
        let held: Vec<_> = (0..4)
            .map(|_| sem.clone().try_acquire_owned().unwrap())
            .collect();
        l.resize(1);
        assert_eq!(l.capacity(), 1);
        drop(held);
        // Give the reclaim task a chance to run.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sem.available_permits(), 1);
        let _one = sem.clone().try_acquire_owned().unwrap();
        assert!(sem.clone().try_acquire_owned().is_err());
    }

    #[tokio::test]
    async fn shrink_then_grow_converges() {
        let l = ConnLimiter::new(3);
        let sem = l.semaphore();
        let held: Vec<_> = (0..3)
            .map(|_| sem.clone().try_acquire_owned().unwrap())
            .collect();
        l.resize(1); // 2 permits owed by the reclaim task
        l.resize(4); // +3
        drop(held);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sem.available_permits(), 4);
    }
}
