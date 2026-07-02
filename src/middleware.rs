//! Plugin middleware system for the proxy validation pipeline.
//!
//! Allows registering custom validators that run at defined phases of
//! connection processing. Built-in validators (IP filter, auth, rate limit,
//! etc.) are hardcoded in the pipeline, but this system enables extensions
//! without modifying core code.
//!
//! # Phases
//!
//! 1. **PreAuth** — Runs before authentication. Has access to client IP only.
//! 2. **PostAuth** — Runs after authentication. Has access to user ID.
//! 3. **PostTarget** — Runs after target resolution. Has access to target host.
//!
//! # Example
//!
//! ```ignore
//! use crabby_proxy::middleware::{Middleware, MiddlewareChain, Phase};
//!
//! struct BlockWeekends;
//!
//! #[async_trait::async_trait]
//! impl Middleware for BlockWeekends {
//!     fn name(&self) -> &str { "block-weekends" }
//!     fn phase(&self) -> Phase { Phase::PreAuth }
//!     async fn check(&self, ctx: &ConnectionContext, state: &AppState) -> Verdict {
//!         let day = chrono::Utc::now().weekday();
//!         if day == chrono::Weekday::Sat || day == chrono::Weekday::Sun {
//!             Verdict::Deny("No weekend access".into())
//!         } else {
//!             Verdict::Allow
//!         }
//!     }
//! }
//! ```

use crate::app_state::AppState;
use crate::proxy::pipeline::{ConnectionContext, Verdict};
use std::sync::Arc;

/// The phase at which a middleware runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Before authentication — only client_addr is available.
    PreAuth,
    /// After authentication — user_id is set.
    PostAuth,
    /// After target parsing — target_host is set.
    PostTarget,
}

/// A middleware that can inspect and optionally deny a connection.
#[async_trait::async_trait]
pub trait Middleware: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Which phase this middleware runs in.
    fn phase(&self) -> Phase;

    /// Check the connection. Return `Verdict::Allow` to proceed,
    /// or `Verdict::Deny(reason)` to reject the connection.
    async fn check(&self, ctx: &ConnectionContext, state: &AppState) -> Verdict;
}

/// An ordered chain of middleware that runs at a given phase.
pub struct MiddlewareChain {
    pre_auth: Vec<Arc<dyn Middleware>>,
    post_auth: Vec<Arc<dyn Middleware>>,
    post_target: Vec<Arc<dyn Middleware>>,
}

impl MiddlewareChain {
    /// Create an empty middleware chain.
    pub fn new() -> Self {
        Self {
            pre_auth: Vec::new(),
            post_auth: Vec::new(),
            post_target: Vec::new(),
        }
    }

    /// Register a middleware. It will be appended to its phase's list.
    pub fn add(&mut self, middleware: Arc<dyn Middleware>) {
        match middleware.phase() {
            Phase::PreAuth => self.pre_auth.push(middleware),
            Phase::PostAuth => self.post_auth.push(middleware),
            Phase::PostTarget => self.post_target.push(middleware),
        }
    }

    /// Run all middleware for a given phase. Returns `Verdict::Deny` on
    /// the first denial, or `Verdict::Allow` if all pass.
    pub async fn run(&self, phase: Phase, ctx: &ConnectionContext, state: &AppState) -> Verdict {
        let chain = match phase {
            Phase::PreAuth => &self.pre_auth,
            Phase::PostAuth => &self.post_auth,
            Phase::PostTarget => &self.post_target,
        };

        for mw in chain {
            let verdict = mw.check(ctx, state).await;
            if let Verdict::Deny(ref reason) = verdict {
                tracing::info!(
                    "[middleware:{}] denied {} (phase: {:?}): {}",
                    mw.name(),
                    ctx.client_addr,
                    phase,
                    reason
                );
                return verdict;
            }
        }

        Verdict::Allow
    }

    /// Number of registered middleware across all phases.
    pub fn len(&self) -> usize {
        self.pre_auth.len() + self.post_auth.len() + self.post_target.len()
    }

    /// Whether the chain has any middleware registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAllow;

    #[async_trait::async_trait]
    impl Middleware for AlwaysAllow {
        fn name(&self) -> &str {
            "always-allow"
        }
        fn phase(&self) -> Phase {
            Phase::PreAuth
        }
        async fn check(&self, _ctx: &ConnectionContext, _state: &AppState) -> Verdict {
            Verdict::Allow
        }
    }

    struct AlwaysDeny;

    #[async_trait::async_trait]
    impl Middleware for AlwaysDeny {
        fn name(&self) -> &str {
            "always-deny"
        }
        fn phase(&self) -> Phase {
            Phase::PreAuth
        }
        async fn check(&self, _ctx: &ConnectionContext, _state: &AppState) -> Verdict {
            Verdict::Deny("blocked by test".into())
        }
    }

    #[test]
    fn test_empty_chain() {
        let chain = MiddlewareChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_add_middleware() {
        let mut chain = MiddlewareChain::new();
        chain.add(Arc::new(AlwaysAllow));
        chain.add(Arc::new(AlwaysDeny));
        assert_eq!(chain.len(), 2);
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_phase_routing() {
        let mut chain = MiddlewareChain::new();

        struct PostAuthMw;
        #[async_trait::async_trait]
        impl Middleware for PostAuthMw {
            fn name(&self) -> &str {
                "post-auth"
            }
            fn phase(&self) -> Phase {
                Phase::PostAuth
            }
            async fn check(&self, _: &ConnectionContext, _: &AppState) -> Verdict {
                Verdict::Allow
            }
        }

        struct PostTargetMw;
        #[async_trait::async_trait]
        impl Middleware for PostTargetMw {
            fn name(&self) -> &str {
                "post-target"
            }
            fn phase(&self) -> Phase {
                Phase::PostTarget
            }
            async fn check(&self, _: &ConnectionContext, _: &AppState) -> Verdict {
                Verdict::Allow
            }
        }

        chain.add(Arc::new(AlwaysAllow)); // PreAuth
        chain.add(Arc::new(PostAuthMw)); // PostAuth
        chain.add(Arc::new(PostTargetMw)); // PostTarget

        assert_eq!(chain.pre_auth.len(), 1);
        assert_eq!(chain.post_auth.len(), 1);
        assert_eq!(chain.post_target.len(), 1);
    }
}
