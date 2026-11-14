//! Standalone validators for the connection pipeline.
//! Each function takes a `ConnectionContext` and `AppState`, returns a `Verdict`.
//! Adding a new validator = add one function here + one call in `handle_client`.
//!
//! Admin handling (#56): post-auth validators are evaluated for admin
//! connections too. A denial is turned into an allow only when the rule is in
//! `filtering.admin_bypass_rules`, and every such bypass is audit-logged and
//! counted via `ConnectionContext::apply_admin_bypass`. Pre-auth (phase 1)
//! validators run before the user is known and are never bypassed.

use super::pipeline::{self, ConnectionContext, Verdict};
use crate::app_state::AppState;

// ─── Phase 1: Pre-Connection (IP only) ─────────────────────────────────────

/// Check client IP against the configured allowlist/blocklist.
pub async fn validate_ip_filter(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    if !ctx.config.ip_filter_enabled {
        return Verdict::Allow;
    }
    let ip_filter = state.ip_filter.read().await;
    if !ip_filter.is_allowed(ctx.client_addr.ip()) {
        crate::metrics::IP_FILTER_ACTIONS
            .with_label_values(&["blocked"])
            .inc();
        return Verdict::Deny(format!("IP {} blocked by IP filter", ctx.client_addr.ip()));
    }
    crate::metrics::IP_FILTER_ACTIONS
        .with_label_values(&["allowed"])
        .inc();
    Verdict::Allow
}

/// Block or allow by country using the GeoIP database.
pub async fn validate_geo_block(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    if !ctx.config.geo_blocking_enabled {
        return Verdict::Allow;
    }
    let geo = match &state.geo_filter {
        Some(g) => g,
        None => {
            // Enabled but no database loaded. Startup and config reload both
            // refuse this state, so reaching here is a bug — fail closed
            // rather than silently dropping every country restriction (#55).
            tracing::error!(
                "geo blocking enabled but no GeoIP database is loaded — denying {} (fail-closed)",
                ctx.client_addr.ip()
            );
            crate::metrics::GEO_FILTER_ACTIONS
                .with_label_values(&["unavailable"])
                .inc();
            return Verdict::Deny("Geo-filter unavailable (fail-closed)".to_string());
        }
    };
    let (allowed, country) = geo.is_ip_allowed(
        ctx.client_addr.ip(),
        &ctx.config.blocked_countries,
        &ctx.config.allowed_countries,
    );
    crate::metrics::GEO_FILTER_ACTIONS
        .with_label_values(&[if allowed { "allowed" } else { "blocked" }])
        .inc();
    if !allowed {
        return Verdict::Deny(format!(
            "IP {} blocked by geo-filter (country: {})",
            ctx.client_addr.ip(),
            country.as_deref().unwrap_or("unknown")
        ));
    }
    Verdict::Allow
}

/// Per-IP rate limiting via the global rate limiter.
pub async fn validate_ip_rate_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    if !ctx.config.rate_limiting_enabled {
        return Verdict::Allow;
    }
    if !state.ip_rate_limiter.check_ip(ctx.client_addr.ip()).await {
        crate::metrics::RATE_LIMIT_EXCEEDED
            .with_label_values(&["ip"])
            .inc();
        return Verdict::Deny(format!(
            "Rate limit exceeded for IP {}",
            ctx.client_addr.ip()
        ));
    }
    Verdict::Allow
}

// ─── Phase 2: Post-Auth (user_id + protocol available) ─────────────────────

/// Enforce protocol restrictions: the global SOCKS4 switch and the per-user
/// `allowed_protocols` list. Each is a separate admin-bypassable rule.
pub async fn validate_protocol_restriction(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let socks4 = ctx.apply_admin_bypass(pipeline::RULE_SOCKS4_DISABLED, check_socks4_enabled(ctx));
    if socks4.is_denied() {
        crate::metrics::AUTH_FAILURES
            .with_label_values(&["socks4_disabled"])
            .inc();
        return socks4;
    }
    ctx.apply_admin_bypass(
        pipeline::RULE_ALLOWED_PROTOCOLS,
        check_allowed_protocols(ctx, state).await,
    )
}

fn check_socks4_enabled(ctx: &ConnectionContext) -> Verdict {
    if ctx.protocol == Some(crate::proxy::protocol::ProxyProtocol::SOCKS4)
        && !ctx.config.socks4_enabled
    {
        return Verdict::Deny(format!(
            "SOCKS4 protocol disabled (client {})",
            ctx.client_addr
        ));
    }
    Verdict::Allow
}

async fn check_allowed_protocols(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let (protocol, uid) = match (&ctx.protocol, ctx.effective_uid()) {
        (Some(p), Some(uid)) => (p, uid),
        _ => return Verdict::Allow,
    };
    if let Some(cached) = state.cached_user_by_id(uid).await {
        if let Some(ref protos) = cached.allowed_protocols {
            let proto_str = protocol.as_str_lower();
            if !protos.iter().any(|p| p.eq_ignore_ascii_case(proto_str)) {
                return Verdict::Deny(format!(
                    "User {} not allowed protocol {} (allowed: {:?})",
                    uid, protocol, protos
                ));
            }
        }
    }
    Verdict::Allow
}

/// Require active IP approval for non-admin users when connection_approval is enabled.
pub async fn validate_approval(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(pipeline::RULE_APPROVAL, check_approval(ctx, state).await)
}

async fn check_approval(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    if !ctx.config.connection_approval {
        return Verdict::Allow;
    }
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    match state.cached_ip_approved(uid, ctx.client_addr.ip()).await {
        Ok(true) => Verdict::Allow,
        Ok(false) => Verdict::Deny(format!(
            "IP {} not approved for user {}",
            ctx.client_addr.ip(),
            uid
        )),
        Err(e) => {
            tracing::error!("Approval check failed for user {}: {}", uid, e);
            Verdict::Deny("Approval check failed (fail-closed)".to_string())
        }
    }
}

/// Per-user RPS rate limiting. Also caches user config for later use.
pub async fn validate_user_rate_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(
        pipeline::RULE_USER_RATE_LIMIT,
        check_user_rate_limit(ctx, state).await,
    )
}

async fn check_user_rate_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    let rate_config = match state.user_rate_limiter.get_cached_config(uid).await {
        Some(config) => config,
        None => match state.cached_user_by_id(uid).await {
            Some(cached) => {
                state
                    .user_rate_limiter
                    .cache_config(
                        uid,
                        cached.rate_limit_rps as u32,
                        cached.rate_limit_burst as u32,
                        cached.rate_limit_enabled,
                        cached.max_connections,
                    )
                    .await;
                crate::rate_limit::UserRateLimitConfig {
                    rps: cached.rate_limit_rps as u32,
                    burst: cached.rate_limit_burst as u32,
                    enabled: cached.rate_limit_enabled,
                    max_connections: cached.max_connections,
                    cached_at: std::time::Instant::now(),
                }
            }
            None => crate::rate_limit::UserRateLimitConfig {
                rps: 10,
                burst: 20,
                enabled: false,
                max_connections: 100,
                cached_at: std::time::Instant::now(),
            },
        },
    };
    if !state
        .user_rate_limiter
        .check_user_cached(uid, rate_config)
        .await
    {
        crate::metrics::RATE_LIMIT_EXCEEDED
            .with_label_values(&["user"])
            .inc();
        return Verdict::Deny(format!("Per-user rate limit exceeded for user {}", uid));
    }
    Verdict::Allow
}

// ─── Phase 3: Post-Target (target host available) ───────────────────────────

/// Check target domain against global + per-user allow/blocklists (union logic).
pub async fn validate_target_domain(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(
        pipeline::RULE_TARGET_FILTER,
        check_target_domain(ctx, state).await,
    )
}

async fn check_target_domain(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let host = match &ctx.target_host {
        Some(h) => h,
        None => return Verdict::Allow,
    };
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => {
            // No DB user (auth disabled, or the config-file credential): the
            // global allow/block lists still apply.
            if !crate::target_filter::is_target_allowed(
                host,
                &ctx.config.global_allowed_targets,
                &ctx.config.global_blocked_targets,
                None,
                None,
            ) {
                return Verdict::Deny(format!("Target {} blocked by global domain filter", host));
            }
            return Verdict::Allow;
        }
    };
    // Use cached user lookup (Redis -> in-memory -> DB) instead of direct DB query.
    // An authenticated user whose record cannot be loaded must not skip
    // their per-user target lists: fail closed (#57).
    let cu = match state.cached_user_by_id(uid).await {
        Some(cu) => cu,
        None => {
            tracing::error!(
                "Target filter: could not load user {} - denying {} (fail-closed)",
                uid,
                host
            );
            return Verdict::Deny(format!(
                "Target filter unavailable for user {} (fail-closed)",
                uid
            ));
        }
    };
    if !crate::target_filter::is_target_allowed(
        host,
        &ctx.config.global_allowed_targets,
        &ctx.config.global_blocked_targets,
        cu.allowed_targets.as_deref(),
        cu.blocked_targets.as_deref(),
    ) {
        return Verdict::Deny(format!(
            "Target {} blocked for user {} by domain filter",
            host, uid
        ));
    }
    Verdict::Allow
}

/// Enforce time-based access restrictions (per-user schedule or global default).
pub async fn validate_access_schedule(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(
        pipeline::RULE_ACCESS_SCHEDULE,
        check_access_schedule(ctx, state).await,
    )
}

async fn check_access_schedule(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    // Per-user parsed schedule cache. Avoids serde_json::from_str on the
    // hot path when the same user reconnects repeatedly.
    if let Some(parsed) = state.parsed_schedule_for_user(uid).await {
        if !crate::target_filter::is_within_parsed_schedule(&parsed) {
            return Verdict::Deny(format!(
                "Access denied for user {} — outside access schedule",
                uid
            ));
        }
        return Verdict::Allow;
    }
    // No per-user schedule — fall back to global default (parsed each call,
    // but the default is rarely set in practice).
    if let Some(ref sched) = ctx.config.default_access_schedule {
        if !crate::target_filter::is_within_schedule(sched) {
            return Verdict::Deny(format!(
                "Access denied for user {} — outside access schedule",
                uid
            ));
        }
    }
    Verdict::Allow
}

// ─── Phase 4: Post-Setup (connection tracked, metrics active) ───────────────

/// Check bandwidth quota against the live tracker.
///
/// The tracker is the single source of truth for quota state — it is
/// seeded once from the database (`get_quota_stats`) and then mutated
/// atomically by the relay loop, so admission decisions and in-flight
/// enforcement always agree. There is no per-connection SUM() and no
/// 30s staleness window. With the Redis backend the admission check first
/// syncs with the shared counter, so usage on other replicas counts too
/// (see `quota_tracker` for the bounds and the Redis-down behaviour).
pub async fn validate_quota(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(pipeline::RULE_QUOTA, check_quota(ctx, state).await)
}

async fn check_quota(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    match state
        .quota_trackers
        .get_for_admission(&state.db_pool, uid)
        .await
    {
        Ok(tracker) => {
            if tracker.is_over() {
                return Verdict::Deny(format!(
                    "Quota exceeded for user {} ({} / {} bytes)",
                    uid,
                    tracker.used(),
                    tracker.limit()
                ));
            }
            Verdict::Allow
        }
        Err(e) => {
            tracing::error!("Error seeding quota tracker for user {}: {}", uid, e);
            Verdict::Deny(format!("Quota check failed for user {} (fail-closed)", uid))
        }
    }
}

/// Per-user limit decision.
///
/// Callers insert the connection record *before* counting (reserve, then
/// check). With a linearizable backend that cannot overshoot: of N racing
/// connections, the k-th insert is visible to its own count, so it sees at
/// least k and only the first `max` can pass. The race can at worst
/// over-reject a burst, never over-admit (#46).
///
/// If the record could not be stored (`self_tracked == false`) the count does
/// not include this connection, so compare with `>=`; the old unconditional
/// `>` let one extra connection through whenever `set_connection` failed.
pub(crate) fn exceeds_connection_limit(
    active_count: usize,
    max_connections: usize,
    self_tracked: bool,
) -> bool {
    if self_tracked {
        active_count > max_connections
    } else {
        active_count >= max_connections
    }
}

/// Enforce per-user concurrent connection limit.
pub async fn validate_connection_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    ctx.apply_admin_bypass(
        pipeline::RULE_CONNECTION_LIMIT,
        check_connection_limit(ctx, state).await,
    )
}

async fn check_connection_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    let active_count = match state.state.count_user_connections(uid).await {
        Ok(count) => count,
        Err(e) => {
            // Fail CLOSED: allowing on a backend error lets a state-backend
            // outage silently lift per-user connection caps, enabling resource
            // exhaustion / quota evasion. Consistent with validate_quota.
            tracing::error!("Error counting user connections for {}: {}", uid, e);
            return Verdict::Deny("Connection count check failed (fail-closed)".to_string());
        }
    };
    let max_connections = match state
        .user_rate_limiter
        .get_cached_max_connections(uid)
        .await
    {
        Some(mc) => mc as usize,
        None => match state.cached_user_by_id(uid).await {
            Some(cu) => {
                state
                    .user_rate_limiter
                    .cache_config(
                        uid,
                        cu.rate_limit_rps as u32,
                        cu.rate_limit_burst as u32,
                        cu.rate_limit_enabled,
                        cu.max_connections,
                    )
                    .await;
                cu.max_connections as usize
            }
            None => 100,
        },
    };
    if exceeds_connection_limit(active_count, max_connections, ctx.conn_tracked) {
        return Verdict::Deny(format!(
            "User {} has {} active connections (max {})",
            uid, active_count, max_connections
        ));
    }
    Verdict::Allow
}

#[cfg(test)]
mod tests {
    use super::exceeds_connection_limit;
    use crate::state::backend::{ConnectionInfo, StateBackend};
    use crate::state::memory::MemoryBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn limit_counts_self_only_when_tracked() {
        // Tracked: the count includes this connection.
        assert!(!exceeds_connection_limit(3, 3, true));
        assert!(exceeds_connection_limit(4, 3, true));
        // Untracked: the count excludes it, so 3 others already fill max=3.
        assert!(!exceeds_connection_limit(2, 3, false));
        assert!(exceeds_connection_limit(3, 3, false));
    }

    /// #46: the reserve-then-count protocol never admits more than `max`
    /// concurrent connections, however the inserts and counts interleave.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reserve_then_count_never_overshoots() {
        const MAX: usize = 5;
        let backend = Arc::new(MemoryBackend::new());
        let admitted_now = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..200u16 {
            let backend = backend.clone();
            let admitted_now = admitted_now.clone();
            let peak = peak.clone();
            tasks.push(tokio::spawn(async move {
                let id = uuid::Uuid::new_v4();
                let info = ConnectionInfo {
                    id,
                    client_addr: ([127, 0, 0, 1], 1000 + i).into(),
                    target_addr: "example.com:443".into(),
                    protocol: crate::proxy::protocol::ProxyProtocol::HTTP,
                    state: crate::connection::ConnectionState::Active,
                    user_id: Some(7),
                    bytes_sent: 0,
                    bytes_received: 0,
                    created_at: 0,
                };
                backend.set_connection(id, info).await.unwrap();
                let count = backend.count_user_connections(7).await.unwrap();
                if !exceeds_connection_limit(count, MAX, true) {
                    let now = admitted_now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    admitted_now.fetch_sub(1, Ordering::SeqCst);
                }
                backend.delete_connection(id).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= MAX);
    }
}
