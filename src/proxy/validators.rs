//! Standalone validators for the connection pipeline.
//! Each function takes a `ConnectionContext` and `AppState`, returns a `Verdict`.
//! Adding a new validator = add one function here + one call in `handle_client`.

use super::pipeline::{ConnectionContext, Verdict};
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
        None => return Verdict::Allow,
    };
    let (allowed, country) = geo.is_ip_allowed(
        ctx.client_addr.ip(),
        &ctx.config.blocked_countries,
        &ctx.config.allowed_countries,
    );
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

/// Enforce SOCKS4 protocol restrictions (disabled protocol with admin bypass).
pub async fn validate_protocol_restriction(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let protocol = match &ctx.protocol {
        Some(p) => p,
        None => return Verdict::Allow,
    };
    // SOCKS4 disabled check
    if *protocol == crate::proxy::protocol::ProxyProtocol::SOCKS4 && !ctx.config.socks4_enabled {
        if ctx.is_admin {
            tracing::debug!("SOCKS4 allowed for admin user {:?}", ctx.user_id);
            return Verdict::Allow;
        }
        crate::metrics::AUTH_FAILURES
            .with_label_values(&["socks4_disabled"])
            .inc();
        return Verdict::Deny(format!(
            "SOCKS4 protocol disabled for non-admin user from {}",
            ctx.client_addr
        ));
    }
    // Per-user allowed_protocols check
    if let Some(uid) = ctx.effective_uid() {
        if !ctx.is_admin {
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
        }
    }
    Verdict::Allow
}

/// Require active IP approval for non-admin users when connection_approval is enabled.
pub async fn validate_approval(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    if !ctx.config.connection_approval {
        return Verdict::Allow;
    }
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    if ctx.is_admin {
        return Verdict::Allow;
    }
    match crate::db::approvals::is_ip_approved(
        &state.db_pool,
        uid,
        &ctx.client_addr.ip().to_string(),
    )
    .await
    {
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
                max_connections: 5,
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
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    if ctx.is_admin {
        return Verdict::Allow;
    }
    let host = match &ctx.target_host {
        Some(h) => h,
        None => return Verdict::Allow,
    };
    let user = match crate::db::users::get_user_by_id(&state.db_pool, uid).await {
        Ok(Some(u)) => u,
        _ => return Verdict::Allow, // Fail-open if user fetch fails
    };
    if !crate::target_filter::is_target_allowed(
        host,
        &ctx.config.global_allowed_targets,
        &ctx.config.global_blocked_targets,
        user.allowed_targets.as_deref(),
        user.blocked_targets.as_deref(),
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
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    if ctx.is_admin {
        return Verdict::Allow;
    }
    let schedule = match crate::db::users::get_user_by_id(&state.db_pool, uid).await {
        Ok(Some(user)) => user
            .access_schedule
            .or(ctx.config.default_access_schedule.clone()),
        _ => ctx.config.default_access_schedule.clone(),
    };
    if let Some(sched) = schedule {
        if !crate::target_filter::is_within_schedule(&sched) {
            return Verdict::Deny(format!(
                "Access denied for user {} — outside access schedule",
                uid
            ));
        }
    }
    Verdict::Allow
}

// ─── Phase 4: Post-Setup (connection tracked, metrics active) ───────────────

/// Check bandwidth quota (Redis → DashMap → DB, with caching).
pub async fn validate_quota(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    // Check Redis cache first
    let quota_allowed = if let Some(ref cache) = state.cache {
        cache.get_quota_allowed(uid).await
    } else {
        None
    };
    // Fallback to DashMap
    let quota_allowed = quota_allowed.or_else(|| {
        state.quota_cache.get(&uid).and_then(|entry| {
            let (allowed, cached_at) = entry.value();
            if cached_at.elapsed() < std::time::Duration::from_secs(30) {
                Some(*allowed)
            } else {
                None
            }
        })
    });
    let has_quota = match quota_allowed {
        Some(allowed) => allowed,
        None => match crate::db::quota::check_quota(&state.db_pool, uid).await {
            Ok(allowed) => {
                if let Some(ref cache) = state.cache {
                    cache.set_quota_allowed(uid, allowed).await;
                }
                state
                    .quota_cache
                    .insert(uid, (allowed, std::time::Instant::now()));
                allowed
            }
            Err(e) => {
                tracing::error!("Error checking quota for user {}: {}", uid, e);
                return Verdict::Deny(format!("Quota check failed for user {} (fail-closed)", uid));
            }
        },
    };
    if !has_quota {
        return Verdict::Deny(format!("Quota exceeded for user {}", uid));
    }
    Verdict::Allow
}

/// Enforce per-user concurrent connection limit.
pub async fn validate_connection_limit(ctx: &ConnectionContext, state: &AppState) -> Verdict {
    let uid = match ctx.effective_uid() {
        Some(uid) => uid,
        None => return Verdict::Allow,
    };
    let active_count = match state.state.count_user_connections(uid).await {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("Error counting user connections for {}: {}", uid, e);
            return Verdict::Allow; // Non-fatal: allow if counting fails
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
            None => 5,
        },
    };
    if active_count >= max_connections {
        return Verdict::Deny(format!(
            "User {} has {} active connections (max {})",
            uid, active_count, max_connections
        ));
    }
    Verdict::Allow
}
