use crate::cache::CacheLayer;
use crate::config::Config;
use crate::state::{MemoryBackend, RedisBackend, StateBackend};
use crate::tunnel::manager::TunnelManager;
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

/// Events that can be published through the notification system
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    NewConnection(Uuid),
    ConnectionApproved(Uuid),
    ConnectionRejected(Uuid),
    ConnectionClosed(Uuid),
    TunnelCreated(u16),
    TunnelClosed(u16),
}

/// Shared application state.
/// Wrapped in `Arc<AppState>` at creation — never deep-cloned.
pub struct AppState {
    // Configuration (hot reload via lock-free ArcSwap)
    pub config: Arc<ArcSwap<Config>>,

    // Pluggable state (memory or Redis)
    pub state: Arc<dyn StateBackend>,

    // Database pool for user management
    pub db_pool: sqlx::SqlitePool,

    // Tunnel manager for reverse tunnels
    pub tunnels: Arc<RwLock<TunnelManager>>,

    // Notification channel for events
    pub notify_tx: mpsc::Sender<ConnectionEvent>,

    // Optional TLS acceptor
    /// TLS acceptor, wrapped in ArcSwap for hot-reloadable certificates.
    pub tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,

    // Runtime start time
    pub start_time: Instant,

    // Authentication credentials (cached from config)
    pub username: Option<String>,
    pub password: Option<String>,

    // Config file path
    pub config_path: Option<String>,

    // Rate limiters
    pub ip_rate_limiter: crate::rate_limit::IpRateLimiter,
    pub user_rate_limiter: crate::rate_limit::UserRateLimiter,
    pub login_rate_limiter: crate::rate_limit::LoginRateLimiter,

    // IP filter
    pub ip_filter: Arc<RwLock<crate::ip_filter::IpFilter>>,

    // GeoIP filter (optional — requires MaxMind DB file)
    pub geo_filter: Option<crate::geo_filter::SharedGeoFilter>,

    // DNS resolution cache (reduces upstream connect latency)
    pub dns_cache: Arc<crate::dns_cache::DnsCache>,

    // Upstream connection pool (reuses idle TCP connections)
    pub connection_pool: Option<Arc<crate::connection_pool::ConnectionPool>>,

    // Auth result cache: HMAC(creds) -> (user_id, cached_at).
    // Avoids DB + argon2 on every connection from the same user (60s TTL).
    // The key is an HMAC-SHA256 of (username, password) under a process-random
    // key, so plaintext credentials are never resident as map keys (heap dumps /
    // swap / cores) while remaining collision-safe (full 256-bit digest).
    pub auth_cache: Arc<dashmap::DashMap<[u8; 32], (i64, std::time::Instant)>>,

    // Negative auth cache: HMAC(failed creds) -> cached_at.
    // Short TTL (5s) absorbs credential-stuffing bursts so a flood of bad
    // attempts hits argon2 once instead of once per try. Bounded to avoid
    // memory blow-up — capped insert silently drops on overflow.
    pub auth_negative_cache: Arc<dashmap::DashMap<[u8; 32], std::time::Instant>>,

    /// Per-user bandwidth throttler registry.
    pub bandwidth_throttlers: Arc<crate::bandwidth::ThrottlerRegistry>,

    /// Plugin middleware chain for custom validators.
    pub middleware: Arc<crate::middleware::MiddlewareChain>,

    // Graceful shutdown signal
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,

    // Bounded background writer for the `usage` table.
    pub usage_writer: crate::usage_writer::UsageWriter,

    // Quota check cache: user_id -> (allowed, cached_at)
    // Caches the boolean result of check_quota for 30s to avoid SUM() per connection
    // (fallback when Redis cache is unavailable)
    pub quota_cache: Arc<dashmap::DashMap<i64, (bool, std::time::Instant)>>,

    // Live per-user quota tracker. Atomic byte counters seeded from the
    // database, mutated on the relay hot path so connections that exceed
    // the limit mid-stream are torn down within one buffer iteration.
    pub quota_trackers: Arc<crate::quota_tracker::QuotaTrackerRegistry>,

    // Parsed access-schedule cache: user_id -> parsed schedule (or None if
    // user has no schedule / JSON was unparseable). Avoids JSON-parsing the
    // schedule on every connection. Invalidated alongside other user caches.
    pub parsed_schedule_cache:
        Arc<dashmap::DashMap<i64, Option<Arc<crate::target_filter::AccessSchedule>>>>,

    // Approval check cache: (user_id, client_ip) -> (approved, cached_at)
    // Avoids hitting DB on every proxy connection; 2-minute TTL
    pub approval_cache: Arc<dashmap::DashMap<(i64, std::net::IpAddr), (bool, std::time::Instant)>>,

    // Redis cache layer for users, API keys, quotas, approvals
    pub cache: Option<CacheLayer>,

    /// Process-local Arc cache for `CachedUser` lookups, in front of Redis.
    /// Avoids deserializing JSON and full struct clones on every validator
    /// call (the hot path runs `cached_user_by_id` 4-6× per connection).
    /// 5-second TTL keeps it close enough to Redis without complex
    /// invalidation; explicit invalidations clear the entry.
    pub user_arc_cache: Arc<dashmap::DashMap<i64, (Arc<crate::cache::CachedUser>, Instant)>>,

    // Event bus for cross-instance coordination (optional — requires Redis)
    pub event_bus: Option<crate::event_bus::EventBus>,

    // Self-loop protection: blocks the proxy from connecting back to its own
    // listener. `None` if the bind address couldn't be parsed.
    pub self_loop_guard: Option<crate::self_loop::SelfLoopGuard>,
}

impl AppState {
    pub async fn new(
        config: Config,
        config_path: Option<String>,
        db_pool: sqlx::SqlitePool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let state: Arc<dyn StateBackend> = match config.state.backend.as_str() {
            "redis" => {
                match RedisBackend::new(
                    &config.state.redis_url,
                    config.state.redis_key_prefix.clone(),
                )
                .await
                {
                    Ok(backend) => {
                        tracing::info!("Using Redis state backend");
                        Arc::new(backend)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to connect to Redis ({}), falling back to memory backend",
                            e
                        );
                        Arc::new(MemoryBackend::new())
                    }
                }
            }
            // Anything other than "redis" (incl. "memory" / unset) uses memory.
            _ => {
                tracing::info!("Using in-memory state backend");
                Arc::new(MemoryBackend::new())
            }
        };

        // Create notification channel
        let (notify_tx, notify_rx) = mpsc::channel(1000);

        // Spawn event processor
        tokio::spawn(process_events(notify_rx, state.clone()));
        let tls_acceptor = if config.server.tls_enabled {
            if config.server.tls_cert_path.is_empty() || config.server.tls_key_path.is_empty() {
                tracing::warn!("TLS enabled but certificate paths not configured");
                None
            } else {
                Some(Arc::new(ArcSwap::from_pointee(
                    crate::utils::create_tls_acceptor_with_client_auth(
                        &config.server.tls_cert_path,
                        &config.server.tls_key_path,
                        config.server.tls_client_ca_path.as_deref(),
                    )?,
                )))
            }
        } else {
            None
        };

        // Cache authentication credentials
        let username = if config.authentication.enabled {
            Some(config.authentication.username.clone())
        } else {
            None
        };
        let password = if config.authentication.enabled {
            Some(config.authentication.password.clone())
        } else {
            None
        };

        // Initialize rate limiters
        let ip_rate_limiter = crate::rate_limit::IpRateLimiter::with_max_entries(
            config.rate_limiting.requests_per_second,
            config.rate_limiting.burst_size,
            config.rate_limiting.max_tracked_ips,
        );
        let user_rate_limiter = crate::rate_limit::UserRateLimiter::new();
        let login_rate_limiter = crate::rate_limit::LoginRateLimiter::new();

        // Initialize IP filter
        let ip_filter = {
            use crate::ip_filter::{FilterMode, IpFilter};

            let mode = if config.filtering.ip_filter_mode == "allowlist" {
                FilterMode::AllowList
            } else {
                FilterMode::BlockList
            };

            let filter = IpFilter::new(
                mode,
                config.filtering.ip_blocklist.clone(),
                config.filtering.ip_allowlist.clone(),
            )
            .map_err(|e| format!("Failed to create IP filter: {}", e))?;

            Arc::new(RwLock::new(filter))
        };

        // Initialize GeoIP filter (optional)
        let geo_filter =
            crate::geo_filter::init_geo_filter(config.filtering.geoip_database_path.as_deref());

        // Build self-loop guard from the proxy bind address.
        let self_loop_guard = crate::self_loop::SelfLoopGuard::from_bind(&config.server.proxy_bind);
        if self_loop_guard.is_none() {
            tracing::warn!(
                "Could not parse proxy_bind '{}' — self-loop protection disabled",
                config.server.proxy_bind
            );
        }

        // Create graceful shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        // Initialize Redis cache layer (uses same Redis URL as state backend)
        let cache = match CacheLayer::new(
            &config.state.redis_url,
            config.state.redis_key_prefix.clone(),
        )
        .await
        {
            Ok(layer) => {
                tracing::info!("Redis cache layer initialized");
                Some(layer)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to initialize Redis cache layer ({}), using DB-only mode",
                    e
                );
                None
            }
        };

        Ok(Self {
            config: Arc::new(ArcSwap::from_pointee(config.clone())),
            state,
            db_pool: db_pool.clone(),
            tunnels: Arc::new(RwLock::new(TunnelManager::new(
                config.features.tunnel_port_start,
                config.features.tunnel_port_end,
            ))),
            notify_tx,
            tls_acceptor,
            start_time: Instant::now(),
            username,
            password,
            config_path,
            ip_rate_limiter,
            user_rate_limiter,
            login_rate_limiter,
            ip_filter,
            geo_filter,
            dns_cache: Arc::new(crate::dns_cache::DnsCache::new(
                config.advanced.dns_cache_ttl,
            )),
            connection_pool: if config.advanced.connection_pooling {
                Some(Arc::new(crate::connection_pool::ConnectionPool::new(
                    config.advanced.pool_max_idle_per_host,
                    60, // 60s idle timeout
                )))
            } else {
                None
            },
            shutdown_tx,
            usage_writer: crate::usage_writer::UsageWriter::spawn(db_pool.clone()),
            quota_cache: Arc::new(dashmap::DashMap::new()),
            quota_trackers: Arc::new(crate::quota_tracker::QuotaTrackerRegistry::new()),
            approval_cache: Arc::new(dashmap::DashMap::new()),
            parsed_schedule_cache: Arc::new(dashmap::DashMap::new()),
            auth_cache: Arc::new(dashmap::DashMap::new()),
            auth_negative_cache: Arc::new(dashmap::DashMap::new()),
            bandwidth_throttlers: Arc::new(crate::bandwidth::ThrottlerRegistry::new()),
            middleware: Arc::new(crate::middleware::MiddlewareChain::new()),
            cache,
            user_arc_cache: Arc::new(dashmap::DashMap::new()),
            event_bus: match crate::event_bus::EventBus::new(
                &config.state.redis_url,
                &config.state.redis_key_prefix,
            )
            .await
            {
                Ok(bus) => Some(bus),
                Err(e) => {
                    tracing::warn!("Event bus disabled: {}", e);
                    None
                }
            },
            self_loop_guard,
        })
    }

    /// Get application uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Reload configuration from file
    /// Reload TLS certificates from disk without restarting.
    pub fn reload_tls(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.load();
        if !config.server.tls_enabled {
            return Ok(());
        }
        if let Some(ref acceptor_swap) = self.tls_acceptor {
            let new_acceptor = crate::utils::create_tls_acceptor_with_client_auth(
                &config.server.tls_cert_path,
                &config.server.tls_key_path,
                config.server.tls_client_ca_path.as_deref(),
            )?;
            acceptor_swap.store(Arc::new(new_acceptor));
            tracing::info!("TLS certificates reloaded successfully");
        }
        Ok(())
    }

    pub async fn reload_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = self
            .config_path
            .as_ref()
            .ok_or("Config path not available for reload")?;
        let mut new_config = Config::from_file(path)?;
        let current = self.config.load();

        // Security-critical fields are NOT hot-reloadable: a runtime file edit
        // must never be able to disable admin auth, rotate the JWT signing key
        // (which would silently invalidate every live session), change the
        // shared passwords, or claim to rebind a listener (which can't actually
        // move at runtime). Preserve the running values and warn if the file
        // tried to change them; these take effect only on restart.
        macro_rules! preserve {
            ($field:expr, $cur:expr, $name:literal) => {
                if $field != $cur {
                    tracing::warn!(
                        "config reload: change to '{}' ignored — restart required for security-critical fields",
                        $name
                    );
                    $field = $cur.clone();
                }
            };
        }
        preserve!(
            new_config.authentication.jwt_secret,
            current.authentication.jwt_secret,
            "authentication.jwt_secret"
        );
        preserve!(
            new_config.authentication.password,
            current.authentication.password,
            "authentication.password"
        );
        preserve!(
            new_config.admin.admin_password,
            current.admin.admin_password,
            "admin.admin_password"
        );
        preserve!(
            new_config.server.proxy_bind,
            current.server.proxy_bind,
            "server.proxy_bind"
        );
        preserve!(
            new_config.server.admin_bind,
            current.server.admin_bind,
            "server.admin_bind"
        );
        if new_config.admin.auth_enabled != current.admin.auth_enabled {
            tracing::warn!(
                "config reload: change to 'admin.auth_enabled' ignored — restart required"
            );
            new_config.admin.auth_enabled = current.admin.auth_enabled;
        }

        drop(current);
        self.config.store(Arc::new(new_config));
        tracing::info!("Configuration reloaded from {}", path);
        Ok(())
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down application");
        // Close all tunnels
        self.tunnels.write().await.shutdown().await;
    }

    // ─── Cache-aside convenience methods ──────────────────────────────
    //
    // These wrap the `if let Some(ref cache)` + DB fallback pattern into
    // single-call APIs. If Redis is absent, they go straight to DB.
    // On cache miss they populate Redis automatically.

    /// Fetch a CachedUser by id: process-local Arc cache -> Redis -> DB.
    /// Returns `Arc<CachedUser>` so the hot path doesn't clone the full
    /// struct; the in-process layer also lets us short-circuit Redis +
    /// JSON deserialization for the 5s TTL window.
    pub async fn cached_user_by_id(&self, user_id: i64) -> Option<Arc<crate::cache::CachedUser>> {
        const ARC_TTL: std::time::Duration = std::time::Duration::from_secs(5);

        if let Some(entry) = self.user_arc_cache.get(&user_id) {
            let (arc, cached_at) = entry.value();
            if cached_at.elapsed() < ARC_TTL {
                return Some(arc.clone());
            }
        }

        let pool = self.db_pool.clone();
        let fetched = if let Some(ref cache) = self.cache {
            let key = format!("{}cache:user:id:{}", cache.prefix(), user_id);
            cache
                .get_or_set(&key, crate::cache::USER_TTL, || async {
                    crate::db::users::get_user_by_id(&pool, user_id)
                        .await
                        .ok()
                        .flatten()
                        .filter(|u| u.is_active)
                        .map(crate::cache::CachedUser::from)
                })
                .await
        } else {
            crate::db::users::get_user_by_id(&pool, user_id)
                .await
                .ok()
                .flatten()
                .filter(|u| u.is_active)
                .map(crate::cache::CachedUser::from)
        };

        let arc = Arc::new(fetched?);
        self.user_arc_cache
            .insert(user_id, (arc.clone(), Instant::now()));
        Some(arc)
    }

    /// Drop a user from the process-local Arc cache. Call alongside any
    /// Redis-level invalidation so the next read reseeds.
    pub fn invalidate_user_arc_cache(&self, user_id: i64) {
        self.user_arc_cache.remove(&user_id);
    }

    /// Fetch a CachedUser by username: Redis -> DB -> populate Redis.
    pub async fn cached_user_by_username(
        &self,
        username: &str,
    ) -> Option<Arc<crate::cache::CachedUser>> {
        let pool = self.db_pool.clone();
        let fetched = if let Some(ref cache) = self.cache {
            let key = format!("{}cache:user:name:{}", cache.prefix(), username);
            // Defer username.to_owned() to cache-miss path only
            let uname = username.to_owned();
            cache
                .get_or_set(&key, crate::cache::USER_TTL, || async {
                    crate::db::users::get_user_by_username(&pool, &uname)
                        .await
                        .ok()
                        .flatten()
                        .filter(|u| u.is_active)
                        .map(crate::cache::CachedUser::from)
                })
                .await
        } else {
            crate::db::users::get_user_by_username(&pool, username)
                .await
                .ok()
                .flatten()
                .filter(|u| u.is_active)
                .map(crate::cache::CachedUser::from)
        };
        let cu = fetched?;
        let id = cu.id;
        let arc = Arc::new(cu);
        // Populate the id-keyed Arc cache too — most lookups after auth
        // happen by id, so this saves the next round-trip.
        self.user_arc_cache
            .insert(id, (arc.clone(), Instant::now()));
        Some(arc)
    }

    /// Fetch a CachedUserRole by id: Redis -> DB -> populate Redis.
    /// Lightweight version used by admin auth middleware.
    pub async fn cached_user_role(&self, user_id: i64) -> Option<crate::cache::CachedUserRole> {
        let pool = self.db_pool.clone();
        if let Some(ref cache) = self.cache {
            let key = format!("{}cache:user:role:{}", cache.prefix(), user_id);
            cache
                .get_or_set(&key, crate::cache::USER_ROLE_TTL, || async {
                    crate::db::users::get_user_by_id(&pool, user_id)
                        .await
                        .ok()
                        .flatten()
                        .map(crate::cache::CachedUserRole::from)
                })
                .await
        } else {
            crate::db::users::get_user_by_id(&pool, user_id)
                .await
                .ok()
                .flatten()
                .map(crate::cache::CachedUserRole::from)
        }
    }

    // ─── Cache invalidation helpers ───────────────────────────────────
    //
    // Fire-and-forget: silently no-ops when Redis is absent.

    pub async fn invalidate_user_cache(&self, user_id: i64, username: &str) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_user(user_id, username).await;
        }
    }

    pub async fn invalidate_api_key_cache(&self, user_id: i64) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_api_keys_for_user(user_id).await;
        }
    }

    /// Single entry point for "this user changed in some way — drop every
    /// cached derivative". Replaces the scattered ad-hoc combinations of
    /// invalidate_user_cache + invalidate_quota_cache + rate limiter +
    /// arc cache that admin handlers used to call individually. Pass the
    /// username if known so the Redis username-keyed entry is dropped too.
    pub async fn invalidate_all_for_user(&self, user_id: i64, username: Option<&str>) {
        if let Some(ref cache) = self.cache {
            if let Some(name) = username {
                cache.invalidate_user(user_id, name).await;
            }
            cache.invalidate_api_keys_for_user(user_id).await;
            cache.invalidate_approvals_for_user(user_id).await;
            cache.invalidate_quota(user_id).await;
        }
        self.user_rate_limiter.invalidate_user(user_id).await;
        self.invalidate_user_arc_cache(user_id);
        self.parsed_schedule_cache.remove(&user_id);
        self.quota_cache.remove(&user_id);
        // The auth-result cache is keyed by an HMAC of credentials, so it can't
        // be invalidated per user_id. Clear it wholesale on any user change so a
        // disabled account / rotated password can't keep authenticating via a
        // cached positive entry for the 60s TTL. It repopulates cheaply.
        self.auth_cache.clear();
        self.auth_negative_cache.clear();
        // Refresh the live quota tracker's limit in place (preserve `used`).
        if let Ok(stats) = crate::db::quota::get_quota_stats(&self.db_pool, user_id).await {
            self.quota_trackers.update_limit(user_id, stats.quota_bytes);
        } else {
            self.quota_trackers.invalidate(user_id);
        }
    }

    pub async fn invalidate_quota_cache(&self, user_id: i64) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_quota(user_id).await;
        }
        self.quota_cache.remove(&user_id);
        // Re-read the new limit from the DB and patch the existing tracker
        // in place. This preserves the live `used` counter (which holds
        // bytes from in-flight tunnels that haven't been written to the
        // `usage` table yet) — dropping the tracker would reset that to
        // zero on next access and silently widen the user's effective quota.
        // Drop the process-local Arc cache too so the next validator call
        // sees the new limit immediately.
        self.invalidate_user_arc_cache(user_id);
        // Re-derive the effective limit using the same merged logic the
        // tracker seed uses (`monthly_bandwidth_quota` if set, else
        // `bandwidth_limit_mb` × 1 MiB; 0 means unlimited).
        match crate::db::quota::get_quota_stats(&self.db_pool, user_id).await {
            Ok(stats) => self.quota_trackers.update_limit(user_id, stats.quota_bytes),
            Err(_) => self.quota_trackers.invalidate(user_id),
        }
    }

    /// Check if IP is approved for user, with in-memory + Redis cache-aside.
    /// Returns true/false. DB is only hit on cache miss.
    pub async fn cached_ip_approved(
        &self,
        user_id: i64,
        client_ip: std::net::IpAddr,
    ) -> Result<bool, sqlx::Error> {
        let cache_key = (user_id, client_ip);
        let ttl = std::time::Duration::from_secs(crate::constants::APPROVAL_CACHE_TTL_SECS);

        // 1. Check in-memory cache
        if let Some(entry) = self.approval_cache.get(&cache_key) {
            let (approved, cached_at) = entry.value();
            if cached_at.elapsed() < ttl {
                return Ok(*approved);
            }
            drop(entry);
            self.approval_cache.remove(&cache_key);
        }

        // Format only on miss (Redis + DB still want a String).
        let ip_str = client_ip.to_string();

        // 2. Check Redis cache
        if let Some(ref cache) = self.cache {
            if let Some(approved) = cache.get_ip_approved(user_id, &ip_str).await {
                self.approval_cache
                    .insert(cache_key, (approved, std::time::Instant::now()));
                return Ok(approved);
            }
        }

        // 3. DB lookup
        let approved =
            crate::db::approvals::is_ip_approved(&self.db_pool, user_id, &ip_str).await?;

        // Store in Redis
        if let Some(ref cache) = self.cache {
            cache.set_ip_approved(user_id, &ip_str, approved).await;
        }
        // Store in memory
        self.approval_cache
            .insert(cache_key, (approved, std::time::Instant::now()));

        Ok(approved)
    }

    /// Get the parsed access schedule for a user, populating the cache on
    /// first access. Returns `None` if the user has no schedule (or has an
    /// unparseable one — which we still cache as `None` to avoid retrying).
    pub async fn parsed_schedule_for_user(
        &self,
        user_id: i64,
    ) -> Option<Arc<crate::target_filter::AccessSchedule>> {
        if let Some(entry) = self.parsed_schedule_cache.get(&user_id) {
            return entry.value().clone();
        }
        // Miss: load from cached user, parse, store.
        let parsed = self
            .cached_user_by_id(user_id)
            .await
            .and_then(|cu| {
                cu.access_schedule
                    .as_deref()
                    .and_then(crate::target_filter::parse_schedule)
            })
            .map(Arc::new);
        self.parsed_schedule_cache.insert(user_id, parsed.clone());
        parsed
    }

    pub async fn invalidate_approval_cache(&self, user_id: i64) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_approvals_for_user(user_id).await;
        }
        // Clear in-memory entries for this user
        self.approval_cache.retain(|k, _| k.0 != user_id);
    }

    /// Populate user cache by both id and username after a successful DB lookup.
    /// Call this after verify_password or any DB user fetch you want to cache.
    /// Uses `From<&User>` to avoid cloning the entire User struct.
    pub async fn populate_user_cache(&self, user: &crate::db::models::User) {
        if let Some(ref cache) = self.cache {
            let cu = crate::cache::CachedUser::from(user);
            cache.set_user_by_id(user.id, &cu).await;
            cache.set_user_by_username(&user.username, &cu).await;
        }
    }
}

/// Process connection events from the notification channel
async fn process_events(mut rx: mpsc::Receiver<ConnectionEvent>, state: Arc<dyn StateBackend>) {
    while let Some(event) = rx.recv().await {
        match event {
            ConnectionEvent::NewConnection(id) => {
                tracing::debug!("New connection: {}", id);
                let _ = state.increment_counter("total_connections", 1).await;
                let _ = state
                    .publish_event("connection", &format!("new:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionClosed(id) => {
                tracing::debug!("Connection closed: {}", id);
                let _ = state.delete_connection(id).await;
                let _ = state
                    .publish_event("connection", &format!("closed:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionApproved(id) => {
                tracing::info!("Connection approved: {}", id);
                let _ = state.remove_pending(id).await;
                let _ = state
                    .publish_event("approval", &format!("approved:{}", id))
                    .await;
            }
            ConnectionEvent::ConnectionRejected(id) => {
                tracing::info!("Connection rejected: {}", id);
                let _ = state.remove_pending(id).await;
                let _ = state
                    .publish_event("approval", &format!("rejected:{}", id))
                    .await;
            }
            ConnectionEvent::TunnelCreated(port) => {
                tracing::info!("Tunnel created on port: {}", port);
                let _ = state
                    .publish_event("tunnel", &format!("created:{}", port))
                    .await;
            }
            ConnectionEvent::TunnelClosed(port) => {
                tracing::info!("Tunnel closed on port: {}", port);
                let _ = state
                    .publish_event("tunnel", &format!("closed:{}", port))
                    .await;
            }
        }
    }
}
