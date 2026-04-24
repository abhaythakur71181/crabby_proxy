use arc_swap::ArcSwap;
use crate::cache::CacheLayer;
use crate::config::Config;
use crate::state::{MemoryBackend, RedisBackend, StateBackend};
use crate::tunnel::manager::TunnelManager;
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

    // Auth result cache: (username, password_hash) -> (user_id, cached_at)
    // Avoids DB + argon2 on every connection from the same user (60s TTL)
    // Uses full string key instead of u64 hash to prevent collision-based auth bypass.
    pub auth_cache: Arc<dashmap::DashMap<(String, String), (i64, std::time::Instant)>>,

    /// Per-user bandwidth throttler registry.
    pub bandwidth_throttlers: Arc<crate::bandwidth::ThrottlerRegistry>,

    // Graceful shutdown signal
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,

    // Quota check cache: user_id -> (allowed, cached_at)
    // Caches the boolean result of check_quota for 30s to avoid SUM() per connection
    // (fallback when Redis cache is unavailable)
    pub quota_cache: Arc<dashmap::DashMap<i64, (bool, std::time::Instant)>>,

    // Redis cache layer for users, API keys, quotas, approvals
    pub cache: Option<CacheLayer>,

    // Event bus for cross-instance coordination (optional — requires Redis)
    pub event_bus: Option<crate::event_bus::EventBus>,
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
            "memory" | _ => {
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
        let ip_rate_limiter = crate::rate_limit::IpRateLimiter::new(
            config.rate_limiting.requests_per_second,
            config.rate_limiting.burst_size,
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
            db_pool,
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
            quota_cache: Arc::new(dashmap::DashMap::new()),
            auth_cache: Arc::new(dashmap::DashMap::new()),
            bandwidth_throttlers: Arc::new(crate::bandwidth::ThrottlerRegistry::new()),
            cache,
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
        if let Some(path) = &self.config_path {
            let new_config = Config::from_file(path)?;
            self.config.store(Arc::new(new_config));
            tracing::info!("Configuration reloaded from {}", path);
            Ok(())
        } else {
            Err("Config path not available for reload".into())
        }
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

    /// Fetch a CachedUser by id: Redis -> DB -> populate Redis.
    pub async fn cached_user_by_id(&self, user_id: i64) -> Option<crate::cache::CachedUser> {
        let pool = self.db_pool.clone();
        if let Some(ref cache) = self.cache {
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
        }
    }

    /// Fetch a CachedUser by username: Redis -> DB -> populate Redis.
    pub async fn cached_user_by_username(
        &self,
        username: &str,
    ) -> Option<crate::cache::CachedUser> {
        let pool = self.db_pool.clone();
        if let Some(ref cache) = self.cache {
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
        }
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

    pub async fn invalidate_quota_cache(&self, user_id: i64) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_quota(user_id).await;
        }
        self.quota_cache.remove(&user_id);
    }

    pub async fn invalidate_approval_cache(&self, user_id: i64) {
        if let Some(ref cache) = self.cache {
            cache.invalidate_approvals_for_user(user_id).await;
        }
    }

    pub async fn track_bandwidth(&self, user_id: i64, bytes: i64) {
        if let Some(ref cache) = self.cache {
            cache.incr_bandwidth(user_id, bytes).await;
        }
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
