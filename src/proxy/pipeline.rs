use std::net::SocketAddr;

use crate::app_state::AppState;
use crate::proxy::protocol::ProxyProtocol;

/// Result of a validation step
pub enum Verdict {
    /// Connection is allowed to proceed
    Allow,
    /// Connection is denied with a reason (logged, then dropped)
    Deny(String),
}

impl Verdict {
    pub fn is_denied(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// Config values snapshotted once per connection to avoid repeated read locks
pub struct ConfigSnapshot {
    pub ip_filter_enabled: bool,
    pub rate_limiting_enabled: bool,
    pub auth_required: bool,
    pub socks4_enabled: bool,
    pub connection_approval: bool,
    pub geo_blocking_enabled: bool,
    pub http2_enabled: bool,
    pub blocked_countries: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub global_allowed_targets: Vec<String>,
    pub global_blocked_targets: Vec<String>,
    pub default_access_schedule: Option<String>,
}

impl ConfigSnapshot {
    pub async fn from_state(state: &AppState) -> Self {
        let config = state.config.load();
        Self {
            ip_filter_enabled: config.filtering.ip_filter_enabled,
            rate_limiting_enabled: config.rate_limiting.enabled,
            auth_required: config.authentication.enabled,
            socks4_enabled: config.protocols.enable_socks4,
            connection_approval: config.features.connection_approval,
            geo_blocking_enabled: config.filtering.geo_blocking_enabled,
            http2_enabled: config.advanced.http2_enabled,
            blocked_countries: config.filtering.blocked_countries.clone(),
            allowed_countries: config.filtering.allowed_countries.clone(),
            global_allowed_targets: config.filtering.global_allowed_targets.clone(),
            global_blocked_targets: config.filtering.global_blocked_targets.clone(),
            default_access_schedule: config.filtering.default_access_schedule.clone(),
        }
    }
}

/// Accumulated state passed through the validation pipeline.
/// Built incrementally as each processing phase completes.
pub struct ConnectionContext {
    pub client_addr: SocketAddr,
    pub conn_id: uuid::Uuid,
    pub conn_start: std::time::Instant,
    pub config: ConfigSnapshot,

    // Set after authentication
    pub user_id: Option<i64>,
    pub protocol: Option<ProxyProtocol>,
    pub is_admin: bool,

    // Set after target parsing
    pub target_host: Option<String>,
}

impl ConnectionContext {
    pub async fn new(client_addr: SocketAddr, conn_id: uuid::Uuid, state: &AppState) -> Self {
        Self {
            client_addr,
            conn_id,
            conn_start: std::time::Instant::now(),
            config: ConfigSnapshot::from_state(state).await,
            user_id: None,
            protocol: None,
            is_admin: false,
            target_host: None,
        }
    }

    /// Effective user ID (skips config-auth sentinel -1)
    pub fn effective_uid(&self) -> Option<i64> {
        self.user_id.filter(|&uid| uid > 0)
    }
}
