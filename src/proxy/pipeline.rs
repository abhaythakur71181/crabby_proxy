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

/// Rule names used for admin bypass accounting (`proxy_admin_bypass_total`
/// label values and `filtering.admin_bypass_rules` entries).
pub const RULE_SOCKS4_DISABLED: &str = "socks4_disabled";
pub const RULE_ALLOWED_PROTOCOLS: &str = "allowed_protocols";
pub const RULE_APPROVAL: &str = "approval";
pub const RULE_USER_RATE_LIMIT: &str = "user_rate_limit";
pub const RULE_TARGET_FILTER: &str = "target_filter";
pub const RULE_ACCESS_SCHEDULE: &str = "access_schedule";
pub const RULE_QUOTA: &str = "quota";
pub const RULE_CONNECTION_LIMIT: &str = "connection_limit";

/// Every post-auth rule an admin may be allowed to bypass. Pre-auth rules
/// (IP filter, geo, IP rate limit) run before the user is known and are
/// never bypassable.
pub const ADMIN_BYPASSABLE_RULES: &[&str] = &[
    RULE_SOCKS4_DISABLED,
    RULE_ALLOWED_PROTOCOLS,
    RULE_APPROVAL,
    RULE_USER_RATE_LIMIT,
    RULE_TARGET_FILTER,
    RULE_ACCESS_SCHEDULE,
    RULE_QUOTA,
    RULE_CONNECTION_LIMIT,
];

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
    pub admin_bypass_rules: Vec<String>,
    pub access_log_enabled: bool,
    pub access_log_client_ip: crate::config::AccessLogIpMode,
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
            admin_bypass_rules: config.filtering.admin_bypass_rules.clone(),
            access_log_enabled: config.logging.access_log_enabled,
            access_log_client_ip: config.logging.access_log_client_ip,
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

    /// Client IP as it should appear in access-log events (#59).
    pub fn access_log_ip(&self) -> String {
        self.config
            .access_log_client_ip
            .render(self.client_addr.ip())
    }

    /// True when this is an admin connection AND `rule` is listed in
    /// `filtering.admin_bypass_rules`.
    pub fn admin_bypasses(&self, rule: &str) -> bool {
        self.is_admin && self.config.admin_bypass_rules.iter().any(|r| r == rule)
    }

    /// Apply the admin bypass policy to a validator verdict. Validators are
    /// evaluated for admins too, so a bypass is only recorded when the rule
    /// would actually have denied the connection: that case is audit-logged
    /// and counted in `proxy_admin_bypass_total{rule}` (#56), then allowed.
    pub fn apply_admin_bypass(&self, rule: &'static str, verdict: Verdict) -> Verdict {
        match verdict {
            Verdict::Deny(reason) if self.admin_bypasses(rule) => {
                tracing::info!(
                    target: "audit",
                    user_id = ?self.user_id,
                    client_addr = %self.client_addr,
                    target_host = ?self.target_host,
                    rule,
                    would_deny = %reason,
                    "admin bypass: rule would have denied this connection"
                );
                crate::metrics::ADMIN_BYPASS_TOTAL
                    .with_label_values(&[rule])
                    .inc();
                Verdict::Allow
            }
            v => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(is_admin: bool, rules: &[&str]) -> ConnectionContext {
        ConnectionContext {
            client_addr: "10.0.0.1:5000".parse().unwrap(),
            conn_id: uuid::Uuid::new_v4(),
            conn_start: std::time::Instant::now(),
            config: ConfigSnapshot {
                ip_filter_enabled: false,
                rate_limiting_enabled: false,
                auth_required: true,
                socks4_enabled: true,
                connection_approval: false,
                geo_blocking_enabled: false,
                http2_enabled: false,
                blocked_countries: vec![],
                allowed_countries: vec![],
                global_allowed_targets: vec![],
                global_blocked_targets: vec![],
                default_access_schedule: None,
                admin_bypass_rules: rules.iter().map(|r| r.to_string()).collect(),
                access_log_enabled: true,
                access_log_client_ip: crate::config::AccessLogIpMode::Full,
            },
            user_id: Some(7),
            protocol: None,
            is_admin,
            target_host: Some("example.com".into()),
        }
    }

    fn bypass_count(rule: &str) -> u64 {
        crate::metrics::ADMIN_BYPASS_TOTAL
            .with_label_values(&[rule])
            .get()
    }

    #[test]
    fn non_admin_denial_is_kept() {
        let c = ctx(false, ADMIN_BYPASSABLE_RULES);
        let v = c.apply_admin_bypass(RULE_QUOTA, Verdict::Deny("over".into()));
        assert!(v.is_denied());
    }

    #[test]
    fn admin_bypass_of_listed_rule_is_counted() {
        let c = ctx(true, &[RULE_TARGET_FILTER]);
        let before = bypass_count(RULE_TARGET_FILTER);
        let v = c.apply_admin_bypass(RULE_TARGET_FILTER, Verdict::Deny("blocked".into()));
        assert!(!v.is_denied());
        assert_eq!(bypass_count(RULE_TARGET_FILTER), before + 1);
    }

    #[test]
    fn admin_allow_is_not_counted_as_bypass() {
        let c = ctx(true, ADMIN_BYPASSABLE_RULES);
        let before = bypass_count(RULE_ACCESS_SCHEDULE);
        let v = c.apply_admin_bypass(RULE_ACCESS_SCHEDULE, Verdict::Allow);
        assert!(!v.is_denied());
        assert_eq!(bypass_count(RULE_ACCESS_SCHEDULE), before);
    }

    #[test]
    fn admin_held_to_unlisted_rule() {
        let c = ctx(true, &[RULE_QUOTA]);
        assert!(c.admin_bypasses(RULE_QUOTA));
        assert!(!c.admin_bypasses(RULE_APPROVAL));
        let v = c.apply_admin_bypass(RULE_APPROVAL, Verdict::Deny("not approved".into()));
        assert!(v.is_denied());
    }
}
