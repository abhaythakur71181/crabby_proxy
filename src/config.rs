use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthConfig,
    pub protocols: ProtocolConfig,
    pub features: FeatureConfig,
    pub state: StateConfig,
    pub rate_limiting: RateLimitConfig,
    pub filtering: FilterConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub admin: AdminConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub proxy_bind: String,
    pub admin_bind: String,
    pub max_connections: usize,
    pub connection_timeout: u64,
    pub tls_enabled: bool,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    /// Enable HAProxy PROXY protocol v1 header parsing on incoming connections.
    /// When enabled, the real client IP is extracted from the PROXY header.
    #[serde(default)]
    pub proxy_protocol_enabled: bool,
    /// Path to CA certificate for mutual TLS (mTLS) client authentication.
    /// When set, clients must present a certificate signed by this CA.
    #[serde(default)]
    pub tls_client_ca_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub method: AuthMethod,
    pub username: String,
    pub password: String,
    pub jwt_secret: String,
    pub jwt_expiration: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Basic,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtocolConfig {
    pub enable_http: bool,
    pub enable_https: bool,
    pub enable_socks4: bool,
    pub enable_socks5: bool,
    pub auto_detect: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeatureConfig {
    pub connection_approval: bool,
    pub approval_timeout: u64,
    pub reverse_tunnels: bool,
    pub tunnel_port_start: u16,
    pub tunnel_port_end: u16,
    pub webhook_url: Option<String>,
    pub webhook_events: Vec<String>, // e.g. ["quota_exceeded", "rate_limit", "auth_failure"]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StateConfig {
    pub backend: String,
    pub redis_url: String,
    pub redis_pool_size: usize,
    pub redis_key_prefix: String,
    pub redis_connection_timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub ban_duration: u64,
    /// Cap on number of distinct IPs tracked by the in-process IP rate limiter.
    /// Bounds memory under IP-spray attacks. Defaults to 100_000 if absent.
    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,
}

fn default_max_tracked_ips() -> usize {
    crate::rate_limit::DEFAULT_MAX_TRACKED_IPS
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub ip_allowlist: Vec<String>,
    pub ip_blocklist: Vec<String>,
    pub geo_blocking_enabled: bool,
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub allowed_countries: Vec<String>, // If non-empty, ONLY these countries are allowed
    #[serde(default)]
    pub geoip_database_path: Option<String>, // Path to MaxMind GeoLite2-Country.mmdb
    #[serde(default = "default_ip_filter_mode")]
    pub ip_filter_mode: String,
    #[serde(default)]
    pub ip_filter_enabled: bool,
    // Target domain filtering (glob patterns: "*.example.com", "api.github.com")
    #[serde(default)]
    pub global_allowed_targets: Vec<String>,
    #[serde(default)]
    pub global_blocked_targets: Vec<String>,
    // Default access schedule (JSON: {"days":["mon","tue"...],"start_hour":9,"end_hour":18,"timezone":"UTC"})
    #[serde(default)]
    pub default_access_schedule: Option<String>,
    // SSRF egress guard. When true, the proxy refuses to connect to a resolved
    // target IP that is private / loopback / link-local / ULA / unspecified /
    // multicast — blocking SSRF into internal services and cloud metadata.
    // Defaults to false so same-machine / internal targets work out of the box;
    // set true to harden a deployment that only proxies to the public internet.
    #[serde(default)]
    pub block_private_targets: bool,
}

fn default_ip_filter_mode() -> String {
    "blocklist".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub file_enabled: bool,
    pub file_path: String,
    pub access_log_enabled: bool,
    pub access_log_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub prometheus_path: String,
    pub update_interval: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    pub enabled: bool,
    pub auth_enabled: bool,
    pub admin_username: String,
    pub admin_password: String,
    pub websocket_enabled: bool,
    pub cors_enabled: bool,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdvancedConfig {
    pub buffer_size: usize,
    pub connection_pooling: bool,
    pub pool_max_idle_per_host: usize,
    pub http2_enabled: bool,
    pub dns_cache_ttl: u64,
}

impl Config {
    /// Load configuration from a TOML file with environment variable overrides
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path.as_ref()))
            .add_source(
                config::Environment::with_prefix("PROXY")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        settings.try_deserialize()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                proxy_bind: "0.0.0.0:8080".to_string(),
                admin_bind: "127.0.0.1:8081".to_string(),
                max_connections: 10000,
                connection_timeout: 30,
                tls_enabled: false,
                tls_cert_path: String::new(),
                tls_key_path: String::new(),
                proxy_protocol_enabled: false,
                tls_client_ca_path: None,
            },
            database: DatabaseConfig {
                path: "sqlite:proxy.db".to_string(),
                max_connections: 10,
            },
            authentication: AuthConfig {
                enabled: true,
                method: AuthMethod::Basic,
                username: "admin".to_string(),
                password: "changeme".to_string(),
                jwt_secret: "change_me_to_a_secure_random_string".to_string(),
                jwt_expiration: 3600 * 24, // 24 hours
            },
            protocols: ProtocolConfig {
                enable_http: true,
                enable_https: true,
                enable_socks4: true,
                enable_socks5: true,
                auto_detect: true,
            },
            features: FeatureConfig {
                connection_approval: false,
                approval_timeout: 300,
                reverse_tunnels: false,
                tunnel_port_start: 10000,
                tunnel_port_end: 10999,
                webhook_url: None,
                webhook_events: vec![],
            },
            state: StateConfig {
                backend: "memory".to_string(),
                redis_url: "redis://localhost:6379".to_string(),
                redis_pool_size: 10,
                redis_key_prefix: "crabby_proxy:".to_string(),
                redis_connection_timeout: 5,
            },
            rate_limiting: RateLimitConfig {
                enabled: true,
                requests_per_second: 100,
                burst_size: 200,
                ban_duration: 300,
                max_tracked_ips: crate::rate_limit::DEFAULT_MAX_TRACKED_IPS,
            },
            filtering: FilterConfig {
                ip_allowlist: vec![],
                ip_blocklist: vec![],
                geo_blocking_enabled: false,
                blocked_countries: vec![],
                allowed_countries: vec![],
                geoip_database_path: None,
                ip_filter_mode: "blocklist".to_string(),
                ip_filter_enabled: false,
                global_allowed_targets: vec![],
                global_blocked_targets: vec![],
                default_access_schedule: None,
                block_private_targets: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: LogFormat::Pretty,
                file_enabled: false,
                file_path: "proxy.log".to_string(),
                access_log_enabled: true,
                access_log_path: "access.log".to_string(),
            },
            metrics: MetricsConfig {
                enabled: true,
                prometheus_path: "/metrics".to_string(),
                update_interval: 10,
            },
            admin: AdminConfig {
                enabled: true,
                auth_enabled: true,
                admin_username: "admin".to_string(),
                admin_password: "secure_admin_password".to_string(),
                websocket_enabled: true,
                cors_enabled: true,
                cors_origins: vec!["http://localhost:3000".to_string()],
            },
            advanced: AdvancedConfig {
                buffer_size: 8192,
                connection_pooling: false,
                pool_max_idle_per_host: 10,
                http2_enabled: false,
                dns_cache_ttl: 300,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Default Config Tests ===

    #[test]
    fn test_default_config_creates_valid_config() {
        let config = Config::default();
        assert_eq!(config.server.proxy_bind, "0.0.0.0:8080");
        assert_eq!(config.server.admin_bind, "127.0.0.1:8081");
        assert_eq!(config.server.max_connections, 10000);
        assert_eq!(config.server.connection_timeout, 30);
        assert!(!config.server.tls_enabled);
    }

    #[test]
    fn test_default_database_config() {
        let config = Config::default();
        assert_eq!(config.database.path, "sqlite:proxy.db");
        assert_eq!(config.database.max_connections, 10);
    }

    #[test]
    fn test_default_auth_config() {
        let config = Config::default();
        assert!(config.authentication.enabled);
        assert!(matches!(config.authentication.method, AuthMethod::Basic));
        assert_eq!(config.authentication.username, "admin");
        assert_eq!(config.authentication.password, "changeme");
        assert_eq!(
            config.authentication.jwt_secret,
            "change_me_to_a_secure_random_string"
        );
        assert_eq!(config.authentication.jwt_expiration, 3600 * 24);
    }

    #[test]
    fn test_default_protocols_all_enabled() {
        let config = Config::default();
        assert!(config.protocols.enable_http);
        assert!(config.protocols.enable_https);
        assert!(config.protocols.enable_socks4);
        assert!(config.protocols.enable_socks5);
        assert!(config.protocols.auto_detect);
    }

    #[test]
    fn test_default_features_config() {
        let config = Config::default();
        assert!(!config.features.connection_approval);
        assert_eq!(config.features.approval_timeout, 300);
        assert!(!config.features.reverse_tunnels);
        assert_eq!(config.features.tunnel_port_start, 10000);
        assert_eq!(config.features.tunnel_port_end, 10999);
    }

    #[test]
    fn test_default_state_config() {
        let config = Config::default();
        assert_eq!(config.state.backend, "memory");
        assert_eq!(config.state.redis_url, "redis://localhost:6379");
        assert_eq!(config.state.redis_pool_size, 10);
    }

    #[test]
    fn test_default_rate_limiting_config() {
        let config = Config::default();
        assert!(config.rate_limiting.enabled);
        assert_eq!(config.rate_limiting.requests_per_second, 100);
        assert_eq!(config.rate_limiting.burst_size, 200);
        assert_eq!(config.rate_limiting.ban_duration, 300);
    }

    #[test]
    fn test_default_filtering_config() {
        let config = Config::default();
        assert!(config.filtering.ip_allowlist.is_empty());
        assert!(config.filtering.ip_blocklist.is_empty());
        assert!(!config.filtering.geo_blocking_enabled);
        assert!(config.filtering.blocked_countries.is_empty());
        assert_eq!(config.filtering.ip_filter_mode, "blocklist");
        assert!(!config.filtering.ip_filter_enabled);
    }

    #[test]
    fn test_default_logging_config() {
        let config = Config::default();
        assert_eq!(config.logging.level, "info");
        assert!(matches!(config.logging.format, LogFormat::Pretty));
        assert!(!config.logging.file_enabled);
        assert!(config.logging.access_log_enabled);
    }

    #[test]
    fn test_default_metrics_config() {
        let config = Config::default();
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.prometheus_path, "/metrics");
        assert_eq!(config.metrics.update_interval, 10);
    }

    #[test]
    fn test_default_admin_config() {
        let config = Config::default();
        assert!(config.admin.enabled);
        assert!(config.admin.auth_enabled);
        assert_eq!(config.admin.admin_username, "admin");
        assert_eq!(config.admin.admin_password, "secure_admin_password");
        assert!(config.admin.websocket_enabled);
        assert!(config.admin.cors_enabled);
        assert_eq!(config.admin.cors_origins.len(), 1);
        assert_eq!(config.admin.cors_origins[0], "http://localhost:3000");
    }

    #[test]
    fn test_default_advanced_config() {
        let config = Config::default();
        assert_eq!(config.advanced.buffer_size, 8192);
        assert!(!config.advanced.connection_pooling);
        assert_eq!(config.advanced.pool_max_idle_per_host, 10);
        assert!(!config.advanced.http2_enabled);
        assert_eq!(config.advanced.dns_cache_ttl, 300);
    }

    // === Config cloneability ===

    #[test]
    fn test_config_is_cloneable() {
        let config1 = Config::default();
        let config2 = config1.clone();
        assert_eq!(config1.server.proxy_bind, config2.server.proxy_bind);
    }

    // === Config serialization/deserialization roundtrip ===

    #[test]
    fn test_config_toml_roundtrip() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).expect("Failed to serialize to TOML");
        let deserialized: Config =
            toml::from_str(&toml_str).expect("Failed to deserialize from TOML");

        assert_eq!(config.server.proxy_bind, deserialized.server.proxy_bind);
        assert_eq!(
            config.server.max_connections,
            deserialized.server.max_connections
        );
        assert_eq!(config.database.path, deserialized.database.path);
        assert_eq!(
            config.authentication.jwt_expiration,
            deserialized.authentication.jwt_expiration
        );
    }

    // === from_file error on missing file ===

    #[test]
    fn test_from_file_nonexistent_file_returns_error() {
        let result = Config::from_file("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    // === FilterConfig default helper ===

    #[test]
    fn test_default_ip_filter_mode_function() {
        assert_eq!(default_ip_filter_mode(), "blocklist");
    }

    // === AuthMethod variants ===

    #[test]
    fn test_auth_method_debug() {
        let basic = AuthMethod::Basic;
        let none = AuthMethod::None;
        assert_eq!(format!("{:?}", basic), "Basic");
        assert_eq!(format!("{:?}", none), "None");
    }

    // === LogFormat variants ===

    #[test]
    fn test_log_format_debug() {
        let json = LogFormat::Json;
        let pretty = LogFormat::Pretty;
        assert_eq!(format!("{:?}", json), "Json");
        assert_eq!(format!("{:?}", pretty), "Pretty");
    }
}
