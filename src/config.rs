use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub method: AuthMethod,
    pub username: String,
    pub password: String,
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub ip_allowlist: Vec<String>,
    pub ip_blocklist: Vec<String>,
    pub geo_blocking_enabled: bool,
    pub blocked_countries: Vec<String>,
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

    /// Generate default configuration
    pub fn default() -> Self {
        Self {
            server: ServerConfig {
                proxy_bind: "0.0.0.0:8080".to_string(),
                admin_bind: "127.0.0.1:8081".to_string(),
                max_connections: 10000,
                connection_timeout: 30,
                tls_enabled: false,
                tls_cert_path: String::new(),
                tls_key_path: String::new(),
            },
            authentication: AuthConfig {
                enabled: true,
                method: AuthMethod::Basic,
                username: "admin".to_string(),
                password: "changeme".to_string(),
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
            },
            filtering: FilterConfig {
                ip_allowlist: vec![],
                ip_blocklist: vec![],
                geo_blocking_enabled: false,
                blocked_countries: vec![],
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
