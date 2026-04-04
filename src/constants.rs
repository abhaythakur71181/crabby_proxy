//! Centralized constants for timeouts, buffer sizes, and defaults.
//!
//! Avoids scattering magic numbers throughout the codebase.
//! Values here can be overridden by config where noted.

use std::time::Duration;

// ── Network timeouts ──────────────────────────────────────────────────

/// Timeout for initial protocol detection peek.
pub const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for upstream TCP connection establishment.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for DNS resolution.
pub const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Graceful shutdown drain period.
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection pool cleanup interval.
pub const POOL_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// DNS cache cleanup interval.
pub const DNS_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

// ── Buffer sizes ──────────────────────────────────────────────────────

/// Initial buffer for HTTP header parsing.
pub const INITIAL_HTTP_HEADER_SIZE: usize = 1024;

/// Maximum HTTP header size (16 KB).
pub const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;

/// Default relay buffer size (8 KB, overridable via config).
pub const DEFAULT_BUFFER_SIZE: usize = 8 * 1024;

/// H2 relay buffer size (16 KB).
pub const H2_RELAY_BUFFER_SIZE: usize = 16 * 1024;

// ── Cache TTLs ────────────────────────────────────────────────────────

/// How long to cache user lookups (seconds).
pub const USER_CACHE_TTL_SECS: u64 = 300;

/// How long to cache quota check results (seconds).
pub const QUOTA_CACHE_TTL_SECS: u64 = 30;

/// How long to cache approval lookups (seconds).
pub const APPROVAL_CACHE_TTL_SECS: u64 = 120;

/// How long to cache API key lookups (seconds).
pub const API_KEY_CACHE_TTL_SECS: u64 = 300;

// ── Protocol detection ────────────────────────────────────────────────

/// Number of bytes to peek for protocol auto-detection.
pub const PROTOCOL_PEEK_SIZE: usize = 4;
