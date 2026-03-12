# 🦀 crabby\_proxy

A multi-protocol forward proxy server written in Rust. Supports HTTP, HTTPS, SOCKS4/4a, and SOCKS5 on a single port with automatic protocol detection, user management, quota enforcement, and a full admin REST API.

---

## Features

### Proxy Protocols

All protocols are auto-detected on a **single listening port** via a 4-byte peek on each incoming TCP connection.

- **HTTP** -- `CONNECT` tunneling and plain HTTP forward proxy
- **HTTPS** -- TLS termination via `rustls` with SNI extraction from ClientHello
- **SOCKS4 / SOCKS4a** -- Including domain name resolution support
- **SOCKS5** -- IPv4, IPv6, domain address types; username/password authentication (RFC 1929)

### Authentication

- **Argon2id** password hashing (run on `spawn_blocking` to avoid blocking the runtime)
- **JWT** tokens for the admin API (configurable secret and expiration)
- **API keys** -- generated per-user with prefix-based lookup, used via `user@apikey` username format in proxy auth
- **Per-protocol auth** -- HTTP `Proxy-Authorization` header, SOCKS5 username/password sub-negotiation
- **Config-based fallback** -- static credentials from TOML config (sentinel `user_id = -1`)
- **RBAC** -- three roles: `root_admin`, `admin`, `user` with scoped permissions

### Rate Limiting

Three independent rate limiters, all using the `governor` crate:

| Limiter | Scope | Data Structure | Default |
|---------|-------|----------------|---------|
| **IP** | Per source IP on the proxy port | `DashMap` (lock-free per-shard) | 100 rps / 200 burst |
| **User** | Per authenticated user (configurable per-user) | `DashMap` + cached config | 10 rps / 20 burst |
| **Login** | Per IP on `/api/login` | `RwLock<LruCache>` (bounded) | 5/min / 10 burst |

IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are normalized to prevent bypass.

### IP Filtering

- **Blocklist** mode (default) -- allow all except listed
- **Allowlist** mode -- block all except listed
- CIDR range support for both IPv4 and IPv6 via `ipnet`
- Runtime add/remove of entries

### Geo-blocking

- **MaxMind GeoLite2** database integration via `maxminddb` crate
- Country-level **allowlist** and **blocklist**
- Configurable via `geoip_database_path` in `[filtering]`
- Fail-open for unknown IPs (no GeoIP data = allowed)

### Target Domain Filtering

- **Global allowlist/blocklist** in config (glob patterns: `*.example.com`, `api.github.com`)
- **Per-user allowlist/blocklist** in DB (JSON arrays)
- **Union logic**: global blocklist → per-user blocklist → union(global + per-user allowlists)
- Admins bypass all restrictions

### Time-Based Access Control

- **Per-user access schedules** (JSON: `{"days":["mon","tue"...],"start_hour":9,"end_hour":18}`)
- **Global default schedule** in config as fallback
- Supports overnight ranges (e.g., 22:00-06:00)
- Admins bypass schedule restrictions

### Quota & Usage Tracking

- Per-user **bandwidth quotas** (daily/monthly) enforced at connection time
- Per-user **concurrent connection limits**
- Per-connection usage records stored in SQLite (client IP, target, protocol, bytes sent/received, duration, status)
- System-wide usage dashboard with top-users-by-bandwidth

### User Groups

- Group users for shared configuration and access control
- Groups can define: `max_connections`, `bandwidth_limit_mb`, `rate_limit_rps/burst`, `allowed_protocols`, `allowed_targets`, `blocked_targets`, `access_schedule`
- Full CRUD API for groups and membership management

### Connection Approval System

- IP-based approval grants for non-admin users
- Time-limited approvals with termination tracking
- Enforced in proxy flow when `connection_approval` is enabled
- Admins bypass approval checks; fail-closed on DB errors

### Caching (Three-Tier)

Quota checks and user lookups go through a cache-aside hierarchy:

1. **Redis** (`CacheLayer`) -- users, API key verifications, quotas, approvals, bandwidth counters, user roles
2. **DashMap** (in-process) -- quota check results (30s TTL), rate limit configs (60s TTL)
3. **SQLite** (source of truth)

Redis is **optional** -- the proxy falls back gracefully to DB-only mode if Redis is unavailable.

### Metrics (Prometheus)

Exposed at `GET /metrics` in Prometheus text format:

| Metric | Type | Labels |
|--------|------|--------|
| `proxy_active_connections` | Gauge | `protocol` |
| `proxy_requests_total` | Counter | `protocol`, `status` |
| `proxy_bytes_transferred_total` | Counter | `direction` (sent/received) |
| `proxy_connection_duration_seconds` | Histogram | `protocol` |
| `proxy_connection_setup_seconds` | Histogram | `protocol` |
| `proxy_upstream_connect_seconds` | Histogram | `protocol` |
| `proxy_ip_filter_actions_total` | Counter | `action` (allowed/blocked) |
| `proxy_rate_limit_exceeded_total` | Counter | `type` (ip/user) |
| `proxy_auth_failures_total` | Counter | `reason` |
| `proxy_auth_total` | Counter | `protocol`, `result` |

### Audit Log

- All admin actions logged to DB (user create/delete, config changes, approval grants)
- Paginated query API with filtering by `user_id` and `action`
- Indexed on `user_id`, `action`, `created_at`

### Session Management

- Token-based sessions with login timestamps and IP/user-agent tracking
- Per-user session listing and force-logout (delete all sessions)
- Expired session cleanup

### Alerting Webhooks

- Configurable webhook URL for event notifications
- Fire-and-forget delivery via `reqwest` with 5s timeout
- Event filtering: `quota_exceeded`, `rate_limit`, `auth_failure`, etc.

### Reverse Tunnels

- `TunnelManager` with configurable port range allocation
- Create, list, and close tunnels via the admin API
- Service type support: `web`, `ssh`, `postgres`, `mysql`, `redis`, `mongodb`, custom

### Structured Logging

- Default: human-readable `tracing-subscriber` output
- Production: `--log-format json` for structured JSON logs (ELK/Loki compatible)
- Includes target module and thread IDs in JSON mode

### Graceful Shutdown

- Listens for `SIGTERM` and `Ctrl+C`
- Broadcast channel stops all listeners from accepting new connections
- 30-second drain period for active connections

---

## Architecture

```
                    +-----------------+
                    |   Admin API     |
                    |   (Axum HTTP)   |
                    +--------+--------+
                             |
            +----------------+----------------+
            |          AppState (Arc)          |
            |                                 |
            |  config     (RwLock<Config>)     |
            |  state      (dyn StateBackend)  |
            |  db_pool    (SqlitePool)        |
            |  cache      (Option<CacheLayer>)|
            |  geo_filter (Option<GeoFilter>) |
            |  rate_limiters, ip_filter, ...   |
            +--------+-----------+------------+
                     |           |
          +----------+--+   +---+-----------+
          | Proxy Server|   | State Backend |
          | (TCP Listen)|   | Memory|Redis  |
          +------+------+   +---+-----------+
                 |               |
    +------------+------------+  |
    | Per-connection task:    |  |
    |  1. IP filter check     |  |
    |  2. Geo-blocking        |  |
    |  3. IP rate limit       |  |
    |  4. Protocol detect     |  |
    |  5. TLS upgrade (opt)   |  |
    |  6. Authenticate        |  |
    |  7. Approval check      |  |
    |  8. Per-user rate limit |  |
    |  9. Protocol restrict   |  |
    | 10. Parse target        |  |
    | 11. Target domain filter|  |
    | 12. Access schedule     |  |
    | 13. Quota check         |  |
    | 14. Connect upstream    |  |
    | 15. Bidirectional relay |  |
    | 16. Record usage in DB  |  |
    +-------------------------+  |
                                 |
                          +------+------+
                          |   SQLite    |
                          |  (sqlx)    |
                          +-------------+
```

---

## Admin API

### Public Endpoints (no auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (status, uptime, version) |
| `GET` | `/metrics` | Prometheus metrics |
| `POST` | `/api/login` | Login, returns JWT token |

### Protected Endpoints (JWT Bearer or Basic auth)

**Dashboard & Server**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/stats` | Uptime, active/total connections, bandwidth |
| `GET` | `/api/dashboard` | Aggregate dashboard (connections, bandwidth, top users, tunnels) |
| `GET` | `/api/config` | Current config (secrets redacted) |
| `POST` | `/api/config/reload` | Reload config from file (admin+) |

**Connections**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/connections` | List active connections |
| `GET` | `/api/connections/count` | Count active connections |

**Users (CRUD)**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/users` | Create user (root_admin only) |
| `GET` | `/api/users` | List all users (admin+) |
| `GET` | `/api/users/:id` | Get user (admin+ or self) |
| `PUT` | `/api/users/:id` | Update user (root_admin or self for password) |
| `DELETE` | `/api/users/:id` | Delete user (root_admin only) |

**API Keys**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/users/:id/api-keys` | Create API key (admin+ or self) |
| `GET` | `/api/users/:id/api-keys` | List API keys (admin+ or self) |
| `DELETE` | `/api/users/:id/api-keys/:key_id` | Revoke API key (admin+ or self) |

**Usage**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/users/:id/usage` | Usage stats for period (admin+ or self) |
| `GET` | `/api/users/:id/usage/recent` | Recent usage records (admin+ or self) |
| `GET` | `/api/users/:id/usage/all-time` | All-time usage (admin+ or self) |
| `GET` | `/api/usage/summary` | System-wide usage dashboard (admin+) |

**Quotas**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/users/:id/quota` | Get quota usage (admin+ or self) |
| `PUT` | `/api/users/:id/quota` | Update quota (admin+) |

**Approvals**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/approvals` | Create IP approval (admin+) |
| `GET` | `/api/approvals` | List all approvals (admin+) |
| `DELETE` | `/api/approvals/:id` | Terminate approval (admin+) |
| `GET` | `/api/users/:id/approvals` | List user's approvals (admin+ or self) |

**Tunnels**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/tunnels` | List active tunnels |
| `POST` | `/api/tunnels` | Create tunnel (service_type, port, target_addr) |
| `DELETE` | `/api/tunnels/:port` | Close tunnel |

**Audit Log**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/audit-log` | Paginated audit log (?limit, ?offset, ?user_id, ?action) |

**Sessions**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/users/:id/sessions` | List user's active sessions |
| `DELETE` | `/api/users/:id/sessions` | Force logout (delete all sessions) |

**User Groups**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/groups` | Create group |
| `GET` | `/api/groups` | List all groups |
| `GET` | `/api/groups/:id` | Get group details |
| `DELETE` | `/api/groups/:id` | Delete group |
| `POST` | `/api/groups/:id/members` | Add user to group |
| `GET` | `/api/groups/:id/members` | List group members |
| `DELETE` | `/api/groups/:id/members/:user_id` | Remove user from group |
| `GET` | `/api/users/:id/groups` | List user's groups |

---

## Database Schema

SQLite with 9 migrations:

- **users** -- credentials (argon2 hash), role, rate limit config, bandwidth limits, protocol restrictions, IP whitelist, target allow/blocklists, access schedule
- **approvals** -- time-limited IP-based access grants, with termination tracking
- **usage** -- per-connection records (client IP, target, protocol, bytes, duration, status)
- **api_keys** -- hashed keys with prefix for display, optional expiration
- **sessions** -- token-based sessions with IP/user-agent tracking
- **user_quotas** -- daily/monthly bandwidth quotas, max concurrent connections
- **audit_log** -- admin action tracking (user_id, action, target, details, IP)
- **user_groups** -- shared configuration for groups of users
- **user_group_members** -- many-to-many user ↔ group relationship

---

## Configuration

Configuration is loaded from a TOML file (default: `crabby-proxy.toml`) with three layers of overrides:

1. **TOML file** -- primary config
2. **Environment variables** -- `PROXY__` prefix with `__` separator (e.g. `PROXY__SERVER__PROXY_BIND`)
3. **CLI arguments** -- `--config`, `--proxy-bind`, `--admin-bind`, `--log-format`

Runtime reload is supported via `POST /api/config/reload`.

### Key Configuration Sections

| Section | Controls |
|---------|----------|
| `[server]` | Bind addresses, max connections, TLS cert/key paths |
| `[database]` | SQLite path, connection pool size |
| `[authentication]` | Enable/disable, method, credentials, JWT secret/expiration |
| `[protocols]` | Enable/disable individual protocols, auto-detect toggle |
| `[features]` | Connection approval, reverse tunnels, tunnel port range, webhook URL/events |
| `[state]` | Backend (memory/redis), Redis URL/pool/prefix |
| `[rate_limiting]` | Global enable, RPS, burst, ban duration |
| `[filtering]` | IP allowlist/blocklist, geo-blocking, target domain allow/blocklists, access schedule |
| `[logging]` | Level, format (json/pretty), file logging |
| `[metrics]` | Enable, Prometheus path, update interval |
| `[admin]` | Enable, auth, credentials, CORS origins |
| `[advanced]` | Buffer size, connection pooling, HTTP/2 |

---

## Quick Start

```bash
# Build
cargo build --release

# Run with default config
./target/release/crabby_proxy

# Run with JSON logging (production)
./target/release/crabby_proxy --log-format json

# Run with custom config
./target/release/crabby_proxy --config my-config.toml

# Override bind addresses
./target/release/crabby_proxy --proxy-bind 0.0.0.0:1080 --admin-bind 127.0.0.1:9090
```

Default ports:
- Proxy: `0.0.0.0:8080`
- Admin API: `127.0.0.1:8081`

A `root_admin` account is auto-created on first run if it doesn't exist.

---

## Testing

```bash
cargo test
```

The project has **398 tests** across all modules, using in-memory SQLite databases and `serial_test` for tests that modify environment variables.

---

## Tech Stack

| Component | Crate |
|-----------|-------|
| Async runtime | `tokio` |
| Proxy protocols | Hand-written parsers (HTTP, SOCKS4/5, TLS SNI) |
| Admin API | `axum` + `tower-http` (CORS) |
| TLS | `tokio-rustls` + `rustls-pemfile` |
| Database | `sqlx` (SQLite, async, migrations) |
| Caching | `redis` (async, connection manager) + `dashmap` + `lru` |
| Auth | `argon2` (password hashing) + `jsonwebtoken` (JWT) |
| Rate limiting | `governor` (token bucket) |
| IP filtering | `ipnet` (CIDR parsing) |
| Geo-blocking | `maxminddb` (MaxMind GeoLite2) |
| Webhooks | `reqwest` (HTTP client) |
| Metrics | `prometheus` |
| Config | `config` + `toml` + `clap` (CLI) |
| Observability | `tracing` + `tracing-subscriber` (text + JSON) |
| Buffer pooling | `byte-pool` |

---

## License

Not yet decided.
