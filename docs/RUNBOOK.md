# Operations Runbook

Quick procedures for running Crabby Proxy in production. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for how the pieces fit.

## Deploy / boot requirements

Set these or the process refuses to start:
- `CRABBY_JWT_SECRET` — ≥32 random bytes (boot panics if weaker).
- `CRABBY_ADMIN_PASSWORD`, `CRABBY_BASIC_AUTH_PASSWORD` — non-default (boot
  panics on the built-in defaults; set `CRABBY_ALLOW_DEFAULT_PASSWORDS=1` for
  local dev only).
- `RUST_LOG` — log level, e.g. `info` or `crabby_proxy=debug,warn` (default `info`).

The admin port (admin API + unauthenticated `/metrics`) binds to `127.0.0.1`
on the host by default. To expose it, set `ADMIN_BIND_HOST=0.0.0.0` **only**
behind a firewall / private network, ideally with a reverse proxy enforcing TLS.

## Config reload

`POST /api/config/reload` (admin) re-reads the config file. Security-critical
fields (`jwt_secret`, passwords, `admin.auth_enabled`, bind addresses) are
**preserved from the running process** — a file edit cannot disable auth or
rotate the signing key at runtime; those require a restart. The endpoint returns
500 on a parse error (check logs for detail).

## TLS certificate rotation

Replace the cert/key files, then `POST /api/config/reload` (reloads the
acceptor). Only PKCS8/RSA keys load today (EC/SEC1 is a known gap). There is no
auto-reload on file change yet.

## Revoking access

- **Disable / delete a user** (admin API) — takes effect on the next request
  (the bearer path re-checks `is_active` each request); deletion also revokes
  the user's sessions and API keys.
- **Logout / password rotation does not yet invalidate outstanding JWTs**
  (token_version revocation is a tracked follow-up). To force-expire all tokens
  now, rotate `CRABBY_JWT_SECRET` and restart (invalidates every session).
- **Terminate an approval / revoke an API key** — effective immediately (caches
  are invalidated on the action).

## Redis outage

Optional. On failure the proxy falls back to the in-memory state backend and
the distributed rate limiter **fails closed** (denies). The event-bus subscriber
reconnects automatically with backoff — cross-instance cache invalidation
resumes when Redis returns. Single-instance deployments are unaffected.

## Backup & restore (SQLite)

State lives in the `crabby-data` volume (`proxy.db`). **No automated backup is
configured** — add one (e.g. `sqlite3 proxy.db ".backup"` on a schedule, or
litestream). Migrations run automatically at boot with no down-migration path;
snapshot the DB before deploying a new version.

## Monitoring

- `/metrics` (Prometheus) on the admin port. Watch:
  - `proxy_usage_records_dropped_total` — should stay flat; growth means the
    usage writer is stalled and quota/billing is under-counting.
  - `proxy_auth_failures_total{reason=...}`, `proxy_ip_rate_limit_evictions_total`,
    `proxy_state_backend_errors_total`.
- `/health` and `/health/deep` (the latter pings DB/Redis).

## Graceful shutdown

SIGTERM/Ctrl+C stops accepting new connections, drains active ones (timeout),
and tears down reverse tunnels. In-flight usage records may be lost if the
writer hasn't flushed (tracked follow-up).
