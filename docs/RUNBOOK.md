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

The admin port (admin API + `/metrics`) binds to `127.0.0.1` on the host by
default. To expose it, set `ADMIN_BIND_HOST=0.0.0.0` **only** behind a
firewall / private network, ideally with a reverse proxy enforcing TLS.

`/metrics` needs a scrape token in the compose setup: the container binds the
admin API to `0.0.0.0:8081`, and without a token a non-loopback bind answers
`403`. Set `CRABBY_METRICS_SCRAPE_TOKEN` in `.env` and configure Prometheus
with `authorization: { credentials: <token> }`. Only if the admin port is
already restricted, `CRABBY_METRICS_ALLOW_UNAUTHENTICATED=true` serves it
without a token instead.

Copy `.env.example` to `.env` for the full list of compose variables.

## Releases & rollback

Tag every build with a version or git SHA instead of relying on `:latest`:

```sh
export CRABBY_IMAGE_TAG=$(git rev-parse --short HEAD)   # or v1.4.0
docker compose build && docker compose up -d
```

Record the tag that is running (or put it in `.env`). To roll back, set
`CRABBY_IMAGE_TAG` to the previous tag and `docker compose up -d`; the image is
still in the local cache (or your registry). Migrations have no down path, so a
rollback across a schema change also needs the pre-deploy DB snapshot (see
"Backup & restore" below). `:latest` is only a local convenience alias.

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

## Scaling (single-instance constraint)

Run **exactly one** proxy process per database. This is a deliberate default,
not an oversight; the following state is per process or per volume:

- **State backend** (`[state] backend`, default `"memory"`): live connections,
  pending approvals and counters live in process memory.
- **Rate limiting**: always in-process (`governor`), whatever the state
  backend. A second replica doubles every client's effective limit.
- **Database**: SQLite is a single-writer file on a local volume. Two
  containers must never mount the same `proxy.db` (and never over NFS/SMB).

`backend = "redis"` shares the first item only, and if Redis is unreachable at
boot the process silently falls back to memory, so two "Redis" replicas can
still split state. Scale vertically (raise `max_connections` and the compose
`PROXY_*` limits) instead. Before running more than one replica, the project
needs: an atomic, tested Redis backend that fails hard instead of falling
back; Redis-backed rate limiting wired in (`RedisRateLimiter` exists but is
not used); and a shared database (e.g. Postgres) in place of SQLite. The
Kubernetes design in `docs/superpowers/specs/` already pins the backend to a
1-replica StatefulSet for this reason; the UI is stateless and can scale.

## Redis outage

Optional. On failure the proxy falls back to the in-memory state backend and
the distributed rate limiter **fails closed** (denies). The event-bus subscriber
reconnects automatically with backoff — cross-instance cache invalidation
resumes when Redis returns. Single-instance deployments are unaffected.

## Backup & restore (SQLite)

All durable state (users, approvals, usage, API keys) lives in one SQLite file,
`proxy.db`, in the `crabby-data` volume. Losing the volume loses everything, so
run backups.

**Taking backups.** `scripts/backup-sqlite.sh` takes an online snapshot with
SQLite's backup API (safe while the proxy runs in WAL mode), runs
`PRAGMA integrity_check` on it, gzips it to `proxy-<UTC timestamp>.db.gz` and
prunes snapshots older than `RETENTION_DAYS` (default 14). Ways to run it:

- **Compose sidecar** (every 6 h by default, into `./backups`):
  ```sh
  docker compose --profile backup up -d
  ```
  Tune with `BACKUP_DIR`, `BACKUP_INTERVAL_SECONDS`, `BACKUP_RETENTION_DAYS`
  in `.env`. The sidecar chowns `BACKUP_DIR` to the app uid (10001).
- **Host cron, one shot** (no long-running sidecar):
  ```cron
  15 */6 * * * cd /srv/crabby_proxy && docker compose --profile backup run --rm --no-deps -e INTERVAL_SECONDS= crabby-backup
  ```
- **Bare metal**: `scripts/backup-sqlite.sh /path/to/proxy.db /path/to/backups`
  (needs the `sqlite3` CLI). Equivalent one-liner without the script:
  `sqlite3 proxy.db "VACUUM INTO '/backups/proxy-$(date +%F).db'"`.

Snapshots on the same disk as the volume do not survive losing that disk: copy
`BACKUP_DIR` off-host (restic, rclone to object storage, rsync) on its own
schedule.

**Before every deploy** take a one-shot snapshot: migrations run automatically
at boot and have no down path, so the pre-deploy snapshot is the only way to
roll back across a schema change.

**Restore.**

```sh
docker compose stop crabby-proxy
docker compose --profile backup run --rm --no-deps --entrypoint sh crabby-backup -c '
  set -e
  rm -f /app/data/proxy.db-wal /app/data/proxy.db-shm
  gunzip -c /backups/proxy-YYYYMMDDTHHMMSSZ.db.gz > /app/data/proxy.db
  chown 10001:10001 /app/data/proxy.db'
docker compose start crabby-proxy
```

Delete the old `-wal`/`-shm` files as shown: a stale WAL replayed over the
restored file corrupts it.

**Test restores** at least monthly: gunzip the newest snapshot somewhere
scratch, run `sqlite3 restored.db "PRAGMA integrity_check; SELECT count(*) FROM users;"`,
or boot a throwaway proxy container against it. An untested backup is not a
backup.

**Automatic pre-migration snapshot.** Before applying pending migrations to an
existing database the proxy also writes a snapshot
(`proxy.db.pre-migrate-<from>-to-<to>-<unix>.bak`) next to it; to roll back,
stop the proxy, restore that file (removing `-wal`/`-shm`), and run the previous
version. These snapshots are not pruned automatically. See ADR-0007.

## Monitoring

- `/metrics` (Prometheus) on the admin port; bearer `scrape_token` required
  unless the admin bind is loopback (see "Deploy / boot requirements"). Watch:
  - `proxy_usage_records_dropped_total` — should stay flat; growth means the
    usage writer is stalled and quota/billing is under-counting.
  - `proxy_auth_failures_total{reason=...}`, `proxy_ip_rate_limit_evictions_total`,
    `proxy_state_backend_errors_total`.
- `/health` and `/health/deep` (the latter pings DB/Redis).

## Graceful shutdown

SIGTERM/Ctrl+C stops accepting new connections, drains active ones (timeout),
and tears down reverse tunnels. In-flight usage records may be lost if the
writer hasn't flushed (tracked follow-up).
