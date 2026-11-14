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
500 on a parse error (check logs for detail). With an event bus (Redis), the
reload is broadcast and every other replica re-reads its own config file.

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

## Scaling

**Default: one proxy process per database** (`[state] backend = "memory"`).
Nothing extra to run; connection state, rate limits and quota counters live in
process memory. Scale vertically first: raise `[server] max_connections`,
`[database] max_connections` (read pool) and the compose `PROXY_*` limits.

**Supported multi-replica configuration: several replicas on one host, sharing
one SQLite file and one Redis.** Requirements:

1. `[state] backend = "redis"` and the same `redis_url` / `redis_key_prefix`
   on every replica. With this backend the proxy **refuses to start** if Redis
   (state backend, cache layer or event bus) is unreachable, instead of
   silently running with split state.
2. All replicas mount the **same `proxy.db` on a local filesystem of the same
   host** (e.g. one Docker named volume). SQLite in WAL mode coordinates
   processes on one host through a shared-memory file; it does **not** work
   across hosts or over NFS/SMB. Running replicas on several hosts needs a
   networked database (e.g. Postgres), which the proxy does not support yet.
3. A TCP load balancer in front of the proxy port and an HTTP load balancer in
   front of the admin API (no stickiness needed, see below).
4. The same `config.toml` on every replica, ideally one shared file. `PUT
   /api/config` writes the file of the replica that served it and broadcasts a
   reload; other replicas re-read *their* file, so a non-shared file diverges.
5. Upgrades: let **one** replica start first and apply migrations (and write
   the pre-migration snapshot), then start the rest. Migrations are not locked
   across processes.

What is shared across replicas in that configuration:

| Concern | Mechanism |
|---|---|
| Live connections, per-user connection counts, pending approvals | Redis state backend |
| IP / user / login rate limits | Redis GCRA buckets (plus the local bucket) |
| Monthly bandwidth quotas | Redis counter per user and window (`{prefix}quota:{user}:{window}`), synced every second and on every admission |
| User, API-key, approval and quota cache invalidation | Redis pub/sub event bus (`{prefix}events`) |
| Config reload (`PUT /api/config`, `POST /api/config/reload`) | event bus `ConfigReloaded` |
| `DELETE /api/connections/:id` | handled locally, or forwarded over the event bus to the replica relaying it (202 Accepted) |
| Live-connections WebSocket ticket | stored in Redis, redeemable on any replica, single use |
| Users, sessions, API keys, approvals, usage, audit | the shared SQLite file |

What stays per replica (by design or as a known limit):

- `[server] max_connections` caps each replica, not the cluster.
- Reverse tunnels (`/api/tunnels`) are listeners inside the replica that
  created them; list/close them on that replica (or run tunnels on a single
  node).
- `/metrics` is per replica: scrape every replica.
- In-process caches have short TTLs (user 5 s, credential checks 60 s,
  approvals 2 min). Changes are pushed over the event bus; if the bus is
  disconnected when a change happens, other replicas see it only when the TTL
  expires.
- The usage retention purge runs on every replica; it is idempotent.
- SQLite still has one write lock for the whole file. Each replica sends its
  writes through one dedicated writer connection, so N replicas means up to N
  writers queueing on `busy_timeout_ms`. Watch
  `proxy_db_write_acquire_seconds` and `proxy_db_contention_errors_total`.

Quota accuracy with several replicas: each replica learns the others' traffic
at most about one second late, so a user can exceed the quota by roughly what
all replicas relay for them in that second (plus about one 64 KiB buffer per
connection admitted at the same instant). See the `quota_tracker` module docs.

## Redis outage

With `backend = "memory"` Redis is optional: the cache layer and event bus are
used when reachable and skipped otherwise; a single instance is unaffected.

With `backend = "redis"`, Redis is **required at startup**. Once running, an
outage degrades each component on its own, and none of them fails closed:

- **Rate limits** fall back to the per-instance limit (log line at most every
  30 s).
- **Quotas** are enforced from each replica's last known global count plus the
  bytes it relayed since; the unpushed bytes are kept and pushed when Redis
  returns (`proxy_quota_sync_errors_total` rises meanwhile). During the outage
  each replica can admit up to the remaining quota on its own.
- **Connection tracking** errors are counted in `proxy_state_backend_errors_total`.
- **Cache layer** reads fall through to SQLite.
- **Event bus** subscribers reconnect with backoff; invalidations published
  during the outage are lost, so other replicas fall back to the cache TTLs.

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
  - `proxy_db_write_acquire_seconds` (wait for the SQLite writer connection)
    and `proxy_db_contention_errors_total{kind=busy|pool_timeout}` — rising
    values mean writes are queueing; see "Scaling".
  - `proxy_quota_sync_errors_total` — with the Redis backend, non-zero growth
    means quotas are being enforced per replica only (see "Redis outage").
- `/health` and `/health/deep` (the latter pings DB/Redis).

## Graceful shutdown

SIGTERM/Ctrl+C stops accepting new connections, drains active ones (timeout),
and tears down reverse tunnels. In-flight usage records may be lost if the
writer hasn't flushed (tracked follow-up).
