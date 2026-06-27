# Crabby Proxy — Architecture

A multi-protocol authenticated forward proxy (HTTP, HTTPS/CONNECT, SOCKS4/5,
HTTP/2) written in Rust, with a React admin console. Sold as multi-tenant
infrastructure: per-user credentials, bandwidth quotas, rate limits, target
allow/deny lists, time-of-day access schedules, IP/geo filtering, and a
connection-approval workflow.

## Components

```
                       ┌──────────────────────────┐
   proxy clients ─────▶│  proxy listener :8080    │  (run_proxy_server)
   (HTTP/SOCKS/h2)     │  src/proxy/listener.rs   │
                       └────────────┬─────────────┘
                                    │ validator pipeline
                                    ▼
                       ┌──────────────────────────┐
                       │ upstream TCP connect      │──▶ target
                       │ + bidirectional relay     │    (egress-guarded)
                       │ src/stream.rs             │
                       └──────────────────────────┘

   admin UI / API ────▶│  admin server :8081       │  (run_admin_server, axum)
   (React, nginx)      │  src/admin/*              │
                       └────────────┬─────────────┘
                                    ▼
                  ┌─────────────┬──────────────┬──────────────┐
                  │ SQLite (sqlx)│ Redis (opt.) │ Prometheus    │
                  │ durable state│ cache/pubsub │ /metrics      │
                  └─────────────┴──────────────┴──────────────┘
```

- **Proxy data plane** — `src/proxy/`: accept, protocol detection + auth,
  the phased validator pipeline, h1 and h2 handlers; `src/stream.rs` is the
  byte relay (throttle + in-flight quota).
- **Admin control plane** — `src/admin/`: JWT/basic auth middleware, ~40 REST
  handlers, a WebSocket live feed. Auth is enforced by typed extractors
  (`AdminUser` / `CurrentUser`) so a handler cannot run without an authz check.
- **Persistence & state** — `src/db/` (sqlx + SQLite, 13 migrations),
  `src/state/` (`memory` | `redis` backends), `src/cache.rs` (Redis cache-aside),
  `src/event_bus.rs` (Redis pub/sub for cross-instance cache invalidation).
- **Accounting** — `src/quota_tracker.rs` (in-process atomic = enforcement),
  `src/usage_writer.rs` (batched MPSC → `usage` table = persistence),
  `src/bandwidth.rs` (token-bucket throttle), `src/metrics.rs` (Prometheus).
- **Reverse tunnels** — `src/tunnel/` (admin-created listeners, ports 10000–10999).

## Request lifecycle (proxy)

1. Accept TCP; acquire a global connection semaphore permit.
2. If `proxy_protocol_enabled` **and** the socket peer is a configured trusted
   CIDR, parse the PROXY header for the real client IP; otherwise use the
   socket address. (Prevents source-IP spoofing — see ADR-0005.)
3. Detect protocol from the first bytes; optional TLS terminate.
4. Authenticate (Basic / SOCKS5 user-pass / API key). Config credentials
   resolve to the real `root_admin` id — never a sentinel (ADR-0003).
5. Run the **validator pipeline** (`src/proxy/validators.rs`), phased:
   - Phase 1 (client IP): ip-filter, geo, ip-rate-limit
   - Phase 2 (user): protocol restriction, approval, user-rate-limit
   - Phase 3 (target): domain filter, access schedule
   - Phase 4 (quota): bandwidth quota, connection limit
6. Resolve DNS → **egress guard** (reject internal/metadata IPs when enabled)
   → self-loop guard → `TcpStream::connect`.
7. Relay bytes bidirectionally with per-chunk throttle + quota enforcement.
8. On close, enqueue a `usage` record (batched writer).

## Security posture

The system is **fail-closed** on the security path: geo/rate-limit/connection
checks deny on backend error; unauthenticated SOCKS4/TCP are rejected when auth
is required; the admin API enforces role via extractors, not per-handler
convention. Egress to private/loopback/cloud-metadata addresses is blocked by
config (`filtering.block_private_targets`). See the ADR log for the rationale
behind each decision.

## Deployment

- Single binary; `docker compose` ships the proxy + nginx-served SPA.
- Admin port (admin API + unauthenticated `/metrics`) binds to `127.0.0.1` on
  the host by default — override `ADMIN_BIND_HOST` only behind a firewall.
- Secrets via env (`CRABBY_JWT_SECRET`, `CRABBY_ADMIN_PASSWORD`,
  `CRABBY_BASIC_AUTH_PASSWORD`); the process refuses to boot with a weak JWT
  secret or default passwords (override with `CRABBY_ALLOW_DEFAULT_PASSWORDS=1`
  for local dev only).
- State is SQLite on a volume. **No automated backup yet** — see runbook.

## Known limitations / follow-ups

- JWT revocation covers disable/delete (per-request `is_active` recheck) but
  not yet logout/password-rotation (`token_version` is a tracked follow-up).
- Connection pool (`src/connection_pool.rs`) is currently inert (never returns
  sockets) — pending a keep-alive-or-remove decision.
- HTTP/2 non-CONNECT forward path doesn't persist `usage` rows yet.
- See `task.md` (Audit Round 3) for the full remaining list.
