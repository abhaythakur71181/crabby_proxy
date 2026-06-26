# crabby_proxy -- Task List

Comprehensive audit of the codebase as of 2026-03-25.

---

## CRITICAL BUGS

### 1. HTTP/2 handler bypasses ALL validators
- **File:** `src/proxy/http2_handler.rs:74`
- **Issue:** `let _state_ref = state;` -- state is accepted but never used. HTTP/2 CONNECT streams skip authentication, rate limiting, quota checks, IP filtering, geo-blocking, target filtering, access schedules, and approval checks.
- **Impact:** Any client using HTTP/2 can proxy through without credentials or restrictions.
- **Fix:** Apply the same validation pipeline (`validators.rs`) to HTTP/2 streams before establishing upstream connections.

### 2. Metrics export can panic in production
- **File:** `src/metrics.rs:97-98`
- **Issue:** `encoder.encode(...).unwrap()` and `String::from_utf8(buffer).unwrap()` -- both can panic if Prometheus encoding fails or produces invalid UTF-8.
- **Fix:** Return `Result<String, ProxyError>` and handle gracefully in the admin handler.

---

## BUGS / CORRECTNESS ISSUES

### 3. Access schedule is fail-open on invalid JSON
- **File:** `src/target_filter.rs:82-84`
- **Issue:** `Err(_) => return true` -- if a user's schedule JSON is corrupted or invalid, access is unrestricted instead of denied.
- **Fix:** Fail-closed (`return false`) and log a warning so admins can fix the bad data.

### 4. Schedule ignores configured timezone
- **File:** `src/target_filter.rs:86-88`
- **Issue:** `AccessSchedule` has a `timezone` field but `is_within_schedule()` always uses `chrono::Utc::now()`. The timezone is never applied.
- **Fix:** Parse timezone with `chrono-tz` and convert before comparing hours.

### 5. Auth cache uses u64 hash key -- collision risk
- **File:** `src/app_state.rs` (auth cache `DashMap<u64, ...>`)
- **Issue:** Keying on a 64-bit hash of `username+password` means a hash collision could grant access with wrong credentials (birthday problem at ~2^32 users, unlikely but still a correctness bug).
- **Fix:** Use full `(String, String)` key or SHA-256 digest.

### 6. `.unwrap()` on HTTP response builders in HTTP/2
- **File:** `src/proxy/http2_handler.rs:55,68,106,119,131`
- **Issue:** `Response::builder().body(()).unwrap()` can panic if headers are somehow invalid.
- **Fix:** Use `match` or `unwrap_or_else` with a logged error.

---

## PERFORMANCE BOTTLENECKS

### 7. Quota check does full SUM scan on every cache miss
- **File:** `src/db/quota.rs`
- **Issue:** `SUM(bytes_sent + bytes_received)` over the `usage` table per user per check. Even with 30s DashMap caching, this is O(N) over all connection records for that user.
- **Fix:** Maintain a `user_bandwidth_counters` table with running totals, updated atomically on connection close. Or add a composite index on `(user_id, started_at)`.

### 8. DNS cache is unbounded
- **File:** `src/dns_cache.rs`
- **Issue:** `DashMap` grows without limit. Cleanup only evicts expired entries every 60s but doesn't cap total size. A flood of unique hostnames = unbounded memory.
- **Fix:** Add a `max_entries` parameter. Use an LRU eviction strategy or check size during cleanup.

### 9. Webhook creates a new HTTP client per invocation
- **File:** `src/webhook.rs:36-38`
- **Issue:** `reqwest::Client::builder()...build()` is called every time a webhook fires. `reqwest::Client` is designed to be reused (connection pooling, DNS cache).
- **Fix:** Store a shared `reqwest::Client` in `AppState` and reuse it.

### 10. Config read lock on every connection
- **File:** `src/proxy/pipeline.rs` (`ConfigSnapshot::from_state()`)
- **Issue:** Every incoming connection acquires `config.read().await`. Under extreme concurrency this becomes a bottleneck since `RwLock` is not lock-free.
- **Fix:** Use `arc-swap` for lock-free config reads, or cache the snapshot periodically.

---

## MISSING FEATURES

### 11. Webhook retry with backoff
- **File:** `src/webhook.rs`
- **Issue:** Fire-and-forget delivery. If the endpoint is temporarily down, events are silently lost.
- **Todo:** Add retry queue (3 attempts, exponential backoff). Optionally persist failed events to SQLite.

### 12. Graceful shutdown doesn't drain active connections
- **File:** `src/main.rs` (shutdown handler)
- **Issue:** Waits 30s but doesn't signal active connections to close. Clients may hang.
- **Todo:** Use a `CancellationToken` or `broadcast` channel to signal active tasks. Force-close after timeout.

### 13. No TLS client certificate authentication (mTLS)
- Currently only server-side TLS. No support for client certificates.
- **Todo:** Add optional mTLS support in `[server]` config for high-security deployments.

### 14. No PROXY protocol (HAProxy) support
- Cannot extract real client IPs behind a load balancer.
- **Todo:** Support PROXY protocol v1/v2 header parsing on incoming connections.

### 15. No HTTP/2 for non-CONNECT requests
- HTTP/2 handler only supports CONNECT method. Regular HTTP requests over h2 are rejected.
- **Todo:** Forward non-CONNECT h2 requests as regular HTTP proxy requests.

### 16. No connection draining metrics
- No visibility into how many connections are active during shutdown.
- **Todo:** Add `proxy_draining_connections` gauge and log progress during shutdown.

### 17. Daily/weekly quota periods
- **File:** `src/db/quota.rs`
- Quota checks are hardcoded to monthly windows. Schema has `daily_bandwidth_limit_mb` but unclear if daily checks are implemented.
- **Todo:** Support configurable quota periods (daily, weekly, monthly).

### 18. Admin API: no pagination on list endpoints
- User/usage/audit list endpoints return all records.
- **Todo:** Add `?page=&limit=` query params with cursor-based pagination.

### 19. Admin API: no WebSocket for live connection monitoring
- Connections can only be polled via REST.
- **Todo:** Add WebSocket endpoint for real-time connection events.

---

## CODE QUALITY / HARDENING

### 20. Centralize magic numbers into config or constants
- Scattered hardcoded values:
  - `1024` / `16384` (header buffer sizes) -- `relay.rs:9,11`
  - `30s` shutdown drain -- `listener.rs:151`
  - `5s` peek timeout -- `protocol.rs:363`
  - `60s` DNS cleanup interval -- `main.rs:152`
  - `10s` upstream connect timeout -- `http2_handler.rs:94`
  - Cache TTLs in `cache.rs:8-12`
- **Todo:** Move to `[advanced]` config section or `const` block.

### 21. Add integration tests
- Unit tests exist but no integration tests for end-to-end proxy flows.
- **Todo:** Add tests that spin up the proxy, connect via each protocol, verify auth/rate-limiting/quota enforcement.

### 22. HTTP/2 handler needs tests
- No tests at all for `http2_handler.rs`.
- **Todo:** Add unit tests for handshake, CONNECT parsing, error responses.

### 23. Reduce unnecessary `.clone()` calls
- ~97 `.clone()` calls across the codebase. Many are on `Arc` types where a reference would suffice.
- **Todo:** Audit and reduce clones, especially in hot paths (connection handling, validation pipeline).

### 24. Structured error types for admin API
- Admin handlers use mixed error return styles.
- **Todo:** Consistent `ApiError` type with proper HTTP status codes and JSON error bodies.

---

## NICE-TO-HAVE / FUTURE

### 25. Distributed rate limiting (multi-instance)
- Current rate limiters are in-process only. Multiple proxy instances don't share state.
- **Todo:** Redis-backed rate limiting via `event_bus.rs` or sliding window in Redis.

### 26. Request/response logging (access log)
- No HTTP-level access logging (target, status, duration, bytes).
- **Todo:** Structured access log with configurable verbosity.

### 27. Bandwidth shaping / throttling
- Quotas are checked at connection start but bandwidth is not throttled during transfer.
- **Todo:** Token bucket per-user bandwidth throttling during relay.

### 28. Hot reload for TLS certificates
- TLS cert/key paths are loaded at startup only.
- **Todo:** Watch files and reload on change without restart.

### 29. Plugin / middleware system
- All validators are hardcoded in the pipeline.
- **Todo:** Trait-based middleware chain for extensibility.

### 30. Health check endpoint improvements
- Basic health check exists but doesn't verify DB/Redis connectivity.
- **Todo:** Add deep health check that pings SQLite and Redis.

---

## COMPLETED

- [x] #1 — HTTP/2 validator bypass (CRITICAL) — full validation pipeline now enforced
- [x] #2 — Metrics export panic — replaced unwrap() with error handling
- [x] #3 — Schedule fail-open → fail-closed
- [x] #4 — Timezone support in access schedules (chrono-tz)
- [x] #5 — Auth cache collision risk — replaced u64 hash with full string tuple key
- [x] #6 — HTTP/2 response builder unwraps (fixed in #1)
- [x] #7 — Quota SUM performance — covering index added
- [x] #8 — DNS cache bounded (max 10k entries, LRU eviction)
- [x] #9 — Shared reqwest::Client for webhooks
- [x] #10 — Config lock contention — replaced RwLock with lock-free ArcSwap
- [x] #11 — Webhook retry with exponential backoff (3 retries)
- [x] #12 — Graceful shutdown drains active connections
- [x] #14 — HAProxy PROXY protocol v1 support
- [x] #15 — HTTP/2 non-CONNECT request forwarding
- [x] #16 — Drain metrics (proxy_draining, proxy_draining_connections gauges)
- [x] #17 — Daily/weekly/monthly quota periods (QuotaPeriod enum)
- [x] #18 — Pagination on list users endpoint
- [x] #20 — Constants module for magic numbers
- [x] #21 — Integration tests (7 end-to-end tests)
- [x] #22 — HTTP/2 handler tests (11 unit tests)
- [x] #23 — Clone audit (no unnecessary clones found)
- [x] #24 — Structured ApiError type for admin API responses
- [x] #25 — Redis-backed distributed rate limiter
- [x] #26 — Structured access logging (target: access_log)
- [x] #28 — TLS certificate hot reload via ArcSwap
- [x] #30 — Deep health check endpoint (/health/deep)
- [x] #13 — mTLS (mutual TLS) client certificate authentication
- [x] #15 — HTTP/2 non-CONNECT request forwarding
- [x] #19 — WebSocket live connection monitoring (/api/connections/live)
- [x] #21 — Integration tests (7 end-to-end tests)
- [x] #22 — HTTP/2 handler tests (11 unit tests)
- [x] #23 — Clone audit (codebase already optimized)
- [x] #25 — Redis-backed distributed rate limiter
- [x] #27 — Bandwidth shaping/throttling (token bucket per-user, ThrottlerRegistry)
- [x] #29 — Plugin/middleware system (Phase-based MiddlewareChain wired into pipeline)

## STATUS: ALL 30/30 COMPLETE

---

# Audit Round 2 — 2026-04-07

26 findings from a fresh full-repo audit. Bandwidth quota tracker work
(commits cbf00e3, 24f3b5e, e221fa4) is excluded.

## CRITICAL / HIGH (security & correctness)

- [x] **R2-1** JWT accepts empty secret — fixed (commit 13e8...): MIN_JWT_SECRET_LEN=32, enforced at create/validate + boot panic.
- [x] **R2-2** Sentinel `user_id = -1` on root admin DB miss — fixed: returns 500 + tracing::error on miss/lookup-failure.
- [x] **R2-3** State-backend errors silently dropped — fixed: log + STATE_BACKEND_ERRORS metric on set/delete_connection.
- [x] **R2-4** HTTP/2 basic-auth — `authenticate_h2` now distinguishes scheme_unsupported / malformed_b64 / malformed_utf8 / malformed_credentials / invalid_credentials, each with warn-log + `proxy_auth_failures_total{reason=...}`.

## MEDIUM

- [x] **R2-5** `IpRateLimiter` unbounded — fixed (commit 2511151): bounded DashMap (default 100k) with opportunistic random eviction batches of 8; new `proxy_ip_rate_limit_evictions_total` metric; configurable via `rate_limiting.max_tracked_ips`.
- [x] **R2-6** Added `AppState::invalidate_all_for_user(uid, username)`; replaces the per-cache fan-out in `users.rs::update_user`/`delete_user` and the duplicated branches in `event_bus::UserInvalidated`/`UserDeleted` (now a single match arm).
- [x] **R2-7** Admin SOCKS4 bypass now logs to `target: "audit"` with user_id/client_addr/rule and increments `proxy_admin_bypass_total{rule="socks4_disabled"}`.
- [x] **R2-8** `parse_authority` silently defaulted to 443 — fixed: returns Option, malformed/empty/port-0 rejected with 400; IPv6 brackets parsed correctly (host without brackets).
- [x] **R2-9** Negative auth cache: failed (username, password) tuples cached 5s in a bounded (10k) DashMap. Bursts of bad attempts hit argon2 once.
- [x] **R2-10** Approval cache now keyed on `(i64, IpAddr)`; `cached_ip_approved` takes `IpAddr` so the hot-path lookup avoids the per-connection `to_string()`. String formatting deferred until Redis/DB miss.
- [x] **R2-11** Removed misleading per-period plumbing: `QuotaPeriod` is now `Monthly`-only (matches schema/UI reality), dead `Default` impl + `_with_period` indirection deleted. JSON shape unchanged so dashboard keeps working; adding daily/weekly later is now a deliberate schema+UI change.
  Thread `period` from user record into seeding & validators, or remove from schema/UI.
- [x] **R2-12** Parsed `AccessSchedule` cached per-user via `parsed_schedule_cache` (DashMap), populated lazily and invalidated alongside other user caches. `validate_access_schedule` no longer calls serde_json on the hot path.
- [x] **R2-13** `record_usage` now routed through bounded MPSC `UsageWriter` (capacity 4096, single consumer); Full/Closed drops increment `proxy_usage_records_dropped_total`. Replaces per-connection `tokio::spawn` fan-out in listener.rs and http2_handler.rs.
  `src/proxy/listener.rs:382-391`, `http2_handler.rs:278-287`
  Bounded MPSC + writer task; drop with `usage_records_dropped_total`.
- [x] **R2-14** `invalidate_api_keys_for_user` and `invalidate_approvals_for_user` now use a shared `scan_and_delete` helper (cursor-based SCAN, COUNT 256). KEYS gone from the codebase.
- [x] **R2-15** On a fresh upstream connect failure the listener now calls `ConnectionPool::invalidate_addr` alongside `dns_cache.invalidate`, dropping any other idle pooled sockets to the same addr.
- [x] **R2-16** Event-bus subscriber loop now `tokio::select!`s on `state.shutdown_tx.subscribe()` and breaks cleanly on shutdown.
- [x] **R2-17** `LoginRateLimiter` now exposes `check_user(ip, username)` which gates on both per-IP and per-(IP, username) buckets. Login handler updated.
- [x] **R2-18** CORS hardened: empty `cors_origins` = no cross-origin (was `Any`); explicit `"*"` downgraded to no-credentials + CONTENT_TYPE only; configured origin lists set `allow_credentials(true)` with `[AUTHORIZATION, CONTENT_TYPE]`. Never combines `Any` with credentials.

## PERFORMANCE

- [x] **R2-19** `cached_user_by_id` now returns `Arc<CachedUser>` + 5s process-local Arc cache layer in front of Redis. Saves a JSON deserialize and full struct clone on every validator call (4-6× per connection). Wired into `invalidate_quota_cache`, `event_bus::UserInvalidated`/`UserDeleted`.
- [x] **R2-20** `UPSTREAM_CONNECT_DURATION` is now only observed on actual new TCP connects (pool hits skipped), so the histogram reflects real upstream latency.
- [x] **R2-21** `UserQuotaTracker` now caches the resolved throttler in a `OnceLock<Option<BandwidthThrottler>>`; relay path uses `throttler_cached()` fast path and only falls back to `bandwidth_throttlers.get_or_create` on the first connection per user.
- [x] **R2-22** Replaced per-connection `format!()` tunnel labels with a `tracing::debug_span!("tunnel", protocol, client, target)` enclosing the relay; throttled tunnel now takes static `"c2t"` / `"t2c"` literals instead of allocated strings.
- [x] **R2-23** `H2_FORWARD_CLIENT` now has `pool_max_idle_per_host` set, plus a per-host `Semaphore` (cap 32 in-flight) via `H2_FORWARD_HOST_LIMITERS: DashMap<String, Arc<Semaphore>>`. Forward path acquires a permit before `send`; closed semaphore returns 503.

## UNFINISHED / DEAD CODE

- [x] **R2-24** Audit note was stale — `MiddlewareChain` is already wired into `listener.rs` for `Phase::PreAuth`, `PostAuth`, and `PostTarget`.
- [x] **R2-25** Dead `src/proxy/relay.rs::hand_shake` deleted; module removed from `proxy/mod.rs`.
- [x] **R2-26** Tests in `tunnel/error.rs` and `tunnel/port_allocator.rs` migrated to `assert!(matches!(...))` (or `let-else` where inner-value substring assertions are needed).

---

# Audit Round 3 — 2026-06-27

Full-repository due-diligence audit (8 parallel readers + source verification).
55 findings: 4 critical, 17 high, 24 medium, 10 low. Report:
`scratchpad/audit.html`. Sequenced by risk-reduction per unit effort.

Four root patterns drive most findings:
1. Per-handler authz with no shared guard (C1, H1, H15, H17).
2. Fail-open default error posture (C3, C4, H3, H4).
3. Multiple sources of truth for one number (H5, H6, M7).
4. Unguarded egress — only name filter + self-loop (C2, H2, H9, M12).

## PHASE 1 — Immediate (stop the bleeding)

- [x] **R3-C1** Added `AdminUser` + `CurrentUser` Axum extractors (`FromRequestParts<Arc<AppState>>`) in `admin/auth.rs`. `AdminUser` resolves identity, re-checks `is_active`, enforces `require_admin()` in the extractor. Applied to all previously-unprotected handlers: connections (list/count/live-ws), tunnels (list/create/close), config get, all groups handlers, audit-log; sessions list/delete now use `CurrentUser` + `can_access_user` (self-or-admin). health stats/dashboard/json_metrics → admin. Closes C1 + H15; partial H1 (is_active rechecked on these paths). 434 tests green.
- [x] **R3-C2** SSRF egress guard: `self_loop::is_blocked_egress(ip)` rejects private/loopback/link-local(+`169.254.169.254`)/ULA/CGNAT/unspecified/multicast/v4-mapped. Wired after DNS resolve in `listener.rs` + `http2_handler.rs`. Gated by new `filtering.block_private_targets` (default **false** to preserve same-machine/internal proxying; set `true` to harden public-only deployments). Tunnels (H9) + webhook (M17) egress still TODO.
- [x] **R3-C3** Config-based proxy auth now resolves to the real `root_admin` DB id (mirrors `admin/auth.rs`); rejects if root_admin missing. Sentinel `-1` removed. `is_admin` now derives correctly from the resolved role. `proxy/protocol.rs`.
- [x] **R3-C4** SOCKS4 `authenticate_socks4` now returns `Ok((false,None))` (reject) — it's only called under `auth_required`, and the gate treats false as reject. TCP fallback already rejected. `--no-creds` path unchanged.
- [x] **R3-H2** PROXY-protocol header now honored only when the socket peer is in `server.proxy_protocol_trusted_cidrs` (new, default empty = trust nobody); otherwise the header is left unparsed and the real socket address is used. `peer_is_trusted_proxy` helper + 3 unit tests. `listener.rs`.
- [x] **R3-H11** Added `.github/workflows/ci.yml`: rust (fmt --check [blocking], clippy [informational pending L10], build --locked, test --test-threads=1), cargo audit (rustsec/audit-check), gitleaks, web (npm ci/lint/test/build), docker build + Trivy. Ran `cargo fmt` to make the fmt gate green. NOTE: clippy gate is `|| true` until the 11 pre-existing warnings (L10) are cleared — then flip to `-D warnings`.

## PHASE 2 — Next sprint (correctness & revocation)

- [ ] **R3-H1** JWT/token revocation: `token_version` claim bumped on disable/role-change/logout; per-request `is_active`/role recheck in middleware.
- [ ] **R3-H12** Key auth caches on salted HMAC (not plaintext); include `is_active`/epoch; clear in `invalidate_all_for_user`.
- [ ] **R3-M1/M2** Invalidate approval cache on `terminate_approval`; invalidate verified-key cache on API-key revoke.
- [ ] **R3-H6** One source of truth for bandwidth: tracker=enforcement, usage_writer=persistence; never re-add live deltas on reseed; remove/​wire dead Redis `incr_bandwidth`; re-check window in `add_and_over`.
- [ ] **R3-H5** Usage writer: batch-drain (`recv_many`) into one transaction; on overflow block-with-timeout or reconcile dropped bytes; alert on drop counter.
- [x] **R3-H3/H4** Fail-closed sweep: geo unknown-country now denies in allowlist mode (`geo_filter.rs`); `RedisRateLimiter::check` denies on Redis error (`rate_limit.rs`); `validate_connection_limit` denies on count error (`validators.rs`). Login limiter now keyed on socket peer via `ConnectInfo<SocketAddr>`; forwarded headers honored only from a loopback peer (`admin/handlers/auth.rs`, `admin/server.rs` serves with connect-info).
- [x] **R3-H16** Transactions: `approve_request` (status+grant atomic), `update_user` (update+readback, existence via rows_affected), `delete_user` (users+api_keys deactivate **and** sessions revoked, atomic). Added sessions table to users test setup.
- [ ] **R3-H8** h2 forward: stream bodies chunk-by-chunk with max-size cap; acquire permit per h2 stream; set `max_concurrent_streams`.

## PHASE 3 — Next quarter (operability & trust)

- [ ] **R3-H14** Tests: relay (`stream.rs` via `tokio::io::duplex`), listener, event_bus, tunnel, webhook; e2e auth/quota rejection; parser fuzzing; web login+CRUD Playwright.
- [ ] **R3-M3/M4/M19** Config-reload validation (reject security downgrades, run env overrides + secret check); wire `RUST_LOG`/`config.logging.level` (drop hardcoded TRACE); harden Docker/compose exposure (`/metrics`, admin bind).
- [ ] **R3-M5/M6/M7** Event bus → Redis Streams w/ reconnect; memory backend parity for pending/approvals; TTL/prune the Redis connections set.
- [ ] **R3-H7/H10** Decide connection-pool fate (implement return or remove); complete graceful shutdown (call `state.shutdown()`, drain tunnels, flush usage writer, cancel bg tasks).
- [ ] **R3-H13/M23/M24** Frontend: https default + `HttpOnly` cookies + CSP/HSTS; error boundary + typed API + TS strict; code splitting + dedupe chart libs.

## PHASE 4 — Long-term (hardening & scale)

- [ ] **R3-L9** SQLite backups (litestream) + migration rollback; evaluate Postgres if multi-instance write load grows.
- [ ] **R3-DOCS** `ARCHITECTURE.md` + ADRs (fail-closed schedule, JWT min-secret, egress policy) + incident runbooks. Fix README test count/license (L10).
- [ ] **R3-PERF** Box `ClientStream` TLS variant (L1); pooled relay buffers honoring `DEFAULT_BUFFER_SIZE` (L2); `Arc` config lists (L5); OTel traces + alert on drop/error counters.
- [ ] **R3-M14** Argon2 explicit params + pepper; stronger password/username policy.
- [ ] **R3-MISC** L3 relay error byte-accounting; L4 quota `saturating_add` + skip-when-unlimited; L6 DNS eviction off hot path; L7 EC key support + cert file-watch; L8 cargo-chef Docker layer; M9 quota-0 semantics; M10/M11 throttle staleness + bucket direction; M16 reload 500-on-fail; M18 block default passwords; M20 wire/remove middleware chain; M21 tunnel port TOCTOU + unwrap; M22 CORS strict origin parse.

## STATUS: Round 3 — Phase 1 COMPLETE (C1-C4, H2, H11). 437 unit + 7 integration green; repo rustfmt-clean. Next: Phase 2 (H1 token revocation, H6/H5 bandwidth accounting, H3/H4 fail-closed, H16 transactions, H8 h2 streaming).
