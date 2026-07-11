# webv2 — Next-Generation Admin Console: Audit & Development Plan

> Produced from a full audit of the `bck` branch: every Rust admin handler, the
> WebSocket implementation, and the entire existing `web/` frontend. `web/` is
> left untouched; the new console lives in `webv2/` and both coexist during
> development.

---

## 1. Repository analysis (summary)

**Backend** — Rust/axum admin API on `:8081` fronting a multi-protocol forward
proxy (HTTP/HTTPS/SOCKS4/SOCKS5, single-port autodetect). SQLite via sqlx,
optional Redis cache, Prometheus metrics, JWT + Basic auth, three roles
(`root_admin` > `admin` > `user`). ~45 REST endpoints + 1 WebSocket.
Error body is `{error, detail}` JSON everywhere **except** `/api/login`
(plain text). All timestamps are unix seconds. Bodies capped at 1 MB.

**Existing frontend (`web/`)** — Lovable-generated TanStack Start (SSR shell,
Nitro node-server) with React 19, Tailwind v4, framer-motion, TanStack
Query/Router. Visually polished dark glass theme, but carries significant
defects (§3).

## 2. API inventory (complete)

### Used by webv2 (everything)

| Area | Endpoints | Notes |
|---|---|---|
| Auth | `POST /api/login` | Returns `{token, expires_in, role}` — **no user id**; webv2 decodes JWT claims (`sub`, `user_id`, `role`, `exp`) |
| Health | `GET /health`, `GET /health/deep` | deep: `checks.{database,state_backend,dns_cache}` with `latency_ms`, `checked_at` |
| Telemetry | `GET /api/dashboard`, `GET /api/metrics` (JSON), `GET /stats` | `/api/metrics`: protocol mix, auth failures by reason, p50/p95/p99, draining |
| Usage | `GET /api/usage/summary?days&limit`, `GET /api/usage/timeseries?days&bucket=hour\|day` | timeseries omits empty buckets — client must gap-fill |
| Users | `GET/POST /api/users` (envelope `{items,total,limit,offset}`, cap 200), `GET/PUT/DELETE /api/users/:id` | create = root_admin; PUT self(password)/root(all) |
| Per-user | `/usage`, `/usage/recent?limit`, `/usage/all-time`, `/quota` (GET/PUT), `/api-keys` (GET/POST/DELETE), `/sessions` (GET/DELETE), `/approvals`, `/groups` | `/groups` is **admin-only even for self**; sessions table is never populated by backend (§3) |
| Connections | `GET /api/connections`, `GET /api/connections/count`, `DELETE /api/connections/:id`, `POST /api/connections/live-ticket`, `WS /api/connections/live?ticket=` | terminate returns 204/404 |
| Tunnels | `GET/POST /api/tunnels`, `DELETE /api/tunnels/:port` | `service_type` returns Rust Debug strings (`"Database(Postgres)"`) — webv2 normalizes |
| Approvals | `GET/POST /api/approvals`, `DELETE /api/approvals/:id` (**JSON body `{reason}` required**), `GET/POST /api/approval-requests`, `POST .../:id/approve`, `POST .../:id/reject` | request POST is self-scoped from token |
| Groups | `GET/POST /api/groups`, `GET/DELETE /api/groups/:id`, `GET/POST /api/groups/:id/members`, `DELETE .../members/:user_id` | groups carry policy fields (limits, schedules) the old UI never displayed |
| Audit | `GET /api/audit-log?limit&offset&user_id&action` | server-side filters — old UI ignored them |
| Config | `GET /api/config`, `PUT /api/config` (root_admin; 3 fields), `POST /api/config/reload` | |

### Previously unused / underused (now integrated)

- `GET /api/metrics` (JSON) — never called by old UI → powers Health + Dashboard.
- `DELETE /api/connections/:id` — existed, no UI → terminate action in webv2.
- `GET /api/connections/count` — cheap poll for topbar live badge.
- `GET /api/users/:id` — enables a real, deep-linkable user detail page.
- Audit server-side `user_id`/`action`/`offset` — real pagination + filters.
- Tunnel telemetry (`bytes_transferred`, `total_connections`, `active_connections`).
- Group policy fields — displayed on group detail.

### Known backend caveats webv2 designs around

1. **WS pushes only when connection count changes** — byte counters do not
   stream. webv2 merges WS (instant add/remove) with REST polling (byte/state
   refresh) and computes client-side transfer rates from deltas.
2. **Sessions are never written** by the backend (`create_session` is never
   called) — webv2 does not ship a dead Sessions tab.
3. Login errors are plain text; everything else `{error, detail}`.
4. `top_users` / audit entries carry only `user_id` — webv2 resolves usernames
   via a cached user directory (admins) and degrades gracefully otherwise.
5. Password rules: create = 8–128 chars with ≥1 letter and ≥1 digit; webv2
   enforces the strict rule client-side everywhere.

## 3. Current UI audit — defects driving the rebuild

**Broken flows**
- `<Toaster>` never mounted → every success/error toast in the app is
  invisible. All mutation feedback is silently lost.
- API Keys page resolves "me" by scanning the full user list — non-admins
  can't list users, so the page is dead for exactly the users it serves.
- Command-palette deep links (`?new=1`, `?id=X`) target search params no route
  reads.
- Connection terminate exists in the API client but has no UI.
- WS fallback-to-polling only engages if the *first* connect throws; a socket
  that opens then drops retries forever with a fixed 3 s delay.
- Copy button in the connection drawer has no click handler.

**Fabricated data** — latency hardcoded `0`, health sparklines are
random-number generators, "all systems normal"/"streaming"/"active" pills are
static strings, `SystemStats.healthy` always `true`, `user.groups`/
`group.policies` always `[]`, login form pre-fills `root`/`crabby`.

**Missing** — pagination (anywhere), server-side filtering, user detail
routes, skeletons, error states, notifications, light mode, reduced-motion
support, mobile navigation (sidebar is `hidden lg:flex` with no replacement —
below 1024 px the app has no nav).

**Waste** — all 48 shadcn `ui/*` primitives unused (yet keep ~25 Radix
packages, recharts, react-hook-form, zod, embla, vaul… in the bundle);
duplicate poll loops on the connections page; the real WS client lives in
`src/mock/live.ts`.

**Accessibility** — clickable `<li>` rows with no keyboard support, hand-rolled
modals without focus traps/Esc, unlabeled inputs, sub-AA contrast at 10–11 px.

## 4. UX & product review (friction points)

| Friction | webv2 answer |
|---|---|
| No feedback after any action | Mounted toast system + inline optimistic states |
| Can't link to a user/group/connection | Real routes: `/users/:id`, `/groups/:id`; drawers carry URL state |
| Non-admin experience is an afterthought (lands on approvals, broken keys page) | Dedicated **Account** area: own profile, quota gauge, API keys, usage, approvals — powered by JWT identity, zero admin endpoints |
| Truncated lists masquerade as complete (users 200, audit 100) | Server-side pagination with visible totals |
| Silent failures render as empty states | Distinct loading / empty / error states with retry, per section |
| Live page can't act on what it shows | Terminate connection (with confirm), copy anything, per-row rates |
| No global navigation speed | ⌘K palette (pages, actions, users) with working deep links + `g` shortcut chords |
| Status is decorative | Live pills driven by `/health/deep`, WS socket state, draining flag |
| Admin can't see "who is this user id" | Username resolution everywhere + linked chips |

## 5. Design vision

**Feel**: premium instrument panel — Linear/Vercel/Stripe school. Calm ink
surfaces, one confident accent, mono for all machine data (IPs, ports, bytes,
IDs), restrained motion that communicates state change rather than decorates.

- **Dark-first** with a true light theme; `system` default, toggle persisted.
- **Color**: ink `oklch` near-black with a subtle blue undertone; layered
  surfaces; hairline borders. Accent: **teal** (instrument/network feel);
  brand **crab coral** reserved for the logomark and hero gradient moments.
  Semantics: success green / warning amber / danger rose / info blue —
  theme-independent, never color-only (always paired with a label or icon).
- **Type**: Inter Variable (UI) + JetBrains Mono Variable (data),
  tabular-nums for all metrics; 12/13/14/16/20/28 scale; uppercase eyebrows.
- **Depth**: 1 px hairlines > shadows; glass only on overlays (palette,
  drawers) where it aids layering.
- **Motion** (all gated by `prefers-reduced-motion`): 150–250 ms springs for
  micro-interactions, page cross-fade + 8 px rise, staggered card reveals,
  count-up numerals, chart draw-in, row enter/exit in live tables, skeleton
  shimmer → content cross-fade, drawer/modal springs, sidebar rail collapse,
  live-dot pulse tied to real socket state.

## 6. New architecture

```
webv2/
├── package.json / vite.config.ts / tsconfig.json / index.html
├── Dockerfile                  # bun build → nginx static (no SSR runtime)
├── README.md
└── src/
    ├── main.tsx                # providers: Query, Theme, Toaster, Router
    ├── app.tsx                 # route table (react-router v7), guards, transitions
    ├── api/
    │   ├── http.ts             # fetch core: base URL, bearer, 401 handling, ApiError
    │   ├── types.ts            # exact wire types for every endpoint
    │   └── endpoints.ts        # one typed function per endpoint (full coverage)
    ├── lib/
    │   ├── auth.ts             # session store, JWT decode (user_id/sub/role/exp)
    │   ├── format.ts           # bytes, duration, relative time, protocol/service names
    │   └── utils.ts            # cn(), gap-fill for timeseries, etc.
    ├── hooks/
    │   ├── queries.ts          # TanStack Query hooks, keys, invalidation map
    │   ├── use-live-connections.ts  # ticket → WS → merge with poll, backoff+jitter,
    │   │                            # fallback engages on ANY drop, rate computation
    │   ├── use-hotkeys.ts      # ⌘K, g-chords
    │   └── use-theme.ts        # dark/light/system, persisted
    ├── components/
    │   ├── ui/                 # button, input, select, dialog(Radix), dropdown(Radix),
    │   │   …                   # tooltip(Radix), tabs, switch, badge, card, table, kbd,
    │   │                       # skeleton, progress, empty/error-state, pagination,
    │   │                       # copy-button, stat-card, search-input, sheet
    │   ├── charts/             # animated SVG: area, bar-list, donut, sparkline, gauge
    │   ├── motion/             # PageTransition, Reveal, AnimatedNumber, Stagger
    │   └── layout/             # AppShell, Sidebar (rail + mobile sheet), Topbar,
    │                           # CommandPalette, NotificationsPopover, ThemeToggle
    └── pages/
        ├── login.tsx
        ├── dashboard.tsx       # bento: KPIs, traffic area chart, protocol donut,
        │                       # top users, live feed, activity timeline, health strip
        ├── connections.tsx     # live table + terminate + rates + filters
        ├── tunnels.tsx         # telemetry cards + create wizard
        ├── users/index.tsx     # paginated directory + create
        ├── users/detail.tsx    # /users/:id — profile, quota, keys, usage, approvals, groups
        ├── groups/{index,detail}.tsx
        ├── approvals.tsx       # request workflow + grants
        ├── usage.tsx           # analytics: range picker, area chart, leaderboard, export
        ├── audit.tsx           # server-side filter + pagination + export
        ├── health.tsx          # real component latencies, protocol mix, failure reasons
        ├── config.tsx          # runtime config + root-admin edit + reload
        └── account.tsx         # self-service home (any role)
```

**Stack**: Vite 7 SPA (no SSR — an authenticated console gains nothing from it
and loses build/runtime simplicity), React 19, TypeScript strict,
react-router 7, TanStack Query 5, Tailwind 4 (CSS-first tokens),
motion (framer-motion 12), small Radix set (dialog/dropdown/tooltip/tabs/
switch/select), cmdk, sonner, lucide-react, self-hosted variable fonts.
Charts are hand-built animated SVG — zero chart-library weight, full motion
control.

**Data layer rules**
- Query keys namespaced per domain, invalidation map alongside mutations.
- Optimistic updates for revoke/terminate/toggle with rollback on error.
- Polling gated by `document.visibilityState` and paused when WS is healthy.
- Every mutation: pending state on the trigger, success/error toast, focus
  return.

## 7. Feature parity + new capabilities

Parity: everything the old UI does (login/role routing, dashboard KPIs, live
connections, tunnels CRUD, users CRUD + quotas + API keys, groups + members,
approvals workflow, usage summary, audit, config view/edit/reload, deep
health).

New in webv2:
1. **Command palette** with real actions + working deep links.
2. **User detail pages** (`/users/:id`) — deep-linkable, tabbed.
3. **Account area** for every role (fixes broken self-service).
4. **Connection terminate** + client-computed live transfer rates.
5. **Server-side pagination/filtering** on users and audit.
6. **Notifications center**: degraded health, draining state, pending
   approval requests (badge count polls cheap endpoints).
7. **Keyboard shortcuts**: ⌘K, `g d/c/u/a…` navigation chords, `?` help.
8. **CSV export** (client-side) for usage leaderboard and audit log.
9. **Theme system**: dark / light / system with FOUC-free boot.
10. **Live health strip** on dashboard driven by `/health/deep` + WS state.
11. **Approval workflow polish**: pending badge, one-click approve with
    reason, terminate with required-reason validation inline.
12. **Copy-anything** mono chips (IPs, IDs, ports, keys) with confirmation.

Deliberately not built: sessions tab (backend never records sessions), bulk
mutations (no backend endpoints), per-connection latency (not exposed).

## 8. Implementation roadmap

1. **Scaffold** — tooling, tokens, fonts, theme boot, providers. ✅ this PR
2. **Design system** — ui/ primitives, motion/ primitives, charts/. ✅ this PR
3. **API layer** — types.ts + endpoints.ts (full coverage), auth, queries. ✅ this PR
4. **Shell** — sidebar/topbar/palette/notifications/theme, route guards. ✅ this PR
5. **Pages** — all 13 routes with loading/empty/error states. ✅ this PR
6. **Hardening** — typecheck, build, lint, responsive + reduced-motion pass. ✅ this PR
7. **Follow-ups** (post-PR): visual QA against a live backend, Playwright
   smoke tests, virtualized tables for >1k rows, backend session recording so
   a Sessions view becomes honest, `/api/usage/timeseries` per-user variant.

---

*Everything in §2 was verified against handler source on `bck`; wire types in
`webv2/src/api/types.ts` mirror the Rust structs field-for-field.*
