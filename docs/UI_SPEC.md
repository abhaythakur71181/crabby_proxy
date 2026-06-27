# Crabby Proxy — UI / System Design Spec

> Complete, implementation-grounded context for redesigning the admin console.
> Everything below is derived from the actual codebase (Rust backend `src/`,
> React frontend `web/src/`), not invented. Assumptions are marked **[A]**.

---

## 1. Product Overview

| | |
|---|---|
| **Product name** | Crabby Proxy |
| **Domain** | Infrastructure / DevSecOps — a self-hosted, multi-tenant **authenticated forward proxy** with an admin control plane |
| **What it is** | A Rust proxy that accepts HTTP, HTTPS (CONNECT), SOCKS4, SOCKS5, and HTTP/2 client traffic, authenticates each client, enforces per-user policy (quotas, rate limits, target allow/deny, schedules, IP/geo filters, connection approval), and relays to upstream targets. A React admin console manages users and observes traffic. |
| **Core problem** | Teams need a controllable, auditable egress proxy: who may use it, where they may go, how much, and when — with a live view of activity. |
| **Target users** | **Operators/SecOps** (run + monitor the proxy), **Team admins** (manage users/quotas/approvals), **End users** (proxy consumers who request access and watch their own usage). |
| **Primary user goals** | Operator: see live connections, health, audit trail; control config. Admin: provision users, set quotas/limits, approve access, revoke. User: request access, get an API key, see own usage/quota. |
| **Business goals** | Sell as multi-tenant egress infrastructure; differentiate on per-user policy granularity, live observability, and a clean admin UX. |

**Tech reality (for the redesign):** Frontend is Vite + React 18 + React Router 6 + TanStack Query + shadcn/ui (Radix) + Tailwind + chart.js, served by nginx, talking to a Rust/axum admin API on `:8081`. Dark theme today via a `glass-card` aesthetic. Auth is a JWT bearer stored in `localStorage` **[A: migrate to HttpOnly cookie is a known backlog item]**.

---

## 2. Roles & Permissions

Three roles exist in the backend (`Role` enum: `root_admin`, `admin`, `user`). Authorization is enforced server-side by axum extractors: `AdminUser` (admin or root_admin) and `CurrentUser` + `can_access_user` (self-or-admin).

| Role | Description | Permissions | Accessible pages | Restrictions |
|---|---|---|---|---|
| **root_admin** | Superuser; the singleton bootstrap account. | Full CRUD on users (incl. create/delete, role change, quota, activate/deactivate), config reload, tunnels, groups, approvals, audit, all telemetry. | All | Cannot be deleted casually; the only role that may change another user's role/quota/active state. |
| **admin** | Team administrator. | Read all users; manage API keys, quotas (via quota endpoint), approvals, groups, tunnels, connections, audit, telemetry. **Cannot** change user role/active/quota fields via `PUT /api/users/:id` (root_admin only) or create/delete users. | All admin pages | No user create/delete; no role escalation. |
| **user** | Proxy consumer. | Read **own** profile, usage, quota, sessions, API keys, approvals; create own approval **requests**; change own password. | Approvals (own requests), own profile / API keys / usage | No access to other users' data; no admin pages, config, tunnels, audit, connections list, or system health. Server returns 403; UI hides nav + routes (AdminRoute guard). |

**Proxy-side auth (separate from UI):** proxy clients authenticate with Basic, SOCKS5 user/pass, or API key (`username@apikey` + key as password). Config-credential auth resolves to the real `root_admin` id.

---

## 3. App Architecture (Information Architecture)

```
Crabby Proxy Admin Console
│
├── Auth
│   └── /login                      Login (public)
│
├── Overview            [admin]
│   ├── /dashboard                  KPIs + 24h trends + top users
│   └── /system-health              Live metrics, latency percentiles, draining state
│
├── Traffic             [admin]
│   ├── /connections                Live active connections (2s WebSocket feed)
│   └── /tunnels                    Reverse tunnels (create / close)
│
├── Access Control
│   ├── /users          [admin]     User list + create
│   │   └── /users/:id  [self|admin] User detail (profile, quota, keys, sessions, usage, groups)
│   ├── /groups         [admin]     User groups
│   │   └── /groups/:id [admin]     Group detail + members
│   ├── /api-keys       [self]      Own API keys (renders UserDetail for self)
│   └── /approvals      [self|admin] Approval requests workflow + active approvals
│
├── Usage               [admin]
│   └── /usage                      System usage summary + top users leaderboard
│
└── Operations          [admin]
    ├── /audit-log                  Admin action audit trail (filter/paginate)
    └── /configuration              Redacted runtime config + reload
```

**Navigation:** collapsible left sidebar (icon-rail when collapsed) + a top bar (page title, user menu). Sidebar items are role-filtered (`adminOnly` flag). Footer of sidebar shows the current user + role badge + logout.

**Surfaces:** Pages, **modals** (create/edit/confirm dialogs), **drawers** **[A: recommend for detail panels]**, **toasts** (sonner).

---

## 4. Complete Page List + Purpose

| Page | Route | Purpose | Key components | Primary actions | Data |
|---|---|---|---|---|---|
| Login | `/login` | Authenticate | Form, error alert | Sign in | — |
| Dashboard | `/dashboard` | At-a-glance system state | KPI cards, top-users bar, status | (read) | dashboard summary |
| System Health | `/system-health` | Operational telemetry | Protocol chart, auth-failure chart, latency bars, counters, draining banner | (read, poll) | `/api/metrics`, health |
| Connections | `/connections` | Live active connections | Live table, count, status dot | (read, live) | connections + count |
| Tunnels | `/tunnels` | Reverse tunnels | Table, create dialog | Create / Close tunnel | tunnels list |
| Users | `/users` | Manage users | Paginated table, search, create dialog | Create user, navigate to detail | users (paginated) |
| User Detail | `/users/:id` | Single user mgmt | Tabs: profile, quota, API keys, sessions, usage, groups; edit/deactivate/reactivate | Edit, deactivate/reactivate, create/revoke key, force-logout, set quota | user + 6 sub-resources |
| Groups | `/groups` | Group list | Table, create dialog | Create / delete group | groups + counts |
| Group Detail | `/groups/:id` | Members | Members table, add/remove | Add / remove member | group + members |
| API Keys | `/api-keys` | Own keys (self) | (UserDetail for self) | Create / revoke key | own keys |
| Usage Summary | `/usage` | System usage | KPI cards, top-users bar + leaderboard | (read) | usage summary |
| Approvals | `/approvals` | Access workflow | Tabs: pending / decided requests, active approvals; create/terminate dialogs | Request, approve, reject, create, terminate | approval requests + approvals |
| Audit Log | `/audit-log` | Admin action trail | Filterable paginated table, expandable rows | Filter, paginate | audit entries |
| Configuration | `/configuration` | Runtime config (redacted) | Read-only cards, reload button | Reload config | config (redacted) |

---

## 5. Page-by-Page UI Breakdown

Conventions for every page: **layout** → **sections (top→bottom)** → **components** → **interactions** → **empty/loading/error** → **responsive**.

### Login `/login`
- **Layout:** centered single-column card on a full-bleed background.
- **Sections:** brand mark → title → username/password form → submit → error region.
- **Components:** text inputs, primary button, inline error alert.
- **Interactions:** submit → `POST /api/login`; on success store token + route by role (admin → `/dashboard`, user → `/approvals`); on 401 show "Invalid credentials".
- **States:** loading (button spinner), error (alert), disabled (while submitting).
- **Responsive:** card max-width ~400px, full-width on mobile.

### Dashboard `/dashboard` (admin)
- **Layout:** KPI card grid (4 across desktop) → charts row → status.
- **Sections:** KPIs (active connections, total connections, 24h bandwidth, total users) → top users (24h) bar chart → tunnels/active count.
- **Components:** StatCard ×N, horizontal bar chart, status dot.
- **Data:** `GET /api/dashboard` → `{uptime_seconds, version, status, active_connections, total_connections, bytes_sent, bytes_received, total_bandwidth, bandwidth_24h, connections_24h, total_users, top_users_24h:[{user_id,bandwidth,connections}], active_tunnels}`.
- **States:** skeleton while loading; cards show "—"/0 if a metric is null; error → inline empty state.
- **Responsive:** 4→2→1 column KPI grid; chart scrolls in its own container.

### System Health `/system-health` (admin)
- **Layout:** draining banner (conditional) → KPI row → charts (protocol mix doughnut, auth-failure-by-reason bar) → latency percentile bars → counters list.
- **Data:** `GET /api/metrics` → `{active_by_protocol{}, bytes_transferred{sent,received}, requests_total{success,failed}, auth_failures_by_reason{}, ip_filter{allowed,blocked}, rate_limit_exceeded{ip,user}, connection_duration_p50/p95/p99, draining, draining_connections}`; plus `GET /health/deep`.
- **Interactions:** polls every 10–30s.
- **States:** skeleton; "no traffic yet" empty; degraded badge if deep-health reports a failing component.

### Connections `/connections` (admin)
- **Layout:** header with live count + status dot → table.
- **Components:** table (client IP, target, protocol, bytes, age), live badge.
- **Data:** `GET /api/connections` (array of ConnectionInfo) + `GET /api/connections/count`; **live** via WebSocket `/api/connections/live` (2s snapshots).
- **States:** "No active connections" empty; reconnecting indicator on WS drop.
- **Responsive:** table → horizontal scroll on mobile; consider card list on small screens.

### Tunnels `/tunnels` (admin)
- **Layout:** header + Create button → table.
- **Components:** table (port, target, service type, created), Create Tunnel dialog (service type, optional port, target addr), Close action.
- **Data:** `GET /api/tunnels` → `{tunnels:[{tunnel_id,listen_port,target_addr,service_type,created_at}], total}`.
- **Interactions:** create → `POST /api/tunnels`; close → `DELETE /api/tunnels/:port`.
- **States:** "Reverse tunnels disabled" (feature flag) / "No tunnels" empty; create errors as toast.

### Users `/users` (admin)
- **Layout:** header + search + Create (root_admin) → paginated table.
- **Components:** table (username, role badge, status dot, max conns, quota, created, last login), pagination, Create User dialog.
- **Data:** `GET /api/users?limit&offset` → `{items:[UserResponse], total, limit, offset}` (always this envelope).
- **Interactions:** row → `/users/:id`; create → `POST /api/users` (root_admin only).
- **States:** skeleton rows; "No users" empty; create validation errors inline.

### User Detail `/users/:id` (self or admin)
- **Layout:** header (name, role badge, status dot, actions) → tabbed sections.
- **Tabs/sections:** Profile (id, role, status, created, last login, max conns, bandwidth limit) · Quota (used/limit/remaining/% with progress) · API Keys (list + create + revoke) · Sessions (list + force-logout) · Recent Usage (table) · Groups (membership).
- **Actions:** Edit (root_admin), Deactivate / **Reactivate** (root_admin), Create/Revoke API key (self+/admin), Force-logout sessions, Set quota (admin).
- **Data:** `GET /api/users/:id`, `/quota`, `/api-keys`, `/sessions`, `/usage/recent`, `/groups`.
- **States:** per-tab skeleton; "no keys/sessions/usage" empties; deactivate dialog clarifies it's reversible.

### Groups `/groups` + Group Detail `/groups/:id` (admin)
- **Groups:** table (name, description, member count), Create dialog, Delete.
- **Detail:** members table, Add member (by user), Remove member.
- **Data:** `GET /api/groups` (array of `{...,member_count}`), `GET /api/groups/:id`, `GET /api/groups/:id/members` → `{group_id, members:[], total}`.

### Usage Summary `/usage` (admin)
- **Layout:** KPI row (total connections, total bandwidth, unique users, data sent) → top-users bar chart + leaderboard table.
- **Data:** `GET /api/usage/summary` → `{period_days, total_connections, total_bytes_sent, total_bytes_received, total_bandwidth, unique_users, top_users:[{user_id, total_bandwidth, connection_count}]}`. (No username on top_users → label by id, link to detail.)
- **States:** skeleton; empty when no usage; guard against missing `top_users`.

### Approvals `/approvals` (self + admin)
- **Layout:** tabs — **Pending requests**, **Decided requests**, **Active approvals** (admin).
- **Components:** request table (user, client IP, duration, reason, requested-at, status), decide dialog (approve/reject + reason), create-approval dialog (admin), terminate dialog (reason required).
- **Data:** `GET /api/approval-requests` (admin: all; user: own), `GET /api/approvals` (admin) → active grants.
- **Interactions:** user → `POST /api/approval-requests`; admin → approve `POST .../:id/approve`, reject `POST .../:id/reject`, create `POST /api/approvals`, **terminate** `DELETE /api/approvals/:id {reason}` (immediate, cache-invalidated).
- **States:** non-admin sees only own requests; empties per tab; reason-required validation on terminate.

### Audit Log `/audit-log` (admin)
- **Layout:** filter bar (user_id, action, limit/offset) → paginated table with expandable detail rows.
- **Data:** `GET /api/audit-log?limit&offset&user_id&action` → `{entries:[{id,user_id,action,target_type,target_id,details,ip_address,created_at}], total, limit, offset}`. (No username → show `User #<id>`.)
- **States:** skeleton; "No audit entries" empty.

### Configuration `/configuration` (admin)
- **Layout:** read-only cards (server bind, max conns, auth enabled, features) → Reload button (admin/root).
- **Data:** `GET /api/config` (redacted — no secrets) → `{server:{proxy_bind,admin_bind,max_connections}, authentication:{enabled}, features:{connection_approval,reverse_tunnels}}`.
- **Interactions:** reload → `POST /api/config/reload` (returns 200/`{success,message}`, 500 on failure). Note: security-critical fields are preserved server-side on reload.

---

## 6. API Design (Full Coverage)

Base: admin API on `:8081`. Auth: `Authorization: Bearer <JWT>` (or Basic) on all non-public routes; middleware re-checks the user is active each request. Error body: `{ "error": string, "detail": string|null }` with matching HTTP status (login returns plain text). List envelopes are mixed today (some bare arrays, `/api/users` + `/api/audit-log` are `{items|entries,total,limit,offset}`).

### Auth
| Endpoint | Method | Auth | Purpose | Request | Response |
|---|---|---|---|---|---|
| `/api/login` | POST | public (rate-limited per IP) | Login | `{username,password}` | `{token, expires_in, role}` |

> **[A] Backlog:** no `/logout` or `/refresh` endpoint today; logout is client-side only, and JWT revocation on logout/password-change is a known follow-up.

### Users & profile
| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/users` | GET | admin | `{items:[UserResponse],total,limit,offset}`; `?limit&offset` (limit cap 200) |
| `/api/users` | POST | root_admin | create `{username,password,role,max_connections?,bandwidth_limit_mb?}` |
| `/api/users/:id` | GET | self/admin | `UserResponse` |
| `/api/users/:id` | PUT | self(password)/root_admin(all) | `{password?,role?,max_connections?,bandwidth_limit_mb?,is_active?}` |
| `/api/users/:id` | DELETE | root_admin | soft delete (deactivate + revoke keys/sessions) |
| `/api/users/:id/groups` | GET | admin | `[UserGroup]` |

`UserResponse`: `{id, username, role, max_connections, bandwidth_limit_mb, is_active, created_at, last_login_at, stats?}`.

### API keys
| Endpoint | Method | Auth |
|---|---|---|
| `/api/users/:id/api-keys` | POST | self/admin — create, returns the secret once |
| `/api/users/:id/api-keys` | GET | self/admin — list (no secret) |
| `/api/users/:id/api-keys/:key_id` | DELETE | self/admin — revoke |

### Usage & quota
| Endpoint | Method | Auth | Response |
|---|---|---|---|
| `/api/users/:id/usage` | GET | self/admin | `{user_id,period_days,connection_count,bytes_sent,bytes_received,total_bandwidth}` |
| `/api/users/:id/usage/recent` | GET | self/admin | `[{id,connection_id,client_ip,target_host,protocol,started_at,ended_at?,duration_seconds?,bytes_sent,bytes_received,status}]` |
| `/api/users/:id/usage/all-time` | GET | self/admin | as usage, `period_days=-1` |
| `/api/usage/summary` | GET | admin | system summary + `top_users[]` |
| `/api/users/:id/quota` | GET | self/admin | `{user_id,quota_bytes?,used_bytes,remaining_bytes?,percentage_used?}` |
| `/api/users/:id/quota` | PUT | admin | `{quota_bytes:number|null}` (null = unlimited) |

### Approvals
| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/approval-requests` | GET | admin all / user own | `[{id,user_id,username?,client_ip,duration_hours,reason?,status,requested_at,decided_by?,decided_at?,decision_reason?}]` |
| `/api/approval-requests` | POST | any (self-scoped) | `{client_ip,duration_hours,reason?}` |
| `/api/approval-requests/:id/approve` | POST | admin | `{reason?}` → creates an active approval (atomic) |
| `/api/approval-requests/:id/reject` | POST | admin | `{reason?}` |
| `/api/approvals` | GET | admin | `[{id,user_id,client_ip,approved_by,approved_at,expires_at,reason?,duration_hours}]` |
| `/api/approvals` | POST | admin | create grant directly |
| `/api/approvals/:id` | DELETE | admin | terminate `{reason}` (required) → immediate, cache-invalidated, audited |
| `/api/users/:id/approvals` | GET | self/admin | user's grants |

### Traffic & ops
| Endpoint | Method | Auth | Notes |
|---|---|---|---|
| `/api/connections` | GET | admin | `[ConnectionInfo]` |
| `/api/connections/count` | GET | admin | integer |
| `/api/connections/:id` | DELETE | admin | **terminate a live connection** (204; 404 if not active on this instance) |
| `/api/connections/live` | GET (WS) | admin | 2s JSON snapshots — see WS-auth caveat below |
| `/api/usage/timeseries` | GET | admin | `?days&bucket=hour\|day` → `{period_days,bucket_secs,points:[{ts,bytes_sent,bytes_received,connections}]}` (trend charts/sparklines) |
| `/api/tunnels` | GET/POST | admin | list / create — `TunnelInfo` now also returns `status, bytes_transferred, total_connections, active_connections` |
| `/api/tunnels/:port` | DELETE | admin | close |
| `/api/audit-log` | GET | admin | `{entries,total,limit,offset}`; `?user_id&action&limit&offset` (limit cap 200) |
| `/api/users/:id/sessions` | GET/DELETE | self/admin | list / force-logout |
| `/api/groups`,`/api/groups/:id`,`/api/groups/:id/members`,`/.../members/:user_id` | GET/POST/DELETE | admin | group CRUD + membership |
| `/api/config` | GET | admin | redacted config |
| `/api/config/reload` | POST | admin | reload from file |
| `/api/dashboard`,`/stats`,`/api/metrics` | GET | admin | summaries |
| `/health`,`/health/deep`,`/metrics` | GET | **public** | liveness + Prometheus (bind to localhost) |

**Pagination/filter/sort:** `?limit` (cap 200) + `?offset` on users & audit-log; audit-log also `user_id`, `action`. Most other lists are unpaginated today **[A: add cursor/limit envelopes uniformly]**.

**Added for this rebuild** (branch `feat/ui-backend-support`): `DELETE /api/connections/:id` (terminate live connection), `GET /api/usage/timeseries` (trend data), per-tunnel telemetry fields on `TunnelInfo`, and `latency_ms`/`checked_at` on deep-health checks.
**One swap caveat still open:** the live WebSocket `/api/connections/live` requires a bearer token, but browsers can't set `Authorization` on a WS handshake — wiring the real feed needs a short-lived ticket (query-param) or cookie auth. Not yet implemented (the UI's mock `useLiveConnections()` sidesteps it).

---

## 7. Data Models (Schema-Level)

From migrations + `src/db/models.rs`.

**User** — `id i64 pk`, `username text unique`, `password_hash text`, `role text('root_admin'|'admin'|'user')`, `created_by i64?`, `created_at i64`, `updated_at i64`, `is_active bool`, `max_connections i64`, `bandwidth_limit_mb i64`, `rate_limit_enabled bool`, `rate_limit_rps i64`, `rate_limit_burst i64`, `allowed_protocols text?(json)`, `ip_whitelist text?`, `allowed_targets text?(json globs)`, `blocked_targets text?(json globs)`, `access_schedule text?(json)`, `monthly_bandwidth_quota i64?`, `bandwidth_rate_bps i64`, `last_login_at i64?`, `notes text?`.

**Role** — enum: `root_admin` | `admin` | `user` (string column).

**ApiKey** — `id`, `user_id fk`, `key_hash`, `key_prefix`, `name`, `created_at`, `expires_at?`, `last_used_at?`, `is_active`.

**Approval** (active grant) — `id`, `user_id fk`, `client_ip`, `approved_by`, `approved_at`, `expires_at`, `approval_duration_hours` (API: `duration_hours`), `reason?`, `is_terminated`, `terminated_by?`, `terminated_at?`, `termination_reason?`.

**ApprovalRequest** — `id`, `user_id fk`, `client_ip`, `duration_hours`, `reason?`, `status('pending'|'approved'|'rejected')`, `requested_at`, `decided_by?`, `decided_at?`, `decision_reason?`.

**UserGroup** — `id`, `name unique`, `description?`, timestamps. **user_group_members** — `(user_id, group_id)` (FK `group_id ON DELETE CASCADE`).

**Usage** — `id`, `user_id fk`, `connection_id`, `client_ip`, `target_host`, `protocol`, `started_at`, `ended_at`, `duration_seconds`, `bytes_sent`, `bytes_received`, `status`.

**Session** — `id`, `user_id fk`, `token_hash?`, `created_at`, `expires_at`, `ip_address?`, `user_agent?`.

**AuditEntry** — `id`, `user_id`, `action`, `target_type?`, `target_id?`, `details?`, `ip_address?`, `created_at`.

**ConnectionInfo** (runtime, in state backend) — `id(uuid)`, `client_addr`, `target_addr`, `protocol`, `state`, `user_id?`, `bytes_sent`, `bytes_received`, `created_at`.

**Tunnel** — `tunnel_id`, `listen_port`, `target_addr`, `service_type`, `created_at`.

**Relationships:** User 1—N ApiKey / Approval / ApprovalRequest / Usage / Session; User N—N UserGroup via members; AuditEntry references user_id (no FK).

---

## 8. UI Component System

Existing base: shadcn/ui (Radix primitives) + Tailwind, dark theme. Reusable pieces to standardize:

- **Buttons** — `primary` (accent), `secondary`/`outline`, `ghost`, `destructive`. States: default, hover, active, focus-ring, disabled, loading (spinner + disabled).
- **Tables** — sortable headers, optional row expansion, pagination footer, sticky header, horizontal scroll container. States: loading (skeleton rows), empty (illustration + CTA), error (retry).
- **Forms** — labeled inputs, inline validation (zod **[A]**), helper/error text, required markers. States: pristine, invalid, submitting, success.
- **Cards** — `StatCard` (label, value, delta, icon, accent), `glass-card` container, section card.
- **Modals/Dialogs** — confirm (destructive variant), create/edit forms, reveal-once (API key). Focus trap, ESC close, reason-required pattern.
- **Charts** — bar (top users), doughnut (protocol mix), percentile bars, sparkline **[A]**. Faint grid, accent fill, emphasized endpoint, tabular-nums in legends.
- **Toasts/alerts** — success / error / info (sonner); inline alert for form-level errors; degraded banner (system health).
- **Navigation** — sidebar (role-filtered, collapsible icon rail), top bar (breadcrumb + user menu), NavLink active state, status dot, role badge, protocol badge, copy button, search input, empty state.
- **Status encodings** — status dot (green active / red disabled), role badge (root_admin red, admin blue, user grey), connection-state pill, severity stripe for health.

Each component documents: `loading | disabled | error | success | empty`.

---

## 9. User Flows (End-to-End)

**Login → role routing**
1. `/login` → submit → `POST /api/login` → store `{token,role}`.
2. role=admin/root_admin → `/dashboard`; role=user → `/approvals`.
3. Every request re-validates the token server-side; 401 → clear + redirect to `/login`.

**User requests access (end user)**
1. User logs in → `/approvals` (only their requests visible).
2. "Request access" → enter client IP (auto-detected), duration, reason → `POST /api/approval-requests` (pending).
3. Admin sees it under Pending → Approve (reason) → `POST .../approve` → an active Approval grant is created.
4. The proxy now authorizes that user+IP until expiry.

**Admin provisions a user (create → configure → revoke)**
1. `/users` → Create User (root_admin) → `POST /api/users`.
2. Open `/users/:id` → set quota (`PUT .../quota`), create API key (revealed once), adjust limits (root_admin `PUT`).
3. Later: Deactivate (`DELETE /api/users/:id`, reversible) or **Reactivate** (`PUT is_active=true`); Force-logout sessions; Revoke key.

**Terminate an active approval**
1. `/approvals` → Active Approvals tab → row → Terminate → enter reason → `DELETE /api/approvals/:id {reason}`.
2. Cache invalidated immediately; client denied on next connection; audit entry written.

**Search → filter → detail**
1. `/users` search by name → row → `/users/:id` tabs.
2. `/audit-log` filter by user/action → expand row for details.

**Observe live traffic**
1. `/connections` opens WebSocket `/api/connections/live` → table updates every 2s; count in header.

---

## 10. Dashboard Design

**KPI cards (row):** Active Connections (live), Total Connections, 24h Bandwidth, Total Users — each with icon, value (tabular-nums), and a small 24h delta/sparkline **[A]**.

**Charts:** Top Users by Bandwidth (24h) horizontal bar; Protocol Mix doughnut (from `/api/metrics.active_by_protocol`); Requests success/failed; latency p50/p95/p99 bars.

**Recent activity feed** **[A]:** stream the last N audit entries + recent connections (from existing data) as a timeline.

**Quick actions:** Create User, Create Approval, Reload Config, Open Live Connections — role-gated.

**Notifications panel** **[A]:** surface degraded health (deep-health), dropped-usage-records alarm (`proxy_usage_records_dropped_total`), draining state.

**Role-based widgets:** end users see a personal mini-dashboard (own quota gauge, recent usage, approval status) instead of system KPIs.

---

## 11. Modern UI/UX Improvements

- **Layout (2025 SaaS):** keep the left rail + top bar; add a command palette (⌘K) for nav + actions (Linear-style); detail views as side drawers over the table to preserve context; density toggle for tables.
- **Dark mode:** the app is dark today — add a proper light theme + system-preference toggle via CSS variables; ensure semantic colors (good/warn/critical) are theme-independent and separate from the accent.
- **Micro-interactions:** optimistic updates on revoke/terminate; row hover affordances; copy-to-clipboard confirmations; live-count tick animation; toast on every mutation (some are missing today).
- **Animation:** restrained — page-load skeleton→content cross-fade, WebSocket row insert highlight, chart endpoint emphasis; respect `prefers-reduced-motion`.
- **Accessibility (WCAG 2.1 AA):** visible focus rings, keyboard-operable tables/dialogs (Radix gives most), aria-labels on icon-only buttons, color-contrast ≥4.5:1, never color-only status (pair dot + label).
- **Mobile-first:** tables → card lists under `md`; sidebar → sheet; sticky action bars; the live connections feed paginates on mobile.
- **Performance UX:** route-level code-splitting (current bundle ~670 KB single chunk), `staleTime`/retry defaults on React Query, skeletons everywhere, virtualized long tables (connections/audit), gate pollers on tab visibility.
- **Reliability UX:** global error boundary + per-page `isError` states (largely missing today); WebSocket reconnect indicator.

---

## 12. Design System

> The current theme is a dark "glass-card" look. Recommendation: keep dark as default, add light, and make the accent deliberate. Below is a proposed token set **[A]** — adapt to brand.

- **Color (proposed):**
  - Ground `#0d1117` (ink, slight blue) / surface `#161b22` / hairline `#222a35`.
  - Text `#e6edf3` / muted `#8b97a6`.
  - Accent (single, confident) `#2dd4bf` teal — instrument/terminal feel, on-subject for a proxy; or GitHub steel `#1f6feb` if a calmer brand is wanted. Use one, not a gradient.
  - Semantic (theme-independent): good `#1f9d57`, warning `#c98a00`, critical `#d6453d`, info `#1f6feb`.
  - Role badges: root_admin red, admin blue, user grey.
- **Typography:** UI sans (e.g. Inter/`system-ui`) for body + labels; a mono (`ui-monospace`) for IDs, IPs, bytes, ports, tokens (data is everywhere here — mono carries it). Display weight only on page titles + KPI numbers. Type scale 12/13/14/16/20/27/34; uppercase eyebrows with `.08em` tracking.
- **Spacing:** 4px base scale (4/8/12/16/24/32/48); layout via flex/grid `gap`.
- **Grid:** 12-col content, max ~1080–1280px; KPI grids `auto-fit minmax(180px,1fr)`.
- **Icons:** lucide (already used) — 1.5px stroke, 16/20px.
- **Component rules:** 8–11px radius on cards/inputs; 1px hairline borders; tables tabular-nums; charts get faint grid + accent fill; focus ring = accent at 2px.

---

## 13. Edge Cases

- **No data:** every list/chart has an empty state with a one-line reason + (where relevant) a CTA ("No users yet — Create one"). Dashboard cards show 0/"—", not blank.
- **API failure:** per-page `isError` → inline "Couldn't load X — Retry"; global error boundary catches render crashes (no white screen); mutations surface errors as toasts (add the missing `onError`s).
- **Slow network:** skeletons on first load; keep last data + subtle "refreshing" on background refetch; disable submit + spinner during mutations.
- **Unauthorized:** server 403 → toast "You don't have access"; AdminRoute hides admin pages from non-admins (redirect to `/approvals`); 401 → clear session + `/login`.
- **Deleted/deactivated records:** deactivated users remain listed as "Disabled" and reactivatable; terminated approvals show terminated state; revoked keys show "Revoked".
- **Partial data:** null-guard every nullable field (`bandwidth_24h`, `last_login_at`, `quota_bytes`, `username` on usage/audit → fall back to `User #<id>`); never `.map` an undefined list.
- **WebSocket loss (connections):** show reconnecting indicator; fall back to REST polling.
- **Config reload failure:** 500 + toast; never reports success on failure; security-critical fields are preserved by the server regardless.

---

*Make this UI feel like a modern 2025 AI-native SaaS product — Notion/Linear/Stripe/Vercel quality and polish: a calm dark-first surface, one confident accent, mono for all the technical data (IPs, ports, bytes, tokens), ⌘K command palette, drawer-over-table detail views, live feeds with restrained motion, and rigorous empty/loading/error states throughout.*
