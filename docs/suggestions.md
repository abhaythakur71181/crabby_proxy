# Crabby Proxy — UI/UX Redesign Suggestions

Opinionated, implementation-aware recommendations for the console rebuild.
Grounded in the actual app (React + TanStack Query + shadcn/Tailwind + chart.js
frontend; axum + SQLite/Redis backend; live WebSocket feed; 3 roles). Pairs with
`docs/UI_SPEC.md` and `docs/ARCHITECTURE.md`.

Priority labels: **[H]** High impact · **[M]** Medium · **[N]** Nice to have.
"Why" is explicit so trade-offs are clear; vague advice omitted on purpose.

---

## 0. The one design idea to commit to

**This is a control plane for a network device, not a generic CRUD dashboard.**
Design it like an instrument panel: a calm dark surface, one confident accent,
**monospace for every piece of machine data** (IPs, ports, bytes, durations,
tokens, UUIDs), and live state that updates without a refresh. The product's job
is "who is going where, how much, and is anything wrong" — surface that answer
before any table. Every suggestion below serves that thesis.

---

## 1. UI/UX Improvements

### Layout restructuring
- **[H] Detail-as-drawer, not full page.** `/users/:id`, a connection, an approval, an audit entry should open in a right-side drawer over the list so the admin keeps context and can move through rows without losing their place/scroll. Full-page navigation for `/users/:id` is the single biggest workflow tax today.
- **[H] Persistent "system status" strip** in the top bar: active connections (live), draining state, and a red dot if deep-health reports a failing component or `proxy_usage_records_dropped_total` is climbing. An operator should never have to open System Health to know something's wrong.
- **[M] Two-pane Approvals.** The current tab split (pending / decided / active) hides the actual job. Use a queue layout: left = pending requests needing a decision (with a count badge), right = the selected request's full context (user, prior usage, existing grants for that IP). Approve/reject inline.
- **[M] Dashboard = answer first.** Lead with 4 KPIs + a live "what's happening now" feed (recent connections + recent audit), then charts. Don't open with a chart that takes a second to populate.
- **[N] Density toggle** (comfortable / compact) for the heavy tables (connections, audit, usage). Operators want compact; new users want comfortable.

### Navigation
- **[H] Command palette (⌘K).** Jump to any page, any user by name, any action (Create user, Reload config, Terminate approval). For an admin tool this collapses 3-click flows to one. The data already exists client-side.
- **[H] Role-aware first screen.** Admin → `/dashboard`; end user → a personal home (their quota gauge, recent usage, approval status) — not the admin dashboard they can't load. (AdminRoute already redirects users to `/approvals`; give them a real home instead.)
- **[M] Breadcrumbs + back-aware drawers** so `/groups/:id` and `/users/:id` don't strand the user.
- **[M] Sidebar grouping** by the IA in the spec (Overview / Traffic / Access / Usage / Operations) with section labels — 11 flat items is a wall.

### Information hierarchy
- **[H] Lead every page with a summary row**, then detail. Connections page: counts by protocol + total bytes/s before the table. Users page: total / active / disabled / over-quota chips before rows. Audit: counts by action type.
- **[H] Encode state in form, not just text.** Status dot + label (never color-only), role badge, a severity stripe on health cards, a quota gauge that turns amber→red near the limit. What needs attention should read at a glance.
- **[M] Quota as a gauge everywhere it appears** (user detail, user row, user's own home): used/limit ring with % and "X left", amber at 80%, red at 100%. Numbers alone bury the signal.

### Consistency / design system
- **[H] One list envelope + one list component.** Backend mixes bare arrays and `{items,total,...}`; standardize the API on the paginated envelope (users + audit already are) and build a single `DataTable` (sort, filter, paginate, empty, loading, error, row-action menu) used by every list. Today each page re-implements tables.
- **[H] One "admin" definition.** UI currently mixes `root_admin`-only vs `admin|root_admin` gates per page. Centralize on the `isAdmin` flag + explicit per-action capability checks; show disabled+tooltip ("root_admin only") rather than hiding, so admins understand the boundary.
- **[M] Mono for machine data, sans for prose.** Apply consistently — IPs/ports/bytes/tokens/UUIDs in mono with `tabular-nums`; never in the body sans.

---

## 2. Feature Enhancements

### For end users
- **[H] Self-service home** — quota ring, this-month usage trend, active approvals + expiry countdown, "Request access" CTA, and their API keys. Today a `user` lands on a bare approvals list.
- **[H] API key UX done right** — reveal-once with a copy button + "store this now" warning; show prefix + last-used + expiry after; one-click "create key for the proxy" with the exact `username@apikey` usage snippet (curl/SOCKS examples) so users can actually wire it up.
- **[M] "Why was I blocked?"** — surface the user's own recent denied connections (target filter / quota / schedule / approval) from their usage data so they self-diagnose instead of filing a ticket.
- **[N] Personal quota alerts** — opt-in toast/email at 80/100%.

### Admin-side
- **[H] Bulk actions** on the users table: multi-select → deactivate / reactivate / add-to-group / set-quota / force-logout. Per-row only is painful at scale.
- **[H] Inline approval decisions** with one click + optional reason, plus an "approve for 24h / 7d / custom" quick-pick. The approval queue is the highest-frequency admin job.
- **[H] Per-user activity timeline** on user detail: merge sessions, approvals, key events, and recent connections into one chronological view — answers "what has this user been doing" without four tabs.
- **[M] Target-filter editor** — the backend supports per-user `allowed_targets`/`blocked_targets` (glob) and `access_schedule` (JSON), but there's no UI. Build a chip editor for globs and a weekly schedule grid. This is a core selling feature with no front door today.
- **[M] Connection actions** — let an admin kill an active connection from the live table (needs a backend `DELETE /api/connections/:id` — currently missing; worth adding).
- **[M] Audit log export** (CSV/JSON) + saved filters; it's the compliance artifact.
- **[N] Config diff on reload** — show what changed (and which security-critical fields were preserved) instead of a bare success toast.

### Missing functionality (product gaps)
- **[H] Real logout / session revocation** — JWT logout is client-only today; add server revocation (token_version) so "force logout" and password change actually invalidate live tokens, and reflect it in the UI.
- **[M] Notifications center** — degraded health, dropped usage records, tunnels opened, approvals pending. The backend already emits these signals (metrics, audit, event bus).
- **[N] Dark/light theme toggle** with system preference (app is dark-only now).

---

## 3. Performance & Responsiveness UX

- **[H] Route-level code splitting.** The build is one ~670 KB chunk; the login page ships the entire admin app + chart libs. `React.lazy` per route + a vendor chunk for charts. Biggest first-paint win.
- **[H] Skeletons on every first load, keep-last on refetch.** Several pages `return null` while loading (blank screen) or render "no data" on error. Add skeletons + an `isError` retry state app-wide (there's no global error boundary today — add one so a render throw doesn't white-screen the SPA).
- **[H] Configure TanStack Query defaults** — `staleTime` (e.g. 15–30s), sane `retry`, `refetchOnWindowFocus: true`, and **gate pollers on tab visibility** (Connections 5s, Dashboard 10s, Health 10–30s pollers run even when hidden today → wasted requests + battery).
- **[M] Virtualize long tables** (connections, audit, usage) — render only visible rows.
- **[M] Optimistic mutations** for revoke key / terminate approval / deactivate — update the row instantly, roll back on error toast.
- **[M] Mobile-first responsive:** tables → card lists under `md`; sidebar → sheet; sticky bottom action bar for primary CTAs; the live feed paginates instead of streaming a giant list on phones.
- **[N] Prefetch on hover** — hovering a user row prefetches `/users/:id` so the drawer opens instantly.

---

## 4. Micro-interactions & Animations

Motion should clarify state change, never decorate. Respect `prefers-reduced-motion`.

- **[H] Live-feed row insert** — new connection rows fade/slide in with a brief accent highlight that decays; removed rows fade out. Makes the WebSocket feed legible instead of a flickering re-sort.
- **[H] Live count tick** — animate the active-connections number on change (count-up), so the operator notices movement peripherally.
- **[H] Mutation feedback loop** — button → inline spinner → success check (200ms) → toast; destructive actions get a confirm with the resource named. Every mutation must visibly resolve (some have no `onError` today → silent failures).
- **[M] Skeleton → content cross-fade** instead of a hard swap.
- **[M] Quota gauge fill animation** on load (0→value, ~400ms ease-out) draws the eye to near-limit users.
- **[M] Drawer slide-in** with a dimmed backdrop; chart endpoint pulse on the latest data point.
- **[N] Copy-to-clipboard** → icon morphs to a check for 1s.
- **[N] Tab/route transitions** — subtle 120ms fade; nothing longer (long animations read as "AI-generated" and slow power users).

---

## 5. Admin Panel Optimizations (faster workflows)

- **[H] Keyboard-first:** ⌘K palette, `/` to focus search, `j/k` to move table rows, `Enter` to open the drawer, `e` edit, `x` select. Operators live in the keyboard.
- **[H] The approval queue as the admin home option** — a count badge in the sidebar + top-bar; decisions in ≤2 keystrokes.
- **[H] Saved views / filters** on users, connections, audit (e.g. "disabled users", "over-quota", "denied connections last 24h"). Persist per admin.
- **[M] Bulk + multiselect** everywhere lists support it (see §2).
- **[M] Cross-links** — every `user_id`/IP/target in connections, audit, usage is a link to the relevant detail/filter. Right now data is shown but not navigable.
- **[M] "Act on this user" menu** reachable from any row (kebab): view, edit, set quota, force logout, deactivate.
- **[N] Inline edit** for quota/limits in the users table (no dialog round-trip).

---

## 6. User Experience Enhancements

### Onboarding
- **[H] First-run admin checklist** — change default password (the backend now refuses defaults at boot, so reflect that), create your first user, set a global target policy, confirm `block_private_targets`. A short, dismissible card on the dashboard.
- **[M] End-user "get connected" wizard** — pick protocol → generate key/approval → copy the exact proxy config snippet. Turns "I have an account" into "my traffic flows" in one screen.

### Reduced friction
- **[H] Auto-fill client IP** in approval requests (already done) + remember the last duration/reason; offer common durations as chips.
- **[M] Inline validation** (zod) with field-level messages on all forms; disable submit until valid; show password policy live.
- **[M] Confirm-by-typing** only for truly destructive/irreversible ops; deactivation is reversible, so a normal confirm (and clear "reversible" copy — already fixed) is enough.

### Error handling & empty states
- **[H] Every list/chart gets a real empty state** with a one-line reason + CTA ("No users yet — Create one", "No active connections", "No approvals pending — you're caught up"). No blank panels.
- **[H] Typed, actionable errors** — map backend `{error,detail}` to human messages; 403 → "You don't have access" (and hide the control); 401 → silent re-login; network → "Couldn't reach the server — Retry". Add the missing `onError` toasts.
- **[M] Stale/degraded indicators** — when polling fails but cached data exists, show "last updated 30s ago — reconnecting" rather than wiping the screen.

### System-level consistency
- **[H] Standard page scaffold:** title + summary chips + primary action (top-right) + filter bar + DataTable/content + drawer. Every page follows it → zero re-learning between pages.
- **[M] Consistent terminology** — "deactivate" (not delete), "terminate" (approvals), "revoke" (keys). Use the same verb in button, dialog, and toast.

---

## 7. Design System Recommendations

- **[H] Tokenize and theme via CSS variables** (color/space/radius/shadow) so dark+light are one source of truth; semantic colors (good/warn/critical) live outside the accent and stay constant across themes.
- **[H] One accent, used sparingly** — teal `#2dd4bf` (instrument feel) or steel `#1f6feb`; no gradients. Spend boldness on the live data, keep chrome quiet.
- **[H] Type scale** 12/13/14/16/20/27/34; sans (Inter/system) for UI, **mono for all machine data**, uppercase eyebrows with `.08em` tracking; `text-wrap: balance` on headings.
- **[M] Spacing** on a 4px scale; lay out with flex/grid `gap`, not per-element margins.
- **[M] Reusable patterns to extract:** `DataTable`, `StatCard`, `QuotaGauge`, `StatusBadge` (role/state/protocol), `EntityLink` (user/IP/target), `ConfirmDialog`, `RevealOnce` (keys), `EmptyState`, `MetricChart` (faint grid + accent fill + endpoint emphasis), `LiveBadge`.
- **[M] Component state matrix** — every interactive component documents default/hover/focus/active/disabled/loading/error; ship them in a Storybook-style page.
- **[N] Icon discipline** — lucide, 1.5px stroke, 16/20px only.

---

## Top 10, ranked (if you do nothing else)

1. **[H]** DataTable + standard page scaffold + single list envelope — kills cross-page inconsistency.
2. **[H]** Detail-as-drawer over the table (users, connections, approvals, audit).
3. **[H]** Command palette (⌘K) + keyboard navigation.
4. **[H]** Live-feed motion + animated live counters + top-bar system-status strip.
5. **[H]** Role-aware end-user home with a quota gauge + "get connected" snippet.
6. **[H]** Global error boundary + per-page skeleton/empty/error states + missing `onError` toasts.
7. **[H]** Route-level code splitting + visibility-gated pollers + Query defaults.
8. **[H]** Approval queue with inline 2-keystroke decisions + quick-duration picks.
9. **[H]** Bulk actions on users (deactivate/reactivate/group/quota/force-logout).
10. **[H]** Target-filter + schedule editor UI (expose the backend policy features that have no front door).

> North star: make Crabby Proxy feel like Linear/Stripe for a network device —
> calm, fast, keyboard-driven, live, with one accent and mono everywhere the
> machine speaks. Quality is in the empty states, the motion on state change,
> and never making an operator refresh to learn something's wrong.
