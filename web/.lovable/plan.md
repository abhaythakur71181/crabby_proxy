# Crabby Proxy — Full UI Reconstruction

A complete rebuild of the admin console as a premium, operator-grade control plane. All business logic is preserved at the data-model level; everything visual, structural, and interactive is rebuilt from scratch.

## Direction (auto-selected)

**Luminous Glass Cockpit** — deep near-black surface, electric-violet accent, glass-backdrop panels, monospace for every IP / port / byte / ID, motion-rich. Closest match to "godly beautiful + cinematic + Apple/Linear/Arc craftsmanship."

If you'd rather build in Industrial Laboratory (emerald, hairline, minimalist) or Tactical Operator Terminal (amber, Bloomberg-density), say so and I'll swap before building.

## Product thesis

This is a **control plane for a network device**, not a CRUD dashboard. Every page answers an operator question first, then exposes the table. Three commitments hold across every screen:

1. **Detail-as-drawer** — selecting a user / connection / approval / audit row opens a right-side drawer over the list. No more full-page navigation losing scroll position.
2. **Persistent system status strip** — top bar always shows active connections (live), version, health dot. Operators never need to open Health to know something's wrong.
3. **⌘K command palette everywhere** — jump to any page, any user, any action (Create user, Reload config, Terminate approval) from one keystroke.

## Mock data layer

A single `src/mock/` module emits:
- Static seed: users, groups, API keys, tunnels, config, approvals, audit entries
- **Simulated live feed**: a `useLiveConnections()` hook ticking every 800–1500ms, adding/removing rows with smooth enter/exit animations, mimicking the real WebSocket
- Typed shapes match the documented axum API so a real backend can be swapped in by replacing `src/lib/api.ts` only

## Design system (built first, in `src/styles.css` + `src/components/ui-system/`)

- **Color**: `--bg` near-black `oklch(0.14 0.01 280)`, layered surface tiers, single accent `oklch(0.68 0.22 295)` (electric violet), semantic emerald/amber/rose for state
- **Type**: Inter Variable (UI) + JetBrains Mono (all machine data). Loaded via `<link>` in `__root.tsx` head
- **Radii**: 6/10/16/24px scale
- **Elevation**: 4-tier glass: flat, raised, floating, overlay — each with backdrop blur + 1px hairline border
- **Motion tokens**: spring `[0.16, 1, 0.3, 1]`, durations 150/250/400/600ms, reduced-motion fallback
- Primitives: Button, Input, Select, Switch, Tabs, Badge, Card, Sheet/Drawer, Dialog, Tooltip, Toast, Skeleton, KBD, Sparkline, Counter (animated), StatusDot, MonoValue, EmptyState, ErrorState

## Motion system (Framer Motion)

- Page transitions: 250ms fade+8px-y, route-scoped via `AnimatePresence`
- Table rows: staggered 30ms enter on mount; live rows slide in from top with accent flash
- Counters: count-up on mount and on data change
- Drawer: spring slide from right + backdrop blur fade
- ⌘K palette: scale 0.96→1 + blur fade
- Hover: subtle lift on cards (translateY -2px, shadow grow)
- KPIs: sparkline draws on mount
- All animations gated on `prefers-reduced-motion`

## Pages (all rebuilt)

| Route | Rebuild |
|---|---|
| `/login` | Centered glass card, animated crab mark, mono "authenticating: crabby" reveal, error shake |
| `/` (Dashboard) | 4 KPI tiles (uptime, active conns, throughput, latency) with animated counters + sparklines · Bandwidth sent/received split · Live connection feed (streaming with enter animation) · Top users mini-table · Recent audit strip |
| `/connections` | Virtualized live table, mono everywhere, protocol pills, search + protocol filter, row click → right drawer with full connection telemetry + terminate action |
| `/users` | Compact table with role/status badges, click → drawer with tabs (Profile, API Keys, Usage, Quota, Groups, Sessions, Approvals), Create User as drawer (not modal) |
| `/groups` | Card grid + drawer for members/policies |
| `/api-keys` | Token table with last-used, copy-on-click with toast, create flow with one-time reveal |
| `/usage` | KPIs + bandwidth-over-time chart (Recharts area) + top-users leaderboard with progress bars |
| `/approvals` | **Two-pane**: left = pending queue with count badge, right = selected request context (user history, prior grants for that IP) with inline approve/reject |
| `/tunnels` | Card list with status indicator, latency, traffic; create/edit drawer |
| `/audit` | Virtualized log stream, filter chips (actor, action, target, time), row → drawer with diff view |
| `/config` | Sectioned form (Network, Auth, Limits, Logging) with dirty-state tracking, "Reload config" action with confirmation |
| `/system-health` | Component cards (DB, Redis, Auth, Proxy, Metrics) each with status, latency, last-check, expand for details |

## Global chrome

- **Left rail**: logo + version pill · grouped nav (Operations / Identity / System) · active state with accent bar · quota mini-widget at bottom · user menu
- **Top bar**: ⌘K trigger pill · live status pill (pulsing dot + "1,204 active · v0.1.0") · breadcrumb · profile avatar
- **⌘K palette**: fuzzy search across pages, users, actions; recent + suggestions; keyboard-first
- **Toast system**: bottom-right, success/error/info with icon + accent stripe
- **Reduced-motion**: respected globally

## Accessibility

- WCAG AA contrast on all text (verified against tokens)
- Full keyboard nav, visible focus rings (accent), `Esc` closes drawers/palette
- Radix primitives for menus/dialogs/tooltips (ARIA correct out of the box)
- All icon-only buttons have `aria-label`
- Single `<main>` per route, semantic headings

## Technical notes

- TanStack Start file-based routes under `src/routes/` (e.g. `dashboard.tsx`, `connections.tsx`, `users.tsx`, `users.$id.tsx` opens as drawer overlay via search-param state, not full page)
- `_authenticated` pathless layout wraps every app route; login at `/login` stays public
- Mock auth: any password works, role pulled from username (`root_admin`, `admin`, anything else → `user`)
- TanStack Query for data fetching (mock fns are async with realistic latency), enabling future real-API swap
- Framer Motion for all motion
- Recharts for analytics charts (themed to match)
- `cmdk` for the command palette
- Drawer state via URL search params so deep links work
- Each route file has its own `head()` with route-specific title + description

## Out of scope (call out separately if you want them)

- Real backend wiring (kept as mock; API client is shaped to swap easily)
- Mobile redesign past responsive collapse (operators are desktop-first; left rail collapses to icons under 1024px, drawer goes full-width under 768px)
- Light mode (operator tool, dark-only by intent — easy to add later)
- Per-user end-user portal as a distinct skin (admin console serves all three roles with permission gating)

## Delivery shape

One large pass building: design system → global chrome → mock data + live feed → all 12 pages → command palette → motion polish. I'll verify the dev build at the end and screenshot the Dashboard + Connections + Approvals + a drawer to confirm the look.
