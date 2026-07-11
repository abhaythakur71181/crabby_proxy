# Crabby Proxy — webv2

Next-generation admin console. Pure Vite SPA (no SSR) with React 19,
TypeScript strict, Tailwind v4, TanStack Query, motion and a hand-built
animated chart kit. Coexists with the legacy `web/` app during rollout —
see [`docs/WEBV2_PLAN.md`](../docs/WEBV2_PLAN.md) for the full audit and
design rationale.

## Highlights over `web/`

- **Every backend endpoint integrated** — including `/api/metrics`,
  connection terminate, audit server-side filters/pagination, tunnel
  telemetry and `/api/usage/timeseries`.
- **Working self-service** — identity is decoded from the JWT, so the
  Account page (quota, API keys, usage, approvals) works for regular
  users, not just admins.
- **Honest live data** — the connections feed merges the WebSocket (which
  only fires on count changes) with REST polling, computes per-connection
  transfer rates client-side, reconnects with jittered backoff and falls
  back to polling on *any* socket drop.
- **Mounted toast system, real loading/empty/error states everywhere,
  dark + light themes, mobile navigation, keyboard-operable tables,
  ⌘K palette with working deep links, `g` navigation chords,
  reduced-motion support.**

## Develop

```bash
bun install
CRABBY_BACKEND=http://127.0.0.1:8081 bun run dev   # http://localhost:5174
```

`/api` and `/health` are proxied to the backend (same-origin, no CORS).
Sign in with a real backend account.

Note: the SPA's health page lives at `/system-health`; bare `/health` is
reserved for the backend liveness endpoint (proxied).

## Build

```bash
bun run build        # typecheck + production bundle → dist/
bun run typecheck    # tsc only
bun run preview      # serve dist/ locally
```

`VITE_API_BASE_URL` (baked at build time) points the bundle at a
cross-origin admin API; leave it empty and front the app with a proxy
(the bundled nginx config does this) for a same-origin setup — no CORS
configuration needed on the backend.

## Deploy

```bash
docker build -t crabby-webv2 .
docker run -p 3001:8080 crabby-webv2
```

The image serves the static bundle with nginx and proxies `/api` +
`/health` to the `crabby-proxy` compose service (edit `nginx.conf` for a
different upstream). A `crabby-webv2` service is included in the repo's
`compose.yaml` on port `3001` so both consoles run side by side.
