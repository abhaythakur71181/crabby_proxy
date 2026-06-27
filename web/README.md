# Crabby Proxy — Admin Console

TanStack Start + React 19 + Tailwind 4 control plane for the Crabby Proxy
admin API. See `../docs/UI_SPEC.md` for the full page/endpoint map.

## Develop

```bash
bun install
# point the dev proxy at a running backend (default http://127.0.0.1:8081)
CRABBY_BACKEND=http://127.0.0.1:8081 bun run dev
```

`/api` and `/health` are proxied to the backend in dev (see `vite.config.ts`),
so the browser talks same-origin. Log in with a real backend user (the root
account is printed on first backend boot, or set `CRABBY_ROOT_PASSWORD`).

## Build & deploy

Production build emits a Nitro **node-server** (`.output/server/index.mjs`):

```bash
NITRO_PRESET=node-server bun run build
PORT=8080 node .output/server/index.mjs
```

The container (`Dockerfile`, compose service `web`) does this and serves on
:8080. The browser calls the admin API directly via `VITE_API_BASE_URL`
(baked at build), so the backend's `[admin] cors_origins` **must include the
web origin**. Set `VITE_API_BASE_URL` and `cors_origins` together.

> Data is fetched client-side (no SSR loaders); the SSR layer only renders the
> shell. A static/SPA deploy is possible later if the node server isn't wanted.
