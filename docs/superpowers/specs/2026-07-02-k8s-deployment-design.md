# Kubernetes Deployment — crabby-proxy (backend + UI)

**Date:** 2026-07-02
**Status:** Approved design, pre-implementation

## Goal

Deploy the two existing services to Kubernetes:

- **Backend** (`crabby_proxy`): Rust forward proxy + admin API, SQLite-backed.
- **UI** (`web/`): TanStack Start admin console, served by a Nitro node-server.

Requirements from brainstorming:

- Resilient: pod auto-restarts on crash; SQLite data survives restarts.
- Easily deployable (Kustomize, `kubectl apply -k`).
- No TLS for now (plain HTTP).
- Secrets as a plain Kubernetes `Secret`.
- Images built + pushed by a Jenkins pipeline on a separate machine; deploy pins image tags.

Both services already have working Dockerfiles and a `compose.yaml` — this design ports that topology to k8s, it does not change application code.

## Architecture

```
                  Ingress (HTTP, no TLS)
        ui.crabby.local ─┐        admin.crabby.local ─┐
                         ▼                            ▼
                 UI Service :8080            Admin Service :8081
                         │                            │
                 UI Deployment                Backend StatefulSet (1 replica)
                 (stateless, N replicas)      ├─ /app/data       ← PVC (SQLite proxy.db)
                                              └─ /app/config.toml ← ConfigMap (ro)

        Proxy port 8080 (forward-proxy TCP) ── separate Service (NodePort/LB in overlay)
                                                 NOT via ingress — not HTTP-routable
```

### Backend — StatefulSet, 1 replica

- **Why StatefulSet, 1 replica:** SQLite is single-writer. One stable pod + one PVC keeps the DB consistent and avoids two pods touching the same file during rolling updates. k8s restarts a crashed pod automatically (`restartPolicy: Always`).
- **Persistence:** `volumeClaimTemplates` → PVC mounted at `/app/data`. `proxy.db` (+ WAL/SHM) lives here. StorageClass left to the overlay (cluster default in base).
- **Config:** ConfigMap-mounted `config.toml` at `/app/config.toml` (read-only, `subPath`), overriding the image-baked copy. Needed so `[admin] cors_origins` includes the UI ingress origin and `[database] path = sqlite:/app/data/proxy.db`.
- **Migrations:** run on startup — `db::connection::create_pool` opens the DB with `mode=rwc` (creates the file) and `run_migrations` applies `sqlx::migrate!("./migrations")`. Fresh PVC → schema built on first boot. **No migration Job required.**
- **Probes:** liveness + readiness `GET /health` on `:8081` (matches the container HEALTHCHECK).
- **Security:** `runAsNonRoot` (image uid 10001), `capabilities: drop: [ALL]`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`. Root FS not forced read-only (SQLite writes to the `/app/data` volume; keep it simple).

### UI — Deployment (stateless)

- Plain Deployment; can scale to N replicas (overlay-controlled).
- `VITE_API_BASE_URL` is **baked at build time** into the client bundle → must equal the admin ingress URL (`http://admin.crabby.local`). Jenkins passes it as a Docker `--build-arg`; it is **not** a runtime env var and cannot be changed post-build.
- Node server listens on `:8080` (`PORT`/`HOST` already set in the image).
- Probes: `GET /` on `:8080`. Same non-root/cap-drop security context (image runs as `node` user).

### Services

- `crabby-admin` — ClusterIP `:8081` → backend admin API (ingress target).
- `crabby-proxy` — Service `:8080` → forward-proxy port. **ClusterIP in base**; overlay flips to NodePort (dev) or LoadBalancer (prod) since a forward proxy speaks raw TCP/CONNECT/SOCKS and cannot be routed by an HTTP ingress.
- `crabby-ui` — ClusterIP `:8080` → UI (ingress target).

### Ingress (HTTP, no TLS)

- `ui.crabby.local`    → `crabby-ui:8080`
- `admin.crabby.local` → `crabby-admin:8081`
- nginx ingress class. No TLS block. Hostnames overridable per overlay. Requires an ingress controller installed in the cluster.

## Config & secrets data flow

- **ConfigMap `crabby-config`** — copy of repo `config.toml` with two changes: `[database] path = "sqlite:/app/data/proxy.db"` and `[admin] cors_origins` includes `http://ui.crabby.local`. Passwords/JWT left as placeholders — injected via env instead.
- **Secret `crabby-secrets`** — keys `CRABBY_JWT_SECRET` (≥32 bytes), `CRABBY_ADMIN_PASSWORD`, `CRABBY_BASIC_AUTH_PASSWORD`. Consumed via `envFrom` on the backend. `config_env.rs` overrides file config from these env vars and panics on weak/missing secrets, so they are mandatory.
- **`backend-secret.example.yaml`** committed as a template with dummy values; the real Secret is gitignored (or created out-of-band by the pipeline).

## Kustomize layout

```
k8s/
  base/
    namespace.yaml
    backend-config.yaml          # ConfigMap
    backend-secret.example.yaml  # template (real one gitignored)
    backend-statefulset.yaml
    backend-service.yaml         # admin (ClusterIP) + proxy (ClusterIP)
    ui-deployment.yaml
    ui-service.yaml
    ingress.yaml
    kustomization.yaml           # resources + images: refs
  overlays/
    dev/
      kustomization.yaml         # 1 UI replica, small resources, proxy → NodePort
    prod/
      kustomization.yaml         # N UI replicas, resource limits, pinned image tags
```

Base uses placeholder image names (`crabby-proxy:latest`, `crabby-proxy-web:latest`) via the kustomize `images:` field so the pipeline repoints registry + tag without editing manifests.

## Jenkins pipeline (deploy contract)

1. Build + push backend image → `$REGISTRY/crabby-proxy:$TAG`.
2. Build + push UI image with `--build-arg VITE_API_BASE_URL=http://admin.crabby.local` → `$REGISTRY/crabby-proxy-web:$TAG`.
3. Ensure `crabby-secrets` exists (create/apply out-of-band; not from repo).
4. `cd k8s/overlays/<env>` → `kustomize edit set image crabby-proxy=$REGISTRY/crabby-proxy:$TAG crabby-proxy-web=$REGISTRY/crabby-proxy-web:$TAG`.
5. `kubectl apply -k .`
6. `kubectl -n crabby-proxy rollout status statefulset/crabby-backend deploy/crabby-ui`.

## Out of scope (YAGNI)

- TLS / cert-manager (no certs yet).
- Redis state backend / horizontal backend scaling (SQLite single-writer stands).
- HPA, network policies, PodDisruptionBudget.
- Separate migration Job (migrations run on startup).

## Open items to confirm during implementation

- Which ingress controller class string (`nginx` assumed).
- Default StorageClass name on the target cluster (left blank → cluster default).
- Registry host for the `images:` refs (pipeline-provided).
