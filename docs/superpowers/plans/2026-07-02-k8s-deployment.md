# Kubernetes Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the `crabby_proxy` backend and the `web/` admin UI to Kubernetes via Kustomize, with an auto-restarting SQLite-backed backend and plain-HTTP ingress.

**Architecture:** Backend runs as a 1-replica StatefulSet with a PVC for the SQLite DB and a ConfigMap-mounted `config.toml`; the UI runs as a stateless Deployment. Traffic reaches the admin API and UI through an nginx Ingress (HTTP, no TLS); the forward-proxy TCP port gets its own Service. A Kustomize base + dev/prod overlays parameterize image tags for a Jenkins pipeline.

**Tech Stack:** Kubernetes, Kustomize (via `kubectl`), nginx Ingress, existing Docker images (`crabby-proxy`, `crabby-proxy-web`).

## Global Constraints

- No TLS anywhere — plain HTTP only.
- Backend is single-writer SQLite → exactly **1** backend replica. Never scale the backend StatefulSet above 1.
- Secrets (`CRABBY_JWT_SECRET` ≥32 bytes, `CRABBY_ADMIN_PASSWORD`, `CRABBY_BASIC_AUTH_PASSWORD`) are mandatory; backend panics without them. Real Secret is never committed.
- Namespace: `crabby-proxy` for all resources.
- Ingress hosts: `ui.crabby.local` (UI), `admin.crabby.local` (admin API). Ingress class: `nginx`.
- `VITE_API_BASE_URL` is a **build-arg** baked into the UI image (`http://admin.crabby.local`), NOT a runtime env var.
- Backend container ports: proxy `8080`, admin `8081`. UI container port: `8080`.
- Validate every manifest change with `kubectl kustomize <dir>` and `kubectl apply --dry-run=client -k <dir>` (no live cluster required). Only `kubectl` is installed — do not call a standalone `kustomize` or `kubeconform` binary.
- Security context on both workloads: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`.

---

### Task 1: Scaffold base namespace + kustomization

**Files:**
- Create: `k8s/base/namespace.yaml`
- Create: `k8s/base/kustomization.yaml`

**Interfaces:**
- Produces: namespace `crabby-proxy`; a base `kustomization.yaml` that later tasks append resources to. The `images:` block names `crabby-proxy` and `crabby-proxy-web` as the logical image names later tasks and overlays repoint.

- [ ] **Step 1: Create the namespace manifest**

`k8s/base/namespace.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: crabby-proxy
  labels:
    app.kubernetes.io/part-of: crabby-proxy
```

- [ ] **Step 2: Create the base kustomization**

`k8s/base/kustomization.yaml`:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: crabby-proxy

commonLabels:
  app.kubernetes.io/part-of: crabby-proxy

resources:
  - namespace.yaml

images:
  - name: crabby-proxy
    newName: crabby-proxy
    newTag: latest
  - name: crabby-proxy-web
    newName: crabby-proxy-web
    newTag: latest
```

- [ ] **Step 3: Validate the base builds**

Run: `kubectl kustomize k8s/base`
Expected: prints the Namespace YAML with no error.

- [ ] **Step 4: Commit**

```bash
git add k8s/base/namespace.yaml k8s/base/kustomization.yaml
git commit -m "feat(k8s): scaffold base namespace + kustomization"
```

---

### Task 2: Backend ConfigMap + Secret template

**Files:**
- Create: `k8s/base/backend-config.yaml`
- Create: `k8s/base/backend-secret.example.yaml`
- Modify: `k8s/base/kustomization.yaml` (add resources)
- Modify: `.gitignore` (ignore the real secret)

**Interfaces:**
- Produces:
  - ConfigMap `crabby-config`, key `config.toml`, consumed by the backend StatefulSet as a mounted file at `/app/config.toml`.
  - Secret `crabby-secrets` with keys `CRABBY_JWT_SECRET`, `CRABBY_ADMIN_PASSWORD`, `CRABBY_BASIC_AUTH_PASSWORD`, consumed via `envFrom` by the backend StatefulSet.

- [ ] **Step 1: Create the ConfigMap**

This is the repo `config.toml` with three edits: `admin_bind` bound to `0.0.0.0`, DB path pointed at the PVC, and the UI ingress origin added to `cors_origins`. Passwords/JWT are placeholders — the Secret overrides them at runtime via `config_env.rs`.

`k8s/base/backend-config.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: crabby-config
data:
  config.toml: |
    [server]
    proxy_bind = "0.0.0.0:8080"
    admin_bind = "0.0.0.0:8081"
    max_connections = 10000
    connection_timeout = 30
    tls_enabled = false
    tls_cert_path = ""
    tls_key_path = ""
    proxy_protocol_enabled = false

    [database]
    path = "sqlite:/app/data/proxy.db"
    max_connections = 10

    [authentication]
    enabled = true
    method = "basic"
    username = "admin"
    password = "overridden-by-env"
    jwt_secret = "overridden-by-env"
    jwt_expiration = 86400

    [protocols]
    enable_http = true
    enable_https = true
    enable_socks4 = true
    enable_socks5 = true
    auto_detect = true

    [features]
    connection_approval = true
    approval_timeout = 300
    reverse_tunnels = false
    tunnel_port_start = 10000
    tunnel_port_end = 10999
    webhook_events = []

    [state]
    backend = "memory"
    redis_url = "redis://localhost:6379"
    redis_pool_size = 10
    redis_key_prefix = "crabby_proxy:"
    redis_connection_timeout = 5

    [rate_limiting]
    enabled = true
    requests_per_second = 100
    burst_size = 200
    ban_duration = 300

    [filtering]
    ip_allowlist = []
    ip_blocklist = []
    geo_blocking_enabled = false
    blocked_countries = []
    allowed_countries = []
    ip_filter_mode = "blocklist"
    ip_filter_enabled = false
    global_allowed_targets = []
    global_blocked_targets = []

    [logging]
    level = "info"
    format = "json"
    file_enabled = false
    file_path = "proxy.log"
    access_log_enabled = true
    access_log_path = "access.log"

    [metrics]
    enabled = true
    prometheus_path = "/metrics"
    update_interval = 10

    [admin]
    enabled = true
    auth_enabled = true
    admin_username = "admin"
    admin_password = "overridden-by-env"
    websocket_enabled = true
    cors_enabled = true
    cors_origins = ["http://ui.crabby.local"]

    [advanced]
    buffer_size = 8192
    connection_pooling = false
    pool_max_idle_per_host = 10
    http2_enabled = false
    dns_cache_ttl = 300
```

- [ ] **Step 2: Create the Secret template**

`k8s/base/backend-secret.example.yaml` (dummy values — copy to `backend-secret.yaml` and fill real values, or create the Secret out-of-band):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: crabby-secrets
type: Opaque
stringData:
  # Must be >=32 bytes or the backend refuses to start.
  CRABBY_JWT_SECRET: "REPLACE_ME_with_a_long_random_string_min_32_bytes"
  CRABBY_ADMIN_PASSWORD: "REPLACE_ME_admin_password"
  CRABBY_BASIC_AUTH_PASSWORD: "REPLACE_ME_basic_auth_password"
```

- [ ] **Step 3: Ignore the real secret**

Append to `.gitignore`:
```
# Kubernetes real secret (never commit)
k8s/**/backend-secret.yaml
```

- [ ] **Step 4: Add ConfigMap to the base kustomization**

Add to the `resources:` list in `k8s/base/kustomization.yaml` (do NOT add the secret example — it is a template, not applied by base):
```yaml
  - backend-config.yaml
```

- [ ] **Step 5: Validate**

Run: `kubectl kustomize k8s/base`
Expected: prints Namespace + ConfigMap `crabby-config`; no Secret (template is excluded by design).

- [ ] **Step 6: Commit**

```bash
git add k8s/base/backend-config.yaml k8s/base/backend-secret.example.yaml k8s/base/kustomization.yaml .gitignore
git commit -m "feat(k8s): backend config + secret template"
```

---

### Task 3: Backend StatefulSet + Services

**Files:**
- Create: `k8s/base/backend-statefulset.yaml`
- Create: `k8s/base/backend-service.yaml`
- Modify: `k8s/base/kustomization.yaml` (add resources)

**Interfaces:**
- Consumes: ConfigMap `crabby-config` (Task 2), Secret `crabby-secrets` (Task 2), image name `crabby-proxy` (Task 1).
- Produces:
  - StatefulSet `crabby-backend`, pods labeled `app.kubernetes.io/name: crabby-backend`, governed by headless service `crabby-backend`.
  - Service `crabby-admin` (ClusterIP, port 8081) → ingress target in Task 5.
  - Service `crabby-proxy` (ClusterIP, port 8080) → forward-proxy entry, overlay may change type.
  - Headless Service `crabby-backend` (clusterIP None) → StatefulSet governance.

- [ ] **Step 1: Create the StatefulSet**

`k8s/base/backend-statefulset.yaml`:
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: crabby-backend
spec:
  serviceName: crabby-backend
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: crabby-backend
  template:
    metadata:
      labels:
        app.kubernetes.io/name: crabby-backend
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: crabby-proxy
          image: crabby-proxy:latest
          # Do NOT override args — the image CMD already binds
          # 0.0.0.0:8080 (proxy) / 0.0.0.0:8081 (admin) and json logs.
          ports:
            - name: proxy
              containerPort: 8080
            - name: admin
              containerPort: 8081
          envFrom:
            - secretRef:
                name: crabby-secrets
          volumeMounts:
            - name: data
              mountPath: /app/data
            - name: config
              mountPath: /app/config.toml
              subPath: config.toml
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: admin
            initialDelaySeconds: 10
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: admin
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: crabby-config
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
```

- [ ] **Step 2: Create the Services**

`k8s/base/backend-service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: crabby-backend
  labels:
    app.kubernetes.io/name: crabby-backend
spec:
  clusterIP: None
  selector:
    app.kubernetes.io/name: crabby-backend
  ports:
    - name: admin
      port: 8081
      targetPort: admin
---
apiVersion: v1
kind: Service
metadata:
  name: crabby-admin
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: crabby-backend
  ports:
    - name: admin
      port: 8081
      targetPort: admin
---
apiVersion: v1
kind: Service
metadata:
  name: crabby-proxy
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: crabby-backend
  ports:
    - name: proxy
      port: 8080
      targetPort: proxy
```

- [ ] **Step 3: Add to the base kustomization**

Add to `resources:` in `k8s/base/kustomization.yaml`:
```yaml
  - backend-service.yaml
  - backend-statefulset.yaml
```

- [ ] **Step 4: Validate build + client dry-run**

Run: `kubectl kustomize k8s/base`
Expected: prints StatefulSet `crabby-backend` with image `crabby-proxy:latest` and three Services.

Run: `kubectl apply --dry-run=client -k k8s/base`
Expected: each resource prints `... (dry run)` with no schema error. (Requires a reachable kube-context for client dry-run; if none, `kubectl kustomize` output is sufficient.)

- [ ] **Step 5: Commit**

```bash
git add k8s/base/backend-statefulset.yaml k8s/base/backend-service.yaml k8s/base/kustomization.yaml
git commit -m "feat(k8s): backend StatefulSet + services"
```

---

### Task 4: UI Deployment + Service

**Files:**
- Create: `k8s/base/ui-deployment.yaml`
- Create: `k8s/base/ui-service.yaml`
- Modify: `k8s/base/kustomization.yaml` (add resources)

**Interfaces:**
- Consumes: image name `crabby-proxy-web` (Task 1).
- Produces:
  - Deployment `crabby-ui`, pods labeled `app.kubernetes.io/name: crabby-ui`.
  - Service `crabby-ui` (ClusterIP, port 8080) → ingress target in Task 5.

- [ ] **Step 1: Create the Deployment**

`k8s/base/ui-deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crabby-ui
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: crabby-ui
  template:
    metadata:
      labels:
        app.kubernetes.io/name: crabby-ui
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: crabby-web
          image: crabby-proxy-web:latest
          ports:
            - name: http
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /
              port: http
            initialDelaySeconds: 8
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              memory: 256Mi
```

- [ ] **Step 2: Create the Service**

`k8s/base/ui-service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: crabby-ui
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: crabby-ui
  ports:
    - name: http
      port: 8080
      targetPort: http
```

- [ ] **Step 3: Add to the base kustomization**

Add to `resources:` in `k8s/base/kustomization.yaml`:
```yaml
  - ui-service.yaml
  - ui-deployment.yaml
```

- [ ] **Step 4: Validate**

Run: `kubectl kustomize k8s/base`
Expected: now includes Deployment `crabby-ui` (image `crabby-proxy-web:latest`) and Service `crabby-ui`.

- [ ] **Step 5: Commit**

```bash
git add k8s/base/ui-deployment.yaml k8s/base/ui-service.yaml k8s/base/kustomization.yaml
git commit -m "feat(k8s): UI deployment + service"
```

---

### Task 5: Ingress (HTTP, no TLS)

**Files:**
- Create: `k8s/base/ingress.yaml`
- Modify: `k8s/base/kustomization.yaml` (add resource)

**Interfaces:**
- Consumes: Service `crabby-ui:8080` (Task 4), Service `crabby-admin:8081` (Task 3).
- Produces: Ingress `crabby-ingress` routing `ui.crabby.local` → UI, `admin.crabby.local` → admin API.

- [ ] **Step 1: Create the Ingress**

`k8s/base/ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: crabby-ingress
spec:
  ingressClassName: nginx
  rules:
    - host: ui.crabby.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: crabby-ui
                port:
                  number: 8080
    - host: admin.crabby.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: crabby-admin
                port:
                  number: 8081
```

- [ ] **Step 2: Add to the base kustomization**

Add to `resources:` in `k8s/base/kustomization.yaml`:
```yaml
  - ingress.yaml
```

- [ ] **Step 3: Validate**

Run: `kubectl kustomize k8s/base`
Expected: includes Ingress `crabby-ingress` with both hosts and `ingressClassName: nginx`.

- [ ] **Step 4: Commit**

```bash
git add k8s/base/ingress.yaml k8s/base/kustomization.yaml
git commit -m "feat(k8s): http ingress for ui + admin"
```

---

### Task 6: Overlays (dev + prod)

**Files:**
- Create: `k8s/overlays/dev/kustomization.yaml`
- Create: `k8s/overlays/dev/proxy-nodeport.yaml`
- Create: `k8s/overlays/prod/kustomization.yaml`

**Interfaces:**
- Consumes: everything in `k8s/base`.
- Produces: two applyable overlays. Dev exposes the forward proxy via NodePort `30080`; prod pins image tags and scales the UI to 2 replicas.

- [ ] **Step 1: Create the dev proxy NodePort patch**

`k8s/overlays/dev/proxy-nodeport.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: crabby-proxy
spec:
  type: NodePort
  ports:
    - name: proxy
      port: 8080
      targetPort: proxy
      nodePort: 30080
```

- [ ] **Step 2: Create the dev kustomization**

`k8s/overlays/dev/kustomization.yaml`:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

patches:
  - path: proxy-nodeport.yaml
    target:
      kind: Service
      name: crabby-proxy
```

- [ ] **Step 3: Create the prod kustomization**

`k8s/overlays/prod/kustomization.yaml` (image tags are placeholders the pipeline overrides with `kustomize edit set image`):
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

replicas:
  - name: crabby-ui
    count: 2

images:
  - name: crabby-proxy
    newName: crabby-proxy
    newTag: latest
  - name: crabby-proxy-web
    newName: crabby-proxy-web
    newTag: latest
```

- [ ] **Step 4: Validate both overlays**

Run: `kubectl kustomize k8s/overlays/dev`
Expected: `crabby-proxy` Service is `type: NodePort` with `nodePort: 30080`; all base resources present.

Run: `kubectl kustomize k8s/overlays/prod`
Expected: Deployment `crabby-ui` shows `replicas: 2`; images resolve to `crabby-proxy:latest` / `crabby-proxy-web:latest`.

- [ ] **Step 5: Commit**

```bash
git add k8s/overlays
git commit -m "feat(k8s): dev + prod overlays"
```

---

### Task 7: Deploy docs (README + Jenkins contract)

**Files:**
- Create: `k8s/README.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: human-facing deploy instructions and the Jenkins pipeline contract from the spec.

- [ ] **Step 1: Write the deploy README**

`k8s/README.md`:
````markdown
# crabby-proxy on Kubernetes

Kustomize manifests for the backend (`crabby_proxy`) and admin UI (`web/`).

## Layout

- `base/` — namespace, backend StatefulSet + services, UI deployment + service, ingress, config.
- `overlays/dev/` — forward proxy exposed via NodePort `30080`.
- `overlays/prod/` — UI scaled to 2 replicas, image tags pinned by the pipeline.

## Prerequisites

- An nginx ingress controller in the cluster.
- A default StorageClass (backend PVC uses it).
- The `crabby-secrets` Secret (NOT in git):

```bash
cp base/backend-secret.example.yaml base/backend-secret.yaml
# edit real values, then:
kubectl create namespace crabby-proxy
kubectl apply -n crabby-proxy -f base/backend-secret.yaml
```

## Deploy

```bash
kubectl apply -k overlays/dev     # or overlays/prod
kubectl -n crabby-proxy rollout status statefulset/crabby-backend
kubectl -n crabby-proxy rollout status deploy/crabby-ui
```

Add to `/etc/hosts` (point at the ingress controller IP) for local access:

```
<INGRESS_IP>  ui.crabby.local admin.crabby.local
```

## Jenkins pipeline contract

1. Build + push backend → `$REGISTRY/crabby-proxy:$TAG`.
2. Build + push UI with `--build-arg VITE_API_BASE_URL=http://admin.crabby.local` → `$REGISTRY/crabby-proxy-web:$TAG`.
3. Ensure `crabby-secrets` exists in the `crabby-proxy` namespace.
4. Pin images:
   ```bash
   cd k8s/overlays/prod
   kubectl kustomize edit set image \
     crabby-proxy=$REGISTRY/crabby-proxy:$TAG \
     crabby-proxy-web=$REGISTRY/crabby-proxy-web:$TAG
   ```
   (`kubectl kustomize edit` requires kubectl ≥1.27; otherwise install the `kustomize` binary for `kustomize edit set image`.)
5. `kubectl apply -k .`
6. `kubectl -n crabby-proxy rollout status statefulset/crabby-backend deploy/crabby-ui`

## Notes

- Backend is single-writer SQLite → never scale above 1 replica.
- Migrations run automatically on backend startup; no separate Job.
- `VITE_API_BASE_URL` is baked at UI build time; changing the admin host means rebuilding the UI image.
````

- [ ] **Step 2: Commit**

```bash
git add k8s/README.md
git commit -m "docs(k8s): deploy instructions + jenkins contract"
```

---

## Self-Review

**Spec coverage:**
- StatefulSet 1 replica + PVC + auto-restart → Task 3. ✓
- ConfigMap-mounted config with CORS + DB path → Task 2. ✓
- Secret (plain) + gitignore → Task 2. ✓
- UI Deployment + build-arg contract → Task 4, Task 7. ✓
- Proxy TCP Service separate from ingress → Task 3 (ClusterIP) + Task 6 (NodePort). ✓
- Ingress HTTP no TLS → Task 5. ✓
- Kustomize base + dev/prod overlays → Task 1, Task 6. ✓
- Migrations on startup (no Job) → confirmed in `src/db/connection.rs`, documented Task 7. ✓
- Jenkins image-pin contract → Task 6 (images field) + Task 7 (README). ✓

**Placeholder scan:** No TBD/TODO. Password/JWT placeholders in the ConfigMap are intentional (overridden by env) and documented. Secret example uses `REPLACE_ME_*` by design.

**Type consistency:** Label selector `app.kubernetes.io/name: crabby-backend` used consistently across StatefulSet, headless service, admin service, proxy service. `crabby-ui` label consistent across Deployment/Service/Ingress. Image logical names `crabby-proxy` / `crabby-proxy-web` consistent across base kustomization, workloads, prod overlay, and README. Ports `proxy`/`admin`/`http` named consistently between containers, services, probes, and ingress.
