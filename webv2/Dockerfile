# syntax=docker/dockerfile:1.7
#
# Build the webv2 SPA with bun, serve the static bundle with nginx.
# No SSR runtime — the app is a pure static bundle; nginx also proxies
# /api and /health to the backend so the browser stays same-origin
# (no CORS configuration needed).

ARG BUN_VERSION=1
ARG NGINX_VERSION=1.27-alpine

########################################
# Stage 1: build
########################################
FROM oven/bun:${BUN_VERSION} AS builder
WORKDIR /app
ENV CI=1

COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY . .

# Public URL of the admin API. Empty (default) = same-origin: nginx below
# proxies /api + /health to the backend, which avoids CORS entirely.
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN bun run build

########################################
# Stage 2: runtime
########################################
FROM nginx:${NGINX_VERSION} AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
