# syntax=docker/dockerfile:1.7
#
# Build + serve the TanStack Start admin console as a Nitro node-server.
# The browser talks to the Rust admin API directly via VITE_API_BASE_URL
# (the backend's CORS allow-list must include this web origin), so no
# reverse-proxy is required in front.

ARG BUN_VERSION=1
ARG NODE_VERSION=22-alpine

########################################
# Stage 1: build (bun + node-server preset)
########################################
FROM oven/bun:${BUN_VERSION} AS builder
WORKDIR /app
ENV CI=1 NODE_ENV=production

COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

COPY . .

# Public base URL of the admin API (e.g. https://admin.example.com). Baked into
# the client bundle at build time. Empty → same-origin (front it with a proxy).
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
# Emit a standalone node server instead of the default cloudflare worker.
ENV NITRO_PRESET=node-server

RUN bun run build

########################################
# Stage 2: runtime (node serves .output)
########################################
FROM node:${NODE_VERSION} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

RUN apk add --no-cache tini curl

COPY --from=builder /app/.output ./.output

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ >/dev/null || exit 1

ENTRYPOINT ["/sbin/tini","--"]
CMD ["node", ".output/server/index.mjs"]
