# syntax=docker/dockerfile:1.7

ARG BUN_VERSION=1
ARG NGINX_VERSION=1.27-alpine

########################################
# Stage 1: build the Vite/React SPA.
#
# bun is the source-of-truth package manager here (bun.lock is committed
# and kept in sync; package-lock.json lags behind), so we install + build
# with bun for a reproducible dep graph.
########################################
FROM oven/bun:${BUN_VERSION} AS builder

WORKDIR /app

ENV CI=1 \
    NODE_ENV=production

# Install deps first for better layer caching. Using --frozen-lockfile
# so CI fails loudly if bun.lock drifts from package.json.
COPY package.json bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile

# Then copy sources and build. VITE_* build-time vars can be passed via
# --build-arg and picked up by Vite automatically.
COPY . .

ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN bun run build

########################################
# Stage 2: serve static assets via nginx.
########################################
FROM nginx:${NGINX_VERSION} AS runtime

# Drop default site, install tini + curl for healthcheck/PID 1 hygiene.
RUN apk add --no-cache tini curl \
 && rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# nginx:alpine already runs as non-root for worker processes; master needs
# root to bind <1024. Keep port 8080 so we can drop root and still bind.
RUN sed -i 's|listen\s*80;|listen 8080;|' /etc/nginx/conf.d/default.conf \
 && chown -R nginx:nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html \
 && touch /var/run/nginx.pid \
 && chown nginx:nginx /var/run/nginx.pid

USER nginx:nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/ >/dev/null || exit 1

ENTRYPOINT ["/sbin/tini","--"]
CMD ["nginx","-g","daemon off;"]
