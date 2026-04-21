# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.90
ARG DEBIAN_CODENAME=bookworm

########################################
# Stage 1: build the Rust binary.
#
# BuildKit cache mounts keep the cargo registry, git index, and target/
# directory hot across rebuilds without baking them into the final image.
########################################
FROM rust:${RUST_VERSION}-${DEBIAN_CODENAME} AS builder

WORKDIR /app

ENV CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked --bin crabby_proxy \
 && install -Dm755 target/release/crabby_proxy /out/crabby_proxy \
 && strip /out/crabby_proxy

########################################
# Stage 2: minimal runtime image.
########################################
FROM debian:${DEBIAN_CODENAME}-slim AS runtime

ARG APP_UID=10001
ARG APP_GID=10001

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
        curl; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid ${APP_GID} crabby; \
    useradd  --system --uid ${APP_UID} --gid crabby \
             --home-dir /app --shell /usr/sbin/nologin crabby; \
    mkdir -p /app/data; \
    chown -R crabby:crabby /app

WORKDIR /app

COPY --from=builder /out/crabby_proxy /usr/local/bin/crabby_proxy
COPY --chown=crabby:crabby config.toml /app/config.toml

# Point SQLite at the mountable data volume rather than cwd.
RUN sed -i 's|sqlite:proxy\.db|sqlite:/app/data/proxy.db|' /app/config.toml

USER crabby:crabby

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8081/metrics >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/crabby_proxy"]
CMD ["--config","/app/config.toml", \
     "--proxy-bind","0.0.0.0:8080", \
     "--admin-bind","0.0.0.0:8081", \
     "--log-format","json"]
