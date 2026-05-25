# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS base
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    curl -fsSL https://deb.nodesource.com/setup_23.x | bash - \
    && apt-get install -qy --no-install-recommends \
        nodejs pkg-config build-essential cmake clang libssl-dev \
    && rustup target add wasm32-unknown-unknown \
    && cargo install trunk --locked

FROM base AS builder
WORKDIR /app

COPY web_frontend/package.json web_frontend/package-lock.json web_frontend/
RUN --mount=type=cache,target=/root/.npm \
    cd web_frontend && npm ci

COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release; rm src/main.rs

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/root/.npm \
    cd web_frontend && trunk build --release \
    && cd .. && cargo build --release \
    && cp target/release/privaxy /app/privaxy-out

# --- Final image ---
FROM gcr.io/distroless/cc-debian12:nonroot
ARG PRIVAXY_BASE_PATH="/conf"
ARG PRIVAXY_PROXY_PORT=8100
ARG PRIVAXY_WEB_PORT=8200
ENV PRIVAXY_BASE_PATH="${PRIVAXY_BASE_PATH}"
COPY --from=builder /app/privaxy-out /app/privaxy
VOLUME ["${PRIVAXY_BASE_PATH}"]
EXPOSE ${PRIVAXY_PROXY_PORT} ${PRIVAXY_WEB_PORT}
WORKDIR /app
ENTRYPOINT ["/app/privaxy"]