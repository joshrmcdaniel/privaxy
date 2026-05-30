# syntax=docker/dockerfile:1
#
# ---------------------------------------------------------------------------
#
# Build modes
#   BUILD_MODE=compile  (default) — full Rust + trunk build inside the image
#   BUILD_MODE=prebuilt           — copy a pre-built binary from build context
#                                    at $PREBUILT_BINARY (default ./privaxy)
# CI uses `prebuilt` after the native `ci` matrix job; local `docker build .`
# falls through to `compile`.
#
# Compile mode for local building.
#
# ---------------------------------------------------------------------------
#
ARG BUILD_MODE=compile
#
FROM rust:1-trixie AS compile-base
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && apt-get install -qy --no-install-recommends \
         nodejs pkg-config build-essential cmake clang libssl-dev \
    && rustup target add wasm32-unknown-unknown \
    && cargo binstall trunk --locked && node -v

FROM compile-base AS compile
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
ARG COMPILE_MODE="release"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/root/.npm \
    cd web_frontend && trunk build --${COMPILE_MODE} \
    && cd .. && cargo build --${COMPILE_MODE} \
    && cp target/${COMPILE_MODE}/privaxy /privaxy-out \
    && chmod +x /privaxy-out

# Prebuilt path: expect $PREBUILT_BINARY to exist in the build context.
FROM debian:trixie-slim AS prebuilt
ARG PREBUILT_BINARY=privaxy
COPY ${PREBUILT_BINARY} /privaxy-out
RUN chmod +x /privaxy-out

FROM ${BUILD_MODE} AS source

FROM debian:trixie-slim AS confdir
ARG PRIVAXY_BASE_PATH="/conf"
RUN mkdir -p "${PRIVAXY_BASE_PATH}"

# --- Final image ---
FROM gcr.io/distroless/cc-debian13:nonroot
ARG PRIVAXY_BASE_PATH="/conf"
ARG PRIVAXY_PROXY_PORT=8100
ARG PRIVAXY_WEB_PORT=8200
ENV PRIVAXY_BASE_PATH="${PRIVAXY_BASE_PATH}"
COPY --from=source /privaxy-out /app/privaxy
COPY --from=confdir --chown=nonroot:nonroot ${PRIVAXY_BASE_PATH} ${PRIVAXY_BASE_PATH}
VOLUME ["${PRIVAXY_BASE_PATH}"]
EXPOSE ${PRIVAXY_PROXY_PORT} ${PRIVAXY_WEB_PORT}
WORKDIR /app
ENTRYPOINT ["/app/privaxy"]
