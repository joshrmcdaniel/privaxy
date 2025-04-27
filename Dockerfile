# syntax=docker/dockerfile:1

ARG PRIVAXY_BASE_PATH="/conf"

# Build stage
FROM rust:1.86.0 AS builder
WORKDIR /app
COPY . .
ARG PRIVAXY_BASE_PATH
RUN rustup target add wasm32-unknown-unknown \
    && apt-get update && apt-get install -y \
    pkg-config \
    build-essential \
    cmake \
    clang \
    libssl-dev \
    nodejs \
    npm \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall trunk \
    && cd web_frontend \
    && npm i && trunk build --release \
    && cd .. && cargo build --release \
    && mkdir -p "${PRIVAXY_BASE_PATH}"

FROM gcr.io/distroless/cc-debian12:latest
ARG PRIVAXY_BASE_PATH
COPY --from=builder /app/target/release/privaxy /app/privaxy
COPY --from=builder "${PRIVAXY_BASE_PATH}" "${PRIVAXY_BASE_PATH}"
ENV PRIVAXY_BASE_PATH="${PRIVAXY_BASE_PATH}"
VOLUME [ "${PRIVAXY_BASE_PATH}" ]

EXPOSE 8100 8200
WORKDIR /app
ENTRYPOINT ["/app/privaxy"]