# syntax=docker/dockerfile:1

ARG PRIVAXY_BASE_PATH="/conf"

FROM node:lts-slim AS node
WORKDIR /app
COPY . .
RUN cd web_frontend \
    && npm i \
    && npx tailwindcss build -i src/tailwind.css -o dist/.stage/tailwind.css


FROM rust:1 AS builder
WORKDIR /app
COPY . .
COPY --from=node /app/web_frontend/dist/ /app/web_frontend/dist/
COPY --from=node /app/web_frontend/node_modules/ /app/web_frontend/node_modules/
COPY --from=node /app/web_frontend/dist/.stage/tailwind.css /app/web_frontend/dist/.stage/tailwind.css
COPY <<EOF /app/web_frontend/Trunk.toml
[build]
target = "index.html"
dist = "dist"
EOF
RUN rustup target add wasm32-unknown-unknown \
    && apt-get update && apt-get install -qy \
    pkg-config \
    build-essential \
    cmake \
    clang \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall trunk \
    && cd web_frontend \
    && trunk build --release \
    && cd .. && cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot-${BUILDARCH}
ARG PRIVAXY_BASE_PATH
COPY --from=builder /app/target/release/privaxy /app/privaxy
ENV PRIVAXY_BASE_PATH="${PRIVAXY_BASE_PATH}"
VOLUME [ "${PRIVAXY_BASE_PATH}" ]

EXPOSE 8100 8200
WORKDIR /app
ENTRYPOINT ["/app/privaxy"]