# syntax=docker/dockerfile:1

ARG PRIVAXY_BASE_PATH="/conf"

FROM rust:1 AS builder
WORKDIR /app
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    & rustup target add wasm32-unknown-unknown \
    && cargo binstall trunk
RUN apt-get update && apt-get install -qy \
    pkg-config \
    build-essential \
    cmake \
    clang \
    libssl-dev \
    git
RUN curl -fsSL https://deb.nodesource.com/setup_23.x -o nodesource_setup.sh \
    && bash nodesource_setup.sh \
    && apt-get install -qy nodejs
COPY . .
RUN cd web_frontend \
    && npm i \
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