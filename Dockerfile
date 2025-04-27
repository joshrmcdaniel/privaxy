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

COPY --from=builder /app/target/release/privaxy /app/privaxy

ARG PRIVAXY_BASE_PATH="/conf"
ENV PRIVAXY_BASE_PATH="${PRIVAXY_BASE_PATH}"
# todo: add support for reading proxy vars
ARG PRIVAXY_PROXY_PORT=8100
ARG PRIVAXY_WEB_PORT=8200

VOLUME [ "${PRIVAXY_BASE_PATH}" ]


EXPOSE ${PRIVAXY_PROXY_PORT} ${PRIVAXY_WEB_PORT}
WORKDIR /app
ENTRYPOINT ["/app/privaxy"]