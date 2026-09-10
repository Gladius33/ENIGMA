# syntax=docker/dockerfile:1.7

FROM rust:1.91.1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp /app/target/release/enigma-e2ee-server /tmp/enigma-e2ee-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 enigma \
    && useradd --system --uid 10001 --gid enigma --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin enigma

COPY --from=builder /tmp/enigma-e2ee-server /usr/local/bin/enigma-e2ee-server

USER 10001:10001

EXPOSE 8080
CMD ["enigma-e2ee-server"]
