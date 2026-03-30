# Cross-compilation images — selected by TARGETARCH (set automatically by buildx)
ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=registry_token \
    mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "shroudb-cratesio"\n\n[source.shroudb-cratesio]\nregistry = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\n\n[registries.shroudb-cratesio]\nindex = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\ncredential-provider = ["cargo:token"]\n\n[registries.shroudb]\nindex = "sparse+https://crates.shroudb.dev/api/v1/crates/"\ncredential-provider = ["cargo:token"]\n' > /root/.cargo/config.toml && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    CARGO_REGISTRIES_SHROUDB_CRATESIO_TOKEN="$(cat /run/secrets/registry_token)" \
    CARGO_REGISTRIES_SHROUDB_TOKEN="$(cat /run/secrets/registry_token)" \
    cargo build --release --target "$RUST_TARGET" -p shroudb-sentry-server -p shroudb-sentry-cli && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-sentry" /out/ && \
    cp "target/$RUST_TARGET/release/shroudb-sentry-cli" /out/

# --- shroudb-sentry: authorization policy engine ---
FROM alpine:3.21 AS shroudb-sentry
RUN adduser -D -u 65532 shroudb && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Sentry" \
      org.opencontainers.image.description="Policy-based authorization engine with signed JWT decisions" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-sentry /shroudb-sentry
VOLUME /data
WORKDIR /data
USER shroudb
EXPOSE 6799
ENTRYPOINT ["/shroudb-sentry"]

# --- shroudb-sentry-cli: CLI tool ---
FROM alpine:3.21 AS shroudb-sentry-cli
RUN adduser -D -u 65532 shroudb
LABEL org.opencontainers.image.title="ShrouDB Sentry CLI" \
      org.opencontainers.image.description="CLI tool for the Sentry authorization policy engine" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-sentry-cli /shroudb-sentry-cli
USER shroudb
ENTRYPOINT ["/shroudb-sentry-cli"]
