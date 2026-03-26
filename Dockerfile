# Cross-compilation images — selected by TARGETARCH (set automatically by buildx)
ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=git_auth,env=GIT_AUTH_URL \
    if [ -n "$GIT_AUTH_URL" ]; then git config --global url."$GIT_AUTH_URL".insteadOf "https://github.com/"; fi && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    cargo build --release --target "$RUST_TARGET" \
    -p shroudb-sentry-server && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-sentry" /out/

# --- shroudb-sentry: policy-based authorization engine ---
FROM alpine:3.21 AS shroudb-sentry
RUN adduser -D -u 65532 shroudb && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Sentry" \
      org.opencontainers.image.description="Policy-based authorization engine — evaluates access control policies and returns signed JWT decisions" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-sentry" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-sentry /shroudb-sentry
VOLUME /data
WORKDIR /data
USER shroudb
EXPOSE 6799 6800
ENTRYPOINT ["/shroudb-sentry"]
