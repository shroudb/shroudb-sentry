# ShrouDB Sentry

Policy-based authorization engine. Sentry evaluates access control policies (principal + action + resource) and returns signed JWT decisions. External services verify decisions using the JWKS endpoint -- no callback to Sentry required.

Built on ShrouDB's cryptographic and storage foundation (shroudb-crypto, shroudb-storage).

## Quick Start

```bash
# Start with ephemeral master key (dev mode)
cargo run -- --config sentry.toml

# Start with persistent master key
export SHROUDB_MASTER_KEY="base64-encoded-32-byte-key"
cargo run -- --config sentry.toml
```

Default port: `6799` (TCP), `6800` (HTTP).

## Installation

### Homebrew

```sh
brew install shroudb/tap/shroudb-sentry
```

Installs `shroudb-sentry` (server) and `shroudb-sentry-cli`.

### Docker

```sh
docker pull shroudb/sentry
```

A CLI image is also available:

```sh
docker pull shroudb/sentry-cli
```

### Binary

Download prebuilt binaries from [GitHub Releases](https://github.com/shroudb/shroudb-sentry/releases). Available for Linux (x86_64, aarch64) and macOS (x86_64, Apple Silicon).

---

## Docker

The server image is `shroudb/sentry`. It runs as a non-root user on a minimal distroless base.

**1. Create a config file** (`sentry.toml`):

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"

[policies]
dir = "/policies"
default_decision = "deny"

[signing]
algorithm = "ES256"
rotation_days = 90
drain_days = 30
```

**2. Run:**

```bash
docker run -d \
  --name shroudb-sentry \
  -p 6799:6799 \
  -p 6800:6800 \
  -v sentry-data:/data \
  -v ./sentry.toml:/sentry.toml:ro \
  -v ./policies:/policies:ro \
  -e SHROUDB_MASTER_KEY="base64-encoded-32-byte-key" \
  shroudb/sentry \
  --config /sentry.toml
```

- `-v sentry-data:/data` -- persists WAL and snapshots. **Without this volume, all signing key material is lost on container restart.**
- `-v ./policies:/policies:ro` -- mounts your policy directory read-only.
- `-e SHROUDB_MASTER_KEY` -- the 32-byte base64-encoded master key. Omit for ephemeral dev mode. Can also use `SHROUDB_MASTER_KEY_FILE` pointing to a mounted secrets file.

A CLI image is also available:

```bash
docker run --rm -it shroudb/sentry-cli --host <sentry-host> --port 6799
```

## Features

- **Policy files** loaded from a directory (TOML format), hot-reloadable via `POLICY_RELOAD` or filesystem watch.
- **Signed decisions** -- every EVALUATE response includes a JWT signed with the server's signing key (ES256, EdDSA, RS256/384/512, or HMAC-SHA256).
- **JWKS endpoint** at `/.well-known/jwks.json` on the HTTP port -- external services verify decision tokens without calling back to Sentry.
- **Decision caching** -- configurable TTL to avoid re-evaluating identical requests.
- **Key lifecycle** -- rotation, drain, retire (Staged -> Active -> Draining -> Retired), same model as Transit.
- **Default-deny** -- configurable default decision when no policy matches (deny or permit).
- **Wire protocol** for programmatic access, plus HTTP sidecar for JWKS.
- **Runtime configuration** via CONFIG GET/SET/LIST without restarts.
- **Telemetry** via shroudb-telemetry (console + audit file + OTEL).

## Architecture

```
shroudb-sentry/
  shroudb-sentry-core/       Core domain types (policies, decisions, signing)
  shroudb-sentry-protocol/   Command parsing, dispatch, handlers, auth
  shroudb-sentry-server/     TCP server, HTTP server, config, TLS
  shroudb-sentry-client/     Async Rust client library
  shroudb-sentry-cli/        Interactive CLI with tab completion
```

## Commands

### EVALUATE

```
EVALUATE <json>
```

Evaluate an authorization request against loaded policies. The JSON payload contains the principal, action, and resource. Returns a PERMIT or DENY decision as a signed JWT.

```
{status: OK, decision: "permit", token: "eyJhbG...", policy: "admin-access", cache_until: 1711469100}
```

The `token` field is a signed JWT that encodes the decision. Verify it against the JWKS endpoint.

### POLICY_RELOAD

```
POLICY_RELOAD
```

Reload all policies from the configured directory. Invalidates the decision cache.

### POLICY_LIST

```
POLICY_LIST
```

List all loaded policy names.

### POLICY_INFO

```
POLICY_INFO <name>
```

Get details about a specific policy: name, version, rule count, load time.

### KEY_ROTATE

```
KEY_ROTATE [FORCE] [DRYRUN]
```

Rotate the signing key. Without `FORCE`, rotation only proceeds if the active key has exceeded `rotation_days`. `DRYRUN` previews the rotation plan without applying changes.

### KEY_INFO

```
KEY_INFO
```

Returns the current signing key metadata: key ID, algorithm, creation time, and state.

### HEALTH

```
HEALTH
```

Server health check. Returns engine state and loaded policy count.

### CONFIG GET / SET / LIST

```
CONFIG GET <key>
CONFIG SET <key> <value>
CONFIG LIST
```

Runtime configuration management. Get, set, or list configuration values without restarting the server.

## Signing Algorithms

| Algorithm | Type | Config value |
|-----------|------|--------------|
| ECDSA P-256 | Asymmetric | `ES256` (default) |
| ECDSA P-384 | Asymmetric | `ES384` |
| Ed25519 | Asymmetric | `EdDSA` |
| RSA 2048+ | Asymmetric | `RS256`, `RS384`, `RS512` |
| HMAC-SHA256 | Symmetric | `HS256` |

Asymmetric algorithms expose public keys via the JWKS endpoint. HMAC-SHA256 requires shared-secret verification.

## Configuration

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"
# tls_client_ca = "/path/to/ca.pem"  # enables mTLS
# rate_limit = 1000  # per-connection commands/sec

[storage]
data_dir = "./sentry-data"
wal_fsync_mode = "batched"          # per_write | batched | periodic
wal_fsync_interval_ms = 10
wal_segment_max_bytes = 67108864    # 64 MB
snapshot_interval_entries = 100000
snapshot_interval_minutes = 60

[auth]
method = "token"  # "none" (default) or "token"

[auth.policies.admin]
token = "${SENTRY_ADMIN_TOKEN}"
commands = ["*"]

[auth.policies.evaluator]
token = "evaluator-token"
commands = ["EVALUATE", "HEALTH"]

[signing]
algorithm = "ES256"
rotation_days = 90
drain_days = 30
decision_ttl_secs = 300

[policies]
dir = "./policies"
default_decision = "deny"       # "deny" (default) or "permit"
watch = false                   # filesystem watch for auto-reload

[evaluation]
cache_enabled = false
cache_ttl_secs = 60
max_batch_size = 100
```

Environment variables can be interpolated with `${VAR}` syntax.

## Key Lifecycle

Signing keys follow a state machine: **Staged -> Active -> Draining -> Retired**.

- **Active**: used to sign new decisions. JWKS endpoint includes the public key.
- **Draining**: no longer used for new signatures, but the public key remains in JWKS so existing tokens can still be verified.
- **Retired**: removed from JWKS. Tokens signed with this key can no longer be verified.

## Authentication

When `auth.method = "token"`, clients must authenticate with `AUTH <token>` before executing commands. Each token maps to a policy that scopes access to specific commands. Wildcard `"*"` allows all.

When `auth.method = "none"` (default), all commands are allowed without authentication.

## Wire Protocol

TCP wire protocol with Sentry-specific command verbs. Supports pipelining via `PIPELINE ... END`.

URI schemes: `shroudb-sentry://[token@]host[:port]` or `shroudb-sentry+tls://[token@]host[:port]`.

## Security Model

- **Decisions are cryptographically signed.** Every EVALUATE response includes a JWT that can be verified offline using the JWKS endpoint. No callback to Sentry required.
- **Default-deny.** When no policy matches, the configured default decision applies (deny by default).
- **Key material is encrypted at rest.** Signing keys are stored in the WAL, encrypted with the master key.
- **Policy isolation.** Policies are loaded from read-only files. Runtime changes require POLICY_RELOAD or filesystem watch.
- **Core dump prevention.** On Linux, `PR_SET_DUMPABLE` is disabled to prevent secrets from leaking via core dumps.

## Client Library

```rust
use shroudb_sentry_client::SentryClient;

let mut client = SentryClient::connect("127.0.0.1:6799").await?;

// Evaluate an authorization request
let result = client.evaluate(r#"{"principal":"user:alice","action":"read","resource":"secrets/prod"}"#).await?;
println!("Decision: {}", result.decision);
println!("Token: {}", result.token);
```

## What ShrouDB Sentry is NOT

- **Not an identity provider.** It does not authenticate users -- it authorizes already-authenticated principals.
- **Not a policy editor.** Policies are TOML files managed outside Sentry. Sentry loads and evaluates them.
- **Not a token issuer for general use.** The signed JWTs encode authorization decisions, not identity claims.
