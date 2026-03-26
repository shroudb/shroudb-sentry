# ShrouDB Sentry Documentation

ShrouDB Sentry is a centralized, policy-based authorization engine. It evaluates access control requests against declarative policies and returns cryptographically signed JWT decisions. Downstream services verify these decisions offline using the public keys served from the JWKS endpoint — no callback to Sentry required.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Policies](#policies)
- [Commands](#commands)
- [Signing & Key Management](#signing--key-management)
- [Authentication](#authentication)
- [JWKS Endpoint](#jwks-endpoint)
- [CLI](#cli)
- [Client Library](#client-library)
- [Docker](#docker)
- [Error Reference](#error-reference)

---

## Quick Start

### Prerequisites

- Rust 1.92+

### Build

```bash
cargo build --release
```

This produces two binaries:

- `shroudb-sentry-server` — the authorization server
- `shroudb-sentry-cli` — interactive command-line client

### Run (development)

```bash
cargo run -- --config sentry.toml
```

Without a master key, Sentry generates an ephemeral key on startup. Signing keys are not persisted across restarts in this mode.

### Run (production)

```bash
export SHROUDB_MASTER_KEY="<base64-encoded-32-byte-key>"
cargo run --release -- --config sentry.toml
```

Or point to a key file:

```bash
export SHROUDB_MASTER_KEY_FILE="/path/to/master.key"
```

**Default ports:**

| Interface | Port | Purpose |
|-----------|------|---------|
| TCP | 6799 | Authorization protocol |
| HTTP | 6800 | JWKS public key endpoint |

---

## Configuration

Sentry is configured with a TOML file. Environment variables can be interpolated using `${VAR}` syntax.

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"
# tls_client_ca = "/path/to/ca.pem"   # enables mTLS
# rate_limit = 1000                    # per-connection commands/sec

[storage]
data_dir = "./sentry-data"
wal_fsync_mode = "batched"             # per_write | batched | periodic
wal_fsync_interval_ms = 10
wal_segment_max_bytes = 67108864       # 64 MB
snapshot_interval_entries = 100000
snapshot_interval_minutes = 60

[auth]
method = "none"                        # "none" or "token"

[signing]
algorithm = "ES256"
rotation_days = 90
drain_days = 30
decision_ttl_secs = 300

[policies]
dir = "./policies"
default_decision = "deny"              # "deny" or "permit"
watch = false                          # hot-reload on file change

[evaluation]
cache_enabled = false
cache_ttl_secs = 60
max_batch_size = 100
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHROUDB_MASTER_KEY` | Base64-encoded 32-byte master key for encrypting key material at rest |
| `SHROUDB_MASTER_KEY_FILE` | Path to a file containing the master key |
| `LOG_LEVEL` | Logging level (`trace`, `debug`, `info`, `warn`, `error`) |

---

## Policies

Policies are defined in TOML files placed in the configured `policies.dir` directory. Each file can contain multiple policies.

### Structure

```toml
[[policies]]
name = "editors-can-write-docs"
description = "Editors can write non-confidential documents during business hours"
effect = "permit"       # permit | deny
priority = 100          # higher priority is evaluated first; default 0

[policies.principal]
role = ["editor", "admin"]                  # match any role (OR)
claims = { department = "engineering" }     # match all claims (AND)

[policies.resource]
type = "document"                           # exact match
attributes = { confidential = false }       # match all attributes (AND)

[policies.action]
name = ["write", "edit"]                    # match any action (OR, case-insensitive)

[policies.conditions]
[policies.conditions.time_window]
after = "09:00"         # UTC, inclusive
before = "17:00"        # UTC, exclusive
```

Every section (`principal`, `resource`, `action`, `conditions`) is optional. An omitted section matches everything.

### Evaluation Rules

1. Policies are sorted by priority, highest first.
2. The first matching policy wins.
3. **At equal priority, deny beats permit.**
4. If no policy matches, the configured `default_decision` applies (default: `deny`).

### Matching Semantics

| Field | Logic | Notes |
|-------|-------|-------|
| `principal.role` | OR | Any listed role matches |
| `principal.claims` | AND | All listed claims must match; supports string, integer, boolean, and array values |
| `resource.type` | Exact | Single value |
| `resource.attributes` | AND | All listed attributes must match |
| `action.name` | OR | Case-insensitive |
| `conditions.time_window` | Range | UTC `HH:MM` format; overnight wrap supported (e.g., `after = "22:00"`, `before = "06:00"`) |

### Example: Multi-Policy File

```toml
[[policies]]
name = "admins-full-access"
effect = "permit"
priority = 100
[policies.principal]
role = ["admin"]

[[policies]]
name = "deny-delete-confidential"
effect = "deny"
priority = 75
[policies.action]
name = ["delete"]
[policies.resource]
attributes = { classification = "confidential" }

[[policies]]
name = "editors-write-public"
effect = "permit"
priority = 50
[policies.principal]
role = ["editor"]
[policies.resource]
type = "document"
attributes = { classification = "public" }
[policies.action]
name = ["read", "write"]

[[policies]]
name = "business-hours-export"
effect = "permit"
priority = 30
[policies.principal]
role = ["analyst"]
[policies.action]
name = ["export"]
[policies.conditions.time_window]
after = "09:00"
before = "17:00"
```

### Hot Reload

Policies can be reloaded without restarting:

- **Manual:** Send the `POLICY_RELOAD` command.
- **Automatic:** Set `policies.watch = true` in the configuration. Sentry watches the policy directory and reloads on changes (with a 1-second debounce).

---

## Commands

All commands are sent over the TCP protocol on port 6799 (default). Commands are case-insensitive.

### EVALUATE

Evaluate an authorization request against loaded policies.

```
EVALUATE <json>
```

**Request JSON:**

```json
{
  "principal": {
    "id": "alice@example.com",
    "roles": ["editor"],
    "claims": { "department": "engineering" }
  },
  "resource": {
    "id": "doc-123",
    "type": "document",
    "attributes": { "classification": "public" }
  },
  "action": "write"
}
```

- `principal.id` — required
- `principal.roles` — optional (default `[]`)
- `principal.claims` — optional (default `{}`)
- `resource.id` — required
- `resource.type` — required
- `resource.attributes` — optional (default `{}`)
- `action` — required

**Response:**

```json
{
  "status": "OK",
  "decision": "permit",
  "token": "eyJhbG...",
  "policy": "editors-write-public",
  "cache_until": 1711469100
}
```

The `token` is a signed JWT containing the decision, principal, resource, action, matched policy, and expiration. The `policy` field is omitted when no policy matched and the default decision was applied.

### POLICY_RELOAD

Reload policies from disk.

```
POLICY_RELOAD
```

**Response:**

```json
{ "status": "OK", "count": 12 }
```

### POLICY_LIST

List all loaded policy names.

```
POLICY_LIST
```

**Response:**

```json
{
  "status": "OK",
  "count": 12,
  "policies": ["admins-full-access", "editors-write-public", "..."]
}
```

### POLICY_INFO

Get details about a specific policy.

```
POLICY_INFO <name>
```

**Response:**

```json
{
  "status": "OK",
  "name": "editors-write-public",
  "description": "Editors can write public documents",
  "effect": "permit",
  "priority": 50
}
```

### KEY_INFO

Get information about the current signing key.

```
KEY_INFO
```

**Response:**

```json
{
  "status": "OK",
  "key_id": "sentry-signing_v1",
  "algorithm": "ES256",
  "state": "Active",
  "created_at": "2024-03-26T09:00:00Z",
  "activated_at": "2024-03-26T09:00:00Z",
  "versions": 1
}
```

### KEY_ROTATE

Rotate the signing key.

```
KEY_ROTATE [FORCE] [DRYRUN]
```

- `FORCE` — rotate regardless of key age
- `DRYRUN` — preview the rotation without applying it

**Response:**

```json
{
  "status": "OK",
  "key_id": "sentry-signing_v2",
  "previous_key_id": "sentry-signing_v1"
}
```

### HEALTH

Server health check.

```
HEALTH
```

**Response:**

```json
{
  "status": "OK",
  "health": "ok",
  "has_active_key": true,
  "policy_count": 12
}
```

### AUTH

Authenticate the connection (required when `auth.method = "token"`).

```
AUTH <token>
```

### CONFIG GET / SET / LIST

Read or modify runtime configuration.

```
CONFIG GET <key>
CONFIG SET <key> <value>
CONFIG LIST
```

Supported keys include `decision_ttl_secs`, `cache_enabled`, `cache_ttl_secs`, and `default_decision`.

### PIPELINE

Batch multiple commands in a single request.

```
PIPELINE
  EVALUATE <json> END
  HEALTH END
  POLICY_LIST END
```

Returns an array of responses, one per command.

---

## Signing & Key Management

Every authorization decision is signed as a JWT. Downstream services verify these tokens using public keys from the [JWKS endpoint](#jwks-endpoint).

### Supported Algorithms

| Algorithm | Type | Notes |
|-----------|------|-------|
| **ES256** (default) | ECDSA P-256 | Recommended. Good balance of security and performance |
| ES384 | ECDSA P-384 | Higher security margin |
| EdDSA | Ed25519 | Modern, fast |
| RS256 / RS384 / RS512 | RSA | For legacy or interoperability requirements |
| HMAC-SHA256 | Symmetric | Shared-secret verification only; no JWKS distribution |

### Key Lifecycle

Keys progress through four states:

```
Staged -> Active -> Draining -> Retired
```

- **Active** — Used for signing new decisions. Public key published in JWKS.
- **Draining** — No longer signs new decisions. Public key remains in JWKS so existing tokens can still be verified.
- **Retired** — Removed from JWKS.

### Automatic Rotation

A background scheduler checks every 30 seconds whether the active key has exceeded `rotation_days`. When it has, a new key is created and the old key transitions to Draining. After `drain_days`, draining keys are retired.

### Decision Token (JWT) Claims

```json
{
  "decision": "permit",
  "principal": "alice@example.com",
  "resource": "doc-123",
  "action": "write",
  "policy": "editors-write-public",
  "iat": 1711468800,
  "exp": 1711469100
}
```

The `exp` claim is controlled by `signing.decision_ttl_secs` (default: 300 seconds).

---

## Authentication

When `auth.method = "token"`, every connection must authenticate before sending other commands.

### Configuration

```toml
[auth]
method = "token"

[auth.policies.admin]
token = "${SENTRY_ADMIN_TOKEN}"
commands = ["*"]                          # all commands

[auth.policies.evaluator]
token = "${SENTRY_EVAL_TOKEN}"
commands = ["EVALUATE", "HEALTH"]         # scoped access
```

### Usage

1. Connect to Sentry.
2. Send `AUTH <token>`.
3. On success, subsequent commands are allowed according to the token's command list.

When `auth.method = "none"` (the default), all commands are allowed without authentication.

---

## JWKS Endpoint

Sentry serves an HTTP endpoint for public key distribution:

```
GET http://<http_bind>/.well-known/jwks.json
```

Default: `http://localhost:6800/.well-known/jwks.json`

This returns the JSON Web Key Set containing public keys for all Active and Draining signing keys. Downstream services use this to verify decision tokens without calling back to Sentry.

**Verification flow:**

1. Receive a decision token from a client or upstream service.
2. Fetch (and cache) the JWKS from Sentry's HTTP endpoint.
3. Decode the JWT header to extract the `kid` (key ID).
4. Find the matching key in the JWKS.
5. Verify the JWT signature.
6. Check the `exp` claim.
7. Read the `decision` claim.

---

## CLI

The `shroudb-sentry-cli` binary provides an interactive REPL with tab completion.

### Usage

```bash
# Interactive mode
shroudb-sentry-cli --host localhost --port 6799

# With URI (includes optional token)
shroudb-sentry-cli --uri "shroudb-sentry://token@host:port"

# TLS
shroudb-sentry-cli --uri "shroudb-sentry+tls://token@host:port"

# Single command (non-interactive)
shroudb-sentry-cli --host localhost HEALTH

# JSON output
shroudb-sentry-cli --host localhost --json POLICY_LIST
```

### Options

| Flag | Description |
|------|-------------|
| `--uri <URI>` | Connection URI |
| `--host <HOST>` | Server host (default: `127.0.0.1`) |
| `--port <PORT>` | Server port (default: `6799`) |
| `--tls` | Connect with TLS |
| `--json` | Output responses as JSON |
| `--raw` | Output raw wire format |

### URI Format

```
shroudb-sentry://[token@]host[:port]
shroudb-sentry+tls://[token@]host[:port]
```

---

## Client Library

The `shroudb-sentry-client` crate provides an async Rust client.

```rust
use shroudb_sentry_client::SentryClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = SentryClient::connect("127.0.0.1:6799").await?;

    // Health check
    let health = client.health().await?;
    println!("Status: {}", health.health);

    // Evaluate an authorization request
    let result = client.evaluate(r#"{
        "principal": { "id": "alice", "roles": ["editor"] },
        "resource": { "id": "doc-1", "type": "document" },
        "action": "write"
    }"#).await?;

    println!("Decision: {}", result.decision);
    println!("Token: {}", result.token);

    Ok(())
}
```

---

## Docker

### Build

```bash
docker build -t shroudb/sentry .
```

### Run

```bash
docker run -d \
  --name shroudb-sentry \
  -p 6799:6799 \
  -p 6800:6800 \
  -v sentry-data:/data \
  -v ./sentry.toml:/sentry.toml:ro \
  -v ./policies:/policies:ro \
  -e SHROUDB_MASTER_KEY="<base64-encoded-32-byte-key>" \
  shroudb/sentry \
  --config /sentry.toml
```

The container runs as a non-root user. Mount a persistent volume at `/data` to retain signing keys across restarts.

---

## Error Reference

| Code | Meaning |
|------|---------|
| `DENIED` | Authentication failed or insufficient permissions |
| `NOTFOUND` | Policy not found |
| `BADARG` | Invalid argument or malformed JSON |
| `NOKEY` | No signing key available |
| `NOTREADY` | Server is starting up or shutting down |
| `INTERNAL` | Unexpected server error |
