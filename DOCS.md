# ShrouDB Sentry Documentation

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

## Quick Start

**1. Create a minimal config file** (`sentry.toml`):

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"

[signing]
algorithm = "ES256"

[policies]
dir = "./policies"
default_decision = "deny"
```

**2. Create a policy** (`policies/editors.toml`):

```toml
[[policies]]
name = "editors-can-write-docs"
description = "Editors can write documents"
effect = "permit"
priority = 100

[policies.principal]
role = ["editor"]

[policies.resource]
type = "document"

[policies.action]
name = ["write", "edit"]
```

**3. Start the engine:**

```bash
shroudb-sentry --config sentry.toml
```

For development, this starts with an ephemeral master key. For production, provide a persistent key:

```bash
export SHROUDB_MASTER_KEY="base64-encoded-32-byte-key"
shroudb-sentry --config sentry.toml
```

**4. Evaluate a request using the CLI:**

```bash
shroudb-sentry-cli --host 127.0.0.1 --port 6799
> EVALUATE {"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}
```

**5. Verify decisions externally:**

Fetch public keys from the JWKS endpoint:

```
GET http://localhost:6800/.well-known/jwks.json
```

Use any JWT library to verify the signed decision token against these keys.

---

## Configuration

ShrouDB Sentry is configured via a TOML file. Environment variables can be interpolated with `${VAR}` syntax.

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"
# tls_client_ca = "/path/to/ca.pem"  # enables mTLS
# rate_limit = 1000                   # per-connection commands/sec

[storage]
data_dir = "./sentry-data"

[signing]
algorithm = "ES256"                   # see Signing Algorithms
rotation_days = 90
drain_days = 30
decision_ttl_secs = 300               # JWT expiration (5 minutes)

[policies]
dir = "./policies"                    # directory of policy TOML files
default_decision = "deny"             # "deny" (default) or "permit"
watch = false                         # filesystem watch for auto-reload

[evaluation]
cache_enabled = false
cache_ttl_secs = 60

[auth]
method = "none"                       # "none" (default) or "token"

[auth.policies.admin]
token = "${SENTRY_ADMIN_TOKEN}"
commands = ["*"]

[auth.policies.evaluator]
token = "evaluator-token"
commands = ["EVALUATE", "HEALTH"]
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHROUDB_MASTER_KEY` | Base64-encoded 32-byte master key for encrypting key material at rest |
| `SHROUDB_MASTER_KEY_FILE` | Path to a file containing the master key |
| `LOG_LEVEL` | Logging verbosity (e.g., `info`, `debug`) |

### Signing Algorithms

| Algorithm | Type | Config value |
|-----------|------|--------------|
| ECDSA P-256 | Asymmetric | `ES256` (default) |
| ECDSA P-384 | Asymmetric | `ES384` |
| Ed25519 | Asymmetric | `EdDSA` |
| RSA 2048+ | Asymmetric | `RS256`, `RS384`, `RS512` |
| HMAC-SHA256 | Symmetric | `HS256` |

Asymmetric algorithms expose public keys via the JWKS endpoint. HMAC-SHA256 requires shared-secret verification (no JWKS).

---

## Commands Reference

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
    "roles": ["editor", "team-lead"],
    "claims": { "department": "engineering", "level": 5 }
  },
  "resource": {
    "id": "doc-123",
    "type": "document",
    "attributes": { "confidential": false, "owner": "alice@example.com" }
  },
  "action": "write"
}
```

**Response:**

```json
{
  "status": "OK",
  "decision": "permit",
  "token": "eyJhbG...",
  "policy": "editors-can-write-docs",
  "cache_until": 1711469100
}
```

The `token` field is a signed JWT encoding the decision. Verify it against the JWKS endpoint.

### POLICY_LIST

List all loaded policy names.

```
POLICY_LIST
```

### POLICY_INFO

Get details about a specific policy.

```
POLICY_INFO <name>
```

### POLICY_RELOAD

Reload all policies from the configured directory. Invalidates the decision cache.

```
POLICY_RELOAD
```

### KEY_INFO

Returns the current signing key metadata: key ID, algorithm, creation time, and state.

```
KEY_INFO
```

### KEY_ROTATE

Rotate the signing key. Without `FORCE`, rotation only proceeds if the active key has exceeded `rotation_days`. `DRYRUN` previews the rotation plan without applying changes.

```
KEY_ROTATE [FORCE] [DRYRUN]
```

### HEALTH

Server health check. Returns engine state and loaded policy count.

```
HEALTH
```

### CONFIG GET / SET / LIST

Runtime configuration management without restarting the engine.

```
CONFIG GET <key>
CONFIG SET <key> <value>
CONFIG LIST
```

### AUTH

Authenticate the connection when token-based auth is enabled.

```
AUTH <token>
```

### PIPELINE

Batch multiple commands in a single round-trip.

```
PIPELINE <cmd1> END <cmd2> END ...
```

---

## Policy File Format

Policies are TOML files placed in the configured `policies.dir` directory. Each file can contain one or more `[[policies]]` entries.

### Full Example

```toml
[[policies]]
name = "editors-can-write-docs"
description = "Team editors can write non-confidential documents during business hours"
effect = "permit"
priority = 100

[policies.principal]
role = ["editor", "admin"]                 # OR: any role matches
claims = { department = "engineering" }     # AND: all claims must match

[policies.resource]
type = "document"
attributes = { confidential = false }      # all attributes must match

[policies.action]
name = ["write", "edit"]                   # OR: any action matches

[policies.conditions]
[policies.conditions.time_window]
after = "09:00"                            # UTC, HH:MM format
before = "17:00"                           # supports overnight wrap
```

### Policy Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique policy identifier |
| `description` | No | Human-readable description |
| `effect` | Yes | `"permit"` or `"deny"` |
| `priority` | Yes | Integer; higher values are evaluated first |
| `principal.role` | No | List of roles (OR match) |
| `principal.claims` | No | Map of claim key-value pairs (AND match) |
| `resource.type` | No | Resource type string |
| `resource.attributes` | No | Map of attribute key-value pairs (AND match) |
| `action.name` | No | List of action names (OR match, case-insensitive) |
| `conditions.time_window.after` | No | Start time in UTC (HH:MM) |
| `conditions.time_window.before` | No | End time in UTC (HH:MM) |

### Evaluation Rules

1. Policies are sorted by priority (highest first).
2. The first matching policy determines the decision.
3. At equal priority, Deny trumps Permit.
4. If no policy matches, the `default_decision` from configuration applies.

### Multiple Policies in One File

```toml
[[policies]]
name = "admin-full-access"
effect = "permit"
priority = 1000

[policies.principal]
role = ["admin"]

[policies.action]
name = ["*"]

[[policies]]
name = "deny-confidential-default"
effect = "deny"
priority = 500

[policies.resource]
attributes = { confidential = true }
```

---

## HTTP Endpoints

ShrouDB Sentry runs an HTTP sidecar (default port 6800) for key distribution.

### JWKS Endpoint

```
GET /.well-known/jwks.json
```

Returns the JSON Web Key Set containing public keys for all active and draining signing keys. Use this endpoint to verify signed decision tokens from any service.

**Example response:**

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "sentry-key-v1",
      "use": "sig",
      "alg": "ES256",
      "x": "...",
      "y": "..."
    }
  ]
}
```

---

## Evaluation Request/Response Examples

### Basic Permit

**Request:**

```
EVALUATE {"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}
```

**Response:**

```json
{
  "status": "OK",
  "decision": "permit",
  "token": "eyJhbGciOiJFUzI1NiJ9...",
  "policy": "editors-can-write-docs",
  "cache_until": 1711469100
}
```

### Deny (No Matching Policy)

**Request:**

```
EVALUATE {"principal":{"id":"bob","roles":["viewer"]},"resource":{"id":"doc-1","type":"document"},"action":"delete"}
```

**Response:**

```json
{
  "status": "OK",
  "decision": "deny",
  "token": "eyJhbGciOiJFUzI1NiJ9...",
  "policy": null,
  "cache_until": 1711469100
}
```

### Decision Token (JWT Payload)

The signed JWT encodes the authorization decision:

```json
{
  "decision": "permit",
  "principal": "alice@example.com",
  "resource": "doc-123",
  "action": "write",
  "policy": "editors-can-write-docs",
  "iat": 1711468800,
  "exp": 1711469100
}
```

---

## Key Lifecycle

Signing keys follow a state machine: **Staged -> Active -> Draining -> Retired**.

| State | Signs new decisions | In JWKS | Description |
|-------|-------------------|---------|-------------|
| Staged | No | No | Newly generated, not yet active |
| Active | Yes | Yes | Used for all new decision signing |
| Draining | No | Yes | Public key remains for verifying existing tokens |
| Retired | No | No | Removed from JWKS; tokens can no longer be verified |

A background scheduler handles automatic transitions:
- Active keys older than `rotation_days` are auto-rotated (new key becomes Active, old moves to Draining).
- Draining keys older than `drain_days` are retired.

---

## Docker Deployment

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

- `-v sentry-data:/data` -- persists state and signing key material. **Without this volume, all signing key material is lost on container restart.**
- `-v ./policies:/policies:ro` -- mounts your policy directory read-only.
- `-e SHROUDB_MASTER_KEY` -- the 32-byte base64-encoded master key. Omit for ephemeral dev mode. Can also use `SHROUDB_MASTER_KEY_FILE` pointing to a mounted secrets file.

**CLI via Docker:**

```bash
docker run --rm -it shroudb/sentry-cli --host <sentry-host> --port 6799
```

---

## Authentication

When `auth.method = "token"`, clients must authenticate with `AUTH <token>` before executing commands. Each token maps to a policy that scopes access to specific commands. Wildcard `"*"` allows all commands.

When `auth.method = "none"` (default), all commands are allowed without authentication.

---

## Telemetry

ShrouDB Sentry uses structured telemetry via `shroudb-telemetry`:

- **Console logging** -- structured JSON output with configurable log levels.
- **Audit file** -- write operations (POLICY_RELOAD, KEY_ROTATE, CONFIG SET) are logged with operation, result, duration, and actor.
- **OpenTelemetry (OTEL)** -- optional export of traces and metrics to an OTEL-compatible collector.

Log level is controlled via the `LOG_LEVEL` environment variable.

---

## Replication

ShrouDB Sentry supports single-leader replication via WAL shipping. A primary streams encrypted WAL entries to replicas over TCP. Replicas apply entries in order and serve read-only queries.

### Configuration

Add a `[replication]` section to your config file:

```toml
[replication]
role = "primary"          # "standalone" (default) | "primary" | "replica"
bind = "0.0.0.0:6400"    # Primary: replication listener address
# primary = "10.0.1.5:6400"  # Replica: primary address
# staleness_budget_ms = 500   # Replica: max lag before rejecting reads
```

### PROMOTE

Promote this replica to primary.

**Syntax:** `PROMOTE`

**Replica behavior:** Disconnects from primary, transitions to Primary role, begins accepting writes.

**Error:** `BADARG` if node is not a replica.

### READONLY Error

Write commands sent to a replica return a `READONLY` error. Clients should redirect writes to the primary.
