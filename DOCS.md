# ShrouDB Sentry Documentation

## Configuration

Sentry loads configuration from a TOML file. All sections are optional and have sensible defaults.

```toml
[server]
tcp_bind = "0.0.0.0:6799"
log_level = "info"

[store]
mode = "embedded"
data_dir = "./sentry-data"

[engine]
signing_algorithm = "ES256"     # ES256, ES384, EdDSA, RS256, RS384, RS512
rotation_days = 90              # Auto-rotate active key after N days
drain_days = 30                 # Keep draining key in JWKS for N days
decision_ttl_secs = 300         # JWT expiration (5 minutes)
scheduler_interval_secs = 3600  # Background scheduler interval

[auth]
method = "token"

[auth.tokens."my-admin-token"]
tenant = "my-org"
actor = "admin"
platform = true

[auth.tokens."my-app-token"]
tenant = "my-org"
actor = "my-service"
platform = false
grants = [
    { namespace = "sentry.policies.*", scopes = ["read"] },
    { namespace = "sentry.evaluate.*", scopes = ["read"] },
]

# Seed policies from config (created on startup if absent)
[policies.editors-can-write]
effect = "permit"
description = "Editors can write documents"
priority = 10
principal_roles = ["editor"]
resource_type = "document"
action_names = ["write", "update"]
```

### Master Key

The master key encrypts all data at rest. Three sources are tried in order:

1. `SHROUDB_MASTER_KEY` environment variable (base64-encoded 32 bytes)
2. `SHROUDB_MASTER_KEY_FILE` environment variable (path to key file)
3. Ephemeral key (random, data lost on restart — dev mode only)

Generate a production key:

```bash
openssl rand -base64 32
```

## Policies

### Create

```
POLICY CREATE <name> <json>
```

The name is passed as a separate argument. The JSON body defines the policy:

```json
{
    "effect": "permit",
    "priority": 10,
    "description": "Editors can write documents",
    "principal": {
        "roles": ["editor"],
        "claims": {"department": "engineering"}
    },
    "resource": {
        "type": "document",
        "attributes": {"classification": "internal"}
    },
    "action": {
        "names": ["write", "update"]
    },
    "conditions": {
        "time_window": {
            "after": "09:00",
            "before": "17:00"
        }
    }
}
```

Response:
```json
{"status": "ok", "name": "editors-write-docs", "effect": "permit", "priority": 10}
```

### Retrieve

```
POLICY GET <name>
```

Response:
```json
{"status": "ok", "name": "editors-write-docs", "description": "...", "effect": "permit", "priority": 10, "created_at": 1711468800, "updated_at": 1711468800}
```

### List

```
POLICY LIST
```

Response:
```json
{"status": "ok", "count": 3, "policies": ["policy-a", "policy-b", "policy-c"]}
```

### Update

```
POLICY UPDATE <name> <json>
```

Replaces the policy definition (effect, priority, matchers, conditions). The name remains unchanged.

### Delete

```
POLICY DELETE <name>
```

## Evaluation

### Request

```
EVALUATE <json>
```

The request JSON must include `principal`, `resource`, and `action`:

```json
{
    "principal": {
        "id": "alice",
        "roles": ["editor", "reviewer"],
        "claims": {"department": "engineering"}
    },
    "resource": {
        "id": "doc-123",
        "type": "document",
        "attributes": {"classification": "internal"}
    },
    "action": "write"
}
```

### Response

```json
{
    "status": "ok",
    "decision": "permit",
    "token": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNlbnRyeS1rZXktdjEiLCJ0eXAiOiJKV1QifQ...",
    "matched_policy": "editors-write-docs",
    "cache_until": 1711469100
}
```

### Decision Token (JWT)

The `token` field is a signed JWT containing:

```json
{
    "decision": "permit",
    "principal": "alice",
    "resource": "doc-123",
    "action": "write",
    "policy": "editors-write-docs",
    "iat": 1711468800,
    "exp": 1711469100
}
```

Verify this token offline using the public keys from the JWKS endpoint.

### Matching Rules

| Matcher | Logic | Empty = |
|---|---|---|
| Principal roles | OR (any role matches) | Match any principal |
| Principal claims | AND (all claims must match) | No claim requirements |
| Resource type | Exact (case-insensitive) | Match any type |
| Resource attributes | AND (all must match) | No attribute requirements |
| Action names | OR (any name matches, case-insensitive) | Match any action |
| Time window | Both after/before optional, overnight wrap supported | Always active |

## Signing Keys

### Key Lifecycle

Keys follow a state machine: **Active** (signing) -> **Draining** (in JWKS, not signing) -> **Retired** (removed).

- `KEY INFO` — current signing key metadata
- `KEY ROTATE [FORCE] [DRYRUN]` — rotate the active key
- `JWKS` — JSON Web Key Set (Active + Draining keys)

### Automatic Rotation

The background scheduler runs every `scheduler_interval_secs` (default: 1 hour) and:
1. Auto-rotates the active key if it exceeds `rotation_days`.
2. Auto-retires draining keys that exceed `drain_days`.
3. Clears private key material from retired keys.

## ACL

When `[auth] method = "token"` is set, connections must authenticate before using protected commands.

| Command | Requirement |
|---|---|
| AUTH, HEALTH, PING, COMMAND LIST, KEY INFO, JWKS | None (pre-auth) |
| POLICY GET, POLICY LIST | `sentry.policies.*` read |
| EVALUATE | `sentry.evaluate.*` read |
| POLICY CREATE/DELETE/UPDATE, KEY ROTATE | Admin (platform token) |

## Rust Client SDK

```rust
use shroudb_sentry_client::SentryClient;

let mut client = SentryClient::connect("127.0.0.1:6799").await?;
client.auth("my-token").await?;

// Policy management
client.policy_create("my-policy", r#"{"effect":"permit","priority":5}"#).await?;
let info = client.policy_get("my-policy").await?;
let policies = client.policy_list().await?;
client.policy_update("my-policy", r#"{"effect":"deny","priority":10}"#).await?;
client.policy_delete("my-policy").await?;

// Evaluation
let result = client.evaluate(r#"{"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}"#).await?;
println!("Decision: {}", result.decision);
println!("JWT: {}", result.token);

// Signing keys
let info = client.key_info().await?;
let result = client.key_rotate(true, false).await?;
let jwks = client.jwks().await?;
```

## CLI

### Single Command

```bash
shroudb-sentry-cli HEALTH
shroudb-sentry-cli POLICY LIST
shroudb-sentry-cli EVALUATE '{"principal":{"id":"alice"},"resource":{"id":"doc-1","type":"doc"},"action":"read"}'
```

### Interactive REPL

```bash
shroudb-sentry-cli
sentry> HEALTH
OK
sentry> POLICY CREATE my-policy {"effect":"permit","priority":10}
{...}
sentry> quit
```

### Options

| Flag | Description |
|---|---|
| `--addr` | Server address (default: `127.0.0.1:6799`, env: `SENTRY_ADDR`) |
