# ShrouDB Sentry

Policy-based authorization engine. Evaluates access control policies and returns cryptographically signed JWT decisions. Downstream services verify decisions offline using the JWKS endpoint.

## Quick Start

```bash
# Generate a master key (hex-encoded 32 bytes; or omit for ephemeral dev mode)
export SHROUDB_MASTER_KEY=$(openssl rand -hex 32)

# Start Sentry on TCP port 6799
cargo run -p shroudb-sentry-server
```

## Commands

```
POLICY CREATE <name> <json>    Create an authorization policy
POLICY GET <name>              Get policy details
POLICY LIST                    List all policy names
POLICY DELETE <name>           Delete a policy
POLICY UPDATE <name> <json>    Update an existing policy
EVALUATE <json>                Evaluate a request and return a signed decision
KEY ROTATE [FORCE] [DRYRUN]   Rotate the signing key
KEY INFO                       Get signing key metadata
JWKS                           Get the JSON Web Key Set
AUTH <token>                   Authenticate the connection
HEALTH                         Server health check
PING                           Connectivity check
COMMAND LIST                   List supported commands
```

## Wire Protocol (RESP3)

All commands are sent as RESP3 arrays of bulk strings. Responses are JSON bulk strings on success, RESP3 simple errors on failure.

## Example Usage

```
> POLICY CREATE editors-write-docs {"effect":"permit","priority":10,"principal":{"roles":["editor"]},"resource":{"type":"document"},"action":{"names":["write"]}}
{"status":"ok","name":"editors-write-docs","effect":"permit","priority":10}

> EVALUATE {"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}
{"status":"ok","decision":"permit","token":"eyJ...","matched_policy":"editors-write-docs","cache_until":1711469100}

> JWKS
{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"sentry-key-v1","use":"sig","x":"...","y":"..."}]}
```

## Configuration

| Environment Variable | Description |
|---|---|
| `SHROUDB_MASTER_KEY` | Hex-encoded 32-byte master key |
| `SHROUDB_MASTER_KEY_FILE` | Path to file containing the master key |
| `SENTRY_CONFIG` | Path to TOML config file |
| `SENTRY_DATA_DIR` | Data directory (default: `./sentry-data`) |
| `SENTRY_TCP_BIND` | TCP bind address (default: `0.0.0.0:6799`) |
| `LOG_LEVEL` | Log level (default: `info`) |

## Policy Format

Policies are JSON objects with these fields:

| Field | Type | Description |
|---|---|---|
| `effect` | `"permit"` or `"deny"` | Whether this policy permits or denies access |
| `priority` | integer | Evaluation priority (higher = evaluated first) |
| `description` | string | Human-readable description |
| `principal` | object | `{ "roles": [...], "claims": {...} }` |
| `resource` | object | `{ "type": "...", "attributes": {...} }` |
| `action` | object | `{ "names": [...] }` |
| `conditions` | object | `{ "time_window": { "after": "HH:MM", "before": "HH:MM" } }` |

## Evaluation Algorithm

1. Policies are evaluated in priority order (highest first).
2. First matching policy determines the decision.
3. At equal priority, **Deny trumps Permit** (fail-closed).
4. No match = **Deny** (default).

## Security

- Signed decisions: JWT tokens prove authorization decisions, verifiable offline via JWKS.
- Key lifecycle: Staged, Active, Draining, Retired. Automatic rotation and retirement.
- Per-path derived encryption keys via HKDF for all Store data.
- Core dumps disabled at startup.
- Token-based ACL with namespace-scoped grants.

## Architecture

| Crate | Purpose |
|---|---|
| `shroudb-sentry-core` | Domain types (Policy, Decision, matchers, errors). No I/O. |
| `shroudb-sentry-engine` | Store-backed logic (PolicyManager, SigningManager, evaluation). |
| `shroudb-sentry-protocol` | RESP3 command parsing, ACL checks, dispatch to engine. |
| `shroudb-sentry-server` | TCP server binary. |
| `shroudb-sentry-client` | Typed Rust client SDK over TCP/RESP3. |
| `shroudb-sentry-cli` | CLI tool with single-command and interactive REPL modes. |

## Rust Client SDK

```rust
let mut client = SentryClient::connect("127.0.0.1:6799").await?;

// Create a policy
client.policy_create("my-policy", r#"{"effect":"permit","priority":10}"#).await?;

// Evaluate a request
let result = client.evaluate(r#"{"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}"#).await?;
println!("Decision: {}, Token: {}", result.decision, result.token);

// Get JWKS for offline verification
let jwks = client.jwks().await?;
```

## License

MIT OR Apache-2.0
