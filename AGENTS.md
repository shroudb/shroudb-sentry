# Sentry — Agent Instructions

> Policy-based authorization engine: evaluates attribute-matching policies against requests, returns cryptographically signed JWT decisions for offline verification.

## Quick Context

- **Role in ecosystem**: Authorization layer — services verify decisions offline using JWKS, eliminating availability dependency
- **Deployment modes**: embedded | remote (TCP port 6799)
- **Wire protocol**: RESP3
- **Backing store**: ShrouDB Store trait (encrypted at rest)

## Workspace Layout

```
shroudb-sentry-core/      # Policy, Decision, matchers, SigningKeyring, errors
shroudb-sentry-engine/    # SentryEngine, PolicyManager, SigningManager, evaluator, scheduler
shroudb-sentry-protocol/  # RESP3 command parsing + dispatch
shroudb-sentry-server/    # Standalone TCP binary
shroudb-sentry-client/    # Typed Rust SDK
shroudb-sentry-cli/       # CLI tool
```

## RESP3 Commands

### Policy Management

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `POLICY CREATE` | `<name> <policy_json>` | `{status, name, effect, priority}` | Create policy (Admin) |
| `POLICY GET` | `<name>` | `{status, name, description, effect, priority, created_at, updated_at}` | Retrieve policy |
| `POLICY LIST` | — | `{status, count, policies}` | List all policy names |
| `POLICY DELETE` | `<name>` | `{status}` | Delete policy (Admin) |
| `POLICY UPDATE` | `<name> <policy_json>` | `{status, name, effect, priority, updated_at}` | Update policy (Admin) |

### Evaluation

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `EVALUATE` | `<request_json>` | `{status, decision, token, matched_policy, cache_until}` | Evaluate request, return signed JWT decision |

### Key Management

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `KEY ROTATE` | `[FORCE] [DRYRUN]` | `{status, rotated, key_version, previous_version?}` | Rotate signing key (Admin) |
| `KEY INFO` | — | `{status, algorithm, rotation_days, drain_days, decision_ttl_secs, active_version, ...}` | Signing key metadata |
| `JWKS` | — | `{keys: [...]}` | Public key set for offline JWT verification |

### Operational

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `AUTH` | `<token>` | `{status}` | Authenticate connection |
| `HEALTH` | — | `{status, policy_count}` | Health check |
| `PING` | — | `PONG` | Liveness |
| `COMMAND LIST` | — | `{status, commands}` | List commands |

### Command Examples

```
> POLICY CREATE editors-write {"effect":"permit","priority":10,"principal":{"roles":["editor"]},"resource":{"type":"document"},"action":{"names":["write"]}}
{"status":"ok","name":"editors-write","effect":"permit","priority":10}

> EVALUATE {"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}
{"status":"ok","decision":"permit","token":"eyJ...","matched_policy":"editors-write","cache_until":1711469100}

> JWKS
{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"sentry-key-v1","use":"sig","x":"...","y":"..."}]}
```

## Policy Format

```json
{
  "name": "policy-name",
  "description": "Human-readable description",
  "effect": "permit",
  "priority": 10,
  "principal": {
    "roles": ["editor", "admin"],
    "claims": { "dept": "engineering" }
  },
  "resource": {
    "type": "document",
    "attributes": { "classification": "internal" }
  },
  "action": {
    "names": ["write", "delete"]
  },
  "conditions": {
    "time_window": { "after": "09:00", "before": "17:00" }
  }
}
```

### Matcher Logic

- **Principal roles**: OR (at least one must match, case-insensitive). Empty = wildcard.
- **Principal claims**: AND (all must match exactly). Empty = no requirements.
- **Resource type**: Exact match (case-insensitive). Empty = wildcard.
- **Resource attributes**: AND (all must match). Empty = no requirements.
- **Action names**: OR (at least one must match, case-insensitive). Empty = wildcard.
- **Time window**: `after`/`before` in `"HH:MM"` UTC. Supports overnight wrap.

### Evaluation Algorithm

1. Sort policies by priority (highest first)
2. Find first matching policy (all matchers + conditions must pass)
3. At equal priority: **Deny trumps Permit** (fail-closed)
4. No match: **Default Deny**
5. Sign decision as JWT with `cache_until = now + decision_ttl_secs`

### Evaluation Request

```json
{
  "principal": { "id": "alice", "roles": ["editor"], "claims": { "dept": "eng" } },
  "resource": { "id": "doc-1", "type": "document", "attributes": { "team": "platform" } },
  "action": "write"
}
```

Simplified form also works: `{"principal": "alice", "resource": "doc-1", "action": "write"}`

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6799"` | TCP listen address |
| `store.data_dir` | `PathBuf` | `"./sentry-data"` | Data directory |
| `engine.signing_algorithm` | `String` | `"ES256"` | ES256, ES384, EdDSA, RS256, RS384, RS512 |
| `engine.rotation_days` | `u32` | `90` | Auto-rotate signing key after N days |
| `engine.drain_days` | `u32` | `30` | Days in Draining before retirement |
| `engine.decision_ttl_secs` | `u64` | `300` | JWT expiration (cache duration) |
| `engine.scheduler_interval_secs` | `u64` | `3600` | Key lifecycle check interval |

## Data Model

| Namespace | Key | Value | Purpose |
|-----------|-----|-------|---------|
| `sentry.policies` | Policy name | JSON `Policy` | All policies |
| `sentry.signing` | Keyring name (`"default"`) | JSON `SigningKeyring` | Signing key versions |

Both backed by `DashMap` cache with write-through to Store.

### Signing Key Lifecycle

```
Staged → Active → Draining → Retired
```

- Active: signs new decisions, in JWKS
- Draining: in JWKS for verification only, not signing
- Retired: removed from JWKS, private key zeroized

## Common Mistakes

- Default decision is **Deny** — if no policy matches, access is denied
- At equal priority, Deny always wins over Permit
- Decision JWTs should be cached until `cache_until` — re-evaluating on every request defeats the purpose
- `JWKS` returns Active + Draining keys — clients should accept signatures from either during rotation
- Policy conditions are AND with matchers — a time window condition on a policy means the policy only matches during that window

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for policy/keyring persistence |
| `shroudb-crypto` | JWT signing (ES256/EdDSA/RS256), key generation |
| `shroudb-sigil` | Optionally evaluates policies via `PolicyEvaluator` trait |
| `shroudb-moat` | Embeds Sentry; initializes first (dependency for other engines) |
