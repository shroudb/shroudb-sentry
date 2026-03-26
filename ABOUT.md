# Understanding ShrouDB Sentry

This document explains ShrouDB Sentry at four levels of depth, plus a complete observability reference. Pick the section that matches your background.

---

## For Everyone: What ShrouDB Sentry Does

Every application needs to answer the question "is this user allowed to do this?" Authorization logic is typically scattered across if-statements, database queries, and middleware — duplicated in every service, inconsistent across teams, and invisible to auditors. When something goes wrong, there's no single place to see what was allowed and why.

**ShrouDB Sentry is a centralized authorization engine.** It evaluates access control requests against a set of declarative policies and returns cryptographically signed decision tokens. These tokens can be verified by any downstream service without contacting Sentry again — they're self-contained proof that "yes, this user was allowed to do this, at this time, because of this policy."

**What it provides:**

- **Policy-based authorization** — Define who can do what using declarative TOML policies. Policies specify principals (users/roles), resources (types/attributes), actions, and optional time-window conditions.
- **Signed decision tokens** — Every authorization decision is signed as a JWT (or HMAC token). Downstream services verify the signature and check the expiry — no callback to Sentry required.
- **Key rotation** — Signing keys rotate automatically. A JWKS endpoint publishes public keys so any service can verify decisions offline.
- **Hot-reloadable policies** — Policies can be updated on disk and reloaded without restarting the server.
- **Decision caching** — Optional caching reduces redundant policy evaluation and signing for repeated requests.

**Why it matters:**

- Authorization logic is defined in one place, not scattered across services.
- Signed decision tokens eliminate the need for every service to call an authorization endpoint on every request.
- JWKS-based verification means services can validate decisions even if Sentry is temporarily unreachable.
- Policy changes take effect immediately via hot reload — no deployment required.

---

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Authorization is typically implemented as ad-hoc code in each service. This leads to inconsistent enforcement, no audit trail, and impossible-to-answer questions like "what can user X access?" or "who approved this operation?" Centralized authorization systems (like OPA or Zanzibar) solve this but introduce latency on every request and become availability bottlenecks.

### What ShrouDB Sentry Is

ShrouDB Sentry is a **policy-based authorization engine** that returns **cryptographically signed decisions**. The key insight is that authorization decisions are cacheable — if "Alice can read documents" was true 10 seconds ago, it's probably still true. By signing decisions as JWTs with a short TTL, Sentry enables stateless verification at the edge while maintaining centralized policy management.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Signed decision tokens** | Decisions are JWTs (or HMAC tokens) that downstream services verify locally. Eliminates per-request callbacks and makes Sentry's availability non-critical for the verify path. |
| **Priority-based policy evaluation** | Policies are sorted by priority. At equal priority, Deny trumps Permit. This creates predictable, debuggable authorization behavior. |
| **JWKS endpoint** | Public keys are published at `/.well-known/jwks.json`. Any service can verify decision tokens without shared secrets or Sentry access. |
| **Hot-reloadable policies** | Policies are TOML files on disk, watched for changes. Updates take effect within 1 second via file watcher with debounce. |
| **Optional decision cache** | DashMap-backed cache keyed on (principal.id, resource.type, resource.id, action). Reduces signing overhead for repeated requests. |

### Operational Model

- **Configuration:** TOML file with signing algorithm, rotation schedule, and policy directory. Policies are separate TOML files in a watched directory.
- **Observability:** Structured JSON logging via tracing. Audit log for write operations. JWKS endpoint for external verification infrastructure.
- **Deployment:** Single static binary. TLS and mTLS supported natively. HTTP sidecar for JWKS.

---

## For Backend Engineers: How It Works

### Dual Interface

**RESP3 Protocol (Port 6799):**

```
EVALUATE <json>                            → signed decision token
POLICY_LIST                                → list all loaded policies
POLICY_INFO <name>                         → policy details
POLICY_RELOAD                              → hot-reload policies from disk
KEY_INFO                                   → signing key versions and states
KEY_ROTATE [FORCE] [DRYRUN]                → rotate signing key
HEALTH                                     → server health
AUTH <token>                               → authenticate connection
CONFIG GET|SET|LIST [key] [value]           → runtime configuration
PIPELINE <cmd1> END <cmd2> END ...          → batch commands
```

**HTTP Sidecar (Port 6800):**

```
GET /.well-known/jwks.json                 → public keys for decision verification
```

### Evaluation Flow

```
EVALUATE {
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

1. Iterate policies sorted by priority (highest first)
2. For each policy, check:
   - Principal: roles match (OR), claims match (AND)
   - Resource: type matches, attributes match (all keys)
   - Action: name matches (OR, case-insensitive)
   - Conditions: time window (if specified)
3. First match wins. At equal priority, Deny trumps Permit.
4. If no match: use default_decision (deny or permit)
5. Sign decision as JWT with active signing key
6. Return: { decision, token, policy, cache_until }
```

### Policy File Format

Policies are TOML files in the configured `policies_dir`:

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
attributes = { confidential = false }      # All attributes must match

[policies.action]
name = ["write", "edit"]                   # OR: any action matches

[policies.conditions]
[policies.conditions.time_window]
after = "09:00"                            # UTC, HH:MM format
before = "17:00"                           # Supports overnight wrap
```

### Decision Token (JWT)

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

Signed with the active signing key. Verifiable via the JWKS endpoint.

### Signing Key Lifecycle

```
Staged → Active → Draining → Retired

Active:   Signs all new decisions. Only one active key at a time.
Draining: No longer signs. Still published in JWKS for verifying existing tokens.
Retired:  Removed from JWKS. Kept in WAL for audit.
```

The background scheduler (every 30 seconds) handles transitions:
- Active keys older than `rotation_days` → auto-rotate (new Active, old to Draining)
- Draining keys older than `drain_days` → retire

### Supported Signing Algorithms

| Algorithm | Type | Key Size |
|-----------|------|----------|
| ES256 | ECDSA (P-256) | 256 bits (default) |
| ES384 | ECDSA (P-384) | 384 bits |
| RS256 | RSA-SHA256 | 2048+ bits |
| RS384 | RSA-SHA384 | 2048+ bits |
| RS512 | RSA-SHA512 | 2048+ bits |
| EdDSA | Ed25519 | 256 bits |
| HMAC-SHA256 | Symmetric | 256 bits |

HMAC-SHA256 uses a shared-secret model (no JWKS). All other algorithms use asymmetric keys with JWKS-based public key distribution.

### Configuration

```toml
[server]
bind = "0.0.0.0:6799"
http_bind = "0.0.0.0:6800"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"
# tls_client_ca = "/path/to/ca.pem"
# rate_limit = 1000

[storage]
data_dir = "./sentry-data"
wal_fsync_mode = "batched"
wal_fsync_interval_ms = 10
wal_segment_max_bytes = 67108864
snapshot_interval_entries = 100000
snapshot_interval_minutes = 60

[signing]
algorithm = "ES256"
rotation_days = 90
drain_days = 30
decision_ttl_secs = 300                    # JWT expiration (5 minutes)

[policies]
dir = "./policies"                         # Directory of policy TOML files
default_decision = "deny"                  # When no policy matches
watch = false                              # Enable file watcher for hot reload

[evaluation]
cache_enabled = false                      # Enable decision cache
cache_ttl_secs = 60                        # Cache entry TTL

[auth]
method = "none"                            # "none" or "token"

[auth.policies.evaluator]
token = "eval-service-token"
commands = ["EVALUATE", "POLICY_LIST"]

[auth.policies.admin]
token = "${SENTRY_ADMIN_TOKEN}"
commands = ["*"]
```

Environment variables: `SHROUDB_MASTER_KEY`, `SHROUDB_MASTER_KEY_FILE`, `LOG_LEVEL`.

### Client Library

```rust
let mut client = SentryClient::connect("127.0.0.1:6799").await?;
client.auth("eval-service-token").await?;

// Evaluate an authorization request
let result = client.evaluate(r#"{
  "principal": {"id": "alice", "roles": ["editor"]},
  "resource": {"id": "doc-123", "type": "document"},
  "action": "write"
}"#).await?;

println!("Decision: {}", result.decision);      // "permit" or "deny"
println!("Token: {}", result.token);             // signed JWT
println!("Policy: {:?}", result.policy);         // matched policy name
println!("Cache until: {}", result.cache_until); // expiration timestamp

// Policy management
let policies = client.policy_list().await?;
let info = client.policy_info("editors-can-write-docs").await?;
client.policy_reload().await?;

// Key management
let key_info = client.key_info().await?;
client.key_rotate(false, false).await?;          // force, dryrun
```

URI format: `shroudb-sentry://[token@]host[:port]` or `shroudb-sentry+tls://[token@]host[:port]`

---

## For Security Engineers: Threat Model and Cryptographic Design

### Trust Boundaries

```
Untrusted:
  Network traffic (mitigated: TLS/mTLS)
  Authorization request content (mitigated: JSON schema validation)
  Decision tokens in transit (mitigated: cryptographic signatures)

Trusted:
  The Sentry process and its memory space
  Policy files on disk (file system permissions apply)
  The master key delivery mechanism (env var or file)
  The host operating system
```

### Cryptographic Primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Decision signing (asymmetric) | ES256, ES384, RS256, RS384, RS512, EdDSA | ring, jsonwebtoken |
| Decision signing (symmetric) | HMAC-SHA256 | ring |
| Key generation | ECDSA/RSA/Ed25519 | shroudb-crypto (uses ring) |
| Key material encryption | AES-256-GCM | shroudb-crypto |
| WAL encryption | AES-256-GCM | shroudb-storage |
| Token generation | CSPRNG (SystemRandom) | ring |

### Key Hierarchy

```
Master Key (32 bytes, provided at startup)
  │
  ├─ HKDF(master, info="sentry_wal")         → WAL encryption key
  ├─ HKDF(master, info="sentry_private")      → signing key material wrapping
  ├─ HKDF(master, info="__snapshot__")        → snapshot encryption key
  └─ HKDF(master, info="__snapshot_hmac__")   → snapshot HMAC key
```

### Decision Token Security

- **Asymmetric signing (recommended):** Decisions are signed with the active private key. Any service can verify using the public key from the JWKS endpoint. Private key compromise affects signing, not verification.
- **Short TTL:** Default 300 seconds (5 minutes). Limits the window during which a stolen decision token is valid.
- **Claims binding:** The JWT includes principal, resource, and action — preventing token reuse across different authorization contexts.
- **Key rotation:** Automatic rotation with drain period ensures continuous verification while transitioning to new keys.

### Policy Evaluation Security

- **Deny-trumps-permit:** At equal priority levels, Deny policies override Permit policies. This prevents accidental over-permitting.
- **Priority ordering:** Higher priority policies are evaluated first. Explicit deny at high priority overrides lower-priority permits.
- **Time-window conditions:** UTC-based time windows support business-hours restrictions. Overnight wrapping (e.g., `after: "22:00"`, `before: "06:00"`) is supported.
- **Fail-closed default:** When `default_decision = "deny"`, unmatched requests are denied.

### Memory Protection

- **Core dumps disabled** — On Linux, `prctl(PR_SET_DUMPABLE, 0)` prevents core dumps containing signing keys.
- **SecretBytes** — Private key material uses `shroudb_crypto::SecretBytes` with automatic zeroization on drop.
- **No plaintext in logs** — Private keys and decision token content are never logged.

### What ShrouDB Sentry Does NOT Protect Against

- **Compromised master key** — All key material encryption derives from it.
- **Compromised host OS** — Root access means access to signing keys in memory.
- **Policy file tampering** — Policies are loaded from disk. File system permissions are the operator's responsibility. Consider using immutable infrastructure or file integrity monitoring.
- **Decision token replay** — A valid decision token can be replayed within its TTL window. Keep `decision_ttl_secs` short (default 300s).
- **JWKS endpoint spoofing** — Services verifying tokens must connect to the authentic JWKS endpoint. Use TLS and certificate pinning.

---

## Observability Reference

### Audit Log

Write operations are logged at INFO level with target `sentry::audit`:

| Field | Description |
|-------|-------------|
| `op` | Command verb (POLICY_RELOAD, KEY_ROTATE, CONFIG SET) |
| `result` | Outcome (ok, error) |
| `duration_ms` | Execution time in milliseconds |
| `actor` | Authenticated policy name or "anonymous" |

### Background Scheduler Events (Every 30 Seconds)

| Event | Level | Description |
|-------|-------|-------------|
| Key retired | INFO | Draining key transitioned to Retired (version) |
| Key auto-rotated | INFO | New key generated, old key moved to Draining (version) |
| Scheduler tick | DEBUG | Periodic lifecycle check completed |

### Policy File Watcher Events

| Event | Level | Description |
|-------|-------|-------------|
| Policies hot-reloaded | INFO | File change detected, policies reloaded (count) |
| Watcher error | ERROR | File system notification error |

### Health Check

The `HEALTH` command returns:
- Server state (READY, STARTING)
- Active signing key version and algorithm
- Total loaded policy count

### Shutdown Behavior

On SIGTERM or SIGINT, Sentry:
1. Stops accepting new connections
2. Drains in-flight connections with a 30-second timeout
3. Shuts down HTTP sidecar (JWKS endpoint)
4. Flushes WAL and fsyncs storage
5. Exits cleanly
