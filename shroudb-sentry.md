# ShrouDB Sentry — Repository Analysis

**Component:** shroudb-sentry  
**Type:** Engine (standalone server binary + library crates + client SDK + CLI)  
**Language:** Rust (edition 2024, MSRV 1.92)  
**License:** MIT OR Apache-2.0  
**Published:** Private registry (`crates.shroudb.dev`), Docker images  
**Analyzed:** /Users/nlucas/dev/shroudb/shroudb-sentry @ v1.4.10

---

## Role in Platform

Sentry is ShrouDB's centralized authorization engine. It evaluates attribute-based policies against principal/resource/action tuples and returns cryptographically signed JWT decisions that downstream services verify offline via JWKS. Without Sentry, every ShrouDB engine must either inline authorization logic or fall back to shroudb-acl's static grant system — losing centralized policy management, signed decision proofs, and auditability.

---

## Behavioral Surface

### Public API

**RESP3 Commands (13 total):**

| Command | ACL | Description |
|---|---|---|
| `AUTH <token>` | None | Authenticate connection |
| `POLICY CREATE <name> <json>` | Admin | Create policy |
| `POLICY GET <name>` | `sentry.policies.*` read | Get policy |
| `POLICY LIST` | `sentry.policies.*` read | List policy names |
| `POLICY DELETE <name>` | Admin | Delete policy |
| `POLICY UPDATE <name> <json>` | Admin | Update policy |
| `EVALUATE <json>` | `sentry.evaluate.*` read | Evaluate request, return signed decision |
| `KEY ROTATE [FORCE] [DRYRUN]` | Admin | Rotate signing key |
| `KEY INFO` | None | Signing key metadata |
| `JWKS` | None | JSON Web Key Set (public keys) |
| `HEALTH` | None | Health check with policy count |
| `PING` | None | Connectivity check |
| `COMMAND LIST` | None | List supported commands |

**Rust Library API:**
- `SentryEngine<S: Store>` — generic over Store implementation. Core type.
- `impl PolicyEvaluator for SentryEngine<S>` — implements `shroudb_acl::PolicyEvaluator` trait, enabling other engines to delegate authorization decisions to Sentry.
- `SentryClient` — typed async TCP client SDK (`shroudb-sentry-client`).

**Crate structure (6 crates):**

| Crate | Role |
|---|---|
| `shroudb-sentry-core` | Domain types (Policy, Decision, SigningKeyring, matchers, errors). No I/O. |
| `shroudb-sentry-engine` | Store-backed PolicyManager, SigningManager, evaluator, background scheduler. |
| `shroudb-sentry-protocol` | RESP3 command parsing, ACL requirement declaration, dispatch to engine. |
| `shroudb-sentry-server` | TCP server binary (`shroudb-sentry`). Config loading, bootstrap, graceful shutdown. |
| `shroudb-sentry-client` | Typed async Rust client over TCP/RESP3. Wraps `shroudb-client-common`. |
| `shroudb-sentry-cli` | CLI tool with single-command and interactive REPL modes. |

### Core operations traced

**1. EVALUATE (policy evaluation + JWT signing):**
1. `dispatch::dispatch` checks ACL via `shroudb_acl::check_dispatch_acl`
2. `evaluator::parse_evaluation_request` parses JSON into `PolicyRequest`
3. `engine.evaluate_request` calls `policies.all_sorted()` (DashMap -> sorted Vec by priority desc)
4. `evaluator::evaluate_policies` iterates sorted policies; first match wins, deny trumps permit at equal priority, no match = deny
5. `evaluator::sign_decision` hex-decodes active key's PKCS#8 private key, builds `DecisionClaims`, calls `shroudb_crypto::sign_jwt`
6. Returns `SignedDecision` with JWT token, matched policy, and cache_until timestamp
7. Fire-and-forget audit event spawned to Chronicle if configured

**2. KEY ROTATE (signing key lifecycle):**
1. `signing_manager.rotate("default", force, dryrun)` checks active key age against `rotation_days`
2. If rotation needed and not dryrun: transitions Active -> Draining (sets `draining_since`), generates new key via `shroudb_crypto::generate_signing_key`, pushes to keyring
3. Persists updated keyring to Store
4. JWKS endpoint now serves both Active and Draining public keys
5. Background scheduler later calls `retire_expired` -> Draining -> Retired when `drain_days` exceeded, `zeroize`s private key material

**3. Policy self-authorization (bootstrap):**
1. On policy mutation (create/update/delete), `authorize_policy_mutation` checks if policy store is empty
2. If empty: permit unconditionally (bootstrap rule -- first policy can always be created)
3. If policies exist: constructs internal `PolicyRequest` with actor as principal, evaluates against all policies
4. If denied: returns `SentryError::AccessDenied`

### Capability gating

No capability traits or feature flags observed. All functionality is available unconditionally. The licensing fence is at the repo level (MIT/Apache-2.0), not code-level.

---

## Cryptographic Constructs

**Signing algorithms:** ES256 (ECDSA P-256, default), ES384, EdDSA (Ed25519), RS256, RS384, RS512. All delegated to `shroudb_crypto`.

**Key generation:** `shroudb_crypto::generate_signing_key(JwtAlgorithm)` -> PKCS#8 DER private key + DER public key. Keys stored hex-encoded.

**JWT signing:** `shroudb_crypto::sign_jwt(private_key_bytes, algorithm, claims, kid)` -> standard JWT with `alg` and `kid` headers.

**JWKS construction:** `shroudb_crypto::public_key_to_jwk(algorithm, public_key_der, kid)` -> standard JWK format.

**Key lifecycle state machine:** `Staged -> Active -> Draining -> Retired`. Transitions validated by `KeyState::can_transition_to`. No backward transitions allowed.

**Key material zeroization:** On retirement, `SigningKeyVersion.private_key` is `zeroize()`d (via the `zeroize` crate) then set to `None`. Debug impl redacts private key as `[REDACTED]`.

**Data-at-rest encryption:** All policy and keyring data stored through the `Store` trait, which provides per-path HKDF-derived encryption keys (handled by `shroudb-storage`). Master key required via env var or file.

**Private key storage format:** PKCS#8 DER, hex-encoded, stored as JSON field within the keyring blob in the encrypted Store.

**Advisory acknowledgments (deny.toml):** RUSTSEC-2023-0071 (RSA Marvin Attack) explicitly ignored -- RSA used only for key generation, not decryption. RUSTSEC-2023-0089 (atomic-polyfill unmaintained) ignored -- transitive dep with no fix available.

---

## Engine Relationships

### Calls out to
- **shroudb-store** -- storage abstraction. PolicyManager and SigningManager use `namespace_create`, `put`, `get`, `list`, `delete`.
- **shroudb-storage** -- `EmbeddedStore` implementation (server binary). Test utilities for engine tests.
- **shroudb-crypto** -- JWT signing (`sign_jwt`), key generation (`generate_signing_key`), JWK construction (`public_key_to_jwk`). All cryptographic operations delegated.
- **shroudb-acl** -- `PolicyEffect`, `PolicyRequest`, `PolicyPrincipal`, `PolicyResource`, `PolicyEvaluator` trait, `AuthContext`, `TokenValidator`, `AclRequirement`, `check_dispatch_acl`. Core policy types defined upstream.
- **shroudb-chronicle-core** -- audit event types (`Event`, `EventResult`, `Engine::Sentry`). Optional `ChronicleOps` trait for audit logging.
- **shroudb-protocol-wire** -- `Resp3Frame` for wire encoding.
- **shroudb-server-tcp** -- `ServerProtocol` trait implementation, `run_tcp` for connection management.
- **shroudb-server-bootstrap** -- logging setup, core dump disabling, master key resolution, storage opening, banner printing, graceful shutdown.
- **shroudb-client-common** -- RESP3 TCP connection for the client SDK.

### Called by
- **Any ShrouDB engine** -- via the `PolicyEvaluator` trait implementation. Engines can delegate authorization decisions to Sentry at runtime.
- **shroudb-moat** -- embeds Sentry alongside other engines in the unified binary (inferred from platform architecture, not visible in this repo).
- **shroudb-codegen** -- downstream consumer (listed in CLAUDE.md dependencies).

### Sentry / ACL integration
Sentry *is* the policy evaluation engine. It implements `shroudb_acl::PolicyEvaluator`, the canonical authorization interface.

Sentry's own commands are protected by `shroudb-acl`'s token-based ACL system (`ServerAuthConfig`, `TokenValidator`, `check_dispatch_acl`). Each command declares an `AclRequirement` (None, Admin, or Namespace-scoped read). Connection-level AUTH validates tokens against configured grants.

Self-authorization: policy mutations are additionally gated by evaluating the mutation itself against existing policies (bootstrap rule: first policy creation is unconditionally permitted).

---

## Store Trait

Sentry is generic over `S: Store`. Two namespaces used:
- `sentry.policies` -- policy documents (JSON-serialized `Policy` structs)
- `sentry.signing` -- signing keyrings (JSON-serialized `SigningKeyring` structs)

Both managers use DashMap as an in-memory cache with write-through to Store.

**Storage backends:** Currently only `EmbeddedStore` (local encrypted KV) is wired in the server binary. Config supports `mode = "remote"` with a `uri` field but this is explicitly unimplemented (`anyhow::bail!("remote store mode is not yet implemented")`).

**Per-engine storage assignment:** Compatible with Moat's multi-engine storage architecture via the `Store` trait generic.

---

## Licensing Tier

**Tier:** Open core (MIT OR Apache-2.0)

All source code in this repository is MIT/Apache-2.0 dual-licensed. No capability traits, feature flags, or license checks fence any behavior. The entire behavioral surface -- policy CRUD, evaluation, key management, signed JWT decisions, JWKS, ACL integration -- is open.

Commercial value derives from:
1. The private crate registry (`crates.shroudb.dev`) -- crates are published there, not to crates.io
2. The upstream dependency chain (`shroudb-store`, `shroudb-storage`, `shroudb-crypto`, `shroudb-acl`) which may have different licensing terms
3. Platform integration (Moat embedding, Chronicle audit, Sigil identity)

---

## Standalone Extractability

**Extractable as independent product:** Yes, with moderate effort.

Sentry is architecturally self-contained. It has its own binary, Dockerfile, client SDK, and CLI. The challenge is the dependency chain:
- `shroudb-store` (Store trait) -- would need a trait-compatible replacement or the dependency itself
- `shroudb-storage` (EmbeddedStore) -- the actual encrypted KV backend
- `shroudb-crypto` -- all cryptographic operations
- `shroudb-acl` -- policy types and ACL system
- `shroudb-server-tcp`, `shroudb-server-bootstrap`, `shroudb-protocol-wire`, `shroudb-client-common` -- server/client infrastructure

None of these are on crates.io. A standalone offering requires either bundling these dependencies or replacing them.

**Value lost without sibling engines:** Audit trail (Chronicle integration becomes a no-op without Chronicle). Identity federation (no Sigil). Encryption key management (no Cipher). The core value proposition -- centralized policy evaluation with signed JWT decisions -- is fully retained.

### Target persona if standalone
Platform engineering teams building authorization infrastructure. Competitors: OPA/Rego, Cedar (AWS), Cerbos, SpiceDB. Differentiator: signed JWT decisions enabling offline verification without a synchronous dependency on the policy engine.

### Pricing model fit if standalone
Open core + support. The open-source engine covers the core use case. Commercial value in: hosted/managed offering, enterprise support, platform integration (Moat bundle), audit integration (Chronicle), advanced key management.

---

## Deployment Profile

**Standalone binary:** `shroudb-sentry` (TCP server on port 6799). Multi-arch Docker image (amd64/arm64, Alpine-based, musl-static). Non-root user (uid 65532).

**CLI tool:** `shroudb-sentry-cli` (separate binary, separate Docker image).

**Embedded mode:** `SentryEngine<S: Store>` can be embedded as a library in any Rust application with a compatible Store implementation.

**Remote mode:** Config supports `mode = "remote"` but implementation is stubbed.

**Infrastructure dependencies:** Filesystem for embedded store. Master key via environment variable or file. No external services required. Optional Chronicle integration for audit logging.

**Self-hostable:** Yes, trivially. Docker image, single binary, env var for master key, data directory.

---

## Monetization Signals

**Absent in this component:**
- No quota enforcement
- No tenant scoping beyond what's inherited from ACL token `tenant` field
- No usage counters or rate limiting
- No API key validation beyond the ACL token system
- No license key checks

The ACL token system includes a `tenant` field and `platform` flag, but these gate access control, not monetization.

---

## Architectural Moat (Component-Level)

The component-level moat is moderate. The core algorithmic complexity (priority-ordered policy evaluation with deny-trumps-permit) is straightforward. What is harder to reproduce:

1. **Signed JWT decisions with JWKS distribution** -- the specific integration of policy evaluation -> JWT signing -> JWKS endpoint -> offline verification is a well-designed pattern that eliminates the synchronous availability dependency most policy engines introduce. This is the key architectural differentiator.

2. **Key lifecycle state machine** (Staged -> Active -> Draining -> Retired) with automatic rotation, drain period, and private key zeroization -- production-grade key management that handles zero-downtime rotation correctly.

3. **Self-authorization bootstrap** -- the engine eats its own cooking: policy mutations are authorized by the engine's own policies, with a bootstrap rule for the first policy.

4. **Platform-level moat** -- the real moat is integration: Store trait generics enabling Moat embedding, PolicyEvaluator trait enabling cross-engine authorization delegation, Chronicle audit integration, ACL system reuse. This is where the value compounds.

---

## Gaps and Liabilities

1. **Remote store mode unimplemented.** Config accepts `mode = "remote"` with a `uri` field but bails at runtime. This means Sentry cannot yet connect to a remote ShrouDB instance as its backing store -- only embedded mode works.

2. **No TLS on the TCP listener.** The server binds plaintext TCP. TLS termination must be handled externally. The `protocol.toml` defines `shroudb-sentry+tls://` URI scheme but no TLS implementation is present.

3. **Evaluation is synchronous.** `evaluate_request` is a sync function that reads from DashMap and signs inline. At high throughput, JWT signing (especially RSA) could become a bottleneck. No caching of signed decisions.

4. **No CHANGELOG.** Version history is only in git commits.

5. **Policy GET does not return full matcher/condition details.** The dispatch handler only returns name, description, effect, priority, and timestamps -- not the principal/resource/action matchers or conditions. Users cannot fully inspect policies via the protocol.

6. **DashMap iteration for evaluation.** `all_sorted()` clones all policies and sorts on every evaluation. At large policy counts this scales poorly. No indexed evaluation path.

7. **Audit event on EVALUATE is fire-and-forget.** Chronicle failures are logged but do not fail the evaluation. This is intentional (availability over auditability for reads) but may not meet strict compliance requirements.

8. **No policy versioning or history.** Policies are replaced in-place. No audit trail of policy changes beyond Chronicle events.

---

## Raw Signals for Evaluator

- **Test coverage is solid.** Unit tests in every module. Integration tests cover full TCP lifecycle, ACL enforcement (4 token tiers), edge cases (max name length, corrupt data, concurrent evaluation during mutation). ~30+ integration tests.
- **Private registry only.** All crates published to `crates.shroudb.dev`, not crates.io. The Dockerfile uses a secret-mounted registry token.
- **`cargo deny` configured.** License allowlist, advisory ignores documented with rationale, multiple versions warned.
- **Workspace version 1.4.10** with internal crate versions pinned at 1.4.5. Active development.
- **Rust edition 2024** with MSRV 1.92 -- bleeding edge.
- **shroudb-acl provides the core policy types** (`PolicyEffect`, `PolicyRequest`, `PolicyPrincipal`, `PolicyResource`, `PolicyEvaluator`, `PolicyDecision`). Sentry extends these with concrete evaluation logic and JWT signing. This is the Sentry fallback pattern: other engines can use shroudb-acl's static grants as baseline, with Sentry as the sophisticated evaluator.
- **Docker multi-stage, multi-arch build** with musl-static binaries. Production-ready container workflow.
- **Core dumps disabled** at startup via `shroudb-server-bootstrap`.
