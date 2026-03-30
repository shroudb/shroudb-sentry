# About ShrouDB Sentry

## For Everyone

Sentry answers one question: "Is this allowed?"

When a service needs to check whether a user can perform an action on a resource, it asks Sentry. Sentry evaluates the request against a set of policies and returns a signed decision — a cryptographic proof that the answer is "yes" or "no." That proof can be verified by any service without calling Sentry again.

This means authorization decisions are centralized (one place to define who can do what), auditable (every decision is traceable to a policy), and fast (signed decisions are cached and verified offline).

## For Technical Leaders

### The Problem

Authorization logic tends to fragment across services. Each team builds its own permission checks, hardcodes roles in middleware, or bolts RBAC onto an ORM. When requirements change — new roles, cross-service policies, time-based access — the cost scales with the number of services that embed that logic.

The alternatives:
- **Embedded authorization** — fast but fragmented, hard to audit, impossible to reason about globally.
- **External policy engines** — centralized but introduce a synchronous dependency on every request.

### What Sentry Is

Sentry is a **policy-based authorization engine** that returns **signed JWT decisions**. It is not an identity provider (that's Sigil) and not a permission store (that's ACL grants in shroudb-acl). Sentry evaluates attribute-based policies and produces self-contained proofs.

### Key Architectural Decisions

**Signed decisions, not callbacks.** Every EVALUATE response includes a JWT signed by Sentry's active key. Downstream services verify the JWT using the JWKS endpoint — no further calls to Sentry required. This eliminates the availability dependency that most external policy engines introduce.

**Deny-by-default.** If no policy matches a request, the decision is Deny. At equal priority, Deny trumps Permit. Every ambiguity resolves to the conservative choice.

**Priority-ordered evaluation.** Policies are evaluated highest-priority first. The first matching policy determines the decision. This avoids the combinatorial explosion of trying to merge conflicting policies.

**Attribute-based matching.** Policies match on principal roles, principal claims, resource type, resource attributes, and action names. This is more flexible than pure RBAC (role-based) but avoids the complexity of full ABAC (no arbitrary boolean expressions).

**Time-window conditions.** Policies can optionally restrict to UTC time windows, including overnight wrap (e.g., 22:00 to 06:00). This covers maintenance windows, business-hours-only access, and scheduled policy changes without external coordination.

**Key lifecycle management.** Signing keys follow a state machine (Active -> Draining -> Retired). On rotation, the old key enters Draining — it stays in JWKS for verification but no longer signs new decisions. After the drain period, it's retired and its private key material is zeroized. This ensures zero-downtime key rotation with forward secrecy.

### Operational Model

- **Policy storage.** Policies are stored in ShrouDB's encrypted KV store. CRUD operations via RESP3 protocol.
- **Evaluation.** Stateless policy matching — no session state, no external lookups. The engine reads policies from an in-memory cache backed by Store.
- **Decision signing.** ES256 (ECDSA P-256) by default. Also supports ES384, EdDSA, RS256, RS384, RS512.
- **JWKS distribution.** Active and Draining key public keys are served via the JWKS command. Services fetch this periodically to verify decision JWTs.
- **Background scheduler.** Auto-rotates active keys after `rotation_days`, auto-retires draining keys after `drain_days`.
- **ACL.** Sentry's own commands are protected by the same token-based ACL system used across all ShrouDB engines.

### Ecosystem

Sentry is one engine in the ShrouDB ecosystem:

| Engine | Role |
|---|---|
| **ShrouDB** | Encrypted KV store (the foundation) |
| **Sigil** | Identity and authentication (credentials, sessions, JWTs) |
| **Cipher** | Encryption key management (keyrings, encrypt/decrypt, signing) |
| **Keep** | Secrets management (versioned, path-based) |
| **Forge** | Certificate authority (x509 issuance, revocation) |
| **Sentry** | Authorization policies (evaluate, signed decisions) |
| **Moat** | Multi-engine orchestrator (single binary, all engines) |

Sentry extends `shroudb-acl` with policy evaluation types (`PolicyEffect`, `PolicyRequest`, `PolicyDecision`, `PolicyEvaluator` trait), enabling other engines to delegate authorization decisions to Sentry.
