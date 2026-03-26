# Understanding ShrouDB Sentry

This document explains ShrouDB Sentry at two levels of depth. Pick the section that matches your background.

---

## For Everyone: What ShrouDB Sentry Does

Every application needs to answer the question "is this user allowed to do this?" Authorization logic is typically scattered across if-statements, database queries, and middleware — duplicated in every service, inconsistent across teams, and invisible to auditors. When something goes wrong, there's no single place to see what was allowed and why.

**ShrouDB Sentry is a centralized authorization engine.** It evaluates access control requests against a set of declarative policies and returns cryptographically signed decision tokens. These tokens can be verified by any downstream service without contacting Sentry again — they're self-contained proof that "yes, this user was allowed to do this, at this time, because of this policy."

**What it provides:**

- **Policy-based authorization** — Define who can do what using declarative TOML policies. Policies specify principals (users/roles), resources (types/attributes), actions, and optional time-window conditions.
- **Signed decision tokens** — Every authorization decision is signed as a JWT. Downstream services verify the signature and check the expiry — no callback to Sentry required.
- **Key rotation** — Signing keys rotate automatically. A JWKS endpoint publishes public keys so any service can verify decisions offline.
- **Hot-reloadable policies** — Policies can be updated on disk and reloaded without restarting the engine.
- **Decision caching** — Optional caching reduces redundant policy evaluation and signing for repeated requests.

**Why it matters:**

- Authorization logic is defined in one place, not scattered across services.
- Signed decision tokens eliminate the need for every service to call an authorization endpoint on every request.
- JWKS-based verification means services can validate decisions even if Sentry is temporarily unreachable.
- Policy changes take effect immediately via hot reload — no deployment required.

---

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Authorization is typically implemented as ad-hoc code in each service. This leads to inconsistent enforcement, no audit trail, and impossible-to-answer questions like "what can user X access?" or "who approved this operation?" Centralized authorization systems solve this but introduce latency on every request and become availability bottlenecks.

### What ShrouDB Sentry Is

ShrouDB Sentry is a **policy-based authorization engine** that returns **cryptographically signed decisions**. The key insight is that authorization decisions are cacheable — if "Alice can read documents" was true 10 seconds ago, it's probably still true. By signing decisions as JWTs with a short TTL, Sentry enables stateless verification at the edge while maintaining centralized policy management.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Signed decision tokens** | Decisions are JWTs that downstream services verify locally. Eliminates per-request callbacks and makes Sentry's availability non-critical for the verify path. |
| **Priority-based policy evaluation** | Policies are sorted by priority. At equal priority, Deny trumps Permit. This creates predictable, debuggable authorization behavior. |
| **JWKS endpoint** | Public keys are published at `/.well-known/jwks.json`. Any service can verify decision tokens without shared secrets or Sentry access. |
| **Hot-reloadable policies** | Policies are TOML files on disk, watched for changes. Updates take effect within 1 second via file watcher with debounce. |
| **Decision caching** | Configurable cache keyed on principal, resource, and action. Reduces signing overhead for repeated requests. |

### Operational Model

- **Configuration:** TOML file with signing algorithm, rotation schedule, and policy directory. Policies are separate TOML files in a watched directory.
- **Observability:** Structured JSON logging via tracing. Audit log for write operations. JWKS endpoint for external verification infrastructure.
- **Deployment:** Single static binary. TLS and mTLS supported natively. HTTP sidecar for JWKS.
