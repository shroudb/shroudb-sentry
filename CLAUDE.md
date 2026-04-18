# ShrouDB Sentry

Policy-based authorization engine. Evaluates access control policies and returns cryptographically signed JWT decisions. Downstream services verify decisions offline using the JWKS endpoint.

## Identity

ShrouDB is **not Redis**. It uses RESP3 as a wire protocol because RESP3 is efficient binary framing — not because ShrouDB is related to Redis in any way. Do not describe ShrouDB as "Redis-compatible," "Redis-like," or use Redis terminology for ShrouDB concepts.

## Architecture

```
shroudb-sentry-core/        Domain types (Policy, Decision, matchers, errors). No I/O.
shroudb-sentry-engine/      Store-backed logic (PolicyManager, SigningManager, evaluation).
shroudb-sentry-protocol/    RESP3 command parsing, ACL checks, dispatch to engine.
shroudb-sentry-server/      TCP server binary. What you deploy standalone.
shroudb-sentry-client/      Typed Rust client SDK over TCP/RESP3.
shroudb-sentry-cli/         CLI tool — single-command and interactive REPL modes.
```

## Security posture

Sentry is security infrastructure. Every change must be evaluated through a security lens:

- **Fail closed, not open.** When in doubt, deny access, reject the request, or return an error. Default policy effect is always deny.
- **No plaintext at rest.** Signing keys are encrypted before touching disk via the Store layer.
- **Minimize exposure windows.** Private key material must be zeroized after use. Retired keys have material cleared from memory.
- **Cryptographic choices are not negotiable.** Do not downgrade algorithms, skip integrity checks, weaken key derivation, or reduce key sizes.
- **Every shortcut is a vulnerability.** Skipping validation, hardcoding credentials, suppressing security-relevant warnings — not acceptable.
- **Audit surface changes require scrutiny.** Any change to policy evaluation, signing, key management, or ACL code must be reviewed with the assumption an attacker will examine it.

## Dependencies

- **Upstream:** shroudb-store, shroudb-storage, shroudb-crypto, shroudb-acl, shroudb-protocol-wire
- **Downstream:** shroudb-moat, shroudb-codegen

## Pre-push checklist (mandatory — no exceptions)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Every check must pass. Pre-existing issues must be fixed. No exceptions.

## No dated audit markdown files

Audit findings live in two places:
1. Failing tests named `debt_<n>_<what>_must_<expected>` (hard ratchet — no `#[ignore]`).
2. This repo's `TODOS.md`, indexing the debt tests by ID.

Do NOT create:
- `ENGINE_REVIEW*.md`, `*_REVIEW*.md`, `AUDIT_*.md`, `REVIEW_*.md`
- Any dated snapshot (`*_2026-*.md`, etc.)
- Status / progress / summary markdown that ages out of date

Past audits accumulated 17+ `ENGINE_REVIEW_v*.md` files claiming "zero open items, production-ready" while real gaps went unfixed. New agents read them as truth. They were all deleted 2026-04-17. The forcing function now is `cargo test -p <crate> debt_` — the tests are the source, `TODOS.md` is the index, and nothing else counts.
