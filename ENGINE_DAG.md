# Sentry Engine DAG

## Overview

Sentry is the ShrouDB policy-based authorization engine. It evaluates
attribute-matching policies (principal roles/claims, resource type/attributes,
action names, optional UTC time windows) against incoming authorization
requests and returns a cryptographically signed JWT decision. Policies are
evaluated highest-priority first; at equal priority, Deny trumps Permit; if
no policy matches, the decision is Deny by default. Signed decisions are
self-contained — downstream services verify them offline against Sentry's
JWKS endpoint, eliminating a synchronous availability dependency on Sentry
for every authorization check. Signing keys follow an
Active -> Draining -> Retired lifecycle with background auto-rotation and
auto-retirement, and Sentry's own policy-mutation commands are subject to
the same policy evaluation (bootstrap-permit when the store is empty, then
default-deny).

## Crate dependency DAG

Internal crates of the `shroudb-sentry` workspace and their edges:

```
                     +------------------------+
                     | shroudb-sentry-core    |
                     | (Policy, Decision,     |
                     |  matchers, signing     |
                     |  types, errors — no IO)|
                     +-----------+------------+
                                 |
                                 v
                     +------------------------+
                     | shroudb-sentry-engine  |
                     | (PolicyManager,        |
                     |  SigningManager,       |
                     |  evaluator, scheduler) |
                     +-----------+------------+
                                 |
                                 v
                     +------------------------+
                     | shroudb-sentry-protocol|
                     | (RESP3 parsing, ACL,   |
                     |  dispatch to engine)   |
                     +-----------+------------+
                                 |
                                 v
                     +------------------------+
                     | shroudb-sentry-server  |
                     | (TCP binary:           |
                     |  shroudb-sentry)       |
                     +------------------------+

                     +------------------------+
                     | shroudb-sentry-client  |
                     | (typed Rust SDK over   |
                     |  TCP/RESP3)            |
                     +-----------+------------+
                                 |
                                 v
                     +------------------------+
                     | shroudb-sentry-cli     |
                     | (one-shot + REPL CLI   |
                     |  binary:               |
                     |  shroudb-sentry-cli)   |
                     +------------------------+
```

Notes:

- `shroudb-sentry-client` is a pure wire-level SDK (no dependency on core,
  engine, or protocol crates) — it links only `shroudb-client-common` and
  `shroudb-acl` (for shared ACL types used in decision payloads).
- `shroudb-sentry-cli` depends only on `shroudb-sentry-client`.
- `shroudb-sentry-protocol` depends on both `-core` (types) and `-engine`
  (dispatch target).
- `shroudb-sentry-server` composes all four lower crates plus commons
  (`shroudb-store`, `shroudb-storage`, `shroudb-client`,
  `shroudb-protocol-wire`, `shroudb-server-tcp`, `shroudb-server-bootstrap`,
  `shroudb-engine-bootstrap` — the latter is used to resolve the `[audit]`
  config section into an explicit Chronicle `Capability`).

## Capabilities

- Policy CRUD over RESP3: `POLICY CREATE | GET | LIST | UPDATE | DELETE |
  HISTORY` (versioned history retained per policy).
- Attribute-based policy evaluation: `EVALUATE <json>` matches principal
  roles (OR) and claims (AND), resource type and attributes (AND), and
  action names (OR, case-insensitive). Empty matcher fields are wildcards.
- Priority-ordered, deny-trumps-permit evaluation with default-deny when
  no policy matches.
- Optional UTC `time_window` conditions on policies, including overnight
  wrap (e.g., 22:00 -> 06:00).
- Signed JWT decisions per `EVALUATE`, with `cache_until` hint derived from
  `decision_ttl_secs`.
- Signing algorithms: ES256 (default), ES384, EdDSA, RS256, RS384, RS512.
- JWKS distribution via `JWKS` — serves public keys for Active and Draining
  key versions so verifiers keep working across rotations.
- Signing key lifecycle: `KEY ROTATE [FORCE] [DRYRUN]`, `KEY INFO`.
  Active -> Draining -> Retired state machine; retired keys have private
  material zeroized.
- Background scheduler: auto-rotates the active key after `rotation_days`
  and auto-retires draining keys after `drain_days`.
- Self-authorization: Sentry's own `POLICY_CREATE | UPDATE | DELETE`
  commands are evaluated against the stored policies (bootstrap-permit
  when the policy set is empty so the first policy can be written).
- Config-seeded policies: server applies `[policies.*]` entries with
  `seed_if_absent` semantics on startup.
- Engine-to-engine integration: `SentryEngine<S>` implements the
  `shroudb_acl::PolicyEvaluator` trait, so other engines (e.g. Sigil via
  Moat) can call Sentry as an in-process authorization source.
- Token-based ACL on all commands (`none`, `namespace:read`, `admin`) per
  `protocol.toml`, backed by `shroudb-acl`.
- Engine identity handshake: `HELLO`, `HEALTH`, `PING`, `COMMAND LIST`.
- Storage mode selection at the server layer: `embedded` (local
  `EmbeddedStore`) or `remote` (`shroudb_client::RemoteStore` over
  `shroudb://` / `shroudb+tls://`).

## Engine dependencies

Sentry depends on exactly one other ShrouDB engine at the engine-crate
level: `chronicle` (through `shroudb-chronicle-core` for audit event
types). The engine crate also pulls in `shroudb-audit` and
`shroudb-server-bootstrap` to consume the `Capability` type used to
wrap the optional Chronicle handle.

### Dependency: chronicle

- **Pinned via**: `shroudb-chronicle-core` workspace dependency on
  `shroudb-sentry-engine`.
- **Integration point**: `SentryEngine::new` accepts an
  `Capability<Arc<dyn ChronicleOps>>` — `Capability::Enabled(...)`,
  `Capability::DisabledForTests`, or
  `Capability::DisabledWithJustification`. Absence is never silent
  (there is no bare `None` path). The engine emits
  `Event { engine: AuditEngine::Sentry, ... }` for `POLICY_CREATE`,
  `POLICY_UPDATE`, `POLICY_DELETE`, `KEY_ROTATE`, and `EVALUATE`.

**What breaks without it (fallback).**
Sentry is fully functional without a Chronicle sink. When the
`chronicle` capability on `SentryEngine::new` is a disabled variant,
`emit_audit_event` is a no-op and `evaluate_request` skips the audit
hook entirely. All policy CRUD, `EVALUATE`, signed-decision issuance,
JWKS, key rotation, draining, retirement, and scheduler behavior
continue unchanged. The only loss is the durable audit trail — there
is no record of who created/updated/deleted policies, when keys
rotated, or which authorization decisions were served.

The `require_audit` config flag interacts with this: if
`require_audit = true` but no Chronicle is configured, `EVALUATE`
returns `SentryError::Internal("require_audit is true but no
Chronicle is configured")`. This is operator-opt-in fail-closed
behavior — the default is `require_audit = false`, so Sentry does not
fail closed on missing Chronicle out of the box.

**What works with it (full behavior).**
When Chronicle is wired in, every policy mutation, key rotation, and
evaluation produces an audit event with operation name, resource id,
actor, duration, and result. Policy mutation events are emitted
synchronously and propagate Chronicle failures back to the caller.
`EVALUATE` audit events are fire-and-forget by default (spawned on a
background task, logged on failure) so audit latency does not block
the authorization path; setting `require_audit = true` promotes them
to synchronous recording that fails the evaluation if Chronicle
cannot accept the event.

## Reverse dependencies

Known consumers of Sentry's published crates:

- **shroudb-moat** — embeds `shroudb-sentry-protocol` and
  `shroudb-sentry-engine` behind the `sentry` feature flag. Moat v1
  multiplexes Sentry alongside other engines in a single binary and
  routes `SENTRY ...`-prefixed commands into Sentry's protocol layer.
- **shroudb-sentry-cli** — in-workspace CLI consumer of
  `shroudb-sentry-client`, used as the operator-facing tool.
- **herald-server** (`/Users/nlucas/dev/herald/herald-server`) — uses
  `shroudb-sentry-client` for remote policy evaluation and also
  embeds `shroudb-sentry-engine` for in-process evaluation against
  its own store.
- **shroudb-codegen** — reads `protocol.toml` to generate SDK clients
  for languages outside Rust.

No other internal workspace or known downstream project links against
`shroudb-sentry-core` directly; `-core` is re-exported through
`-engine` / `-protocol` for engine embedders and is not expected to
be a public surface.

## Deployment modes

Sentry supports two deployment shapes. Both share the same engine
logic in `shroudb-sentry-engine`; they differ in how the engine is
wrapped and how callers reach it.

**Standalone (TCP server, `shroudb-sentry-server`).**
The `shroudb-sentry` binary opens a TCP (optionally TLS) listener on
`default_tcp_port = 6799`, speaks RESP3, and dispatches commands into
`shroudb-sentry-protocol`. Storage is selected at startup via
`cfg.store.mode`:

- `embedded` — opens a local `EmbeddedStore` under `data_dir` through
  `shroudb-server-bootstrap` and `shroudb-storage`.
- `remote` — connects to a remote ShrouDB via
  `shroudb_client::RemoteStore::connect(uri)` using
  `shroudb://` / `shroudb+tls://`.

The server also starts the background scheduler
(`start_scheduler`) for auto-rotation / auto-retirement, seeds
policies from `[policies.*]` config, wires the ACL token validator,
and prints a startup banner via `shroudb-server-bootstrap`.
Chronicle is resolved at this layer from a mandatory `[audit]`
config section (one of `mode = "remote"`, `mode = "embedded"`, or
`mode = "disabled"` with a `justification`); the server calls
`audit_cfg.resolve(storage).await` via `shroudb-engine-bootstrap` and
passes the resulting `Capability<Arc<dyn ChronicleOps>>` into
`SentryEngine::new`. There is no silent `None` — if `[audit]` is
missing, startup fails with an explicit error listing the three
accepted shapes.

**Embedded (in-process, via Moat or a host service).**
A host crate constructs `SentryEngine<S>` directly with its own
`Arc<S: Store>` and optionally an `Arc<dyn ChronicleOps>`. Moat does
this behind the `sentry` feature: all engines share one
`StorageEngine`, and the host can supply a live Chronicle handle so
Sentry audit events land in the same audit stream as other engines.
Hosts that need to let other engines delegate authorization can pass
the `SentryEngine` as an `Arc<dyn PolicyEvaluator>` (the trait is
implemented directly on `SentryEngine<S>`), which is the integration
path used for policy-delegated engines like Sigil.
