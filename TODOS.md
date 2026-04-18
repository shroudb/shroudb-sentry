# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p shroudb-sentry-engine --test debt_tests_test` is the live punch list.

### Cross-cutting root causes

1. **Server binary hardcodes `None` for Chronicle.** `main.rs:104` builds `SentryEngine::new(store, sentry_config, None)`. Sentry — the policy engine itself — runs with zero audit trail.
2. **Mutations commit before audit.** `policy_create`/`update`/`delete` persist to Store THEN emit audit. Audit failure returns Err but the mutation is already durable. An attacker who breaks Chronicle gets unaudited mutations.
3. **Bootstrap gate re-opens on empty state.** `authorize_policy_mutation` checks `policies.count() == 0`; attacker who reaches an empty state gets unconditional write.

### Open

- [x] **DEBT-1** — `policy_create` must rollback on audit failure (currently half-committed). Test: `debt_1_policy_create_must_rollback_when_audit_fails` @ `shroudb-sentry-engine/tests/debt_tests_test.rs`.
- [x] **DEBT-2** — `policy_delete` must rollback on audit failure. Test: `debt_2_policy_delete_must_rollback_when_audit_fails` @ same file.
- [x] **DEBT-3** — `SentryConfig::default().require_audit` must be `true`. Test: `debt_3_sentry_config_default_require_audit_must_be_true` @ same file.
- [x] **DEBT-4** — EVALUATE must fail-closed on audit error by default (currently fire-and-forget `tokio::spawn` with dropped JoinHandle). Test: `debt_4_evaluate_default_must_fail_closed_on_audit_error` @ same file.
- [ ] **DEBT-5** — bootstrap gate must not reopen after last policy is deleted (one-shot latch). Test: `debt_5_bootstrap_gate_must_not_reopen_after_policy_delete` @ same file.
- [ ] **DEBT-6** — `main.rs` must not hardcode Chronicle=None. Test: `debt_6_server_main_must_not_hardcode_chronicle_none` @ same file.
