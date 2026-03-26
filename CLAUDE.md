# ShrouDB Sentry

Policy-based authorization engine — evaluates access control policies and returns signed JWT decisions.

## Pre-push checklist (mandatory — no exceptions)

Every check below **must** pass locally before pushing to any branch. Do not rely on GitHub Actions to catch these — CI is a safety net, not the first line of defense.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

### Rules

1. **Run all checks before every push.** No shortcuts, no "I'll fix it in the next commit."
2. **Pre-existing issues must be fixed.** If any check reveals warnings, formatting drift, deny failures, or any other issue — even if you didn't introduce it — fix it in the same changeset. Do not skip it as "not in scope", "pre-existing", or "unrelated." If the tool flags it, it gets fixed.
3. **Never suppress or bypass checks.** Do not add `#[allow(...)]` to silence clippy, do not skip `cargo deny`, do not push with known failures. Do not use `--no-verify` on git push.
4. **Warnings are errors.** `RUSTFLAGS="-D warnings"` is set in CI. Clippy runs with `-D warnings`. Both compiler warnings and clippy warnings fail the build.
5. **Dependency issues require resolution.** If `cargo deny` flags a new advisory or license issue, investigate and resolve it (update the dep, or add a justified exemption to `deny.toml`). Do not ignore it.
6. **`cargo audit` exists as a separate CI job** with `--ignore` flags for specific RUSTSECs. Those flags must stay in sync with `deny.toml` exemptions. Prefer upgrading the affected dep over adding new ignores.
7. **Documentation must stay in sync.** Any change that affects CLI commands, config keys, public API, or user-facing behavior **must** include corresponding updates to `README.md`, `DOCS.md`, and `ABOUT.md` in the same changeset. Do not merge code changes with stale docs.
8. **Cross-repo impact must be addressed.** If a change affects shared types, protocols, or APIs consumed by other ShrouDB repos, update those downstream repos in the same effort. Do not leave other repos broken or out of sync.
