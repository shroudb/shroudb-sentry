//! Debt tests (AUDIT_2026-04-17) — hard-ratchet FAILING tests that encode
//! the correct behavior Sentry must exhibit.
//!
//! These tests currently fail. They are not to be marked `#[ignore]`.
//! Each test corresponds to a finding documented in the audit.

use std::sync::Arc;

use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::Event;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_sentry_core::matcher::{ActionMatcher, Conditions, PrincipalMatcher, ResourceMatcher};
use shroudb_sentry_core::policy::Policy;
use shroudb_sentry_engine::engine::{SentryConfig, SentryEngine};
use shroudb_server_bootstrap::Capability;

// ── Test doubles (colocated per Rust integration-test conventions) ───

struct RecordingChronicle {
    events: Arc<std::sync::Mutex<Vec<Event>>>,
}

fn recording_chronicle() -> (Arc<dyn ChronicleOps>, Arc<std::sync::Mutex<Vec<Event>>>) {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let arc: Arc<dyn ChronicleOps> = Arc::new(RecordingChronicle {
        events: events.clone(),
    });
    (arc, events)
}

impl ChronicleOps for RecordingChronicle {
    fn record(
        &self,
        event: Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let events = self.events.clone();
        Box::pin(async move {
            events.lock().unwrap().push(event);
            Ok(())
        })
    }

    fn record_batch(
        &self,
        events: Vec<Event>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        let inner = self.events.clone();
        Box::pin(async move {
            inner.lock().unwrap().extend(events);
            Ok(())
        })
    }
}

struct FailingChronicle;

fn failing_chronicle() -> Arc<dyn ChronicleOps> {
    Arc::new(FailingChronicle)
}

impl ChronicleOps for FailingChronicle {
    fn record(
        &self,
        _event: Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Err("simulated chronicle failure".to_string()) })
    }

    fn record_batch(
        &self,
        _events: Vec<Event>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Err("simulated chronicle failure".to_string()) })
    }
}

fn permit_all(name: &str, priority: i32) -> Policy {
    Policy {
        name: name.into(),
        description: "permit-all".into(),
        effect: PolicyEffect::Permit,
        priority,
        principal: PrincipalMatcher::default(),
        resource: ResourceMatcher::default(),
        action: ActionMatcher::default(),
        conditions: Conditions::default(),
        version: 0,
        created_at: 0,
        updated_at: 0,
    }
}

fn eval_request(principal: &str, resource: &str, action: &str) -> PolicyRequest {
    PolicyRequest {
        principal: PolicyPrincipal {
            id: principal.into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: PolicyResource {
            id: resource.into(),
            resource_type: "resource".into(),
            attributes: Default::default(),
        },
        action: action.into(),
    }
}

// ── Debt tests ───────────────────────────────────────────────────────

// F-sentry-1: policy_create commits the mutation THEN audits. If audit
// fails, the policy is already persisted. An attacker who can fail
// Chronicle gets unaudited policy changes. Audit must either precede
// the commit or the commit must roll back on audit failure.
#[tokio::test]
async fn debt_1_policy_create_must_rollback_when_audit_fails() {
    let store = shroudb_storage::test_util::create_test_store("sentry-debt-1").await;
    let engine = SentryEngine::new(
        store,
        SentryConfig::default(),
        Capability::Enabled(failing_chronicle()),
    )
    .await
    .unwrap();

    let result = engine
        .policy_create(permit_all("ghost-policy", 10), "attacker")
        .await;
    assert!(
        result.is_err(),
        "policy_create must surface audit failure as Err"
    );

    assert_eq!(
        engine.policy_count(),
        0,
        "policy must NOT persist when audit failed — audit is not optional, it is a gate"
    );
    assert!(
        engine.policy_get("ghost-policy").is_err(),
        "ghost-policy must not be retrievable after audit failure"
    );
}

// F-sentry-2: policy_delete commits the delete THEN audits. If audit
// fails, the policy is destroyed with no audit trail. Attacker who
// bricks Chronicle can silently delete policies.
#[tokio::test]
async fn debt_2_policy_delete_must_rollback_when_audit_fails() {
    let store = shroudb_storage::test_util::create_test_store("sentry-debt-2").await;

    // Seed with a recording chronicle so the create succeeds.
    let (rec, _) = recording_chronicle();
    let seeder = SentryEngine::new(
        store.clone(),
        SentryConfig::default(),
        Capability::Enabled(rec),
    )
    .await
    .unwrap();
    seeder
        .policy_create(permit_all("victim", 10), "admin")
        .await
        .unwrap();
    assert_eq!(seeder.policy_count(), 1);
    drop(seeder);

    // Re-open on the same store with a failing chronicle to attempt delete.
    let engine = SentryEngine::new(
        store,
        SentryConfig::default(),
        Capability::Enabled(failing_chronicle()),
    )
    .await
    .unwrap();
    assert_eq!(engine.policy_count(), 1, "setup precondition");

    let result = engine.policy_delete("victim", "attacker").await;
    assert!(
        result.is_err(),
        "policy_delete must surface audit failure as Err"
    );
    assert!(
        engine.policy_get("victim").is_ok(),
        "victim policy must still exist — policy destroyed without audit is a security regression"
    );
}

// F-sentry-3: default SentryConfig has require_audit=false. EVALUATE
// is fire-and-forget. Sentry is THE audit authority for authorization
// decisions — silent loss under capability failure is incompatible
// with fail-closed posture. The secure default is true.
#[test]
fn debt_3_sentry_config_default_require_audit_must_be_true() {
    let default = SentryConfig::default();
    assert!(
        default.require_audit,
        "SentryConfig::default().require_audit MUST be true — Sentry is \
         the audit authority for authorization decisions; silent loss on \
         capability failure is incompatible with fail-closed posture"
    );
}

// F-sentry-4: evaluate_request with a failing chronicle (default config)
// swallows the audit failure via tokio::spawn + tracing::warn. That means
// the very event Sentry exists to record is silently dropped when
// Chronicle is configured-but-unhealthy. Must fail-closed by default.
#[tokio::test]
async fn debt_4_evaluate_default_must_fail_closed_on_audit_error() {
    let store = shroudb_storage::test_util::create_test_store("sentry-debt-4").await;

    // Seed a permit-all policy.
    let (rec, _) = recording_chronicle();
    let seeder = SentryEngine::new(
        store.clone(),
        SentryConfig::default(),
        Capability::Enabled(rec),
    )
    .await
    .unwrap();
    seeder
        .policy_create(permit_all("all", 10), "admin")
        .await
        .unwrap();
    drop(seeder);

    // Evaluate with a failing chronicle under DEFAULT config.
    let engine = SentryEngine::new(
        store,
        SentryConfig::default(),
        Capability::Enabled(failing_chronicle()),
    )
    .await
    .unwrap();
    let result = engine
        .evaluate_request(&eval_request("alice", "doc-1", "read"))
        .await;
    assert!(
        result.is_err(),
        "evaluate_request MUST fail-closed on configured-but-failing \
         Chronicle — silent audit drop for authorization decisions is a \
         security regression"
    );
}

// F-sentry-5: `authorize_policy_mutation` bootstrap gate is
// `policies.count() == 0`. It re-opens every time the last policy is
// deleted. An attacker who observes (or forces) an empty state gets
// unconditional write access. The bootstrap gate must be a one-shot
// latch — once any policy has ever existed, bootstrap is permanently
// closed.
#[tokio::test]
async fn debt_5_bootstrap_gate_must_not_reopen_after_policy_delete() {
    let store = shroudb_storage::test_util::create_test_store("sentry-debt-5").await;
    let (rec, _) = recording_chronicle();
    let engine = SentryEngine::new(store, SentryConfig::default(), Capability::Enabled(rec))
        .await
        .unwrap();

    engine
        .policy_create(permit_all("admin-only", 100), "admin")
        .await
        .unwrap();
    assert_eq!(engine.policy_count(), 1);

    engine.policy_delete("admin-only", "admin").await.unwrap();
    assert_eq!(engine.policy_count(), 0);

    // Attacker exploits the reopened bootstrap gate.
    let result = engine
        .policy_create(permit_all("attacker-backdoor", 999), "attacker")
        .await;
    assert!(
        result.is_err(),
        "bootstrap gate must NOT reopen after policies are deleted — \
         attacker installed a permit-all policy with no authorization"
    );
}

// F-sentry-6: the server entrypoint hard-codes `chronicle: None` when
// constructing SentryEngine. Every production Sentry therefore runs
// without any audit trail, regardless of `require_audit` config. This
// is the capability-wiring bug class the audit exists to catch.
#[test]
fn debt_6_server_main_must_not_hardcode_chronicle_none() {
    let src = include_str!("../../shroudb-sentry-server/src/main.rs");
    let stripped: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !stripped.contains("SentryEngine::new(store, sentry_config, Capability::DisabledForTests)"),
        "shroudb-sentry-server/src/main.rs hard-codes `None` for the \
         Chronicle slot when constructing SentryEngine. The server MUST \
         wire a real ChronicleOps capability (config-driven, with a \
         logging stub as fallback) so policy mutations and evaluations \
         are audited. Today every production Sentry has no audit trail."
    );
}
