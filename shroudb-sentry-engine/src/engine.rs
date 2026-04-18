use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use shroudb_acl::{
    AclError, PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest,
    PolicyResource,
};
use shroudb_chronicle_core::event::{Engine as AuditEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_server_bootstrap::Capability;
use shroudb_store::Store;

use shroudb_sentry_core::decision::SignedDecision;
use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::policy::Policy;
use shroudb_sentry_core::signing::SigningAlgorithm;

use crate::evaluator;
use crate::policy_manager::PolicyManager;
use crate::signing_manager::{RotateResult, SigningManager};

/// Configuration for the Sentry engine.
#[derive(Debug, Clone)]
pub struct SentryConfig {
    /// Default signing algorithm for new keyrings.
    pub signing_algorithm: SigningAlgorithm,
    /// Days before automatic key rotation.
    pub rotation_days: u32,
    /// Days a draining key stays in JWKS.
    pub drain_days: u32,
    /// Seconds before a signed decision JWT expires.
    pub decision_ttl_secs: u64,
    /// Interval in seconds for the background scheduler.
    pub scheduler_interval_secs: u64,
    /// When true, EVALUATE fails if the Chronicle audit event cannot be
    /// recorded. When false (default), audit is fire-and-forget.
    pub require_audit: bool,
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            signing_algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            scheduler_interval_secs: 3600,
            // Sentry is the audit authority for authorization decisions.
            // Silent audit loss on a configured-but-unhealthy Chronicle is
            // incompatible with fail-closed posture — default to requiring
            // audit so operators must explicitly opt out.
            require_audit: true,
        }
    }
}

/// Persistent sentinel namespace used to record that bootstrap has
/// completed. Once any entry exists in this namespace, the bootstrap
/// gate is permanently closed for this store — the gate does not
/// reopen when the last policy is deleted.
const BOOTSTRAP_NAMESPACE: &str = "sentry.meta";
const BOOTSTRAP_KEY: &[u8] = b"bootstrap-completed";

/// The Sentry authorization engine, generic over the Store implementation.
pub struct SentryEngine<S: Store> {
    store: Arc<S>,
    policies: PolicyManager<S>,
    signing: SigningManager<S>,
    chronicle: Capability<Arc<dyn ChronicleOps>>,
    require_audit: bool,
    /// One-shot latch: once any policy has ever been persisted in this
    /// store, bootstrap is permanently closed. Persisted as a sentinel
    /// key so restarts do not re-open the gate; mirrored in memory so
    /// the hot path is an atomic load.
    bootstrap_latched: AtomicBool,
}

impl<S: Store> SentryEngine<S> {
    /// Create and initialize a new Sentry engine.
    ///
    /// The `chronicle` capability is explicit: `Capability::Enabled(...)`,
    /// `Capability::DisabledForTests`, or `Capability::DisabledWithJustification`.
    /// Absence is never silent.
    pub async fn new(
        store: Arc<S>,
        config: SentryConfig,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Result<Self, SentryError> {
        let policies = PolicyManager::new(store.clone());
        let signing = SigningManager::new(store.clone());

        policies.init().await?;
        signing.init().await?;

        // Ensure a default signing keyring exists
        signing
            .seed_if_absent(
                "default",
                config.signing_algorithm,
                config.rotation_days,
                config.drain_days,
                config.decision_ttl_secs,
            )
            .await?;

        // Ensure the bootstrap-meta namespace exists, then read the latch
        // state. `policies.count() > 0` also latches: an upgraded engine
        // with pre-existing policies but no sentinel yet must still be
        // considered bootstrapped.
        let ns_cfg = shroudb_store::NamespaceConfig::default();
        if let Err(e) = store.namespace_create(BOOTSTRAP_NAMESPACE, ns_cfg).await {
            let msg = e.to_string();
            if !msg.contains("already exists") {
                return Err(SentryError::Store(msg));
            }
        }
        let latched_on_disk = store
            .get(BOOTSTRAP_NAMESPACE, BOOTSTRAP_KEY, None)
            .await
            .is_ok();
        let bootstrap_latched = AtomicBool::new(latched_on_disk || policies.count() > 0);

        Ok(Self {
            store,
            policies,
            signing,
            chronicle,
            require_audit: config.require_audit,
            bootstrap_latched,
        })
    }

    /// Persist and set the in-memory bootstrap latch. Idempotent — safe
    /// to call on every successful policy create.
    async fn latch_bootstrap(&self) -> Result<(), SentryError> {
        if self.bootstrap_latched.load(Ordering::Acquire) {
            return Ok(());
        }
        self.store
            .put(BOOTSTRAP_NAMESPACE, BOOTSTRAP_KEY, b"1", None)
            .await
            .map_err(|e| SentryError::Store(e.to_string()))?;
        self.bootstrap_latched.store(true, Ordering::Release);
        Ok(())
    }

    /// Emit an audit event to Chronicle. If chronicle is not configured, this
    /// is a no-op. If chronicle is configured but unreachable, returns an error
    /// so security-critical callers can fail closed.
    async fn emit_audit_event(
        &self,
        operation: &str,
        resource: &str,
        result: EventResult,
        actor: Option<&str>,
        start: Instant,
    ) -> Result<(), SentryError> {
        let Some(chronicle) = self.chronicle.as_ref() else {
            return Ok(());
        };
        let mut event = Event::new(
            AuditEngine::Sentry,
            operation.to_string(),
            "policy".to_string(),
            resource.to_string(),
            result,
            actor.unwrap_or("anonymous").to_string(),
        );
        event.duration_ms = start.elapsed().as_millis() as u64;
        chronicle
            .record(event)
            .await
            .map_err(|e| SentryError::Internal(format!("audit failed: {e}")))?;
        Ok(())
    }

    // --- Self-authorization ---

    /// Evaluate whether a policy mutation is permitted.
    ///
    /// Bootstrap rule: the first mutation on a virgin store is permitted
    /// unconditionally so the first policy can be created. Once ANY
    /// policy has ever existed, the bootstrap latch closes permanently —
    /// deleting all policies does not reopen the gate. Without this
    /// one-shot semantic, an attacker who reaches an empty state (by
    /// gaining delete rights or forcing a rollback) would get
    /// unconditional write access.
    ///
    /// After the latch closes, the request is evaluated against existing
    /// policies. If no policy explicitly permits the operation, the
    /// default-deny applies and the mutation is rejected.
    fn authorize_policy_mutation(
        &self,
        policy_name: &str,
        action: &str,
        actor: &str,
    ) -> Result<(), SentryError> {
        // Bootstrap is only open for a truly virgin store: no in-memory
        // policies AND no persisted latch from a prior incarnation.
        if !self.bootstrap_latched.load(Ordering::Acquire) && self.policies.count() == 0 {
            return Ok(());
        }

        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor.to_string(),
                roles: vec![],
                claims: std::collections::HashMap::from([("sub".to_string(), actor.to_string())]),
            },
            resource: PolicyResource {
                id: format!("sentry.policies.{policy_name}"),
                resource_type: "sentry.policies".to_string(),
                attributes: Default::default(),
            },
            action: action.to_string(),
        };

        let policies = self.policies.all_sorted();
        let decision = evaluator::evaluate_policies(&policies, &request);

        if decision.effect == PolicyEffect::Deny {
            return Err(SentryError::AccessDenied(format!(
                "{action} on sentry.policies.{policy_name} denied for {actor}{}",
                decision
                    .matched_policy
                    .map(|p| format!(" by policy '{p}'"))
                    .unwrap_or_default()
            )));
        }

        Ok(())
    }

    // --- Policy operations ---

    /// Create a new policy.
    ///
    /// Audit is a gate, not a footnote. If Chronicle is configured and the
    /// audit event cannot be recorded, the newly-created policy is rolled
    /// back (deleted from store and cache) before the error is returned so
    /// no mutation lands without a matching audit record.
    pub async fn policy_create(&self, policy: Policy, actor: &str) -> Result<Policy, SentryError> {
        let start = Instant::now();
        let name = policy.name.clone();
        self.authorize_policy_mutation(&name, "create", actor)?;
        let result = self.policies.create(policy).await?;
        // Latch the bootstrap gate the first time a policy lands. This
        // persists to disk so a restart on an empty store (because every
        // policy was later deleted) does not re-open the gate.
        if let Err(latch_err) = self.latch_bootstrap().await {
            // Latching failed — roll back the create so the store never
            // contains a policy without a matching closed-latch.
            if let Err(rollback_err) = self.policies.delete(&name).await {
                return Err(SentryError::Internal(format!(
                    "bootstrap latch failed ({latch_err}) and rollback \
                     of policy '{name}' also failed ({rollback_err})"
                )));
            }
            return Err(latch_err);
        }
        if let Err(audit_err) = self
            .emit_audit_event("POLICY_CREATE", &name, EventResult::Ok, Some(actor), start)
            .await
        {
            // Compensating rollback: audit failed, so the mutation must not
            // remain durable. If the rollback itself fails we surface that
            // too — a half-committed state is the worst outcome. The
            // bootstrap latch stays closed: a policy did exist, and the
            // operator must re-authorize the next create through the
            // normal ABAC path.
            if let Err(rollback_err) = self.policies.delete(&name).await {
                return Err(SentryError::Internal(format!(
                    "audit failed ({audit_err}) and rollback of policy \
                     '{name}' also failed ({rollback_err})"
                )));
            }
            return Err(audit_err);
        }
        Ok(result)
    }

    /// Get a policy by name.
    pub fn policy_get(&self, name: &str) -> Result<Policy, SentryError> {
        self.policies.get(name)
    }

    /// List all policy names.
    pub fn policy_list(&self) -> Vec<String> {
        self.policies.list()
    }

    /// Delete a policy.
    ///
    /// Audit is a gate, not a footnote. If Chronicle is configured and the
    /// audit event cannot be recorded, the deleted policy is restored
    /// before the error is returned so no mutation lands without a
    /// matching audit record.
    pub async fn policy_delete(&self, name: &str, actor: &str) -> Result<(), SentryError> {
        let start = Instant::now();
        self.authorize_policy_mutation(name, "delete", actor)?;
        // Snapshot the policy before deletion so we can restore it if the
        // audit event fails to record.
        let snapshot = self.policies.get(name)?;
        self.policies.delete(name).await?;
        if let Err(audit_err) = self
            .emit_audit_event("POLICY_DELETE", name, EventResult::Ok, Some(actor), start)
            .await
        {
            // Compensating restore. `restore_version` preserves the
            // pre-delete version so history stays consistent; if the
            // restore itself fails, surface the full story.
            if let Err(restore_err) = self.policies.restore_version(snapshot).await {
                return Err(SentryError::Internal(format!(
                    "audit failed ({audit_err}) and restore of policy \
                     '{name}' also failed ({restore_err})"
                )));
            }
            return Err(audit_err);
        }
        Ok(())
    }

    /// Update a policy.
    pub async fn policy_update(
        &self,
        name: &str,
        updates: Policy,
        actor: &str,
    ) -> Result<Policy, SentryError> {
        let start = Instant::now();
        self.authorize_policy_mutation(name, "update", actor)?;
        let now = unix_now();
        let result = self
            .policies
            .update(name, |p| {
                p.description = updates.description;
                p.effect = updates.effect;
                p.priority = updates.priority;
                p.principal = updates.principal;
                p.resource = updates.resource;
                p.action = updates.action;
                p.conditions = updates.conditions;
                p.updated_at = now;
            })
            .await?;
        self.emit_audit_event("POLICY_UPDATE", name, EventResult::Ok, Some(actor), start)
            .await?;
        Ok(result)
    }

    /// Retrieve the version history of a policy (all past versions + current).
    pub async fn policy_history(&self, name: &str) -> Result<Vec<Policy>, SentryError> {
        self.policies.history(name).await
    }

    /// Number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.count()
    }

    // --- Evaluation ---

    /// Evaluate an authorization request against all policies and return
    /// a cryptographically signed decision.
    ///
    /// When `require_audit` is true and Chronicle is configured, the audit
    /// event is recorded synchronously and failure causes the evaluation to
    /// return an error. When `require_audit` is false (the default), audit
    /// is fire-and-forget.
    pub async fn evaluate_request(
        &self,
        request: &PolicyRequest,
    ) -> Result<SignedDecision, SentryError> {
        let start = Instant::now();
        let policies = self.policies.all_sorted();
        let decision = evaluator::evaluate_policies(&policies, request);
        let keyring = self.signing.get("default")?;
        let signed = evaluator::sign_decision(&decision, request, &keyring)?;

        if let Some(chronicle) = self.chronicle.as_ref() {
            let resource = request.resource.id.clone();
            let actor = request.principal.id.clone();
            let duration_ms = start.elapsed().as_millis() as u64;

            // Record synchronously in-task. The previous fire-and-forget
            // `tokio::spawn` dropped the JoinHandle, so the task could be
            // cancelled on runtime shutdown and its error was unobservable
            // to the caller. Recording in-task means `require_audit` is the
            // only knob: on failure we either surface the error (fail-closed)
            // or log and continue, but the audit attempt is always awaited.
            let mut event = Event::new(
                AuditEngine::Sentry,
                "EVALUATE".to_string(),
                "resource".to_string(),
                resource.clone(),
                EventResult::Ok,
                actor,
            );
            event.duration_ms = duration_ms;
            if let Err(e) = chronicle.record(event).await {
                if self.require_audit {
                    return Err(SentryError::Internal(format!("required audit failed: {e}")));
                }
                tracing::warn!(resource, error = %e, "failed to emit audit event");
            }
        } else if self.require_audit {
            return Err(SentryError::Internal(
                "require_audit is true but no Chronicle is configured".into(),
            ));
        }

        Ok(signed)
    }

    // --- Signing key operations ---

    /// Rotate the signing key.
    pub async fn key_rotate(&self, force: bool, dryrun: bool) -> Result<RotateResult, SentryError> {
        let start = Instant::now();
        let result = self.signing.rotate("default", force, dryrun).await?;
        if result.rotated && !dryrun {
            self.emit_audit_event("KEY_ROTATE", "default", EventResult::Ok, None, start)
                .await?;
        }
        Ok(result)
    }

    /// Get signing key info.
    pub fn key_info(&self) -> Result<serde_json::Value, SentryError> {
        let keyring = self.signing.get("default")?;
        let active = keyring.active_key();
        Ok(serde_json::json!({
            "algorithm": keyring.algorithm.wire_name(),
            "rotation_days": keyring.rotation_days,
            "drain_days": keyring.drain_days,
            "decision_ttl_secs": keyring.decision_ttl_secs,
            "active_version": active.map(|k| k.version),
            "active_kid": active.map(|k| k.kid.as_str()),
            "total_versions": keyring.key_versions.len(),
            "jwks_keys": keyring.jwks_keys().len(),
        }))
    }

    /// Build the JWKS (JSON Web Key Set) for the default keyring.
    pub fn jwks(&self) -> Result<serde_json::Value, SentryError> {
        let keyring = self.signing.get("default")?;
        evaluator::build_jwks(&keyring)
    }

    /// Access the signing manager (for scheduler).
    pub fn signing_manager(&self) -> &SigningManager<S> {
        &self.signing
    }

    /// Seed a policy if it doesn't already exist (for config-based seeding).
    /// Closes the bootstrap latch: a seeded policy is still a policy, and
    /// the gate must not reopen if the operator later deletes it.
    pub async fn seed_policy(&self, policy: Policy) -> Result<(), SentryError> {
        self.policies.seed_if_absent(policy).await?;
        self.latch_bootstrap().await?;
        Ok(())
    }
}

impl<S: Store> PolicyEvaluator for SentryEngine<S> {
    fn evaluate(
        &self,
        request: &PolicyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, AclError>> + Send + '_>> {
        let request = request.clone();
        Box::pin(async move {
            self.evaluate_request(&request)
                .await
                .map(|signed| PolicyDecision {
                    effect: signed.decision,
                    matched_policy: signed.matched_policy,
                    token: Some(signed.token),
                    cache_until: Some(signed.cache_until),
                })
                .map_err(|e| AclError::Internal(format!("sentry evaluation failed: {e}")))
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_sentry_core::matcher::*;

    async fn setup() -> SentryEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("sentry-test").await;
        // Chronicle is DisabledForTests, so require_audit must also be
        // off — otherwise the two settings are contradictory and every
        // evaluation would fail closed before reaching the behavior
        // under test.
        let cfg = SentryConfig {
            require_audit: false,
            ..SentryConfig::default()
        };
        SentryEngine::new(store, cfg, Capability::DisabledForTests)
            .await
            .unwrap()
    }

    fn make_request(principal_id: &str, resource_type: &str, action: &str) -> PolicyRequest {
        PolicyRequest {
            principal: PolicyPrincipal {
                id: principal_id.into(),
                roles: vec![],
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: "res-1".into(),
                resource_type: resource_type.into(),
                attributes: Default::default(),
            },
            action: action.into(),
        }
    }

    #[tokio::test]
    async fn concurrent_evaluate_during_policy_update() {
        let engine = Arc::new(setup().await);

        // Create a permit-all policy
        let permit_all = Policy {
            name: "allow-all".into(),
            description: "permit everything".into(),
            effect: PolicyEffect::Permit,
            priority: 10,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        engine.policy_create(permit_all, "admin").await.unwrap();

        let mut handles = Vec::new();

        // Spawn 10 tasks that each evaluate the policy 5 times
        for _ in 0..10u32 {
            let eng = Arc::clone(&engine);
            handles.push(tokio::spawn(async move {
                let mut decisions = Vec::new();
                for _ in 0..5u32 {
                    let req = make_request("alice", "doc", "read");
                    let result = eng.evaluate_request(&req).await.unwrap();
                    decisions.push(result.decision);
                }
                decisions
            }));
        }

        // Update the policy while evaluations are in flight: change effect to Deny
        let deny_all = Policy {
            name: "allow-all".into(),
            description: "now denies everything".into(),
            effect: PolicyEffect::Deny,
            priority: 10,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        engine
            .policy_update("allow-all", deny_all, "admin")
            .await
            .unwrap();

        // Collect all results — no task should have panicked
        let mut all_decisions = Vec::new();
        for handle in handles {
            let decisions = handle.await.unwrap();
            all_decisions.extend(decisions);
        }

        assert_eq!(all_decisions.len(), 50);

        // Every decision must be either Permit (old policy) or Deny (updated policy).
        // No corrupted/partial state.
        for decision in &all_decisions {
            assert!(
                *decision == PolicyEffect::Permit || *decision == PolicyEffect::Deny,
                "unexpected decision: {decision:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_corrupt_policy_data_handled() {
        let store = shroudb_storage::test_util::create_test_store("sentry-test").await;

        // Create the namespace manually and write invalid JSON bytes
        store
            .namespace_create("sentry.policies", shroudb_store::NamespaceConfig::default())
            .await
            .unwrap();
        store
            .put(
                "sentry.policies",
                b"corrupt-policy",
                b"not valid json {{{",
                None,
            )
            .await
            .unwrap();

        // SentryEngine::new calls policies.init() which should skip the corrupt
        // entry with a warning rather than panic. The engine should initialize
        // successfully with zero policies loaded.
        let engine =
            SentryEngine::new(store, SentryConfig::default(), Capability::DisabledForTests)
                .await
                .unwrap();

        // The corrupt entry should have been skipped, not loaded
        assert_eq!(engine.policy_count(), 0, "corrupt policy should be skipped");
        assert!(
            engine.policy_list().is_empty(),
            "no policies should be loaded from corrupt data"
        );
    }

    #[tokio::test]
    async fn test_self_authorization_permits_when_no_policies() {
        let engine = setup().await;

        // With an empty policy store, bootstrap allows any actor to create
        assert_eq!(engine.policy_count(), 0);

        let policy = Policy {
            name: "first-policy".into(),
            description: "bootstrap policy".into(),
            effect: PolicyEffect::Permit,
            priority: 100,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };

        let result = engine.policy_create(policy, "any-actor").await;
        assert!(
            result.is_ok(),
            "bootstrap create should succeed: {result:?}"
        );
        assert_eq!(engine.policy_count(), 1);
    }

    #[tokio::test]
    async fn test_self_authorization_denies_unauthorized_mutation() {
        let engine = setup().await;

        // Bootstrap: create a permit-all policy so we can create more policies
        let permit_all = Policy {
            name: "permit-all".into(),
            description: "allow everything during setup".into(),
            effect: PolicyEffect::Permit,
            priority: 1,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        engine.policy_create(permit_all, "admin").await.unwrap();

        // Create a higher-priority deny policy targeting "evil-actor" on
        // sentry.policies resources
        let deny_evil = Policy {
            name: "deny-evil-policy-mutations".into(),
            description: "block evil-actor from policy mutations".into(),
            effect: PolicyEffect::Deny,
            priority: 100,
            principal: PrincipalMatcher {
                roles: vec![],
                claims: std::collections::HashMap::from([(
                    "sub".to_string(),
                    "evil-actor".to_string(),
                )]),
            },
            resource: ResourceMatcher {
                resource_type: "sentry.policies".into(),
                ..Default::default()
            },
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        engine.policy_create(deny_evil, "admin").await.unwrap();

        // evil-actor tries to create a policy -- should be denied
        let new_policy = Policy {
            name: "evil-policy".into(),
            description: "should not be created".into(),
            effect: PolicyEffect::Permit,
            priority: 999,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        let result = engine.policy_create(new_policy, "evil-actor").await;
        assert!(result.is_err(), "evil-actor should be denied");
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentryError::AccessDenied(_)),
            "expected AccessDenied, got: {err:?}"
        );

        // admin can still create policies (permit-all matches, deny only
        // targets claims sub=evil-actor)
        let admin_policy = Policy {
            name: "admin-policy".into(),
            description: "admin can do this".into(),
            effect: PolicyEffect::Permit,
            priority: 1,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        let result = engine.policy_create(admin_policy, "admin").await;
        assert!(result.is_ok(), "admin should be permitted: {result:?}");
    }
}
