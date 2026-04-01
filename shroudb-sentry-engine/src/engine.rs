use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use shroudb_acl::{
    AclError, PolicyDecision, PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest,
    PolicyResource,
};
use shroudb_chronicle_core::event::{Engine as AuditEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
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
}

impl Default for SentryConfig {
    fn default() -> Self {
        Self {
            signing_algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            scheduler_interval_secs: 3600,
        }
    }
}

/// The Sentry authorization engine, generic over the Store implementation.
pub struct SentryEngine<S: Store> {
    policies: PolicyManager<S>,
    signing: SigningManager<S>,
    chronicle: Option<Arc<dyn ChronicleOps>>,
}

impl<S: Store> SentryEngine<S> {
    /// Create and initialize a new Sentry engine.
    pub async fn new(
        store: Arc<S>,
        config: SentryConfig,
        chronicle: Option<Arc<dyn ChronicleOps>>,
    ) -> Result<Self, SentryError> {
        let policies = PolicyManager::new(store.clone());
        let signing = SigningManager::new(store);

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

        Ok(Self {
            policies,
            signing,
            chronicle,
        })
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
        let Some(chronicle) = &self.chronicle else {
            return Ok(());
        };
        let mut event = Event::new(
            AuditEngine::Sentry,
            operation.to_string(),
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
    /// Bootstrap rule: if no policies exist yet, the operation is permitted
    /// unconditionally so the first policy can be created.
    ///
    /// Once policies exist, the request is evaluated against them. If no
    /// policy explicitly permits the operation, the default-deny applies
    /// and the mutation is rejected.
    fn authorize_policy_mutation(
        &self,
        policy_name: &str,
        action: &str,
        actor: &str,
    ) -> Result<(), SentryError> {
        if self.policies.count() == 0 {
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
    pub async fn policy_create(&self, policy: Policy, actor: &str) -> Result<Policy, SentryError> {
        let start = Instant::now();
        let name = policy.name.clone();
        self.authorize_policy_mutation(&name, "create", actor)?;
        let result = self.policies.create(policy).await?;
        self.emit_audit_event("POLICY_CREATE", &name, EventResult::Ok, Some(actor), start)
            .await?;
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
    pub async fn policy_delete(&self, name: &str, actor: &str) -> Result<(), SentryError> {
        let start = Instant::now();
        self.authorize_policy_mutation(name, "delete", actor)?;
        self.policies.delete(name).await?;
        self.emit_audit_event("POLICY_DELETE", name, EventResult::Ok, Some(actor), start)
            .await?;
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

    /// Number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.count()
    }

    // --- Evaluation ---

    /// Evaluate an authorization request against all policies and return
    /// a cryptographically signed decision.
    pub fn evaluate_request(&self, request: &PolicyRequest) -> Result<SignedDecision, SentryError> {
        let start = Instant::now();
        let policies = self.policies.all_sorted();
        let decision = evaluator::evaluate_policies(&policies, request);
        let keyring = self.signing.get("default")?;
        let signed = evaluator::sign_decision(&decision, request, &keyring)?;

        // Fire-and-forget audit — evaluate_request is sync so we spawn.
        if let Some(chronicle) = self.chronicle.clone() {
            let resource = request.resource.id.clone();
            let actor = request.principal.id.clone();
            let duration_ms = start.elapsed().as_millis() as u64;
            tokio::spawn(async move {
                let mut event = Event::new(
                    AuditEngine::Sentry,
                    "EVALUATE".to_string(),
                    resource.clone(),
                    EventResult::Ok,
                    actor,
                );
                event.duration_ms = duration_ms;
                if let Err(e) = chronicle.record(event).await {
                    tracing::warn!(resource, error = %e, "failed to emit audit event");
                }
            });
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
    pub async fn seed_policy(&self, policy: Policy) -> Result<(), SentryError> {
        self.policies.seed_if_absent(policy).await
    }
}

impl<S: Store> PolicyEvaluator for SentryEngine<S> {
    fn evaluate(
        &self,
        request: &PolicyRequest,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, AclError>> + Send + '_>> {
        // evaluate_request is synchronous — compute eagerly, wrap result in ready future.
        let result = self
            .evaluate_request(request)
            .map(|signed| PolicyDecision {
                effect: signed.decision,
                matched_policy: signed.matched_policy,
                token: Some(signed.token),
                cache_until: Some(signed.cache_until),
            })
            .map_err(|e| AclError::Internal(format!("sentry evaluation failed: {e}")));
        Box::pin(std::future::ready(result))
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
        SentryEngine::new(store, SentryConfig::default(), None)
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
                    let result = eng.evaluate_request(&req).unwrap();
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
        let engine = SentryEngine::new(store, SentryConfig::default(), None)
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
            created_at: 0,
            updated_at: 0,
        };
        let result = engine.policy_create(admin_policy, "admin").await;
        assert!(result.is_ok(), "admin should be permitted: {result:?}");
    }
}
