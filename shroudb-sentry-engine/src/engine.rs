use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclError, PolicyDecision, PolicyEvaluator, PolicyRequest};
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
    config: SentryConfig,
}

impl<S: Store> SentryEngine<S> {
    /// Create and initialize a new Sentry engine.
    pub async fn new(store: Arc<S>, config: SentryConfig) -> Result<Self, SentryError> {
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
            config,
        })
    }

    // --- Policy operations ---

    /// Create a new policy.
    pub async fn policy_create(&self, policy: Policy) -> Result<Policy, SentryError> {
        self.policies.create(policy).await
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
    pub async fn policy_delete(&self, name: &str) -> Result<(), SentryError> {
        self.policies.delete(name).await
    }

    /// Update a policy.
    pub async fn policy_update(&self, name: &str, updates: Policy) -> Result<Policy, SentryError> {
        let now = unix_now();
        self.policies
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
            .await
    }

    /// Number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.count()
    }

    // --- Evaluation ---

    /// Evaluate an authorization request against all policies and return
    /// a cryptographically signed decision.
    pub fn evaluate_request(&self, request: &PolicyRequest) -> Result<SignedDecision, SentryError> {
        let policies = self.policies.all_sorted();
        let decision = evaluator::evaluate_policies(&policies, request);
        let keyring = self.signing.get("default")?;
        evaluator::sign_decision(&decision, request, &keyring)
    }

    // --- Signing key operations ---

    /// Rotate the signing key.
    pub async fn key_rotate(&self, force: bool, dryrun: bool) -> Result<RotateResult, SentryError> {
        self.signing.rotate("default", force, dryrun).await
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

    /// Access the engine config.
    pub fn config(&self) -> &SentryConfig {
        &self.config
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
