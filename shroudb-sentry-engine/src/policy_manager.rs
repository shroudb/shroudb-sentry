use std::sync::Arc;

use dashmap::DashMap;
use shroudb_store::Store;

use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::policy::{Policy, validate_policy_name};

const POLICIES_NAMESPACE: &str = "sentry.policies";

/// Manages authorization policies with an in-memory DashMap cache
/// backed by the Store for persistence.
pub struct PolicyManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Policy>,
}

impl<S: Store> PolicyManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
        }
    }

    /// Initialize: create namespace if absent, load all policies into cache.
    pub async fn init(&self) -> Result<(), SentryError> {
        let config = shroudb_store::NamespaceConfig::default();
        if let Err(e) = self
            .store
            .namespace_create(POLICIES_NAMESPACE, config)
            .await
        {
            let msg = e.to_string();
            if !msg.contains("already exists") {
                return Err(SentryError::Store(msg));
            }
        }

        // Load all policies from store into cache
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(POLICIES_NAMESPACE, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| SentryError::Store(e.to_string()))?;

            for key in &page.keys {
                let key_str = String::from_utf8_lossy(key).to_string();
                match self.store.get(POLICIES_NAMESPACE, key, None).await {
                    Ok(entry) => {
                        if let Ok(policy) = serde_json::from_slice::<Policy>(&entry.value) {
                            self.cache.insert(key_str, policy);
                        } else {
                            tracing::warn!(key = %key_str, "failed to deserialize policy, skipping");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(key = %key_str, error = %e, "failed to load policy");
                    }
                }
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        tracing::info!(count = self.cache.len(), "policies loaded");
        Ok(())
    }

    /// Create a new policy.
    pub async fn create(&self, policy: Policy) -> Result<Policy, SentryError> {
        validate_policy_name(&policy.name)?;

        if self.cache.contains_key(&policy.name) {
            return Err(SentryError::PolicyExists(policy.name.clone()));
        }

        self.save(&policy).await?;
        self.cache.insert(policy.name.clone(), policy.clone());
        Ok(policy)
    }

    /// Get a policy by name (from cache).
    pub fn get(&self, name: &str) -> Result<Policy, SentryError> {
        self.cache
            .get(name)
            .map(|r| r.value().clone())
            .ok_or_else(|| SentryError::PolicyNotFound(name.into()))
    }

    /// List all policy names.
    pub fn list(&self) -> Vec<String> {
        self.cache.iter().map(|r| r.key().clone()).collect()
    }

    /// Delete a policy.
    pub async fn delete(&self, name: &str) -> Result<(), SentryError> {
        if !self.cache.contains_key(name) {
            return Err(SentryError::PolicyNotFound(name.into()));
        }

        self.store
            .delete(POLICIES_NAMESPACE, name.as_bytes())
            .await
            .map_err(|e| SentryError::Store(e.to_string()))?;

        self.cache.remove(name);
        Ok(())
    }

    /// Update an existing policy. The closure receives a mutable reference
    /// to the current policy and can modify it in place.
    pub async fn update<F>(&self, name: &str, f: F) -> Result<Policy, SentryError>
    where
        F: FnOnce(&mut Policy),
    {
        let mut policy = self.get(name)?;
        f(&mut policy);
        self.save(&policy).await?;
        self.cache.insert(name.to_string(), policy.clone());
        Ok(policy)
    }

    /// Get all policies, sorted by priority (highest first).
    pub fn all_sorted(&self) -> Vec<Policy> {
        let mut policies: Vec<Policy> = self.cache.iter().map(|r| r.value().clone()).collect();
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        policies
    }

    /// Number of loaded policies.
    pub fn count(&self) -> usize {
        self.cache.len()
    }

    /// Seed a policy if it doesn't already exist.
    pub async fn seed_if_absent(&self, policy: Policy) -> Result<(), SentryError> {
        if self.cache.contains_key(&policy.name) {
            tracing::debug!(name = %policy.name, "policy already exists, skipping seed");
            return Ok(());
        }
        self.create(policy).await?;
        Ok(())
    }

    async fn save(&self, policy: &Policy) -> Result<(), SentryError> {
        let data = serde_json::to_vec(policy).map_err(|e| SentryError::Internal(e.to_string()))?;
        self.store
            .put(POLICIES_NAMESPACE, policy.name.as_bytes(), &data, None)
            .await
            .map_err(|e| SentryError::Store(e.to_string()))?;
        Ok(())
    }
}
