use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use shroudb_store::Store;

use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::policy::{Policy, validate_policy_name};

const POLICIES_NAMESPACE: &str = "sentry.policies";
const HISTORY_NAMESPACE: &str = "sentry.policy-history";

/// Manages authorization policies with an in-memory DashMap cache
/// backed by the Store for persistence.
///
/// A secondary sorted cache avoids re-sorting on every evaluation.
/// Mutations (create, update, delete) invalidate the sorted cache.
pub struct PolicyManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Policy>,
    /// Lazily populated sorted policy list. `None` means cache is stale.
    sorted: RwLock<Option<Arc<Vec<Policy>>>>,
}

impl<S: Store> PolicyManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
            sorted: RwLock::new(None),
        }
    }

    /// Initialize: create namespaces if absent, load all policies into cache.
    pub async fn init(&self) -> Result<(), SentryError> {
        let config = shroudb_store::NamespaceConfig::default();
        for ns in [POLICIES_NAMESPACE, HISTORY_NAMESPACE] {
            if let Err(e) = self.store.namespace_create(ns, config.clone()).await {
                let msg = e.to_string();
                if !msg.contains("already exists") {
                    return Err(SentryError::Store(msg));
                }
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
    pub async fn create(&self, mut policy: Policy) -> Result<Policy, SentryError> {
        validate_policy_name(&policy.name)?;

        if self.cache.contains_key(&policy.name) {
            return Err(SentryError::PolicyExists(policy.name.clone()));
        }

        policy.version = 1;
        self.save(&policy).await?;
        self.cache.insert(policy.name.clone(), policy.clone());
        self.invalidate_sorted();
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
        self.invalidate_sorted();
        Ok(())
    }

    /// Update an existing policy. The closure receives a mutable reference
    /// to the current policy and can modify it in place. The previous version
    /// is archived in the history namespace before the update is applied.
    pub async fn update<F>(&self, name: &str, f: F) -> Result<Policy, SentryError>
    where
        F: FnOnce(&mut Policy),
    {
        let mut policy = self.get(name)?;

        // Archive the current version before mutation
        self.archive_version(&policy).await?;

        f(&mut policy);
        policy.version += 1;
        self.save(&policy).await?;
        self.cache.insert(name.to_string(), policy.clone());
        self.invalidate_sorted();
        Ok(policy)
    }

    /// Get all policies, sorted by priority (highest first).
    ///
    /// Returns a shared reference to the cached sorted list. The list is
    /// recomputed only after mutations (create, update, delete) invalidate it.
    pub fn all_sorted(&self) -> Arc<Vec<Policy>> {
        // Fast path: read lock, check if cached
        {
            let guard = self.sorted.read().unwrap();
            if let Some(ref cached) = *guard {
                return Arc::clone(cached);
            }
        }

        // Slow path: recompute and cache
        let mut policies: Vec<Policy> = self.cache.iter().map(|r| r.value().clone()).collect();
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        let sorted = Arc::new(policies);

        let mut guard = self.sorted.write().unwrap();
        // Double-check in case another thread populated while we waited for write lock
        if guard.is_none() {
            *guard = Some(Arc::clone(&sorted));
        }
        guard.as_ref().map(Arc::clone).unwrap_or(sorted)
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

    /// Retrieve the version history of a policy.
    ///
    /// Returns all archived versions sorted by version number (ascending),
    /// plus the current live version as the last entry. Returns an error
    /// if the policy does not exist.
    pub async fn history(&self, name: &str) -> Result<Vec<Policy>, SentryError> {
        let current = self.get(name)?;

        let prefix = format!("{name}:");
        let mut versions = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let page = self
                .store
                .list(
                    HISTORY_NAMESPACE,
                    Some(prefix.as_bytes()),
                    cursor.as_deref(),
                    100,
                )
                .await
                .map_err(|e| SentryError::Store(e.to_string()))?;

            for key in &page.keys {
                match self.store.get(HISTORY_NAMESPACE, key, None).await {
                    Ok(entry) => {
                        if let Ok(policy) = serde_json::from_slice::<Policy>(&entry.value) {
                            versions.push(policy);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            key = %String::from_utf8_lossy(key),
                            error = %e,
                            "failed to load policy version"
                        );
                    }
                }
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        versions.sort_by_key(|p| p.version);
        versions.push(current);
        Ok(versions)
    }

    /// Archive a policy version to the history namespace.
    async fn archive_version(&self, policy: &Policy) -> Result<(), SentryError> {
        let key = format!("{}:{:010}", policy.name, policy.version);
        let data = serde_json::to_vec(policy).map_err(|e| SentryError::Internal(e.to_string()))?;
        self.store
            .put(HISTORY_NAMESPACE, key.as_bytes(), &data, None)
            .await
            .map_err(|e| SentryError::Store(e.to_string()))?;
        Ok(())
    }

    /// Invalidate the sorted policy cache. Called after any mutation.
    fn invalidate_sorted(&self) {
        let mut guard = self.sorted.write().unwrap();
        *guard = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_acl::PolicyEffect;
    use shroudb_sentry_core::matcher::*;

    fn make_policy(name: &str, priority: i32) -> Policy {
        Policy {
            name: name.into(),
            description: String::new(),
            effect: PolicyEffect::Permit,
            priority,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[tokio::test]
    async fn sorted_cache_populated_on_first_call() {
        let store = shroudb_storage::test_util::create_test_store("sentry-cache").await;
        let mgr = PolicyManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(make_policy("low", 10)).await.unwrap();
        mgr.create(make_policy("high", 100)).await.unwrap();
        mgr.create(make_policy("mid", 50)).await.unwrap();

        let sorted = mgr.all_sorted();
        assert_eq!(sorted.len(), 3);
        // Highest priority first
        assert_eq!(sorted[0].name, "high");
        assert_eq!(sorted[1].name, "mid");
        assert_eq!(sorted[2].name, "low");

        // Second call returns the same Arc (cached)
        let sorted2 = mgr.all_sorted();
        assert!(Arc::ptr_eq(&sorted, &sorted2), "should return cached Arc");
    }

    #[tokio::test]
    async fn mutation_invalidates_cache() {
        let store = shroudb_storage::test_util::create_test_store("sentry-cache-inv").await;
        let mgr = PolicyManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(make_policy("a", 10)).await.unwrap();
        let before = mgr.all_sorted();
        assert_eq!(before.len(), 1);

        // Create new policy invalidates cache
        mgr.create(make_policy("b", 20)).await.unwrap();
        let after = mgr.all_sorted();
        assert_eq!(after.len(), 2);
        assert!(
            !Arc::ptr_eq(&before, &after),
            "cache should be new after create"
        );

        // Update invalidates cache
        let cached = mgr.all_sorted();
        mgr.update("a", |p| p.priority = 100).await.unwrap();
        let after_update = mgr.all_sorted();
        assert!(
            !Arc::ptr_eq(&cached, &after_update),
            "cache should be new after update"
        );
        assert_eq!(
            after_update[0].name, "a",
            "a should be highest priority now"
        );

        // Delete invalidates cache
        let cached = mgr.all_sorted();
        mgr.delete("a").await.unwrap();
        let after_delete = mgr.all_sorted();
        assert!(
            !Arc::ptr_eq(&cached, &after_delete),
            "cache should be new after delete"
        );
        assert_eq!(after_delete.len(), 1);
    }
}
