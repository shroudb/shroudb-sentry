use std::sync::Arc;

use dashmap::DashMap;
use shroudb_store::Store;
use zeroize::Zeroize;

use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::signing::{KeyState, SigningAlgorithm, SigningKeyVersion, SigningKeyring};

const SIGNING_NAMESPACE: &str = "sentry.signing";

/// Manages signing keyrings with an in-memory DashMap cache
/// backed by the Store for persistence.
///
/// Keyrings are stored behind Arc to avoid cloning key material on every
/// cache lookup. Mutations clone-on-write via `Arc::unwrap_or_clone`.
pub struct SigningManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Arc<SigningKeyring>>,
}

impl<S: Store> SigningManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
        }
    }

    /// Initialize: create namespace if absent, load keyrings from store.
    pub async fn init(&self) -> Result<(), SentryError> {
        let config = shroudb_store::NamespaceConfig::default();
        if let Err(e) = self.store.namespace_create(SIGNING_NAMESPACE, config).await {
            let msg = e.to_string();
            if !msg.contains("already exists") {
                return Err(SentryError::Store(msg));
            }
        }

        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .store
                .list(SIGNING_NAMESPACE, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| SentryError::Store(e.to_string()))?;

            for key in &page.keys {
                let key_str = String::from_utf8_lossy(key).to_string();
                match self.store.get(SIGNING_NAMESPACE, key, None).await {
                    Ok(entry) => {
                        if let Ok(keyring) = serde_json::from_slice::<SigningKeyring>(&entry.value)
                        {
                            self.cache.insert(key_str, Arc::new(keyring));
                        } else {
                            tracing::warn!(key = %key_str, "failed to deserialize keyring");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(key = %key_str, error = %e, "failed to load keyring");
                    }
                }
            }

            cursor = page.cursor;
            if cursor.is_none() {
                break;
            }
        }

        tracing::info!(count = self.cache.len(), "signing keyrings loaded");
        Ok(())
    }

    /// Create a new signing keyring with an initial active key.
    pub async fn create(
        &self,
        name: &str,
        algorithm: SigningAlgorithm,
        rotation_days: u32,
        drain_days: u32,
        decision_ttl_secs: u64,
    ) -> Result<Arc<SigningKeyring>, SentryError> {
        if self.cache.contains_key(name) {
            return Err(SentryError::InvalidArgument(format!(
                "signing keyring already exists: {name}"
            )));
        }

        let now = unix_now();
        let key_version = generate_key_version(algorithm, 1, now)?;

        let keyring = SigningKeyring {
            name: name.to_string(),
            algorithm,
            rotation_days,
            drain_days,
            decision_ttl_secs,
            key_versions: vec![key_version],
            created_at: now,
        };

        self.save(&keyring).await?;
        let keyring = Arc::new(keyring);
        self.cache.insert(name.to_string(), keyring.clone());
        Ok(keyring)
    }

    /// Get a keyring by name (from cache). Returns Arc to avoid cloning key material.
    pub fn get(&self, name: &str) -> Result<Arc<SigningKeyring>, SentryError> {
        self.cache
            .get(name)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                SentryError::InvalidArgument(format!("signing keyring not found: {name}"))
            })
    }

    /// Update a keyring. The closure receives a mutable reference.
    /// Clone-on-write: the Arc is unwrapped for mutation, then re-wrapped.
    pub async fn update<F>(&self, name: &str, f: F) -> Result<Arc<SigningKeyring>, SentryError>
    where
        F: FnOnce(&mut SigningKeyring) -> Result<(), SentryError>,
    {
        let arc = self.get(name)?;
        let mut keyring = Arc::unwrap_or_clone(arc);
        f(&mut keyring)?;
        self.save(&keyring).await?;
        let keyring = Arc::new(keyring);
        self.cache.insert(name.to_string(), keyring.clone());
        Ok(keyring)
    }

    /// Rotate the signing key: demote active → draining, create new active key.
    pub async fn rotate(
        &self,
        name: &str,
        force: bool,
        dryrun: bool,
    ) -> Result<RotateResult, SentryError> {
        let keyring = self.get(name)?;
        let now = unix_now();

        let active = keyring.active_key().ok_or(SentryError::NoActiveKey)?;

        // Check if rotation is needed
        if !force && let Some(activated_at) = active.activated_at {
            let age_days = (now.saturating_sub(activated_at)) / 86400;
            if age_days < u64::from(keyring.rotation_days) {
                return Ok(RotateResult {
                    rotated: false,
                    key_version: active.version,
                    previous_version: None,
                });
            }
        }

        if dryrun {
            return Ok(RotateResult {
                rotated: true,
                key_version: keyring.latest_version() + 1,
                previous_version: Some(active.version),
            });
        }

        let new_version = keyring.latest_version() + 1;
        let previous_version = active.version;

        let updated = self
            .update(name, |kr| {
                // Demote active → draining (validated transition)
                for kv in &mut kr.key_versions {
                    if kv.state == KeyState::Active
                        && kv.state.can_transition_to(KeyState::Draining)
                    {
                        kv.state = KeyState::Draining;
                        kv.draining_since = Some(now);
                    }
                }
                // Create new active key
                let new_key = generate_key_version(kr.algorithm, new_version, now)?;
                kr.key_versions.push(new_key);
                Ok(())
            })
            .await?;

        tracing::info!(
            keyring = name,
            new_version = updated.latest_version(),
            "signing key rotated"
        );

        Ok(RotateResult {
            rotated: true,
            key_version: new_version,
            previous_version: Some(previous_version),
        })
    }

    /// Retire draining keys that have exceeded the drain period.
    pub async fn retire_expired(&self, name: &str) -> Result<Vec<u32>, SentryError> {
        let keyring = self.get(name)?;
        let now = unix_now();
        let drain_secs = u64::from(keyring.drain_days) * 86400;

        let to_retire: Vec<u32> = keyring
            .key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Draining)
            .filter(|kv| {
                kv.draining_since
                    .is_some_and(|ds| now.saturating_sub(ds) >= drain_secs)
            })
            .map(|kv| kv.version)
            .collect();

        if to_retire.is_empty() {
            return Ok(Vec::new());
        }

        self.update(name, |kr| {
            for kv in &mut kr.key_versions {
                if to_retire.contains(&kv.version) && kv.state.can_transition_to(KeyState::Retired)
                {
                    kv.state = KeyState::Retired;
                    kv.retired_at = Some(now);
                    // Clear private key material
                    if let Some(ref mut pk) = kv.private_key {
                        pk.zeroize();
                    }
                    kv.private_key = None;
                }
            }
            Ok(())
        })
        .await?;

        for v in &to_retire {
            tracing::info!(keyring = name, version = v, "signing key retired");
        }

        Ok(to_retire)
    }

    /// Seed a keyring if it doesn't already exist.
    pub async fn seed_if_absent(
        &self,
        name: &str,
        algorithm: SigningAlgorithm,
        rotation_days: u32,
        drain_days: u32,
        decision_ttl_secs: u64,
    ) -> Result<(), SentryError> {
        if self.cache.contains_key(name) {
            tracing::debug!(name = name, "signing keyring already exists, skipping seed");
            return Ok(());
        }
        self.create(
            name,
            algorithm,
            rotation_days,
            drain_days,
            decision_ttl_secs,
        )
        .await?;
        Ok(())
    }

    async fn save(&self, keyring: &SigningKeyring) -> Result<(), SentryError> {
        let data = serde_json::to_vec(keyring).map_err(|e| SentryError::Internal(e.to_string()))?;
        self.store
            .put(SIGNING_NAMESPACE, keyring.name.as_bytes(), &data, None)
            .await
            .map_err(|e| SentryError::Store(e.to_string()))?;
        Ok(())
    }
}

pub struct RotateResult {
    pub rotated: bool,
    pub key_version: u32,
    pub previous_version: Option<u32>,
}

fn generate_key_version(
    algorithm: SigningAlgorithm,
    version: u32,
    now: u64,
) -> Result<SigningKeyVersion, SentryError> {
    let jwt_algo = algorithm.to_jwt_algorithm();
    let generated = shroudb_crypto::generate_signing_key(jwt_algo)
        .map_err(|e| SentryError::SigningFailed(e.to_string()))?;

    let kid = format!("sentry-key-v{version}");
    let private_key_hex = hex::encode(generated.private_key_pkcs8.as_bytes());
    let public_key_hex = hex::encode(&generated.public_key_der);

    Ok(SigningKeyVersion {
        version,
        state: KeyState::Active,
        private_key: Some(private_key_hex),
        public_key: public_key_hex,
        kid,
        created_at: now,
        activated_at: Some(now),
        draining_since: None,
        retired_at: None,
    })
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

    #[tokio::test]
    async fn test_get_returns_arc_without_clone() {
        let store = shroudb_storage::test_util::create_test_store("sentry-signing-test").await;
        let mgr = SigningManager::new(store);
        mgr.init().await.unwrap();

        mgr.create("default", SigningAlgorithm::ES256, 90, 30, 300)
            .await
            .unwrap();

        // Two sequential gets should return Arcs pointing to the same allocation
        let a = mgr.get("default").unwrap();
        let b = mgr.get("default").unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "sequential gets must return the same Arc, not cloned copies"
        );
    }
}
