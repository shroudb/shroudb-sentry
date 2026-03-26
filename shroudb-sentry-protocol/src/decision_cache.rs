//! Decision cache: caches evaluation results to avoid repeated policy evaluation and signing.

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use shroudb_sentry_core::decision::SignedDecision;
use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::policy::Effect;

/// A cached evaluation result.
struct CachedEntry {
    decision: Effect,
    token: String,
    matched_policy: Option<String>,
    cache_until: u64,
}

/// Thread-safe decision cache backed by DashMap.
pub struct DecisionCache {
    entries: DashMap<u64, CachedEntry>,
    ttl_secs: u64,
}

impl DecisionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
            ttl_secs,
        }
    }

    /// Look up a cached decision for the given request.
    pub fn get(&self, request: &EvaluationRequest) -> Option<SignedDecision> {
        let key = cache_key(request);
        let entry = self.entries.get(&key)?;
        let now = now_secs();

        if now >= entry.cache_until {
            // Expired — remove and return None.
            drop(entry);
            self.entries.remove(&key);
            return None;
        }

        Some(SignedDecision {
            decision: entry.decision,
            token: entry.token.clone(),
            matched_policy: entry.matched_policy.clone(),
            cache_until: entry.cache_until,
        })
    }

    /// Store a decision in the cache.
    pub fn put(&self, request: &EvaluationRequest, decision: &SignedDecision) {
        let key = cache_key(request);
        let now = now_secs();
        let cache_until = now + self.ttl_secs;

        self.entries.insert(
            key,
            CachedEntry {
                decision: decision.decision,
                token: decision.token.clone(),
                matched_policy: decision.matched_policy.clone(),
                cache_until,
            },
        );
    }

    /// Invalidate all cached entries (e.g., on policy reload).
    pub fn invalidate_all(&self) {
        self.entries.clear();
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute a cache key from the evaluation request.
/// Uses a fast hash of (principal.id, resource.type, resource.id, action).
fn cache_key(request: &EvaluationRequest) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    request.principal.id.hash(&mut hasher);
    request.resource.resource_type.hash(&mut hasher);
    request.resource.id.hash(&mut hasher);
    request.action.hash(&mut hasher);
    hasher.finish()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_sentry_core::evaluation::{Principal, Resource};
    use std::collections::HashMap;

    fn make_request(principal_id: &str, action: &str) -> EvaluationRequest {
        EvaluationRequest {
            principal: Principal {
                id: principal_id.into(),
                roles: vec![],
                claims: HashMap::new(),
            },
            resource: Resource {
                id: "res-1".into(),
                resource_type: "doc".into(),
                attributes: HashMap::new(),
            },
            action: action.into(),
        }
    }

    fn make_signed_decision() -> SignedDecision {
        SignedDecision {
            decision: Effect::Permit,
            token: "eyJtest".into(),
            matched_policy: Some("test-policy".into()),
            cache_until: now_secs() + 300,
        }
    }

    #[test]
    fn put_and_get() {
        let cache = DecisionCache::new(60);
        let req = make_request("user1", "read");
        let decision = make_signed_decision();

        cache.put(&req, &decision);
        let cached = cache.get(&req).unwrap();
        assert_eq!(cached.decision, Effect::Permit);
        assert_eq!(cached.token, "eyJtest");
    }

    #[test]
    fn miss_on_different_request() {
        let cache = DecisionCache::new(60);
        let req1 = make_request("user1", "read");
        let req2 = make_request("user2", "read");
        let decision = make_signed_decision();

        cache.put(&req1, &decision);
        assert!(cache.get(&req2).is_none());
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let cache = DecisionCache::new(60);
        let req = make_request("user1", "read");
        let decision = make_signed_decision();

        cache.put(&req, &decision);
        assert_eq!(cache.len(), 1);

        cache.invalidate_all();
        assert!(cache.is_empty());
        assert!(cache.get(&req).is_none());
    }

    #[test]
    fn expired_entries_are_removed() {
        let cache = DecisionCache::new(0); // 0 TTL means immediate expiry
        let req = make_request("user1", "read");
        let decision = make_signed_decision();

        cache.put(&req, &decision);
        // The entry was stored with cache_until = now + 0, so it should expire immediately.
        assert!(cache.get(&req).is_none());
    }
}
