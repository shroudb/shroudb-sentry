use std::time::{SystemTime, UNIX_EPOCH};

use crate::decision::{Decision, SignedDecision, SignedDecisionClaims};
use crate::error::SentryError;
use crate::evaluation::EvaluationRequest;
use crate::key_state::KeyState;

/// A single version of a signing key in the keyring.
pub struct SigningKeyVersion {
    pub version: u32,
    pub state: KeyState,
    pub algorithm: shroudb_crypto::JwtAlgorithm,
    pub private_key: Option<shroudb_crypto::SecretBytes>,
    pub public_key: Vec<u8>,
    pub kid: String,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    pub draining_since: Option<u64>,
    pub retired_at: Option<u64>,
}

/// A keyring that holds versioned signing keys for decision tokens.
pub struct SigningKeyring {
    pub name: String,
    pub algorithm: shroudb_crypto::JwtAlgorithm,
    pub rotation_days: u32,
    pub drain_days: u32,
    pub decision_ttl_secs: u64,
    pub key_versions: Vec<SigningKeyVersion>,
}

impl SigningKeyring {
    /// Get the active key version (the one currently used for signing).
    pub fn active_key(&self) -> Option<&SigningKeyVersion> {
        self.key_versions
            .iter()
            .find(|kv| kv.state == KeyState::Active)
    }

    /// Get a mutable reference to the active key version.
    pub fn active_key_mut(&mut self) -> Option<&mut SigningKeyVersion> {
        self.key_versions
            .iter_mut()
            .find(|kv| kv.state == KeyState::Active)
    }

    /// Compute the next version number.
    pub fn next_version(&self) -> u32 {
        self.key_versions
            .iter()
            .map(|kv| kv.version)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// Keys that can be used for verification (Active + Draining).
    pub fn verifiable_keys(&self) -> Vec<&SigningKeyVersion> {
        self.key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Active || kv.state == KeyState::Draining)
            .collect()
    }

    /// Sign a decision into a JWT token.
    pub fn sign_decision(
        &self,
        decision: &Decision,
        request: &EvaluationRequest,
        now: u64,
    ) -> Result<SignedDecision, SentryError> {
        let active = self.active_key().ok_or(SentryError::NoActiveKey)?;
        let private_key = active
            .private_key
            .as_ref()
            .ok_or(SentryError::NoActiveKey)?;

        let exp = now + self.decision_ttl_secs;

        let claims = SignedDecisionClaims {
            decision: decision.effect.to_string(),
            principal: request.principal.id.clone(),
            resource: request.resource.id.clone(),
            action: request.action.clone(),
            policy: decision.matched_policy.clone(),
            iat: now,
            exp,
        };

        let claims_json =
            serde_json::to_value(&claims).map_err(|e| SentryError::SigningError(e.to_string()))?;

        let token = shroudb_crypto::sign_jwt(
            private_key.as_bytes(),
            active.algorithm,
            &claims_json,
            &active.kid,
        )
        .map_err(|e| SentryError::SigningError(e.to_string()))?;

        Ok(SignedDecision {
            decision: decision.effect,
            token,
            matched_policy: decision.matched_policy.clone(),
            cache_until: exp,
        })
    }

    /// Build a JWKS response with all verifiable keys.
    pub fn jwks(&self) -> Result<serde_json::Value, SentryError> {
        let mut keys = Vec::new();
        for kv in self.verifiable_keys() {
            let jwk = shroudb_crypto::public_key_to_jwk(kv.algorithm, &kv.public_key, &kv.kid)
                .map_err(|e| SentryError::SigningError(e.to_string()))?;
            keys.push(jwk);
        }
        Ok(serde_json::json!({ "keys": keys }))
    }
}

/// Helper to get the current Unix timestamp.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation::{Principal, Resource};
    use crate::policy::Effect;
    use std::collections::HashMap;

    fn make_keyring() -> SigningKeyring {
        let kp = shroudb_crypto::generate_signing_key(shroudb_crypto::JwtAlgorithm::ES256).unwrap();
        SigningKeyring {
            name: "test-keyring".into(),
            algorithm: shroudb_crypto::JwtAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![SigningKeyVersion {
                version: 1,
                state: KeyState::Active,
                algorithm: shroudb_crypto::JwtAlgorithm::ES256,
                private_key: Some(kp.private_key_pkcs8),
                public_key: kp.public_key_der,
                kid: "test-kid-v1".into(),
                created_at: now_unix(),
                activated_at: Some(now_unix()),
                draining_since: None,
                retired_at: None,
            }],
        }
    }

    fn make_request() -> EvaluationRequest {
        EvaluationRequest {
            principal: Principal {
                id: "user-123".into(),
                roles: vec!["admin".into()],
                claims: HashMap::new(),
            },
            resource: Resource {
                id: "doc-456".into(),
                resource_type: "document".into(),
                attributes: HashMap::new(),
            },
            action: "read".into(),
        }
    }

    #[test]
    fn sign_decision_produces_valid_jwt() {
        let keyring = make_keyring();
        let decision = Decision {
            effect: Effect::Permit,
            matched_policy: Some("test-policy".into()),
        };
        let request = make_request();
        let now = now_unix();

        let signed = keyring.sign_decision(&decision, &request, now).unwrap();
        assert_eq!(signed.decision, Effect::Permit);
        assert!(!signed.token.is_empty());
        assert_eq!(signed.matched_policy.as_deref(), Some("test-policy"));
        assert_eq!(signed.cache_until, now + 300);

        // Verify the token.
        let active = keyring.active_key().unwrap();
        let claims =
            shroudb_crypto::verify_jwt(&active.public_key, active.algorithm, &signed.token, 0)
                .unwrap();
        assert_eq!(claims["decision"], "permit");
        assert_eq!(claims["principal"], "user-123");
        assert_eq!(claims["resource"], "doc-456");
        assert_eq!(claims["action"], "read");
        assert_eq!(claims["policy"], "test-policy");
    }

    #[test]
    fn sign_decision_deny() {
        let keyring = make_keyring();
        let decision = Decision {
            effect: Effect::Deny,
            matched_policy: None,
        };
        let request = make_request();
        let now = now_unix();

        let signed = keyring.sign_decision(&decision, &request, now).unwrap();
        assert_eq!(signed.decision, Effect::Deny);

        let active = keyring.active_key().unwrap();
        let claims =
            shroudb_crypto::verify_jwt(&active.public_key, active.algorithm, &signed.token, 0)
                .unwrap();
        assert_eq!(claims["decision"], "deny");
        assert!(claims["policy"].is_null());
    }

    #[test]
    fn sign_decision_no_active_key_fails() {
        let keyring = SigningKeyring {
            name: "empty".into(),
            algorithm: shroudb_crypto::JwtAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![],
        };
        let decision = Decision {
            effect: Effect::Permit,
            matched_policy: None,
        };
        let request = make_request();

        let result = keyring.sign_decision(&decision, &request, now_unix());
        assert!(result.is_err());
    }

    #[test]
    fn jwks_contains_verifiable_keys() {
        let kp1 =
            shroudb_crypto::generate_signing_key(shroudb_crypto::JwtAlgorithm::ES256).unwrap();
        let kp2 =
            shroudb_crypto::generate_signing_key(shroudb_crypto::JwtAlgorithm::ES256).unwrap();

        let keyring = SigningKeyring {
            name: "test".into(),
            algorithm: shroudb_crypto::JwtAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![
                SigningKeyVersion {
                    version: 1,
                    state: KeyState::Draining,
                    algorithm: shroudb_crypto::JwtAlgorithm::ES256,
                    private_key: Some(kp1.private_key_pkcs8),
                    public_key: kp1.public_key_der,
                    kid: "kid-v1".into(),
                    created_at: 0,
                    activated_at: Some(0),
                    draining_since: Some(100),
                    retired_at: None,
                },
                SigningKeyVersion {
                    version: 2,
                    state: KeyState::Active,
                    algorithm: shroudb_crypto::JwtAlgorithm::ES256,
                    private_key: Some(kp2.private_key_pkcs8),
                    public_key: kp2.public_key_der,
                    kid: "kid-v2".into(),
                    created_at: 100,
                    activated_at: Some(100),
                    draining_since: None,
                    retired_at: None,
                },
            ],
        };

        let jwks = keyring.jwks().unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn jwks_excludes_retired_keys() {
        let kp = shroudb_crypto::generate_signing_key(shroudb_crypto::JwtAlgorithm::ES256).unwrap();

        let keyring = SigningKeyring {
            name: "test".into(),
            algorithm: shroudb_crypto::JwtAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![SigningKeyVersion {
                version: 1,
                state: KeyState::Retired,
                algorithm: shroudb_crypto::JwtAlgorithm::ES256,
                private_key: None,
                public_key: kp.public_key_der,
                kid: "kid-v1".into(),
                created_at: 0,
                activated_at: Some(0),
                draining_since: Some(100),
                retired_at: Some(200),
            }],
        };

        let jwks = keyring.jwks().unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn next_version_starts_at_one() {
        let keyring = SigningKeyring {
            name: "empty".into(),
            algorithm: shroudb_crypto::JwtAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![],
        };
        assert_eq!(keyring.next_version(), 1);
    }

    #[test]
    fn next_version_increments() {
        let keyring = make_keyring();
        assert_eq!(keyring.next_version(), 2);
    }
}
