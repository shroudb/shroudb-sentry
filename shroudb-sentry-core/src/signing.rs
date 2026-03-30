use serde::{Deserialize, Serialize};

/// Supported JWT signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    ES256,
    ES384,
    EdDSA,
    RS256,
    RS384,
    RS512,
}

impl SigningAlgorithm {
    /// Wire-format name for this algorithm.
    pub fn wire_name(&self) -> &'static str {
        match self {
            SigningAlgorithm::ES256 => "ES256",
            SigningAlgorithm::ES384 => "ES384",
            SigningAlgorithm::EdDSA => "EdDSA",
            SigningAlgorithm::RS256 => "RS256",
            SigningAlgorithm::RS384 => "RS384",
            SigningAlgorithm::RS512 => "RS512",
        }
    }

    /// Convert to shroudb-crypto's JwtAlgorithm.
    pub fn to_jwt_algorithm(&self) -> shroudb_crypto::JwtAlgorithm {
        match self {
            SigningAlgorithm::ES256 => shroudb_crypto::JwtAlgorithm::ES256,
            SigningAlgorithm::ES384 => shroudb_crypto::JwtAlgorithm::ES384,
            SigningAlgorithm::EdDSA => shroudb_crypto::JwtAlgorithm::EdDSA,
            SigningAlgorithm::RS256 => shroudb_crypto::JwtAlgorithm::RS256,
            SigningAlgorithm::RS384 => shroudb_crypto::JwtAlgorithm::RS384,
            SigningAlgorithm::RS512 => shroudb_crypto::JwtAlgorithm::RS512,
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.wire_name())
    }
}

impl std::str::FromStr for SigningAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "ES256" => Ok(SigningAlgorithm::ES256),
            "ES384" => Ok(SigningAlgorithm::ES384),
            "EDDSA" | "ED25519" => Ok(SigningAlgorithm::EdDSA),
            "RS256" => Ok(SigningAlgorithm::RS256),
            "RS384" => Ok(SigningAlgorithm::RS384),
            "RS512" => Ok(SigningAlgorithm::RS512),
            _ => Err(format!(
                "unknown signing algorithm: {s} (expected ES256, ES384, EdDSA, RS256, RS384, RS512)"
            )),
        }
    }
}

/// Key lifecycle state machine: Staged → Active → Draining → Retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// Key has been generated but is not yet active.
    Staged,
    /// Key is currently used for signing new decisions.
    Active,
    /// Key is no longer signing but its public key remains in JWKS for verification.
    Draining,
    /// Key has been removed from JWKS. Material has been cleared.
    Retired,
}

impl KeyState {
    /// Validate a state transition.
    pub fn can_transition_to(&self, target: KeyState) -> bool {
        matches!(
            (self, target),
            (KeyState::Staged, KeyState::Active)
                | (KeyState::Active, KeyState::Draining)
                | (KeyState::Draining, KeyState::Retired)
        )
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Staged => write!(f, "staged"),
            KeyState::Active => write!(f, "active"),
            KeyState::Draining => write!(f, "draining"),
            KeyState::Retired => write!(f, "retired"),
        }
    }
}

/// A single version of a signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyVersion {
    /// Incrementing version number.
    pub version: u32,
    /// Current lifecycle state.
    pub state: KeyState,
    /// PKCS#8 DER private key, hex-encoded. Cleared on retire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// DER public key, hex-encoded.
    pub public_key: String,
    /// Key ID for JWT `kid` header.
    pub kid: String,
    /// Unix timestamp when this key version was created.
    pub created_at: u64,
    /// Unix timestamp when this key became active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<u64>,
    /// Unix timestamp when this key began draining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining_since: Option<u64>,
    /// Unix timestamp when this key was retired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
}

/// A signing keyring that manages versioned signing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyring {
    /// Keyring name (e.g., "default").
    pub name: String,
    /// Signing algorithm for all keys in this keyring.
    pub algorithm: SigningAlgorithm,
    /// Days before automatic key rotation.
    pub rotation_days: u32,
    /// Days a draining key stays in JWKS before retirement.
    pub drain_days: u32,
    /// Seconds before a signed decision JWT expires.
    pub decision_ttl_secs: u64,
    /// All key versions, ordered by version number.
    pub key_versions: Vec<SigningKeyVersion>,
    /// Unix timestamp when this keyring was created.
    pub created_at: u64,
}

impl SigningKeyring {
    /// Find the active key version.
    pub fn active_key(&self) -> Option<&SigningKeyVersion> {
        self.key_versions
            .iter()
            .find(|kv| kv.state == KeyState::Active)
    }

    /// Get the latest version number.
    pub fn latest_version(&self) -> u32 {
        self.key_versions
            .iter()
            .map(|kv| kv.version)
            .max()
            .unwrap_or(0)
    }

    /// Get all key versions whose public keys should appear in JWKS
    /// (Active + Draining states).
    pub fn jwks_keys(&self) -> Vec<&SigningKeyVersion> {
        self.key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Active || kv.state == KeyState::Draining)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_parse() {
        assert_eq!(
            "ES256".parse::<SigningAlgorithm>().unwrap(),
            SigningAlgorithm::ES256
        );
        assert_eq!(
            "eddsa".parse::<SigningAlgorithm>().unwrap(),
            SigningAlgorithm::EdDSA
        );
        assert_eq!(
            "ed25519".parse::<SigningAlgorithm>().unwrap(),
            SigningAlgorithm::EdDSA
        );
        assert!("invalid".parse::<SigningAlgorithm>().is_err());
    }

    #[test]
    fn key_state_transitions() {
        assert!(KeyState::Staged.can_transition_to(KeyState::Active));
        assert!(KeyState::Active.can_transition_to(KeyState::Draining));
        assert!(KeyState::Draining.can_transition_to(KeyState::Retired));

        assert!(!KeyState::Staged.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Active.can_transition_to(KeyState::Staged));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Active));
    }

    #[test]
    fn keyring_active_key() {
        let kr = SigningKeyring {
            name: "test".into(),
            algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![
                SigningKeyVersion {
                    version: 1,
                    state: KeyState::Draining,
                    private_key: None,
                    public_key: "abc".into(),
                    kid: "v1".into(),
                    created_at: 100,
                    activated_at: Some(100),
                    draining_since: Some(200),
                    retired_at: None,
                },
                SigningKeyVersion {
                    version: 2,
                    state: KeyState::Active,
                    private_key: Some("def".into()),
                    public_key: "ghi".into(),
                    kid: "v2".into(),
                    created_at: 200,
                    activated_at: Some(200),
                    draining_since: None,
                    retired_at: None,
                },
            ],
            created_at: 100,
        };

        let active = kr.active_key().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.kid, "v2");

        assert_eq!(kr.jwks_keys().len(), 2);
        assert_eq!(kr.latest_version(), 2);
    }

    #[test]
    fn keyring_no_active_key() {
        let kr = SigningKeyring {
            name: "test".into(),
            algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![SigningKeyVersion {
                version: 1,
                state: KeyState::Retired,
                private_key: None,
                public_key: "abc".into(),
                kid: "v1".into(),
                created_at: 100,
                activated_at: Some(100),
                draining_since: Some(200),
                retired_at: Some(300),
            }],
            created_at: 100,
        };
        assert!(kr.active_key().is_none());
    }

    #[test]
    fn keyring_empty_versions() {
        let kr = SigningKeyring {
            name: "test".into(),
            algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![],
            created_at: 100,
        };
        assert!(kr.active_key().is_none());
        assert_eq!(kr.latest_version(), 0);
        assert!(kr.jwks_keys().is_empty());
    }

    #[test]
    fn jwks_keys_excludes_staged_and_retired() {
        let kr = SigningKeyring {
            name: "test".into(),
            algorithm: SigningAlgorithm::ES256,
            rotation_days: 90,
            drain_days: 30,
            decision_ttl_secs: 300,
            key_versions: vec![
                SigningKeyVersion {
                    version: 1,
                    state: KeyState::Retired,
                    private_key: None,
                    public_key: "a".into(),
                    kid: "v1".into(),
                    created_at: 100,
                    activated_at: None,
                    draining_since: None,
                    retired_at: Some(300),
                },
                SigningKeyVersion {
                    version: 2,
                    state: KeyState::Draining,
                    private_key: None,
                    public_key: "b".into(),
                    kid: "v2".into(),
                    created_at: 200,
                    activated_at: Some(200),
                    draining_since: Some(300),
                    retired_at: None,
                },
                SigningKeyVersion {
                    version: 3,
                    state: KeyState::Active,
                    private_key: Some("c".into()),
                    public_key: "d".into(),
                    kid: "v3".into(),
                    created_at: 300,
                    activated_at: Some(300),
                    draining_since: None,
                    retired_at: None,
                },
                SigningKeyVersion {
                    version: 4,
                    state: KeyState::Staged,
                    private_key: Some("e".into()),
                    public_key: "f".into(),
                    kid: "v4".into(),
                    created_at: 400,
                    activated_at: None,
                    draining_since: None,
                    retired_at: None,
                },
            ],
            created_at: 100,
        };
        let jwks = kr.jwks_keys();
        assert_eq!(jwks.len(), 2);
        assert!(
            jwks.iter()
                .all(|k| k.state == KeyState::Active || k.state == KeyState::Draining)
        );
    }

    #[test]
    fn key_state_display() {
        assert_eq!(KeyState::Staged.to_string(), "staged");
        assert_eq!(KeyState::Active.to_string(), "active");
        assert_eq!(KeyState::Draining.to_string(), "draining");
        assert_eq!(KeyState::Retired.to_string(), "retired");
    }

    #[test]
    fn algorithm_wire_name_roundtrip() {
        for algo in [
            SigningAlgorithm::ES256,
            SigningAlgorithm::ES384,
            SigningAlgorithm::EdDSA,
            SigningAlgorithm::RS256,
            SigningAlgorithm::RS384,
            SigningAlgorithm::RS512,
        ] {
            let name = algo.wire_name();
            let parsed: SigningAlgorithm = name.parse().unwrap();
            assert_eq!(parsed, algo);
        }
    }

    #[test]
    fn key_state_no_self_transition() {
        assert!(!KeyState::Active.can_transition_to(KeyState::Active));
        assert!(!KeyState::Draining.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Retired));
    }

    #[test]
    fn key_state_no_backward_transition() {
        assert!(!KeyState::Draining.can_transition_to(KeyState::Active));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Staged));
    }
}
