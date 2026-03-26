//! Thread-safe wrapper around SigningKeyring.

use std::sync::RwLock;

use shroudb_sentry_core::decision::{Decision, SignedDecision};
use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::signing::{SigningKeyring, now_unix};

/// Thread-safe signing key index.
pub struct SigningIndex {
    keyring: RwLock<SigningKeyring>,
}

impl SigningIndex {
    pub fn new(keyring: SigningKeyring) -> Self {
        Self {
            keyring: RwLock::new(keyring),
        }
    }

    /// Read access to the keyring.
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, SigningKeyring> {
        self.keyring.read().expect("signing keyring lock poisoned")
    }

    /// Write access to the keyring.
    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, SigningKeyring> {
        self.keyring.write().expect("signing keyring lock poisoned")
    }

    /// Sign a decision using the active key.
    pub fn sign_decision(
        &self,
        decision: &Decision,
        request: &EvaluationRequest,
    ) -> Result<SignedDecision, SentryError> {
        let keyring = self.read();
        keyring.sign_decision(decision, request, now_unix())
    }

    /// Build a JWKS response.
    pub fn jwks(&self) -> Result<serde_json::Value, SentryError> {
        let keyring = self.read();
        keyring.jwks()
    }
}
