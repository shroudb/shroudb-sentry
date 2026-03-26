//! Thread-safe wrapper around SigningKeyring.

use std::sync::RwLock;

use shroudb_sentry_core::decision::{Decision, SignedDecision};
use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::signing::{SigningKeyring, SigningMode, now_unix};

/// Thread-safe signing key index.
pub struct SigningIndex {
    keyring: RwLock<SigningKeyring>,
    mode: SigningMode,
}

impl SigningIndex {
    pub fn new(keyring: SigningKeyring, mode: SigningMode) -> Self {
        Self {
            keyring: RwLock::new(keyring),
            mode,
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

    /// The signing mode (JWT or HMAC).
    pub fn mode(&self) -> SigningMode {
        self.mode
    }

    /// Sign a decision using the active key.
    pub fn sign_decision(
        &self,
        decision: &Decision,
        request: &EvaluationRequest,
    ) -> Result<SignedDecision, SentryError> {
        let keyring = self.read();
        match self.mode {
            SigningMode::Hmac => keyring.sign_decision_hmac(decision, request, now_unix()),
            SigningMode::Jwt => keyring.sign_decision(decision, request, now_unix()),
        }
    }

    /// Build a JWKS response.
    pub fn jwks(&self) -> Result<serde_json::Value, SentryError> {
        let keyring = self.read();
        match self.mode {
            SigningMode::Hmac => Ok(serde_json::json!({ "keys": [] })),
            SigningMode::Jwt => keyring.jwks(),
        }
    }
}
