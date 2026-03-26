use serde::{Deserialize, Serialize};

use crate::policy::Effect;

/// The result of evaluating policies against a request.
#[derive(Debug, Clone)]
pub struct Decision {
    pub effect: Effect,
    pub matched_policy: Option<String>,
}

/// JWT claims for a signed decision token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDecisionClaims {
    pub decision: String,
    pub principal: String,
    pub resource: String,
    pub action: String,
    pub policy: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

/// A decision with a signed JWT token for downstream verification.
pub struct SignedDecision {
    pub decision: Effect,
    pub token: String,
    pub matched_policy: Option<String>,
    pub cache_until: u64,
}
