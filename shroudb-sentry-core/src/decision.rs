use serde::{Deserialize, Serialize};
use shroudb_acl::PolicyEffect;

/// The result of evaluating policies against a request.
#[derive(Debug, Clone)]
pub struct Decision {
    /// Whether access is permitted or denied.
    pub effect: PolicyEffect,
    /// The name of the policy that matched, if any.
    /// `None` when the default decision was applied.
    pub matched_policy: Option<String>,
}

/// A decision with a cryptographically signed JWT proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDecision {
    /// The authorization decision.
    pub decision: PolicyEffect,
    /// A signed JWT token encoding the decision.
    pub token: String,
    /// The policy that matched, if any.
    pub matched_policy: Option<String>,
    /// Unix timestamp until which this decision can be cached.
    pub cache_until: u64,
}

/// JWT claims embedded in a signed decision token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionClaims {
    /// The authorization decision ("permit" or "deny").
    pub decision: String,
    /// The principal ID from the request.
    pub principal: String,
    /// The resource ID from the request.
    pub resource: String,
    /// The action from the request.
    pub action: String,
    /// The policy that matched, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Issued-at timestamp (unix seconds).
    pub iat: u64,
    /// Expiration timestamp (unix seconds).
    pub exp: u64,
}
