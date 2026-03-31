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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_default_deny() {
        let d = Decision {
            effect: PolicyEffect::Deny,
            matched_policy: None,
        };
        assert_eq!(d.effect, PolicyEffect::Deny);
        assert!(d.matched_policy.is_none());
    }

    #[test]
    fn decision_with_matched_policy() {
        let d = Decision {
            effect: PolicyEffect::Permit,
            matched_policy: Some("allow-editors".into()),
        };
        assert_eq!(d.effect, PolicyEffect::Permit);
        assert_eq!(d.matched_policy.as_deref(), Some("allow-editors"));
    }

    #[test]
    fn signed_decision_serde_roundtrip() {
        let sd = SignedDecision {
            decision: PolicyEffect::Permit,
            token: "eyJ0eXAi.payload.signature".into(),
            matched_policy: Some("my-policy".into()),
            cache_until: 1700000000,
        };
        let json = serde_json::to_string(&sd).unwrap();
        let parsed: SignedDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, PolicyEffect::Permit);
        assert_eq!(parsed.token, "eyJ0eXAi.payload.signature");
        assert_eq!(parsed.matched_policy.as_deref(), Some("my-policy"));
        assert_eq!(parsed.cache_until, 1700000000);
    }

    #[test]
    fn signed_decision_no_matched_policy() {
        let sd = SignedDecision {
            decision: PolicyEffect::Deny,
            token: "token".into(),
            matched_policy: None,
            cache_until: 0,
        };
        let json = serde_json::to_string(&sd).unwrap();
        let parsed: SignedDecision = serde_json::from_str(&json).unwrap();
        assert!(parsed.matched_policy.is_none());
        assert_eq!(parsed.decision, PolicyEffect::Deny);
    }

    #[test]
    fn decision_claims_serde_roundtrip() {
        let claims = DecisionClaims {
            decision: "permit".into(),
            principal: "user-42".into(),
            resource: "doc/secret".into(),
            action: "read".into(),
            policy: Some("allow-readers".into()),
            iat: 1700000000,
            exp: 1700000300,
        };
        let json = serde_json::to_string(&claims).unwrap();
        let parsed: DecisionClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, "permit");
        assert_eq!(parsed.principal, "user-42");
        assert_eq!(parsed.resource, "doc/secret");
        assert_eq!(parsed.action, "read");
        assert_eq!(parsed.policy.as_deref(), Some("allow-readers"));
        assert_eq!(parsed.iat, 1700000000);
        assert_eq!(parsed.exp, 1700000300);
    }

    #[test]
    fn decision_claims_skips_none_policy() {
        let claims = DecisionClaims {
            decision: "deny".into(),
            principal: "anon".into(),
            resource: "any".into(),
            action: "write".into(),
            policy: None,
            iat: 0,
            exp: 0,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("policy"));
    }

    #[test]
    fn deny_trumps_permit_at_same_priority() {
        // Domain rule: at equal priority, Deny wins. Verify we can represent
        // both effects and that Deny != Permit (policy evaluation lives in engine,
        // but the core types must distinguish them).
        let deny = Decision {
            effect: PolicyEffect::Deny,
            matched_policy: Some("block-all".into()),
        };
        let permit = Decision {
            effect: PolicyEffect::Permit,
            matched_policy: Some("allow-all".into()),
        };
        assert_ne!(deny.effect, permit.effect);
        // Convention: when selecting between equal-priority decisions, pick Deny
        let decisions = [&deny, &permit];
        let winner = decisions
            .iter()
            .find(|d| d.effect == PolicyEffect::Deny)
            .unwrap();
        assert_eq!(winner.effect, PolicyEffect::Deny);
    }
}
