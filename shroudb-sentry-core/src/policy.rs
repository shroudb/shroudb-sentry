use serde::{Deserialize, Serialize};
use shroudb_acl::PolicyEffect;

use crate::matcher::{ActionMatcher, Conditions, PrincipalMatcher, ResourceMatcher};

/// An authorization policy rule.
///
/// Policies are evaluated in priority order (highest first). At equal
/// priority, Deny trumps Permit (fail-closed). If no policy matches,
/// the default decision is Deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy name.
    #[serde(default)]
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Whether this policy permits or denies access.
    pub effect: PolicyEffect,
    /// Evaluation priority (higher = evaluated first).
    #[serde(default)]
    pub priority: i32,
    /// Principal matcher.
    #[serde(default)]
    pub principal: PrincipalMatcher,
    /// Resource matcher.
    #[serde(default)]
    pub resource: ResourceMatcher,
    /// Action matcher.
    #[serde(default)]
    pub action: ActionMatcher,
    /// Optional conditions (time windows, etc.).
    #[serde(default)]
    pub conditions: Conditions,
    /// Policy version. Starts at 1, increments on each update.
    #[serde(default)]
    pub version: u64,
    /// Unix timestamp when this policy was created.
    #[serde(default)]
    pub created_at: u64,
    /// Unix timestamp when this policy was last updated.
    #[serde(default)]
    pub updated_at: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            effect: PolicyEffect::Deny,
            priority: 0,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        }
    }
}

/// Validate a policy name.
///
/// Names must be 1–255 chars, ASCII alphanumeric plus `-` and `_`.
pub fn validate_policy_name(name: &str) -> Result<(), crate::error::SentryError> {
    if name.is_empty() {
        return Err(crate::error::SentryError::InvalidArgument(
            "policy name cannot be empty".into(),
        ));
    }
    if name.len() > 255 {
        return Err(crate::error::SentryError::InvalidArgument(
            "policy name cannot exceed 255 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(crate::error::SentryError::InvalidArgument(
            "policy name must be alphanumeric, dashes, or underscores".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_policy_names() {
        assert!(validate_policy_name("my-policy").is_ok());
        assert!(validate_policy_name("policy_123").is_ok());
        assert!(validate_policy_name("a").is_ok());
    }

    #[test]
    fn invalid_policy_names() {
        assert!(validate_policy_name("").is_err());
        assert!(validate_policy_name("has spaces").is_err());
        assert!(validate_policy_name("has.dots").is_err());
        assert!(validate_policy_name(&"a".repeat(256)).is_err());
    }

    #[test]
    fn boundary_name_255_chars() {
        assert!(validate_policy_name(&"a".repeat(255)).is_ok());
        assert!(validate_policy_name(&"a".repeat(256)).is_err());
    }

    #[test]
    fn invalid_name_special_chars() {
        assert!(validate_policy_name("has/slash").is_err());
        assert!(validate_policy_name("has@sign").is_err());
        assert!(validate_policy_name("has!bang").is_err());
        assert!(validate_policy_name("has.dot").is_err());
        assert!(validate_policy_name("has:colon").is_err());
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = Policy {
            name: "editors-write-docs".into(),
            description: "Editors can write documents".into(),
            effect: PolicyEffect::Permit,
            priority: 10,
            principal: PrincipalMatcher {
                roles: vec!["editor".into()],
                ..Default::default()
            },
            resource: ResourceMatcher {
                resource_type: "document".into(),
                ..Default::default()
            },
            action: ActionMatcher {
                names: vec!["write".into()],
            },
            conditions: Default::default(),
            version: 1,
            created_at: 1000,
            updated_at: 1000,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "editors-write-docs");
        assert_eq!(parsed.effect, PolicyEffect::Permit);
        assert_eq!(parsed.priority, 10);
    }
}
