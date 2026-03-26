use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::decision::Decision;
use crate::error::SentryError;
use crate::evaluation::EvaluationRequest;
use crate::matcher::{ActionMatcher, Conditions, PrincipalMatcher, ResourceMatcher};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: Option<String>,
    pub effect: Effect,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub principal: PrincipalMatcher,
    #[serde(default)]
    pub resource: ResourceMatcher,
    #[serde(default)]
    pub action: ActionMatcher,
    #[serde(default)]
    pub conditions: Option<Conditions>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Permit,
    Deny,
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Effect::Permit => write!(f, "permit"),
            Effect::Deny => write!(f, "deny"),
        }
    }
}

fn default_priority() -> i32 {
    0
}

/// A compiled set of policies, sorted by priority descending.
pub struct PolicySet {
    policies: Vec<Policy>,
}

impl PolicySet {
    /// Load all `.toml` policy files from a directory.
    pub fn load_dir(path: &Path) -> Result<Self, SentryError> {
        let mut all_policies = Vec::new();

        if !path.exists() {
            return Ok(Self {
                policies: all_policies,
            });
        }

        let entries =
            std::fs::read_dir(path).map_err(|e| SentryError::PolicyParse(e.to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| SentryError::PolicyParse(e.to_string()))?;
            let file_path = entry.path();
            if file_path.extension().is_some_and(|ext| ext == "toml") {
                let mut file_policies = Self::load_file(&file_path)?;
                all_policies.append(&mut file_policies);
            }
        }

        // Validate unique names.
        let mut seen = std::collections::HashSet::new();
        for p in &all_policies {
            if !seen.insert(&p.name) {
                return Err(SentryError::PolicyConflict(format!(
                    "duplicate policy name: {}",
                    p.name
                )));
            }
        }

        // Sort by priority descending (highest priority first).
        all_policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(Self {
            policies: all_policies,
        })
    }

    /// Parse a single TOML policy file.
    pub fn load_file(path: &Path) -> Result<Vec<Policy>, SentryError> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| SentryError::PolicyParse(e.to_string()))?;
        let file: PolicyFile =
            toml::from_str(&contents).map_err(|e| SentryError::PolicyParse(e.to_string()))?;
        Ok(file.policies)
    }

    /// Create a PolicySet from an in-memory list of policies.
    pub fn from_policies(mut policies: Vec<Policy>) -> Result<Self, SentryError> {
        let mut seen = std::collections::HashSet::new();
        for p in &policies {
            if !seen.insert(&p.name) {
                return Err(SentryError::PolicyConflict(format!(
                    "duplicate policy name: {}",
                    p.name
                )));
            }
        }
        policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(Self { policies })
    }

    /// Evaluate a request against all policies.
    ///
    /// Algorithm:
    /// 1. Iterate policies in priority order (highest first).
    /// 2. For each matching policy, record it.
    /// 3. If any Deny policy matches, the result is Deny (deny trumps permit at equal priority).
    /// 4. Otherwise, use the highest-priority match.
    /// 5. If no policy matches, use the default decision.
    pub fn evaluate(&self, request: &EvaluationRequest, default_decision: Effect) -> Decision {
        let now_minutes = crate::matcher::current_utc_minutes();
        self.evaluate_at(request, default_decision, now_minutes)
    }

    /// Evaluate with a specific time (for testing).
    pub fn evaluate_at(
        &self,
        request: &EvaluationRequest,
        default_decision: Effect,
        now_utc_minutes: u32,
    ) -> Decision {
        let mut best_match: Option<&Policy> = None;

        for policy in &self.policies {
            // Check if this policy's matchers all match the request.
            if !policy.principal.matches(&request.principal) {
                continue;
            }
            if !policy.resource.matches(&request.resource) {
                continue;
            }
            if !policy.action.matches(&request.action) {
                continue;
            }

            // Check conditions (time window, etc.).
            if let Some(ref conditions) = policy.conditions
                && !conditions.evaluate(now_utc_minutes)
            {
                continue;
            }

            // If we already have a match at a higher priority, skip lower-priority policies
            // unless this one is Deny at the same priority (deny trumps permit).
            match best_match {
                Some(current) => {
                    if policy.priority == current.priority {
                        // At the same priority, Deny trumps Permit.
                        if policy.effect == Effect::Deny && current.effect == Effect::Permit {
                            best_match = Some(policy);
                        }
                    }
                    // Lower priority policies don't override higher ones.
                }
                None => {
                    best_match = Some(policy);
                }
            }
        }

        match best_match {
            Some(policy) => Decision {
                effect: policy.effect,
                matched_policy: Some(policy.name.clone()),
            },
            None => Decision {
                effect: default_decision,
                matched_policy: None,
            },
        }
    }

    /// Get all policies.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Look up a policy by name.
    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation::{Principal, Resource};
    use std::collections::HashMap;

    fn eval_request(
        principal_id: &str,
        roles: &[&str],
        resource_type: &str,
        action: &str,
    ) -> EvaluationRequest {
        EvaluationRequest {
            principal: Principal {
                id: principal_id.into(),
                roles: roles.iter().map(|s| s.to_string()).collect(),
                claims: HashMap::new(),
            },
            resource: Resource {
                id: "res-1".into(),
                resource_type: resource_type.into(),
                attributes: HashMap::new(),
            },
            action: action.into(),
        }
    }

    fn permit_policy(name: &str, priority: i32) -> Policy {
        Policy {
            name: name.into(),
            description: None,
            effect: Effect::Permit,
            priority,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: None,
        }
    }

    fn deny_policy(name: &str, priority: i32) -> Policy {
        Policy {
            name: name.into(),
            description: None,
            effect: Effect::Deny,
            priority,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: None,
        }
    }

    #[test]
    fn permit_policy_returns_permit() {
        let ps = PolicySet::from_policies(vec![permit_policy("allow-all", 0)]).unwrap();
        let req = eval_request("user1", &["admin"], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Deny);
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.matched_policy.as_deref(), Some("allow-all"));
    }

    #[test]
    fn deny_policy_returns_deny() {
        let ps = PolicySet::from_policies(vec![deny_policy("deny-all", 0)]).unwrap();
        let req = eval_request("user1", &["admin"], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Permit);
        assert_eq!(decision.effect, Effect::Deny);
        assert_eq!(decision.matched_policy.as_deref(), Some("deny-all"));
    }

    #[test]
    fn deny_trumps_permit_at_same_priority() {
        let ps = PolicySet::from_policies(vec![permit_policy("allow", 0), deny_policy("deny", 0)])
            .unwrap();
        let req = eval_request("user1", &[], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Permit);
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn higher_priority_wins() {
        let ps = PolicySet::from_policies(vec![
            deny_policy("deny-low", 0),
            permit_policy("allow-high", 10),
        ])
        .unwrap();
        let req = eval_request("user1", &[], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Deny);
        assert_eq!(decision.effect, Effect::Permit);
        assert_eq!(decision.matched_policy.as_deref(), Some("allow-high"));
    }

    #[test]
    fn default_decision_when_no_match() {
        let mut policy = permit_policy("admin-only", 0);
        policy.principal = PrincipalMatcher {
            role: Some(vec!["admin".into()]),
            claims: HashMap::new(),
        };
        let ps = PolicySet::from_policies(vec![policy]).unwrap();

        // User without admin role — no policy matches.
        let req = eval_request("user1", &["viewer"], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Deny);
        assert_eq!(decision.effect, Effect::Deny);
        assert!(decision.matched_policy.is_none());
    }

    #[test]
    fn default_permit_when_no_match() {
        let ps = PolicySet::from_policies(vec![]).unwrap();
        let req = eval_request("user1", &[], "doc", "read");
        let decision = ps.evaluate(&req, Effect::Permit);
        assert_eq!(decision.effect, Effect::Permit);
    }

    #[test]
    fn role_scoped_policy() {
        let mut admin_allow = permit_policy("admin-allow", 10);
        admin_allow.principal = PrincipalMatcher {
            role: Some(vec!["admin".into()]),
            claims: HashMap::new(),
        };
        let global_deny = deny_policy("global-deny", 0);

        let ps = PolicySet::from_policies(vec![admin_allow, global_deny]).unwrap();

        // Admin gets the higher-priority permit.
        let admin_req = eval_request("admin1", &["admin"], "doc", "write");
        assert_eq!(ps.evaluate(&admin_req, Effect::Deny).effect, Effect::Permit);

        // Non-admin matches only the deny.
        let user_req = eval_request("user1", &["viewer"], "doc", "write");
        assert_eq!(ps.evaluate(&user_req, Effect::Deny).effect, Effect::Deny);
    }

    #[test]
    fn resource_type_scoped_policy() {
        let mut doc_allow = permit_policy("doc-allow", 0);
        doc_allow.resource = ResourceMatcher {
            resource_type: Some("document".into()),
            attributes: HashMap::new(),
        };

        let ps = PolicySet::from_policies(vec![doc_allow]).unwrap();

        let doc_req = eval_request("user1", &[], "document", "read");
        assert_eq!(ps.evaluate(&doc_req, Effect::Deny).effect, Effect::Permit);

        let img_req = eval_request("user1", &[], "image", "read");
        assert_eq!(ps.evaluate(&img_req, Effect::Deny).effect, Effect::Deny);
    }

    #[test]
    fn action_scoped_policy() {
        let mut read_allow = permit_policy("read-allow", 0);
        read_allow.action = ActionMatcher {
            name: Some(vec!["read".into(), "list".into()]),
        };

        let ps = PolicySet::from_policies(vec![read_allow]).unwrap();

        let read_req = eval_request("user1", &[], "doc", "read");
        assert_eq!(ps.evaluate(&read_req, Effect::Deny).effect, Effect::Permit);

        let write_req = eval_request("user1", &[], "doc", "write");
        assert_eq!(ps.evaluate(&write_req, Effect::Deny).effect, Effect::Deny);
    }

    #[test]
    fn duplicate_names_rejected() {
        let result = PolicySet::from_policies(vec![
            permit_policy("same-name", 0),
            deny_policy("same-name", 1),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn policies_sorted_by_priority() {
        let ps = PolicySet::from_policies(vec![
            permit_policy("low", 1),
            permit_policy("high", 100),
            permit_policy("mid", 50),
        ])
        .unwrap();
        let names: Vec<&str> = ps.policies().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["high", "mid", "low"]);
    }

    #[test]
    fn get_policy_by_name() {
        let ps = PolicySet::from_policies(vec![permit_policy("alpha", 0), deny_policy("beta", 1)])
            .unwrap();
        assert!(ps.get("alpha").is_some());
        assert!(ps.get("gamma").is_none());
    }

    #[test]
    fn toml_round_trip() {
        let toml_str = r#"
[[policies]]
name = "allow-admins"
description = "Allow admin role to do anything"
effect = "permit"
priority = 100

[policies.principal]
role = ["admin"]

[[policies]]
name = "deny-delete"
effect = "deny"
priority = 50

[policies.action]
name = ["delete"]
"#;

        let file: PolicyFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.policies.len(), 2);
        assert_eq!(file.policies[0].name, "allow-admins");
        assert_eq!(file.policies[0].effect, Effect::Permit);
        assert_eq!(file.policies[0].priority, 100);
        assert_eq!(file.policies[1].name, "deny-delete");
        assert_eq!(file.policies[1].effect, Effect::Deny);
    }

    #[test]
    fn load_dir_creates_empty_set_for_missing_dir() {
        let ps = PolicySet::load_dir(Path::new("/nonexistent/path")).unwrap();
        assert!(ps.policies().is_empty());
    }
}
