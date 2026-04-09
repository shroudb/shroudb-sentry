use shroudb_acl::{PolicyEffect, PolicyPrincipal, PolicyRequest, PolicyResource};

use shroudb_sentry_core::decision::{Decision, DecisionClaims, SignedDecision};
use shroudb_sentry_core::error::SentryError;
use shroudb_sentry_core::policy::Policy;
use shroudb_sentry_core::signing::SigningKeyring;

/// Evaluate policies against a request and return a decision.
///
/// Algorithm:
/// 1. Policies are evaluated in priority order (highest first).
/// 2. First matching policy determines the decision.
/// 3. At equal priority, Deny trumps Permit (fail-closed).
/// 4. No match → default is Deny.
pub fn evaluate_policies(policies: &[Policy], request: &PolicyRequest) -> Decision {
    let mut best_match: Option<(&Policy, bool)> = None; // (policy, is_deny)

    for policy in policies {
        if !policy_matches(policy, request) {
            continue;
        }

        let is_deny = policy.effect == PolicyEffect::Deny;

        match best_match {
            None => {
                best_match = Some((policy, is_deny));
            }
            Some((current, current_is_deny)) => {
                if policy.priority > current.priority {
                    best_match = Some((policy, is_deny));
                } else if policy.priority == current.priority && is_deny && !current_is_deny {
                    // At equal priority, deny trumps permit
                    best_match = Some((policy, is_deny));
                }
            }
        }
    }

    match best_match {
        Some((policy, _)) => Decision {
            effect: policy.effect,
            matched_policy: Some(policy.name.clone()),
        },
        None => Decision {
            effect: PolicyEffect::Deny,
            matched_policy: None,
        },
    }
}

/// Check if a single policy matches a request.
fn policy_matches(policy: &Policy, request: &PolicyRequest) -> bool {
    // Check principal
    if !policy
        .principal
        .matches(&request.principal.roles, &request.principal.claims)
    {
        return false;
    }

    // Check resource
    if !policy.resource.matches(
        &request.resource.resource_type,
        &request.resource.attributes,
    ) {
        return false;
    }

    // Check action
    if !policy.action.matches(&request.action) {
        return false;
    }

    // Check conditions (time window)
    let (hour, minute) = current_utc_hhmm();
    if !policy.conditions.satisfied(hour, minute) {
        return false;
    }

    true
}

/// Sign a decision into a JWT.
pub fn sign_decision(
    decision: &Decision,
    request: &PolicyRequest,
    keyring: &SigningKeyring,
) -> Result<SignedDecision, SentryError> {
    let active = keyring.active_key().ok_or(SentryError::NoActiveKey)?;

    let private_key_hex = active
        .private_key
        .as_ref()
        .ok_or(SentryError::NoActiveKey)?;

    let private_key_bytes =
        hex::decode(private_key_hex).map_err(|e| SentryError::SigningFailed(e.to_string()))?;

    let now = unix_now();
    let exp = now + keyring.decision_ttl_secs;

    let claims = DecisionClaims {
        decision: decision.effect.to_string(),
        principal: request.principal.id.clone(),
        resource: request.resource.id.clone(),
        action: request.action.clone(),
        policy: decision.matched_policy.clone(),
        iat: now,
        exp,
    };

    let claims_value =
        serde_json::to_value(&claims).map_err(|e| SentryError::Internal(e.to_string()))?;

    let jwt_algo = keyring.algorithm.to_jwt_algorithm();
    let token = shroudb_crypto::sign_jwt(&private_key_bytes, jwt_algo, &claims_value, &active.kid)
        .map_err(|e| SentryError::SigningFailed(e.to_string()))?;

    Ok(SignedDecision {
        decision: decision.effect,
        token,
        matched_policy: decision.matched_policy.clone(),
        cache_until: exp,
    })
}

/// Build the JWKS (JSON Web Key Set) from a keyring.
pub fn build_jwks(keyring: &SigningKeyring) -> Result<serde_json::Value, SentryError> {
    let jwt_algo = keyring.algorithm.to_jwt_algorithm();
    let mut keys = Vec::new();

    for kv in keyring.jwks_keys() {
        let pub_bytes =
            hex::decode(&kv.public_key).map_err(|e| SentryError::Internal(e.to_string()))?;

        let jwk = shroudb_crypto::public_key_to_jwk(jwt_algo, &pub_bytes, &kv.kid)
            .map_err(|e| SentryError::Internal(e.to_string()))?;

        keys.push(jwk);
    }

    Ok(serde_json::json!({ "keys": keys }))
}

/// Parse a JSON string into a PolicyRequest.
pub fn parse_evaluation_request(json: &str) -> Result<PolicyRequest, SentryError> {
    // Try parsing the full PolicyRequest structure first
    if let Ok(req) = serde_json::from_str::<PolicyRequest>(json) {
        if req.principal.id.is_empty() {
            return Err(SentryError::InvalidArgument(
                "principal.id is required".into(),
            ));
        }
        if req.resource.id.is_empty() {
            return Err(SentryError::InvalidArgument(
                "resource.id is required".into(),
            ));
        }
        if req.action.is_empty() {
            return Err(SentryError::InvalidArgument("action is required".into()));
        }
        return Ok(req);
    }

    // Try a simplified format: { "principal": "...", "resource": "...", "action": "..." }
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| SentryError::InvalidArgument(format!("invalid JSON: {e}")))?;

    let principal_id = value["principal"]
        .as_str()
        .or_else(|| value["principal"]["id"].as_str())
        .ok_or_else(|| SentryError::InvalidArgument("principal.id is required".into()))?;

    let resource_id = value["resource"]
        .as_str()
        .or_else(|| value["resource"]["id"].as_str())
        .ok_or_else(|| SentryError::InvalidArgument("resource.id is required".into()))?;

    let resource_type = value["resource"]["type"].as_str().unwrap_or("").to_string();

    let action = value["action"]
        .as_str()
        .ok_or_else(|| SentryError::InvalidArgument("action is required".into()))?;

    let roles: Vec<String> = value["principal"]["roles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let claims = value["principal"]["claims"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let attributes = value["resource"]["attributes"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(PolicyRequest {
        principal: PolicyPrincipal {
            id: principal_id.to_string(),
            roles,
            claims,
        },
        resource: PolicyResource {
            id: resource_id.to_string(),
            resource_type,
            attributes,
        },
        action: action.to_string(),
    })
}

fn current_utc_hhmm() -> (u32, u32) {
    let now = unix_now();
    let secs_in_day = now % 86400;
    let hour = (secs_in_day / 3600) as u32;
    let minute = ((secs_in_day % 3600) / 60) as u32;
    (hour, minute)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use shroudb_sentry_core::matcher::*;

    fn make_request(
        principal_id: &str,
        roles: Vec<&str>,
        resource_type: &str,
        action: &str,
    ) -> PolicyRequest {
        PolicyRequest {
            principal: PolicyPrincipal {
                id: principal_id.into(),
                roles: roles.into_iter().map(String::from).collect(),
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: "res-1".into(),
                resource_type: resource_type.into(),
                attributes: Default::default(),
            },
            action: action.into(),
        }
    }

    fn make_policy(name: &str, effect: PolicyEffect, priority: i32) -> Policy {
        Policy {
            name: name.into(),
            description: String::new(),
            effect,
            priority,
            principal: PrincipalMatcher::default(),
            resource: ResourceMatcher::default(),
            action: ActionMatcher::default(),
            conditions: Conditions::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn no_policies_default_deny() {
        let req = make_request("alice", vec![], "doc", "read");
        let decision = evaluate_policies(&[], &req);
        assert_eq!(decision.effect, PolicyEffect::Deny);
        assert!(decision.matched_policy.is_none());
    }

    #[test]
    fn single_permit_policy() {
        let policies = vec![make_policy("allow-all", PolicyEffect::Permit, 0)];
        let req = make_request("alice", vec![], "doc", "read");
        let decision = evaluate_policies(&policies, &req);
        assert_eq!(decision.effect, PolicyEffect::Permit);
        assert_eq!(decision.matched_policy.as_deref(), Some("allow-all"));
    }

    #[test]
    fn higher_priority_wins() {
        let policies = vec![
            make_policy("low-permit", PolicyEffect::Permit, 1),
            make_policy("high-deny", PolicyEffect::Deny, 10),
        ];
        let req = make_request("alice", vec![], "doc", "read");
        let decision = evaluate_policies(&policies, &req);
        assert_eq!(decision.effect, PolicyEffect::Deny);
        assert_eq!(decision.matched_policy.as_deref(), Some("high-deny"));
    }

    #[test]
    fn equal_priority_deny_trumps_permit() {
        let policies = vec![
            make_policy("permit-rule", PolicyEffect::Permit, 5),
            make_policy("deny-rule", PolicyEffect::Deny, 5),
        ];
        let req = make_request("alice", vec![], "doc", "read");
        let decision = evaluate_policies(&policies, &req);
        assert_eq!(decision.effect, PolicyEffect::Deny);
    }

    #[test]
    fn role_matching() {
        let mut policy = make_policy("editors-write", PolicyEffect::Permit, 10);
        policy.principal = PrincipalMatcher {
            roles: vec!["editor".into()],
            claims: Default::default(),
        };
        policy.action = ActionMatcher {
            names: vec!["write".into()],
        };

        let policies = vec![policy];

        // Editor can write
        let req = make_request("alice", vec!["editor"], "doc", "write");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        // Viewer cannot write (no matching policy → default deny)
        let req = make_request("bob", vec!["viewer"], "doc", "write");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn parse_full_request() {
        let json = r#"{"principal":{"id":"alice","roles":["editor"]},"resource":{"id":"doc-1","type":"document"},"action":"write"}"#;
        let req = parse_evaluation_request(json).unwrap();
        assert_eq!(req.principal.id, "alice");
        assert_eq!(req.resource.resource_type, "document");
        assert_eq!(req.action, "write");
    }

    #[test]
    fn parse_missing_fields() {
        let json = r#"{"principal":{"id":""},"resource":{"id":"x","type":"y"},"action":"z"}"#;
        assert!(parse_evaluation_request(json).is_err());
    }

    #[test]
    fn parse_missing_resource_id() {
        let json =
            r#"{"principal":{"id":"alice"},"resource":{"id":"","type":"doc"},"action":"read"}"#;
        assert!(parse_evaluation_request(json).is_err());
    }

    #[test]
    fn parse_missing_action() {
        let json = r#"{"principal":{"id":"alice"},"resource":{"id":"x","type":"doc"},"action":""}"#;
        assert!(parse_evaluation_request(json).is_err());
    }

    #[test]
    fn parse_invalid_json() {
        assert!(parse_evaluation_request("not json at all").is_err());
        assert!(parse_evaluation_request("{broken").is_err());
    }

    #[test]
    fn parse_simplified_string_ids() {
        let json = r#"{"principal":{"id":"alice"},"resource":{"id":"doc-1","type":"doc"},"action":"read"}"#;
        let req = parse_evaluation_request(json).unwrap();
        assert_eq!(req.principal.id, "alice");
        assert_eq!(req.resource.id, "doc-1");
        assert_eq!(req.action, "read");
    }

    #[test]
    fn parse_with_roles_and_claims() {
        let json = r#"{"principal":{"id":"alice","roles":["admin","editor"],"claims":{"dept":"eng"}},"resource":{"id":"x","type":"doc","attributes":{"team":"platform"}},"action":"write"}"#;
        let req = parse_evaluation_request(json).unwrap();
        assert_eq!(req.principal.roles, vec!["admin", "editor"]);
        assert_eq!(req.principal.claims.get("dept").unwrap(), "eng");
        assert_eq!(req.resource.attributes.get("team").unwrap(), "platform");
    }

    #[test]
    fn resource_type_matching() {
        let mut policy = make_policy("docs-only", PolicyEffect::Permit, 10);
        policy.resource = ResourceMatcher {
            resource_type: "document".into(),
            ..Default::default()
        };

        let policies = vec![policy];

        // Matching type
        let req = make_request("alice", vec![], "document", "read");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        // Non-matching type
        let req = make_request("alice", vec![], "endpoint", "read");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn action_name_matching() {
        let mut policy = make_policy("read-only", PolicyEffect::Permit, 10);
        policy.action = ActionMatcher {
            names: vec!["read".into(), "list".into()],
        };

        let policies = vec![policy];

        let req = make_request("alice", vec![], "doc", "read");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        let req = make_request("alice", vec![], "doc", "write");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn multiple_policies_specific_match() {
        let mut broad = make_policy("deny-all-writes", PolicyEffect::Deny, 5);
        broad.action = ActionMatcher {
            names: vec!["write".into()],
        };

        let mut specific = make_policy("editors-can-write", PolicyEffect::Permit, 10);
        specific.principal = PrincipalMatcher {
            roles: vec!["editor".into()],
            ..Default::default()
        };
        specific.action = ActionMatcher {
            names: vec!["write".into()],
        };

        let policies = vec![broad, specific];

        // Editor writing: higher-priority permit wins
        let req = make_request("alice", vec!["editor"], "doc", "write");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        // Viewer writing: only deny matches
        let req = make_request("bob", vec!["viewer"], "doc", "write");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );

        // Editor reading: neither matches (no policy for read)
        let req = make_request("alice", vec!["editor"], "doc", "read");
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn claims_matching_in_evaluation() {
        let mut policy = make_policy("eng-only", PolicyEffect::Permit, 10);
        policy.principal = PrincipalMatcher {
            roles: Vec::new(),
            claims: HashMap::from([("dept".into(), "engineering".into())]),
        };

        let policies = vec![policy];

        let mut req = make_request("alice", vec![], "doc", "read");
        req.principal.claims = HashMap::from([("dept".into(), "engineering".into())]);
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        let mut req = make_request("bob", vec![], "doc", "read");
        req.principal.claims = HashMap::from([("dept".into(), "sales".into())]);
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn attributes_matching_in_evaluation() {
        let mut policy = make_policy("internal-docs", PolicyEffect::Permit, 10);
        policy.resource = ResourceMatcher {
            resource_type: "document".into(),
            attributes: HashMap::from([("classification".into(), "internal".into())]),
        };

        let policies = vec![policy];

        let mut req = make_request("alice", vec![], "document", "read");
        req.resource.attributes = HashMap::from([("classification".into(), "internal".into())]);
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Permit
        );

        let mut req = make_request("alice", vec![], "document", "read");
        req.resource.attributes = HashMap::from([("classification".into(), "secret".into())]);
        assert_eq!(
            evaluate_policies(&policies, &req).effect,
            PolicyEffect::Deny
        );
    }
}
