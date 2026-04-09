mod common;

use common::{TestPolicySeed, TestServer, TestServerConfig, auth_server_config};
use shroudb_sentry_client::SentryClient;

// ── Basic operations ────────────────────────────────────────────────

#[tokio::test]
async fn tcp_health() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();
    client.health().await.unwrap();
}

#[tokio::test]
async fn tcp_policy_lifecycle() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Create a policy
    let policy_json = r#"{"effect":"permit","priority":10,"description":"editors can write docs"}"#;
    let resp = client
        .policy_create("editors-write", policy_json)
        .await
        .unwrap();
    assert_eq!(resp["name"].as_str().unwrap(), "editors-write");

    // Get the policy
    let info = client.policy_get("editors-write").await.unwrap();
    assert_eq!(info.name, "editors-write");
    assert_eq!(info.effect, "permit");
    assert_eq!(info.priority, 10);

    // List policies
    let policies = client.policy_list().await.unwrap();
    assert!(policies.contains(&"editors-write".to_string()));

    // Update the policy
    let update_json = r#"{"effect":"deny","priority":20,"description":"updated"}"#;
    let resp = client
        .policy_update("editors-write", update_json)
        .await
        .unwrap();
    assert_eq!(resp["effect"].as_str().unwrap(), "deny");
    assert_eq!(resp["priority"].as_i64().unwrap(), 20);

    // Delete the policy
    client.policy_delete("editors-write").await.unwrap();
    let policies = client.policy_list().await.unwrap();
    assert!(!policies.contains(&"editors-write".to_string()));
}

#[tokio::test]
async fn tcp_evaluate_permit() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Create a permit policy for editors writing documents
    let policy_json = r#"{
        "effect": "permit",
        "priority": 10,
        "principal": {"roles": ["editor"]},
        "resource": {"type": "document"},
        "action": {"names": ["write"]}
    }"#;
    client
        .policy_create("editors-write-docs", policy_json)
        .await
        .unwrap();

    // Evaluate: editor writing a document → permit
    let request = r#"{
        "principal": {"id": "alice", "roles": ["editor"]},
        "resource": {"id": "doc-1", "type": "document"},
        "action": "write"
    }"#;
    let result = client.evaluate(request).await.unwrap();
    assert_eq!(result.decision, "permit");
    assert_eq!(result.matched_policy.as_deref(), Some("editors-write-docs"));
    assert!(!result.token.is_empty());
    assert!(result.cache_until > 0);
}

#[tokio::test]
async fn tcp_evaluate_deny_no_match() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // No policies → default deny
    let request = r#"{
        "principal": {"id": "bob", "roles": ["viewer"]},
        "resource": {"id": "doc-1", "type": "document"},
        "action": "write"
    }"#;
    let result = client.evaluate(request).await.unwrap();
    assert_eq!(result.decision, "deny");
    assert!(result.matched_policy.is_none());
}

#[tokio::test]
async fn tcp_evaluate_deny_trumps_permit() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Create permit and deny at same priority
    let permit = r#"{"effect": "permit", "priority": 10}"#;
    client.policy_create("allow-all", permit).await.unwrap();

    let deny = r#"{"effect": "deny", "priority": 10}"#;
    client.policy_create("deny-all", deny).await.unwrap();

    let request = r#"{
        "principal": {"id": "alice"},
        "resource": {"id": "x", "type": "any"},
        "action": "read"
    }"#;
    let result = client.evaluate(request).await.unwrap();
    assert_eq!(result.decision, "deny");
}

#[tokio::test]
async fn tcp_key_info_and_jwks() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Key info
    let info = client.key_info().await.unwrap();
    assert_eq!(info["algorithm"].as_str().unwrap(), "ES256");
    assert!(info["active_version"].as_u64().is_some());

    // JWKS
    let jwks = client.jwks().await.unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"].as_str().unwrap(), "EC");
    assert_eq!(keys[0]["alg"].as_str().unwrap(), "ES256");
}

#[tokio::test]
async fn tcp_key_rotate() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Force rotation
    let result = client.key_rotate(true, false).await.unwrap();
    assert!(result.rotated);
    assert_eq!(result.key_version, 2);
    assert_eq!(result.previous_version, Some(1));

    // JWKS should now have 2 keys (active + draining)
    let jwks = client.jwks().await.unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
}

#[tokio::test]
async fn tcp_key_rotate_dryrun() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let result = client.key_rotate(true, true).await.unwrap();
    assert!(result.rotated);
    assert_eq!(result.key_version, 2);

    // Dryrun should not actually rotate
    let info = client.key_info().await.unwrap();
    assert_eq!(info["active_version"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn tcp_config_seeded_policies() {
    let config = TestServerConfig {
        tokens: vec![],
        policies: vec![TestPolicySeed {
            name: "seeded-policy".to_string(),
            effect: "permit".to_string(),
            priority: 5,
            principal_roles: vec!["admin".to_string()],
            resource_type: "system".to_string(),
            action_names: vec!["manage".to_string()],
        }],
    };

    let server = TestServer::start_with_config(config)
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let policies = client.policy_list().await.unwrap();
    assert!(policies.contains(&"seeded-policy".to_string()));

    let info = client.policy_get("seeded-policy").await.unwrap();
    assert_eq!(info.effect, "permit");
    assert_eq!(info.priority, 5);
}

#[tokio::test]
async fn tcp_error_responses() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Get nonexistent policy
    let err = client.policy_get("nonexistent").await;
    assert!(err.is_err());

    // Delete nonexistent policy
    let err = client.policy_delete("nonexistent").await;
    assert!(err.is_err());

    // Create duplicate policy
    let json = r#"{"effect":"permit"}"#;
    client.policy_create("dup-test", json).await.unwrap();
    let err = client.policy_create("dup-test", json).await;
    assert!(err.is_err());

    // Invalid evaluate JSON
    let err = client.evaluate("not json").await;
    assert!(err.is_err());
}

// ── Edge cases ────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_length_policy_name() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // 255-char name is the maximum allowed
    let long_name = "a".repeat(255);
    let json = r#"{"effect":"permit","priority":1}"#;
    let resp = client
        .policy_create(&long_name, json)
        .await
        .expect("255-char policy name should be accepted");
    assert_eq!(resp["name"].as_str().unwrap(), long_name);

    // Verify it's retrievable
    let info = client.policy_get(&long_name).await.unwrap();
    assert_eq!(info.name, long_name);
}

#[tokio::test]
async fn test_policy_name_too_long() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // 256-char name exceeds the limit
    let too_long = "a".repeat(256);
    let json = r#"{"effect":"permit","priority":1}"#;
    let err = client.policy_create(&too_long, json).await;
    assert!(err.is_err(), "256-char policy name should be rejected");
}

// ── ACL integration tests ──────────────────────────────────────────

#[tokio::test]
async fn acl_unauthenticated_rejection() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Unauthenticated: health should work (AclRequirement::None)
    client.health().await.unwrap();

    // Unauthenticated: JWKS should work (AclRequirement::None)
    client.jwks().await.unwrap();

    // Unauthenticated: POLICY LIST should be rejected
    let err = client.policy_list().await;
    assert!(err.is_err());
}

#[tokio::test]
async fn acl_admin_token_full_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    client.auth("admin-token").await.unwrap();

    // Admin can create policies
    let json = r#"{"effect":"permit","priority":1}"#;
    client.policy_create("admin-test", json).await.unwrap();

    // Admin can list policies
    let policies = client.policy_list().await.unwrap();
    assert!(policies.contains(&"admin-test".to_string()));

    // Admin can evaluate
    let request = r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"read"}"#;
    let result = client.evaluate(request).await.unwrap();
    assert!(!result.token.is_empty());

    // Admin can rotate keys
    let result = client.key_rotate(true, true).await.unwrap();
    assert!(result.rotated);
}

#[tokio::test]
async fn acl_app_token_scoped_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    client.auth("app-token").await.unwrap();

    // App can list/get policies (has sentry.policies.* read)
    let policies = client.policy_list().await.unwrap();
    // Only the self-auth-permit seed policy should exist
    assert!(!policies.contains(&"app-test".to_string()));

    // App can evaluate (has sentry.evaluate.* read)
    let request = r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"read"}"#;
    let result = client.evaluate(request).await.unwrap();
    assert!(!result.token.is_empty());

    // App cannot create policies (requires admin)
    let json = r#"{"effect":"permit"}"#;
    let err = client.policy_create("app-test", json).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn acl_readonly_token_limited() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    client.auth("readonly-token").await.unwrap();

    // Readonly can list policies (has sentry.policies.* read)
    client.policy_list().await.unwrap();

    // Readonly cannot create policies (requires admin)
    let json = r#"{"effect":"permit"}"#;
    let err = client.policy_create("ro-test", json).await;
    assert!(err.is_err());

    // Readonly cannot evaluate (no sentry.evaluate.* grant)
    let request = r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"read"}"#;
    let err = client.evaluate(request).await;
    assert!(err.is_err());
}

#[tokio::test]
async fn acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let err = client.auth("wrong-token").await;
    assert!(err.is_err());
}

// ── Additional edge cases ──────────────────────────────────────────

#[tokio::test]
async fn tcp_evaluate_complex_policy_matching() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Policy: editors can write documents
    let policy = r#"{
        "effect": "permit",
        "priority": 10,
        "principal": {"roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"type": "document", "attributes": {"team": "platform"}},
        "action": {"names": ["write", "update"]}
    }"#;
    client.policy_create("complex-match", policy).await.unwrap();

    // Full match: editor in eng dept, writing platform document
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "platform"}},
        "action": "write"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "permit");
    assert_eq!(result.matched_policy.as_deref(), Some("complex-match"));

    // Wrong role
    let req = r#"{
        "principal": {"id": "bob", "roles": ["viewer"], "claims": {"dept": "eng"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "platform"}},
        "action": "write"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");

    // Wrong claim
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "sales"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "platform"}},
        "action": "write"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");

    // Wrong resource type
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"id": "ep-1", "type": "endpoint", "attributes": {"team": "platform"}},
        "action": "write"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");

    // Wrong attribute
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "mobile"}},
        "action": "write"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");

    // Wrong action
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "platform"}},
        "action": "delete"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");

    // Alternate matching action (update)
    let req = r#"{
        "principal": {"id": "alice", "roles": ["editor"], "claims": {"dept": "eng"}},
        "resource": {"id": "doc-1", "type": "document", "attributes": {"team": "platform"}},
        "action": "update"
    }"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "permit");
}

#[tokio::test]
async fn tcp_evaluate_after_delete() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let json = r#"{"effect":"permit","priority":10}"#;
    client.policy_create("temp", json).await.unwrap();

    let req = r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"a"}"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "permit");

    client.policy_delete("temp").await.unwrap();

    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");
}

#[tokio::test]
async fn tcp_evaluate_priority_ordering() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Low priority permit
    let json = r#"{"effect":"permit","priority":1}"#;
    client.policy_create("low-permit", json).await.unwrap();

    // High priority deny
    let json = r#"{"effect":"deny","priority":100}"#;
    client.policy_create("high-deny", json).await.unwrap();

    let req = r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"a"}"#;
    let result = client.evaluate(req).await.unwrap();
    assert_eq!(result.decision, "deny");
    assert_eq!(result.matched_policy.as_deref(), Some("high-deny"));
}

#[tokio::test]
async fn tcp_key_rotate_without_force() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Without FORCE, key is too fresh (rotation_days=90)
    let result = client.key_rotate(false, false).await.unwrap();
    assert!(!result.rotated);
    assert_eq!(result.key_version, 1);
    assert!(result.previous_version.is_none());
}

#[tokio::test]
async fn tcp_multiple_rotations_jwks_count() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    client.key_rotate(true, false).await.unwrap();
    client.key_rotate(true, false).await.unwrap();

    let jwks = client.jwks().await.unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    // 1 active + 2 draining = 3
    assert_eq!(keys.len(), 3);

    let info = client.key_info().await.unwrap();
    assert_eq!(info["active_version"].as_u64().unwrap(), 3);
}

#[tokio::test]
async fn tcp_policy_invalid_name_via_wire() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let err = client
        .policy_create("bad name!", r#"{"effect":"permit"}"#)
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn tcp_policy_update_nonexistent() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    let err = client
        .policy_update("nonexistent", r#"{"effect":"deny"}"#)
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn tcp_evaluate_missing_required_fields() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Missing principal.id
    let err = client
        .evaluate(r#"{"principal":{},"resource":{"id":"x","type":"y"},"action":"z"}"#)
        .await;
    assert!(err.is_err());

    // Missing resource.id
    let err = client
        .evaluate(r#"{"principal":{"id":"x"},"resource":{},"action":"z"}"#)
        .await;
    assert!(err.is_err());

    // Missing action
    let err = client
        .evaluate(r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"}}"#)
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn tcp_multiple_commands_same_connection() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Run several different commands on the same connection
    client.health().await.unwrap();
    client.jwks().await.unwrap();
    client.key_info().await.unwrap();
    client.policy_list().await.unwrap();

    let json = r#"{"effect":"permit"}"#;
    client.policy_create("multi-cmd-test", json).await.unwrap();
    let info = client.policy_get("multi-cmd-test").await.unwrap();
    assert_eq!(info.effect, "permit");

    client.policy_delete("multi-cmd-test").await.unwrap();
    assert!(
        !client
            .policy_list()
            .await
            .unwrap()
            .contains(&"multi-cmd-test".to_string())
    );
}

#[tokio::test]
async fn acl_key_info_and_jwks_always_public() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Unauthenticated: KEY INFO and JWKS should work (AclRequirement::None)
    client.key_info().await.unwrap();
    client.jwks().await.unwrap();
}

#[tokio::test]
async fn acl_app_cannot_delete_or_rotate() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    client.auth("app-token").await.unwrap();

    // App cannot delete policies (requires admin)
    let err = client.policy_delete("anything").await;
    assert!(err.is_err());

    // App cannot rotate keys (requires admin)
    let err = client.key_rotate(true, false).await;
    assert!(err.is_err());

    // App cannot update policies (requires admin)
    let err = client
        .policy_update("anything", r#"{"effect":"deny"}"#)
        .await;
    assert!(err.is_err());
}

// ── POLICY GET full document (MED-12) ────────────────────────────

#[tokio::test]
async fn test_policy_get_returns_full_document() {
    let server = TestServer::start().await.expect("start server");
    let mut client = SentryClient::connect(&server.tcp_addr).await.unwrap();

    // Create a policy with matchers and conditions
    let policy_json = serde_json::json!({
        "effect": "permit",
        "priority": 50,
        "description": "editors can write docs during business hours",
        "principal": {
            "roles": ["editor", "admin"],
            "claims": {"department": "engineering"}
        },
        "resource": {
            "type": "document",
            "attributes": {"sensitivity": "internal"}
        },
        "action": {
            "names": ["read", "write", "delete"]
        },
        "conditions": {
            "time_window": {
                "after": "09:00",
                "before": "18:00"
            }
        }
    });

    client
        .policy_create("full-doc-test", &policy_json.to_string())
        .await
        .unwrap();

    // GET should return all fields including matchers and conditions
    let info = client.policy_get("full-doc-test").await.unwrap();

    assert_eq!(info.name, "full-doc-test");
    assert_eq!(info.effect, "permit");
    assert_eq!(info.priority, 50);
    assert_eq!(
        info.description,
        "editors can write docs during business hours"
    );

    // Verify principal matchers
    let principal = &info.principal;
    let roles = principal["roles"].as_array().unwrap();
    assert_eq!(roles.len(), 2);
    assert_eq!(principal["claims"]["department"], "engineering");

    // Verify resource matchers
    let resource = &info.resource;
    assert_eq!(resource["type"], "document");
    assert_eq!(resource["attributes"]["sensitivity"], "internal");

    // Verify action matchers
    let action = &info.action;
    let names = action["names"].as_array().unwrap();
    assert_eq!(names.len(), 3);

    // Verify conditions
    let conditions = &info.conditions;
    let tw = &conditions["time_window"];
    assert_eq!(tw["after"], "09:00");
    assert_eq!(tw["before"], "18:00");
}
