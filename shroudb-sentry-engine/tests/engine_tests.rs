use shroudb_sentry_core::signing::SigningAlgorithm;
use shroudb_sentry_engine::engine::{SentryConfig, SentryEngine};
use shroudb_storage::EmbeddedStore;

async fn create_test_engine() -> SentryEngine<EmbeddedStore> {
    let store = shroudb_storage::test_util::create_test_store("sentry-test").await;

    let sentry_config = SentryConfig {
        signing_algorithm: SigningAlgorithm::ES256,
        rotation_days: 90,
        drain_days: 30,
        decision_ttl_secs: 300,
        scheduler_interval_secs: 3600,
        require_audit: false,
    };

    SentryEngine::new(store, sentry_config, None).await.unwrap()
}

// ── PolicyManager via Engine ────────────────────────────────────────

#[tokio::test]
async fn engine_policy_create_and_get() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "test-policy".into(),
        description: "A test policy".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 10,
        ..Default::default()
    };

    let created = engine.policy_create(policy, "test-actor").await.unwrap();
    assert_eq!(created.name, "test-policy");

    let fetched = engine.policy_get("test-policy").unwrap();
    assert_eq!(fetched.effect, shroudb_acl::PolicyEffect::Permit);
    assert_eq!(fetched.priority, 10);
}

#[tokio::test]
async fn engine_policy_create_duplicate_fails() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "dup".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };

    engine
        .policy_create(policy.clone(), "test-actor")
        .await
        .unwrap();
    let err = engine.policy_create(policy, "test-actor").await;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("already exists"));
}

#[tokio::test]
async fn engine_policy_create_invalid_name() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "has spaces".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };

    let err = engine.policy_create(policy, "test-actor").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn engine_policy_create_empty_name() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: String::new(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };

    let err = engine.policy_create(policy, "test-actor").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn engine_policy_list_and_count() {
    let engine = create_test_engine().await;

    assert_eq!(engine.policy_count(), 0);
    assert!(engine.policy_list().is_empty());

    for i in 0..3 {
        let policy = shroudb_sentry_core::policy::Policy {
            name: format!("policy-{i}"),
            effect: shroudb_acl::PolicyEffect::Permit,
            ..Default::default()
        };
        engine.policy_create(policy, "test-actor").await.unwrap();
    }

    assert_eq!(engine.policy_count(), 3);
    let names = engine.policy_list();
    assert_eq!(names.len(), 3);
}

#[tokio::test]
async fn engine_policy_delete() {
    let engine = create_test_engine().await;

    // First create a permit-all so self-authorization passes for mutations
    let permit = shroudb_sentry_core::policy::Policy {
        name: "permit-all".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 100,
        ..Default::default()
    };
    engine.policy_create(permit, "test-actor").await.unwrap();

    // Now create the policy we intend to delete (scoped deny that won't
    // block self-authorization thanks to the higher-priority permit-all)
    let policy = shroudb_sentry_core::policy::Policy {
        name: "to-delete".into(),
        effect: shroudb_acl::PolicyEffect::Deny,
        ..Default::default()
    };
    engine.policy_create(policy, "test-actor").await.unwrap();
    assert_eq!(engine.policy_count(), 2);

    engine
        .policy_delete("to-delete", "test-actor")
        .await
        .unwrap();
    assert_eq!(engine.policy_count(), 1);

    // Delete again should fail
    let err = engine.policy_delete("to-delete", "test-actor").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn engine_policy_get_nonexistent() {
    let engine = create_test_engine().await;
    let err = engine.policy_get("nonexistent");
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn engine_policy_update() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "update-me".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 5,
        ..Default::default()
    };
    engine.policy_create(policy, "test-actor").await.unwrap();

    let updates = shroudb_sentry_core::policy::Policy {
        effect: shroudb_acl::PolicyEffect::Deny,
        priority: 20,
        description: "updated".into(),
        ..Default::default()
    };
    let updated = engine
        .policy_update("update-me", updates, "test-actor")
        .await
        .unwrap();
    assert_eq!(updated.effect, shroudb_acl::PolicyEffect::Deny);
    assert_eq!(updated.priority, 20);
    assert_eq!(updated.description, "updated");

    // Verify the update persisted
    let fetched = engine.policy_get("update-me").unwrap();
    assert_eq!(fetched.effect, shroudb_acl::PolicyEffect::Deny);
}

#[tokio::test]
async fn engine_policy_update_nonexistent() {
    let engine = create_test_engine().await;
    let updates = shroudb_sentry_core::policy::Policy {
        effect: shroudb_acl::PolicyEffect::Deny,
        ..Default::default()
    };
    let err = engine
        .policy_update("nonexistent", updates, "test-actor")
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn engine_seed_policy() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "seeded".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };

    engine.seed_policy(policy.clone()).await.unwrap();
    assert_eq!(engine.policy_count(), 1);

    // Seed again — should be idempotent
    engine.seed_policy(policy).await.unwrap();
    assert_eq!(engine.policy_count(), 1);
}

// ── Evaluation with real engine ─────────────────────────────────────

#[tokio::test]
async fn engine_evaluate_returns_signed_jwt() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "allow-read".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 10,
        action: shroudb_sentry_core::matcher::ActionMatcher {
            names: vec!["read".into()],
        },
        ..Default::default()
    };
    engine.policy_create(policy, "test-actor").await.unwrap();

    let request = shroudb_acl::PolicyRequest {
        principal: shroudb_acl::PolicyPrincipal {
            id: "alice".into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: shroudb_acl::PolicyResource {
            id: "doc-1".into(),
            resource_type: "document".into(),
            attributes: Default::default(),
        },
        action: "read".into(),
    };

    let signed = engine.evaluate_request(&request).await.unwrap();
    assert_eq!(signed.decision, shroudb_acl::PolicyEffect::Permit);
    assert!(!signed.token.is_empty());
    assert!(signed.token.contains('.')); // JWT format: header.payload.signature
    assert_eq!(signed.matched_policy.as_deref(), Some("allow-read"));
    assert!(signed.cache_until > 0);
}

#[tokio::test]
async fn engine_evaluate_default_deny() {
    let engine = create_test_engine().await;

    let request = shroudb_acl::PolicyRequest {
        principal: shroudb_acl::PolicyPrincipal {
            id: "alice".into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: shroudb_acl::PolicyResource {
            id: "doc-1".into(),
            resource_type: "document".into(),
            attributes: Default::default(),
        },
        action: "read".into(),
    };

    let signed = engine.evaluate_request(&request).await.unwrap();
    assert_eq!(signed.decision, shroudb_acl::PolicyEffect::Deny);
    assert!(signed.matched_policy.is_none());
}

#[tokio::test]
async fn engine_evaluate_after_policy_delete() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "temp-permit".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };
    engine.policy_create(policy, "test-actor").await.unwrap();

    let request = shroudb_acl::PolicyRequest {
        principal: shroudb_acl::PolicyPrincipal {
            id: "alice".into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: shroudb_acl::PolicyResource {
            id: "x".into(),
            resource_type: "y".into(),
            attributes: Default::default(),
        },
        action: "z".into(),
    };

    // Initially permitted
    let signed = engine.evaluate_request(&request).await.unwrap();
    assert_eq!(signed.decision, shroudb_acl::PolicyEffect::Permit);

    // Delete the policy
    engine
        .policy_delete("temp-permit", "test-actor")
        .await
        .unwrap();

    // Now denied (default)
    let signed = engine.evaluate_request(&request).await.unwrap();
    assert_eq!(signed.decision, shroudb_acl::PolicyEffect::Deny);
}

// ── Signing key operations ──────────────────────────────────────────

#[tokio::test]
async fn engine_key_info() {
    let engine = create_test_engine().await;
    let info = engine.key_info().unwrap();
    assert_eq!(info["algorithm"].as_str().unwrap(), "ES256");
    assert_eq!(info["active_version"].as_u64().unwrap(), 1);
    assert_eq!(info["jwks_keys"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn engine_jwks() {
    let engine = create_test_engine().await;
    let jwks = engine.jwks().unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["alg"].as_str().unwrap(), "ES256");
    assert_eq!(keys[0]["kty"].as_str().unwrap(), "EC");
    assert!(keys[0]["kid"].as_str().unwrap().contains("sentry-key"));
}

#[tokio::test]
async fn engine_key_rotate_force() {
    let engine = create_test_engine().await;

    let result = engine.key_rotate(true, false).await.unwrap();
    assert!(result.rotated);
    assert_eq!(result.key_version, 2);
    assert_eq!(result.previous_version, Some(1));

    // JWKS should have 2 keys now
    let jwks = engine.jwks().unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn engine_key_rotate_not_needed() {
    let engine = create_test_engine().await;

    // Without FORCE, rotation_days=90 means key is too new to rotate
    let result = engine.key_rotate(false, false).await.unwrap();
    assert!(!result.rotated);
    assert_eq!(result.key_version, 1);
}

#[tokio::test]
async fn engine_key_rotate_dryrun() {
    let engine = create_test_engine().await;

    let result = engine.key_rotate(true, true).await.unwrap();
    assert!(result.rotated);
    assert_eq!(result.key_version, 2);

    // Dryrun should not actually change the key
    let info = engine.key_info().unwrap();
    assert_eq!(info["active_version"].as_u64().unwrap(), 1);
    assert_eq!(info["total_versions"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn engine_multiple_rotations() {
    let engine = create_test_engine().await;

    engine.key_rotate(true, false).await.unwrap();
    engine.key_rotate(true, false).await.unwrap();
    engine.key_rotate(true, false).await.unwrap();

    let info = engine.key_info().unwrap();
    assert_eq!(info["active_version"].as_u64().unwrap(), 4);
    assert_eq!(info["total_versions"].as_u64().unwrap(), 4);

    // JWKS: 1 active + 3 draining
    let jwks = engine.jwks().unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 4);
}

// ── Policy versioning (LOW-13) ─────────────────────────────────────

#[tokio::test]
async fn engine_policy_create_sets_version_1() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "versioned".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };
    let created = engine.policy_create(policy, "admin").await.unwrap();
    assert_eq!(created.version, 1);

    let fetched = engine.policy_get("versioned").unwrap();
    assert_eq!(fetched.version, 1);
}

#[tokio::test]
async fn engine_policy_update_increments_version() {
    let engine = create_test_engine().await;

    // Permit-all so self-authorization passes for mutations
    let permit = shroudb_sentry_core::policy::Policy {
        name: "permit-all-ver".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 1000,
        ..Default::default()
    };
    engine.policy_create(permit, "admin").await.unwrap();

    let policy = shroudb_sentry_core::policy::Policy {
        name: "ver-test".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 5,
        ..Default::default()
    };
    engine.policy_create(policy, "admin").await.unwrap();

    let updates = shroudb_sentry_core::policy::Policy {
        effect: shroudb_acl::PolicyEffect::Deny,
        priority: 10,
        ..Default::default()
    };
    let updated = engine
        .policy_update("ver-test", updates, "admin")
        .await
        .unwrap();
    assert_eq!(updated.version, 2);

    // Update again
    let updates2 = shroudb_sentry_core::policy::Policy {
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 20,
        ..Default::default()
    };
    let updated2 = engine
        .policy_update("ver-test", updates2, "admin")
        .await
        .unwrap();
    assert_eq!(updated2.version, 3);
}

#[tokio::test]
async fn engine_policy_history_returns_all_versions() {
    let engine = create_test_engine().await;

    // Permit-all so self-authorization passes for mutations
    let permit = shroudb_sentry_core::policy::Policy {
        name: "permit-all-hist".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 1000,
        ..Default::default()
    };
    engine.policy_create(permit, "admin").await.unwrap();

    let policy = shroudb_sentry_core::policy::Policy {
        name: "hist-test".into(),
        description: "original".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 1,
        ..Default::default()
    };
    engine.policy_create(policy, "admin").await.unwrap();

    // Update twice
    let updates1 = shroudb_sentry_core::policy::Policy {
        description: "first update".into(),
        effect: shroudb_acl::PolicyEffect::Deny,
        priority: 2,
        ..Default::default()
    };
    engine
        .policy_update("hist-test", updates1, "admin")
        .await
        .unwrap();

    let updates2 = shroudb_sentry_core::policy::Policy {
        description: "second update".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        priority: 3,
        ..Default::default()
    };
    engine
        .policy_update("hist-test", updates2, "admin")
        .await
        .unwrap();

    // History should have 3 entries: v1 (archived), v2 (archived), v3 (current)
    let history = engine.policy_history("hist-test").await.unwrap();
    assert_eq!(history.len(), 3);

    assert_eq!(history[0].version, 1);
    assert_eq!(history[0].description, "original");
    assert_eq!(history[0].effect, shroudb_acl::PolicyEffect::Permit);

    assert_eq!(history[1].version, 2);
    assert_eq!(history[1].description, "first update");
    assert_eq!(history[1].effect, shroudb_acl::PolicyEffect::Deny);

    assert_eq!(history[2].version, 3);
    assert_eq!(history[2].description, "second update");
    assert_eq!(history[2].effect, shroudb_acl::PolicyEffect::Permit);
}

#[tokio::test]
async fn engine_policy_history_nonexistent_fails() {
    let engine = create_test_engine().await;
    let err = engine.policy_history("nonexistent").await;
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn engine_policy_history_no_updates() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "no-updates".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };
    engine.policy_create(policy, "admin").await.unwrap();

    // History should have just the current version (no archived versions)
    let history = engine.policy_history("no-updates").await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, 1);
}

// ── Audit configurability (LOW-14) ─────────────────────────────────

#[tokio::test]
async fn engine_require_audit_no_chronicle_fails() {
    let store = shroudb_storage::test_util::create_test_store("sentry-audit").await;

    let config = SentryConfig {
        require_audit: true,
        ..Default::default()
    };

    // No Chronicle configured
    let engine = SentryEngine::new(store, config, None).await.unwrap();

    // Create a policy so evaluation has something to work with
    let policy = shroudb_sentry_core::policy::Policy {
        name: "allow-all".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };
    engine.policy_create(policy, "admin").await.unwrap();

    let request = shroudb_acl::PolicyRequest {
        principal: shroudb_acl::PolicyPrincipal {
            id: "alice".into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: shroudb_acl::PolicyResource {
            id: "doc-1".into(),
            resource_type: "document".into(),
            attributes: Default::default(),
        },
        action: "read".into(),
    };

    // Should fail because require_audit=true but no Chronicle
    let result = engine.evaluate_request(&request).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("require_audit is true")
    );
}

#[tokio::test]
async fn engine_default_audit_mode_succeeds_without_chronicle() {
    let engine = create_test_engine().await;

    let policy = shroudb_sentry_core::policy::Policy {
        name: "allow-all".into(),
        effect: shroudb_acl::PolicyEffect::Permit,
        ..Default::default()
    };
    engine.policy_create(policy, "admin").await.unwrap();

    let request = shroudb_acl::PolicyRequest {
        principal: shroudb_acl::PolicyPrincipal {
            id: "alice".into(),
            roles: vec![],
            claims: Default::default(),
        },
        resource: shroudb_acl::PolicyResource {
            id: "doc-1".into(),
            resource_type: "document".into(),
            attributes: Default::default(),
        },
        action: "read".into(),
    };

    // Default (require_audit=false) succeeds without Chronicle
    let result = engine.evaluate_request(&request).await;
    assert!(result.is_ok());
}
