//! Integration tests for ShrouDB Sentry — policy-based authorization.
//!
//! Handler-level tests: exercises every command through the CommandDispatcher
//! without network overhead. Tests EVALUATE, POLICY_RELOAD/LIST/INFO,
//! KEY_ROTATE/INFO, HEALTH, plus error cases, WAL recovery, and auth.

use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_crypto::SecretBytes;
use shroudb_storage::{
    MasterKeySource, RecoveryMode, StorageEngine, StorageEngineConfig, StorageError,
};

use shroudb_sentry_core::policy::{Effect, PolicySet};
use shroudb_sentry_core::signing::{SigningKeyring, SigningMode};

use shroudb_sentry_protocol::auth::{AuthPolicy, AuthRegistry};
use shroudb_sentry_protocol::recovery::{replay_sentry_wal, seed_signing_key};
use shroudb_sentry_protocol::signing_index::SigningIndex;
use shroudb_sentry_protocol::{Command, CommandDispatcher, CommandResponse, ResponseValue};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TestKeySource;

impl MasterKeySource for TestKeySource {
    fn load(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, StorageError>> + Send + '_>>
    {
        Box::pin(async { Ok(SecretBytes::new(vec![0x42; 32])) })
    }

    fn source_name(&self) -> &str {
        "test"
    }
}

fn test_config(dir: &Path) -> StorageEngineConfig {
    StorageEngineConfig {
        data_dir: dir.to_path_buf(),
        recovery_mode: RecoveryMode::Recover,
        fsync_mode: shroudb_storage::FsyncMode::PerWrite,
        ..Default::default()
    }
}

async fn open_engine(dir: &Path) -> StorageEngine {
    StorageEngine::open(test_config(dir), &TestKeySource)
        .await
        .unwrap()
}

fn make_signing_index() -> SigningIndex {
    let keyring = SigningKeyring {
        name: "sentry".into(),
        algorithm: shroudb_crypto::JwtAlgorithm::ES256,
        rotation_days: 90,
        drain_days: 30,
        decision_ttl_secs: 300,
        key_versions: Vec::new(),
    };
    SigningIndex::new(keyring, SigningMode::Jwt)
}

async fn setup(dir: &Path) -> Arc<CommandDispatcher> {
    setup_with_policies(dir, PolicySet::load_dir(Path::new("/nonexistent")).unwrap()).await
}

async fn setup_with_policies(dir: &Path, policy_set: PolicySet) -> Arc<CommandDispatcher> {
    let engine = Arc::new(open_engine(dir).await);
    let signing_index = Arc::new(make_signing_index());
    let auth = Arc::new(AuthRegistry::permissive());
    let policies_dir = dir.join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();

    replay_sentry_wal(&engine, &signing_index, "sentry")
        .await
        .unwrap();
    seed_signing_key(&engine, &signing_index, "sentry")
        .await
        .unwrap();

    Arc::new(CommandDispatcher::new(
        engine,
        Arc::new(std::sync::RwLock::new(policy_set)),
        signing_index,
        auth,
        Effect::Deny,
        policies_dir,
    ))
}

fn eval_request_json(principal_id: &str, roles: &[&str], resource_type: &str, action: &str) -> String {
    let roles_json: Vec<String> = roles.iter().map(|r| format!("\"{r}\"")).collect();
    format!(
        r#"{{"principal":{{"id":"{principal_id}","roles":[{}]}},"resource":{{"id":"res-1","type":"{resource_type}"}},"action":"{action}"}}"#,
        roles_json.join(",")
    )
}

fn is_success(resp: &CommandResponse) -> bool {
    matches!(resp, CommandResponse::Success(_))
}

fn is_error(resp: &CommandResponse) -> bool {
    matches!(resp, CommandResponse::Error(_))
}

fn error_code(resp: &CommandResponse) -> &'static str {
    match resp {
        CommandResponse::Error(e) => e.error_code(),
        _ => panic!("expected error, got success"),
    }
}

fn field_str(resp: &CommandResponse, key: &str) -> String {
    match resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                ResponseValue::String(s) => s.clone(),
                ResponseValue::Integer(n) => n.to_string(),
                ResponseValue::Boolean(b) => b.to_string(),
                other => format!("{other:?}"),
            })
            .unwrap_or_else(|| {
                let keys: Vec<&str> = map.fields.iter().map(|(k, _)| k.as_str()).collect();
                panic!("field '{key}' not found, available: {keys:?}")
            }),
        other => panic!("expected Success, got: {other:?}"),
    }
}

fn field_int(resp: &CommandResponse, key: &str) -> i64 {
    match resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                ResponseValue::Integer(n) => *n,
                other => panic!("field '{key}' is not an integer: {other:?}"),
            })
            .unwrap_or_else(|| panic!("field '{key}' not found")),
        other => panic!("expected Success, got: {other:?}"),
    }
}

fn field_array(resp: &CommandResponse, key: &str) -> Vec<ResponseValue> {
    match resp {
        CommandResponse::Success(map) => map
            .fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| match v {
                ResponseValue::Array(arr) => arr.clone(),
                other => panic!("field '{key}' is not an array: {other:?}"),
            })
            .unwrap_or_else(|| panic!("field '{key}' not found")),
        other => panic!("expected Success, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// HEALTH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::Health, None).await;
    assert!(is_success(&resp), "HEALTH should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "status"), "OK");
}

// ---------------------------------------------------------------------------
// PING
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ping_returns_pong() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::Ping, None).await;
    assert!(is_success(&resp), "PING should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "message"), "PONG");
}

// ---------------------------------------------------------------------------
// COMMAND LIST
// ---------------------------------------------------------------------------

#[tokio::test]
async fn command_list_returns_all_verbs() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::CommandList, None).await;
    assert!(is_success(&resp), "COMMAND LIST should succeed: {resp:?}");
    let count = field_int(&resp, "count");
    assert!(count >= 10, "should have at least 10 commands, got {count}");
}

// ---------------------------------------------------------------------------
// KEY_INFO / KEY_ROTATE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_info_returns_signing_key() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::KeyInfo, None).await;
    assert!(is_success(&resp), "KEY_INFO should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "status"), "OK");
    assert_eq!(field_str(&resp, "name"), "sentry");
    // Should have at least one key version after seeding
    let versions = field_array(&resp, "key_versions");
    assert!(!versions.is_empty(), "should have at least 1 key version");
}

#[tokio::test]
async fn key_rotate_creates_new_version() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    // Check initial state
    let info1 = dispatcher.execute(Command::KeyInfo, None).await;
    let versions1 = field_array(&info1, "key_versions");
    let count1 = versions1.len();

    // Rotate (force)
    let rot_resp = dispatcher
        .execute(
            Command::KeyRotate {
                force: true,
                dryrun: false,
            },
            None,
        )
        .await;
    assert!(is_success(&rot_resp), "KEY_ROTATE should succeed: {rot_resp:?}");
    assert_eq!(field_str(&rot_resp, "rotated"), "true");

    // Check new state — should have more key versions
    let info2 = dispatcher.execute(Command::KeyInfo, None).await;
    let versions2 = field_array(&info2, "key_versions");
    assert!(
        versions2.len() > count1,
        "should have more key versions after rotation"
    );
}

#[tokio::test]
async fn key_rotate_dryrun_does_not_change_version() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let info1 = dispatcher.execute(Command::KeyInfo, None).await;
    let count1 = field_array(&info1, "key_versions").len();

    let rot_resp = dispatcher
        .execute(
            Command::KeyRotate {
                force: true,
                dryrun: true,
            },
            None,
        )
        .await;
    assert!(is_success(&rot_resp), "KEY_ROTATE DRYRUN should succeed: {rot_resp:?}");
    assert_eq!(field_str(&rot_resp, "dryrun"), "true");

    let info2 = dispatcher.execute(Command::KeyInfo, None).await;
    let count2 = field_array(&info2, "key_versions").len();
    assert_eq!(count1, count2, "dryrun should not change key versions");
}

// ---------------------------------------------------------------------------
// POLICY_LIST / POLICY_INFO / POLICY_RELOAD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_list_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher.execute(Command::PolicyList, None).await;
    assert!(is_success(&resp), "POLICY_LIST should succeed: {resp:?}");
    assert_eq!(field_int(&resp, "count"), 0);
}

#[tokio::test]
async fn policy_reload_from_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    // Write a policy file to the policies dir
    let policies_dir = tmp.path().join("policies");
    std::fs::write(
        policies_dir.join("test.toml"),
        r#"
[[policies]]
name = "allow-admins"
effect = "permit"
priority = 100

[policies.principal]
role = ["admin"]
"#,
    )
    .unwrap();

    // Reload
    let reload_resp = dispatcher.execute(Command::PolicyReload, None).await;
    assert!(is_success(&reload_resp), "POLICY_RELOAD should succeed: {reload_resp:?}");
    assert_eq!(field_int(&reload_resp, "policies_loaded"), 1);

    // Verify via POLICY_LIST
    let list_resp = dispatcher.execute(Command::PolicyList, None).await;
    assert_eq!(field_int(&list_resp, "count"), 1);
}

#[tokio::test]
async fn policy_info_returns_details() {
    let tmp = tempfile::tempdir().unwrap();

    // Create policies before setup
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(
        policies_dir.join("test.toml"),
        r#"
[[policies]]
name = "allow-all"
description = "Allow everything"
effect = "permit"
priority = 50
"#,
    )
    .unwrap();

    let ps = PolicySet::load_dir(&policies_dir).unwrap();
    let dispatcher = setup_with_policies(tmp.path(), ps).await;

    let resp = dispatcher
        .execute(Command::PolicyInfo { name: "allow-all".into() }, None)
        .await;
    assert!(is_success(&resp), "POLICY_INFO should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "name"), "allow-all");
}

#[tokio::test]
async fn policy_info_nonexistent_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher
        .execute(Command::PolicyInfo { name: "nonexistent".into() }, None)
        .await;
    assert!(is_error(&resp), "POLICY_INFO for unknown policy should error: {resp:?}");
    assert_eq!(error_code(&resp), "NOTFOUND");
}

// ---------------------------------------------------------------------------
// EVALUATE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evaluate_with_matching_permit_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(
        policies_dir.join("test.toml"),
        r#"
[[policies]]
name = "allow-all"
effect = "permit"
priority = 0
"#,
    )
    .unwrap();

    let ps = PolicySet::load_dir(&policies_dir).unwrap();
    let dispatcher = setup_with_policies(tmp.path(), ps).await;

    let json = eval_request_json("user1", &["admin"], "document", "read");
    let resp = dispatcher
        .execute(Command::Evaluate { json }, None)
        .await;

    assert!(is_success(&resp), "EVALUATE should succeed: {resp:?}");
    assert_eq!(field_str(&resp, "decision"), "permit");
    assert_eq!(field_str(&resp, "policy"), "allow-all");
    // Should contain a signed JWT token
    let token = field_str(&resp, "token");
    assert!(!token.is_empty(), "should return a signed decision token");
}

#[tokio::test]
async fn evaluate_default_deny_when_no_policy_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    // No policies loaded → default decision (Deny)
    let json = eval_request_json("user1", &[], "document", "read");
    let resp = dispatcher
        .execute(Command::Evaluate { json }, None)
        .await;

    assert!(is_success(&resp), "EVALUATE should succeed even with deny: {resp:?}");
    assert_eq!(field_str(&resp, "decision"), "deny");
}

#[tokio::test]
async fn evaluate_role_scoped_permit() {
    let tmp = tempfile::tempdir().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(
        policies_dir.join("test.toml"),
        r#"
[[policies]]
name = "admin-only"
effect = "permit"
priority = 10

[policies.principal]
role = ["admin"]
"#,
    )
    .unwrap();

    let ps = PolicySet::load_dir(&policies_dir).unwrap();
    let dispatcher = setup_with_policies(tmp.path(), ps).await;

    // Admin should be permitted
    let admin_json = eval_request_json("admin1", &["admin"], "doc", "write");
    let admin_resp = dispatcher
        .execute(Command::Evaluate { json: admin_json }, None)
        .await;
    assert_eq!(field_str(&admin_resp, "decision"), "permit");

    // Non-admin should be denied (no matching policy → default deny)
    let user_json = eval_request_json("user1", &["viewer"], "doc", "write");
    let user_resp = dispatcher
        .execute(Command::Evaluate { json: user_json }, None)
        .await;
    assert_eq!(field_str(&user_resp, "decision"), "deny");
}

#[tokio::test]
async fn evaluate_invalid_json_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dispatcher = setup(tmp.path()).await;

    let resp = dispatcher
        .execute(
            Command::Evaluate {
                json: "not json!".into(),
            },
            None,
        )
        .await;

    assert!(is_error(&resp), "invalid JSON should error: {resp:?}");
    assert_eq!(error_code(&resp), "BADARG");
}

// ---------------------------------------------------------------------------
// WAL RECOVERY
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wal_recovery_persists_signing_keys() {
    let tmp = tempfile::tempdir().unwrap();

    // Phase 1: setup with seeded key, then rotate
    {
        let dispatcher = setup(tmp.path()).await;

        // Rotate to create a second key
        let rot = dispatcher
            .execute(
                Command::KeyRotate {
                    force: true,
                    dryrun: false,
                },
                None,
            )
            .await;
        assert!(is_success(&rot), "rotation should succeed: {rot:?}");

        let info = dispatcher.execute(Command::KeyInfo, None).await;
        let versions = field_array(&info, "key_versions");
        assert!(versions.len() >= 2, "should have at least 2 key versions after rotation");
    }

    // Phase 2: reopen — key versions should be recovered
    {
        let engine = Arc::new(open_engine(tmp.path()).await);
        let signing_index = Arc::new(make_signing_index());
        let auth = Arc::new(AuthRegistry::permissive());
        let policies_dir = tmp.path().join("policies");

        // Replay WAL (should recover key versions without re-seeding)
        let replayed = replay_sentry_wal(&engine, &signing_index, "sentry")
            .await
            .unwrap();
        assert!(replayed > 0, "should have replayed key version entries");

        // Should NOT need seeding since keys were recovered
        let seeded = seed_signing_key(&engine, &signing_index, "sentry")
            .await
            .unwrap();
        assert!(!seeded, "should not need to seed — keys recovered from WAL");

        let dispatcher = Arc::new(CommandDispatcher::new(
            engine,
            Arc::new(std::sync::RwLock::new(
                PolicySet::load_dir(Path::new("/nonexistent")).unwrap(),
            )),
            signing_index,
            auth,
            Effect::Deny,
            policies_dir,
        ));

        // Should still be able to evaluate (signing works)
        let json = eval_request_json("user1", &[], "doc", "read");
        let resp = dispatcher
            .execute(Command::Evaluate { json }, None)
            .await;
        assert!(is_success(&resp), "EVALUATE after recovery should work: {resp:?}");
        assert!(!field_str(&resp, "token").is_empty());
    }
}

// ---------------------------------------------------------------------------
// AUTH ENFORCEMENT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_required_without_policy_returns_denied() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_engine(tmp.path()).await);
    let signing_index = Arc::new(make_signing_index());
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();

    replay_sentry_wal(&engine, &signing_index, "sentry").await.unwrap();
    seed_signing_key(&engine, &signing_index, "sentry").await.unwrap();

    let mut policies = HashMap::new();
    policies.insert("valid-token".to_string(), AuthPolicy::system());
    let auth = Arc::new(AuthRegistry::new(policies, true));

    let dispatcher = CommandDispatcher::new(
        engine,
        Arc::new(std::sync::RwLock::new(
            PolicySet::load_dir(Path::new("/nonexistent")).unwrap(),
        )),
        signing_index,
        auth,
        Effect::Deny,
        policies_dir,
    );

    // EVALUATE without auth → denied
    let json = eval_request_json("user1", &[], "doc", "read");
    let resp = dispatcher
        .execute(Command::Evaluate { json }, None)
        .await;
    assert!(is_error(&resp));
    assert_eq!(error_code(&resp), "DENIED");
}

#[tokio::test]
async fn auth_health_always_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = Arc::new(open_engine(tmp.path()).await);
    let signing_index = Arc::new(make_signing_index());
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();

    replay_sentry_wal(&engine, &signing_index, "sentry").await.unwrap();
    seed_signing_key(&engine, &signing_index, "sentry").await.unwrap();

    let auth = Arc::new(AuthRegistry::new(HashMap::new(), true));

    let dispatcher = CommandDispatcher::new(
        engine,
        Arc::new(std::sync::RwLock::new(
            PolicySet::load_dir(Path::new("/nonexistent")).unwrap(),
        )),
        signing_index,
        auth,
        Effect::Deny,
        policies_dir,
    );

    let resp = dispatcher.execute(Command::Health, None).await;
    assert!(is_success(&resp), "HEALTH should always be allowed");
}
