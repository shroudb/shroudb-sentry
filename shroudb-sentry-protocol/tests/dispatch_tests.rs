use std::sync::Arc;

use shroudb_sentry_core::signing::SigningAlgorithm;
use shroudb_sentry_engine::engine::{SentryConfig, SentryEngine};
use shroudb_sentry_protocol::commands::{SentryCommand, parse_command};
use shroudb_sentry_protocol::dispatch::dispatch;
use shroudb_sentry_protocol::response::SentryResponse;
use shroudb_storage::{EmbeddedStore, MasterKeySource, StorageEngine, StorageEngineConfig};

struct EphemeralKey;

impl MasterKeySource for EphemeralKey {
    fn source_name(&self) -> &str {
        "test"
    }

    fn load<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<shroudb_crypto::SecretBytes, shroudb_storage::StorageError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(shroudb_crypto::SecretBytes::new(vec![0x42u8; 32])) })
    }
}

async fn create_test_engine() -> SentryEngine<EmbeddedStore> {
    let dir = tempfile::tempdir().unwrap().keep();
    let config = StorageEngineConfig {
        data_dir: dir,
        ..Default::default()
    };
    let storage = StorageEngine::open(config, &EphemeralKey).await.unwrap();
    let store = Arc::new(EmbeddedStore::new(Arc::new(storage), "sentry-test"));

    SentryEngine::new(
        store,
        SentryConfig {
            signing_algorithm: SigningAlgorithm::ES256,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn assert_ok(resp: &SentryResponse) {
    match resp {
        SentryResponse::Ok(_) => {}
        SentryResponse::Error(e) => panic!("expected Ok, got Error: {e}"),
    }
}

fn assert_err(resp: &SentryResponse) {
    assert!(
        matches!(resp, SentryResponse::Error(_)),
        "expected Error, got Ok"
    );
}

fn get_json(resp: &SentryResponse) -> &serde_json::Value {
    match resp {
        SentryResponse::Ok(v) => v,
        SentryResponse::Error(e) => panic!("expected Ok, got Error: {e}"),
    }
}

// ── Dispatch with no auth (all commands allowed) ────────────────────

#[tokio::test]
async fn dispatch_health() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["HEALTH"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    let json = get_json(&resp);
    assert_eq!(json["status"].as_str().unwrap(), "ok");
    assert!(json["policy_count"].as_u64().is_some());
}

#[tokio::test]
async fn dispatch_ping() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["PING"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
}

#[tokio::test]
async fn dispatch_command_list() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["COMMAND", "LIST"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    let json = get_json(&resp);
    let commands = json["commands"].as_array().unwrap();
    assert!(commands.len() >= 13);
}

#[tokio::test]
async fn dispatch_policy_lifecycle() {
    let engine = create_test_engine().await;

    // Create
    let cmd = parse_command(&[
        "POLICY",
        "CREATE",
        "test-pol",
        r#"{"effect":"permit","priority":5}"#,
    ])
    .unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["name"].as_str().unwrap(), "test-pol");

    // Get
    let cmd = parse_command(&["POLICY", "GET", "test-pol"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["effect"].as_str().unwrap(), "permit");

    // List
    let cmd = parse_command(&["POLICY", "LIST"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["count"].as_u64().unwrap(), 1);

    // Update
    let cmd = parse_command(&[
        "POLICY",
        "UPDATE",
        "test-pol",
        r#"{"effect":"deny","priority":20}"#,
    ])
    .unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["effect"].as_str().unwrap(), "deny");

    // Delete
    let cmd = parse_command(&["POLICY", "DELETE", "test-pol"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);

    // Get after delete should error
    let cmd = parse_command(&["POLICY", "GET", "test-pol"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_evaluate() {
    let engine = create_test_engine().await;

    // Create a policy
    let cmd = parse_command(&[
        "POLICY",
        "CREATE",
        "readers",
        r#"{"effect":"permit","priority":10,"action":{"names":["read"]}}"#,
    ])
    .unwrap();
    dispatch(&engine, cmd, None).await;

    // Evaluate matching request
    let cmd = parse_command(&[
        "EVALUATE",
        r#"{"principal":{"id":"alice"},"resource":{"id":"x","type":"doc"},"action":"read"}"#,
    ])
    .unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    let json = get_json(&resp);
    assert_eq!(json["decision"].as_str().unwrap(), "permit");
    assert!(!json["token"].as_str().unwrap().is_empty());

    // Evaluate non-matching request
    let cmd = parse_command(&[
        "EVALUATE",
        r#"{"principal":{"id":"alice"},"resource":{"id":"x","type":"doc"},"action":"write"}"#,
    ])
    .unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["decision"].as_str().unwrap(), "deny");
}

#[tokio::test]
async fn dispatch_evaluate_invalid_json() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["EVALUATE", "not-json"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_key_info() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["KEY", "INFO"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert_eq!(get_json(&resp)["algorithm"].as_str().unwrap(), "ES256");
}

#[tokio::test]
async fn dispatch_jwks() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["JWKS"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert!(!get_json(&resp)["keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn dispatch_key_rotate() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["KEY", "ROTATE", "FORCE"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_ok(&resp);
    assert!(get_json(&resp)["rotated"].as_bool().unwrap());
}

#[tokio::test]
async fn dispatch_policy_create_invalid_name() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["POLICY", "CREATE", "bad name!", r#"{"effect":"permit"}"#]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_policy_create_invalid_json() {
    let engine = create_test_engine().await;
    let cmd = parse_command(&["POLICY", "CREATE", "good-name", "not-json"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_policy_update_invalid_json() {
    let engine = create_test_engine().await;

    // Create first
    let cmd = parse_command(&["POLICY", "CREATE", "upd", r#"{"effect":"permit"}"#]).unwrap();
    dispatch(&engine, cmd, None).await;

    // Update with bad JSON
    let cmd = parse_command(&["POLICY", "UPDATE", "upd", "not-json"]).unwrap();
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_auth_returns_error() {
    let engine = create_test_engine().await;
    // AUTH should never reach dispatch — connection layer handles it
    let cmd = SentryCommand::Auth {
        token: "test".into(),
    };
    let resp = dispatch(&engine, cmd, None).await;
    assert_err(&resp);
}

// ── ACL enforcement in dispatch ─────────────────────────────────────

#[tokio::test]
async fn dispatch_acl_admin_required() {
    let engine = create_test_engine().await;

    // Non-admin context
    let ctx = shroudb_acl::AuthContext::tenant(
        "t",
        "actor",
        vec![shroudb_acl::Grant {
            namespace: "sentry.policies.*".into(),
            scopes: vec![shroudb_acl::Scope::Read],
        }],
        None,
    );

    // POLICY CREATE requires Admin
    let cmd = parse_command(&["POLICY", "CREATE", "test", r#"{"effect":"permit"}"#]).unwrap();
    let resp = dispatch(&engine, cmd, Some(&ctx)).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_acl_namespace_check() {
    let engine = create_test_engine().await;

    // Context with no grants
    let ctx = shroudb_acl::AuthContext::tenant("t", "actor", vec![], None);

    // POLICY LIST requires sentry.policies.* read
    let cmd = parse_command(&["POLICY", "LIST"]).unwrap();
    let resp = dispatch(&engine, cmd, Some(&ctx)).await;
    assert_err(&resp);

    // EVALUATE requires sentry.evaluate.* read
    let cmd = parse_command(&[
        "EVALUATE",
        r#"{"principal":{"id":"x"},"resource":{"id":"y","type":"z"},"action":"a"}"#,
    ])
    .unwrap();
    let resp = dispatch(&engine, cmd, Some(&ctx)).await;
    assert_err(&resp);
}

#[tokio::test]
async fn dispatch_acl_none_commands_pass() {
    let engine = create_test_engine().await;

    // Empty grants context — HEALTH/PING/JWKS/KEY INFO should still work
    let ctx = shroudb_acl::AuthContext::tenant("t", "actor", vec![], None);

    for args in [
        vec!["HEALTH"],
        vec!["PING"],
        vec!["JWKS"],
        vec!["KEY", "INFO"],
        vec!["COMMAND", "LIST"],
    ] {
        let cmd = parse_command(&args.to_vec()).unwrap();
        let resp = dispatch(&engine, cmd, Some(&ctx)).await;
        assert_ok(&resp);
    }
}
