use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use shroudb_sentry_client::SentryClient;

pub struct TestServer {
    child: Child,
    pub tcp_addr: String,
    _data_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
}

#[derive(Default)]
pub struct TestServerConfig {
    pub tokens: Vec<TestToken>,
    pub policies: Vec<TestPolicySeed>,
}

pub struct TestToken {
    pub raw: String,
    pub tenant: String,
    pub actor: String,
    pub platform: bool,
    pub grants: Vec<TestGrant>,
}

pub struct TestGrant {
    pub namespace: String,
    pub scopes: Vec<String>,
}

pub struct TestPolicySeed {
    pub name: String,
    pub effect: String,
    pub priority: i32,
    pub principal_roles: Vec<String>,
    pub resource_type: String,
    pub action_names: Vec<String>,
}

impl TestServer {
    pub async fn start() -> Option<Self> {
        // Default config includes a permit-all seed so that
        // self-authorization does not block policy mutations in tests
        Self::start_with_config(TestServerConfig::with_self_auth_permit()).await
    }

    pub async fn start_with_config(config: TestServerConfig) -> Option<Self> {
        let binary = find_binary()?;
        let tcp_port = free_port();
        let tcp_addr = format!("127.0.0.1:{tcp_port}");
        let data_dir = tempfile::tempdir().ok()?;
        let config_dir = tempfile::tempdir().ok()?;

        let config_path = config_dir.path().join("config.toml");
        let toml = generate_config(&tcp_addr, &config);
        std::fs::write(&config_path, toml).ok()?;

        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let mut server = TestServer {
            child,
            tcp_addr: tcp_addr.clone(),
            _data_dir: data_dir,
            _config_dir: config_dir,
        };

        // Poll for readiness
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("TestServer: startup deadline exceeded");
                return None;
            }
            if server.child.try_wait().ok().flatten().is_some() {
                eprintln!("TestServer: process exited during startup");
                return None;
            }
            if let Ok(client) = SentryClient::connect(&tcp_addr).await
                && client.health().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Some(server)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        PathBuf::from(manifest_dir).join("../target/debug/shroudb-sentry"),
        PathBuf::from(manifest_dir).join("target/debug/shroudb-sentry"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral port addr")
        .port()
}

fn generate_config(tcp_bind: &str, config: &TestServerConfig) -> String {
    let mut toml = format!("[server]\ntcp_bind = \"{tcp_bind}\"\n\n[store]\nmode = \"embedded\"\n");

    // Auth tokens
    if !config.tokens.is_empty() {
        toml.push_str("\n[auth]\nmethod = \"token\"\n\n");
        for token in &config.tokens {
            toml.push_str(&format!(
                "[auth.tokens.\"{}\"]\ntenant = \"{}\"\nactor = \"{}\"\nplatform = {}\n",
                token.raw, token.tenant, token.actor, token.platform
            ));
            if !token.grants.is_empty() {
                toml.push_str("grants = [\n");
                for grant in &token.grants {
                    let scopes: Vec<String> =
                        grant.scopes.iter().map(|s| format!("\"{s}\"")).collect();
                    toml.push_str(&format!(
                        "  {{ namespace = \"{}\", scopes = [{}] }},\n",
                        grant.namespace,
                        scopes.join(", ")
                    ));
                }
                toml.push_str("]\n");
            }
            toml.push('\n');
        }
    }

    // Seed policies
    for seed in &config.policies {
        toml.push_str(&format!("\n[policies.\"{}\"]\n", seed.name));
        toml.push_str(&format!("effect = \"{}\"\n", seed.effect));
        toml.push_str(&format!("priority = {}\n", seed.priority));
        if !seed.principal_roles.is_empty() {
            let roles: Vec<String> = seed
                .principal_roles
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect();
            toml.push_str(&format!("principal_roles = [{}]\n", roles.join(", ")));
        }
        if !seed.resource_type.is_empty() {
            toml.push_str(&format!("resource_type = \"{}\"\n", seed.resource_type));
        }
        if !seed.action_names.is_empty() {
            let actions: Vec<String> = seed
                .action_names
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect();
            toml.push_str(&format!("action_names = [{}]\n", actions.join(", ")));
        }
    }

    toml
}

impl TestServerConfig {
    /// Default config with a high-priority permit policy scoped to
    /// sentry.policies so self-authorization permits policy mutations
    /// in tests without affecting general evaluation results.
    pub fn with_self_auth_permit() -> Self {
        TestServerConfig {
            policies: vec![TestPolicySeed {
                name: "self-auth-permit".to_string(),
                effect: "permit".to_string(),
                priority: 1000,
                principal_roles: vec![],
                resource_type: "sentry.policies".to_string(),
                action_names: vec![],
            }],
            ..Default::default()
        }
    }
}

pub fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![
                    TestGrant {
                        namespace: "sentry.policies.*".to_string(),
                        scopes: vec!["read".to_string(), "write".to_string()],
                    },
                    TestGrant {
                        namespace: "sentry.evaluate.*".to_string(),
                        scopes: vec!["read".to_string()],
                    },
                ],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "sentry.policies.*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        policies: vec![TestPolicySeed {
            name: "self-auth-permit".to_string(),
            effect: "permit".to_string(),
            priority: 1000,
            principal_roles: vec![],
            resource_type: "sentry.policies".to_string(),
            action_names: vec![],
        }],
    }
}
