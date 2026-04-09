use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

#[derive(Debug, Deserialize)]
pub struct SentryServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default)]
    pub policies: HashMap<String, PolicySeedConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    pub log_level: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            log_level: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6799".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Remote store URI. Used when `mode = "remote"`.
    pub uri: Option<String>,
}

impl StoreConfig {
    /// Validates the store config mode is supported.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.mode.as_str() {
            "embedded" => Ok(()),
            "remote" => {
                let _uri = self
                    .uri
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("remote mode requires a uri"))?;
                anyhow::bail!("remote store mode is not yet implemented")
            }
            other => anyhow::bail!("unknown store mode: {other}"),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".into()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./sentry-data")
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_signing_algorithm")]
    pub signing_algorithm: String,
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default = "default_decision_ttl_secs")]
    pub decision_ttl_secs: u64,
    #[serde(default = "default_scheduler_interval_secs")]
    pub scheduler_interval_secs: u64,
    #[serde(default)]
    pub require_audit: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            signing_algorithm: default_signing_algorithm(),
            rotation_days: default_rotation_days(),
            drain_days: default_drain_days(),
            decision_ttl_secs: default_decision_ttl_secs(),
            scheduler_interval_secs: default_scheduler_interval_secs(),
            require_audit: false,
        }
    }
}

fn default_signing_algorithm() -> String {
    "ES256".into()
}
fn default_rotation_days() -> u32 {
    90
}
fn default_drain_days() -> u32 {
    30
}
fn default_decision_ttl_secs() -> u64 {
    300
}
fn default_scheduler_interval_secs() -> u64 {
    3600
}

/// A policy seed from config (simplified for TOML).
#[derive(Debug, Deserialize)]
pub struct PolicySeedConfig {
    pub effect: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub principal_roles: Vec<String>,
    #[serde(default)]
    pub resource_type: String,
    #[serde(default)]
    pub action_names: Vec<String>,
}

pub fn load_config(path: Option<&str>) -> anyhow::Result<SentryServerConfig> {
    match path {
        Some(p) => {
            let content = std::fs::read_to_string(p)?;
            Ok(toml::from_str(&content)?)
        }
        None => Ok(toml::from_str("")?),
    }
}
