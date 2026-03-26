//! Configuration loading for ShrouDB Sentry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use shroudb_sentry_protocol::auth::{AuthPolicy, AuthRegistry};
use shroudb_storage::StorageEngineConfig;

#[derive(Debug, Default, Deserialize)]
pub struct SentryConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    #[serde(default)]
    pub policies: PoliciesConfig,
    #[serde(default)]
    pub evaluation: EvaluationConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_client_ca: Option<PathBuf>,
    pub rate_limit: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            http_bind: default_http_bind(),
            tls_cert: None,
            tls_key: None,
            tls_client_ca: None,
            rate_limit: None,
        }
    }
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:6799".parse().unwrap()
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:6800".parse().unwrap()
}

#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_fsync_mode")]
    pub wal_fsync_mode: String,
    #[serde(default = "default_fsync_interval")]
    pub wal_fsync_interval_ms: u64,
    #[serde(default = "default_segment_max")]
    pub wal_segment_max_bytes: u64,
    #[serde(default = "default_snapshot_entries")]
    pub snapshot_interval_entries: u64,
    #[serde(default = "default_snapshot_minutes")]
    pub snapshot_interval_minutes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            wal_fsync_mode: default_fsync_mode(),
            wal_fsync_interval_ms: default_fsync_interval(),
            wal_segment_max_bytes: default_segment_max(),
            snapshot_interval_entries: default_snapshot_entries(),
            snapshot_interval_minutes: default_snapshot_minutes(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./sentry-data")
}
fn default_fsync_mode() -> String {
    "batched".into()
}
fn default_fsync_interval() -> u64 {
    10
}
fn default_segment_max() -> u64 {
    67_108_864
}
fn default_snapshot_entries() -> u64 {
    100_000
}
fn default_snapshot_minutes() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_method")]
    pub method: String,
    #[serde(default)]
    pub policies: HashMap<String, PolicyConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: default_auth_method(),
            policies: HashMap::new(),
        }
    }
}

fn default_auth_method() -> String {
    "none".into()
}

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    pub token: String,
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SigningConfig {
    #[serde(default = "default_signing_mode")]
    pub mode: String,
    #[serde(default = "default_signing_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub drain_days: u32,
    #[serde(default = "default_decision_ttl")]
    pub decision_ttl_secs: u64,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            mode: default_signing_mode(),
            algorithm: default_signing_algorithm(),
            rotation_days: default_rotation_days(),
            drain_days: default_drain_days(),
            decision_ttl_secs: default_decision_ttl(),
        }
    }
}

fn default_signing_mode() -> String {
    "local".into()
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
fn default_decision_ttl() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct PoliciesConfig {
    #[serde(default = "default_policies_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_decision")]
    pub default_decision: String,
    #[serde(default)]
    pub watch: bool,
}

impl Default for PoliciesConfig {
    fn default() -> Self {
        Self {
            dir: default_policies_dir(),
            default_decision: default_decision(),
            watch: false,
        }
    }
}

fn default_policies_dir() -> PathBuf {
    PathBuf::from("./policies")
}
fn default_decision() -> String {
    "deny".into()
}

#[derive(Debug, Deserialize)]
pub struct EvaluationConfig {
    #[serde(default)]
    pub cache_enabled: bool,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: usize,
}

impl Default for EvaluationConfig {
    fn default() -> Self {
        Self {
            cache_enabled: false,
            cache_ttl_secs: default_cache_ttl(),
            max_batch_size: default_max_batch_size(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    60
}
fn default_max_batch_size() -> usize {
    100
}

/// Load and parse config file with env var interpolation.
pub fn load(path: &Path) -> anyhow::Result<Option<SentryConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let expanded = expand_env_vars(&contents);
    let config: SentryConfig = toml::from_str(&expanded)?;
    Ok(Some(config))
}

/// Expand `${VAR_NAME}` patterns in a string.
fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let value = std::env::var(var_name).unwrap_or_default();
            result = format!(
                "{}{}{}",
                &result[..start],
                value,
                &result[start + end + 1..]
            );
        } else {
            break;
        }
    }
    result
}

/// Convert storage config to engine config.
pub fn to_engine_config(cfg: &SentryConfig) -> StorageEngineConfig {
    StorageEngineConfig {
        data_dir: cfg.storage.data_dir.clone(),
        fsync_mode: match cfg.storage.wal_fsync_mode.as_str() {
            "per_write" => shroudb_storage::FsyncMode::PerWrite,
            "periodic" => shroudb_storage::FsyncMode::Periodic {
                interval_ms: cfg.storage.wal_fsync_interval_ms,
            },
            _ => shroudb_storage::FsyncMode::Batched {
                interval_ms: cfg.storage.wal_fsync_interval_ms,
            },
        },
        max_segment_bytes: cfg.storage.wal_segment_max_bytes,
        snapshot_entry_threshold: cfg.storage.snapshot_interval_entries,
        snapshot_time_threshold_secs: cfg.storage.snapshot_interval_minutes * 60,
        ..Default::default()
    }
}

/// Parse JwtAlgorithm from config string.
pub fn parse_algorithm(s: &str) -> anyhow::Result<shroudb_crypto::JwtAlgorithm> {
    match s.to_uppercase().as_str() {
        "ES256" => Ok(shroudb_crypto::JwtAlgorithm::ES256),
        "ES384" => Ok(shroudb_crypto::JwtAlgorithm::ES384),
        "RS256" => Ok(shroudb_crypto::JwtAlgorithm::RS256),
        "RS384" => Ok(shroudb_crypto::JwtAlgorithm::RS384),
        "RS512" => Ok(shroudb_crypto::JwtAlgorithm::RS512),
        "EDDSA" | "ED25519" => Ok(shroudb_crypto::JwtAlgorithm::EdDSA),
        _ => anyhow::bail!("unsupported signing algorithm: {s}"),
    }
}

/// Parse default decision from config string.
pub fn parse_default_decision(s: &str) -> anyhow::Result<shroudb_sentry_core::policy::Effect> {
    match s.to_lowercase().as_str() {
        "deny" => Ok(shroudb_sentry_core::policy::Effect::Deny),
        "permit" => Ok(shroudb_sentry_core::policy::Effect::Permit),
        _ => anyhow::bail!("invalid default_decision: {s} (expected 'deny' or 'permit')"),
    }
}

/// Build the auth registry from config.
pub fn build_auth_registry(cfg: &SentryConfig) -> AuthRegistry {
    if cfg.auth.method == "none" {
        return AuthRegistry::permissive();
    }

    let policies: HashMap<String, AuthPolicy> = cfg
        .auth
        .policies
        .iter()
        .map(|(name, pc)| {
            let policy = AuthPolicy {
                name: name.clone(),
                commands: if pc.commands.is_empty() {
                    vec!["*".into()]
                } else {
                    pc.commands.clone()
                },
            };
            (pc.token.clone(), policy)
        })
        .collect();

    AuthRegistry::new(policies, true)
}
