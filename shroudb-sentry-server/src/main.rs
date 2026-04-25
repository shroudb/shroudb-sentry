mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_sentry_core::signing::SigningAlgorithm;
use shroudb_sentry_engine::engine::{SentryConfig, SentryEngine};
use shroudb_store::Store;

use crate::config::{SentryServerConfig, load_config};

#[derive(Parser)]
#[command(name = "shroudb-sentry", about = "ShrouDB Sentry authorization engine")]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', long, env = "SENTRY_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config)
    #[arg(long, env = "SENTRY_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config)
    #[arg(long, env = "SENTRY_TCP_BIND")]
    tcp_bind: Option<String>,

    /// Log level
    #[arg(long, default_value = "info", env = "LOG_LEVEL")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Apply CLI overrides
    if let Some(ref data_dir) = cli.data_dir {
        cfg.store.data_dir = data_dir.into();
    }
    if let Some(ref tcp_bind) = cli.tcp_bind {
        cfg.server.tcp_bind = tcp_bind.parse()?;
    }
    if cfg.server.log_level.is_none() {
        cfg.server.log_level = Some(cli.log_level.clone());
    }

    // Bootstrap: logging + core dumps + key source
    let log_level = cfg.server.log_level.as_deref().unwrap_or("info");
    let key_source = shroudb_server_bootstrap::bootstrap(log_level);

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            let storage =
                shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?;
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(
                storage.clone(),
                "sentry",
            ));
            run_server(cfg, store, Some(storage)).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store, None).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: SentryServerConfig,
    store: Arc<S>,
    storage: Option<Arc<shroudb_storage::StorageEngine>>,
) -> anyhow::Result<()> {
    // Resolve [audit] via engine-bootstrap. An omitted [audit] section
    // defaults to embedded Chronicle on the shared storage (engine-bootstrap
    // 0.3.0 behavior). Sentry has no [policy] section: Sentry IS the policy
    // evaluator. Embedded init failures still surface as startup errors.
    let audit_cfg = cfg.audit.clone().unwrap_or_default();
    let audit_cap = audit_cfg
        .resolve(storage)
        .await
        .context("failed to resolve [audit] capability")?;

    // Parse signing algorithm
    let signing_algorithm: SigningAlgorithm = cfg
        .engine
        .signing_algorithm
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Sentry engine
    let sentry_config = SentryConfig {
        signing_algorithm,
        rotation_days: cfg.engine.rotation_days,
        drain_days: cfg.engine.drain_days,
        decision_ttl_secs: cfg.engine.decision_ttl_secs,
        scheduler_interval_secs: cfg.engine.scheduler_interval_secs,
        require_audit: cfg.engine.require_audit,
    };
    let engine = Arc::new(SentryEngine::new(store, sentry_config, audit_cap).await?);

    // Seed policies from config
    for (name, seed) in &cfg.policies {
        let effect: shroudb_acl::PolicyEffect = seed
            .effect
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;

        let policy = shroudb_sentry_core::policy::Policy {
            name: name.clone(),
            description: seed.description.clone(),
            effect,
            priority: seed.priority,
            principal: shroudb_sentry_core::matcher::PrincipalMatcher {
                roles: seed.principal_roles.clone(),
                ..Default::default()
            },
            resource: shroudb_sentry_core::matcher::ResourceMatcher {
                resource_type: seed.resource_type.clone(),
                ..Default::default()
            },
            action: shroudb_sentry_core::matcher::ActionMatcher {
                names: seed.action_names.clone(),
            },
            conditions: Default::default(),
            version: 0,
            created_at: 0,
            updated_at: 0,
        };
        engine.seed_policy(policy).await?;
    }

    // Graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start background scheduler
    let _scheduler = shroudb_sentry_engine::scheduler::start_scheduler(
        engine.clone(),
        cfg.engine.scheduler_interval_secs,
        shutdown_rx.clone(),
    );

    // Auth
    let token_validator = cfg.auth.build_validator();

    // Audit-on requires an authenticated actor at the engine layer.
    // Refuse to start with [audit] enabled but [auth].tokens empty.
    audit_cfg
        .require_auth_validator(token_validator.is_some())
        .context("invalid [audit] / [auth] composition")?;

    // TCP listener
    let listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind).await?;

    // Banner
    shroudb_server_bootstrap::print_banner(
        "Sentry",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind.to_string(),
        &cfg.store.data_dir,
    );

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_handle = tokio::spawn(tcp::run_tcp(
        listener,
        engine,
        token_validator,
        shutdown_rx,
        tls_acceptor,
    ));

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_asserts() {
        Cli::command().debug_assert();
    }
}
