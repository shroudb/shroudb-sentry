use std::sync::Arc;

use clap::Parser;
use shroudb_sentry_core::signing::SigningAlgorithm;
use shroudb_sentry_engine::engine::{SentryConfig, SentryEngine};
use tokio::net::TcpListener;

mod config;
mod tcp;

use config::{build_token_validator, load_config};

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

    // Validate store config
    cfg.store.validate()?;

    // Storage engine
    let storage =
        shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref()).await?;
    let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "sentry"));

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
    };
    let engine = Arc::new(SentryEngine::new(store, sentry_config, None).await?);

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
    let token_validator = build_token_validator(&cfg.auth);

    // TCP listener
    let listener = TcpListener::bind(cfg.server.tcp_bind).await?;

    // Banner
    shroudb_server_bootstrap::print_banner(
        "Sentry",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind.to_string(),
        &cfg.store.data_dir,
    );

    let tcp_handle = tokio::spawn(tcp::run_tcp(listener, engine, token_validator, shutdown_rx));

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    Ok(())
}
