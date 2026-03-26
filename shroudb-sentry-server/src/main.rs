//! ShrouDB Sentry — policy-based authorization engine.
//!
//! Binary entry point: CLI argument parsing, config loading, and server startup.

mod config;
mod connection;
mod http;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use shroudb_crypto::SecretBytes;
use shroudb_sentry_core::signing::SigningKeyring;
use shroudb_storage::{ChainedMasterKeySource, MasterKeySource, StorageEngine};
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(
    name = "shroudb-sentry",
    about = "Policy-based authorization engine",
    version
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "sentry.toml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 0. Disable core dumps to prevent leaking signing private keys (Linux only).
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // 1. Parse CLI arguments.
    let cli = Cli::parse();

    // 2. Load configuration (or use defaults if no config file).
    let cfg = match config::load(&cli.config)? {
        Some(cfg) => {
            let data_dir = &cfg.storage.data_dir;
            std::fs::create_dir_all(data_dir)?;

            init_logging(data_dir)?;

            tracing::info!(config = %cli.config.display(), "configuration loaded");
            cfg
        }
        None => {
            let data_dir = std::path::PathBuf::from("./sentry-data");
            std::fs::create_dir_all(&data_dir)?;

            init_logging(&data_dir)?;

            tracing::info!("no config file found, starting with defaults");
            config::SentryConfig::default()
        }
    };

    // 3. Resolve master key source.
    let key_source = resolve_master_key()?;

    // 4. Convert storage section to engine config.
    let engine_config = config::to_engine_config(&cfg);

    // 5. Open storage engine (runs WAL recovery).
    let engine = StorageEngine::open(engine_config, &*key_source).await?;
    let engine = Arc::new(engine);
    tracing::info!("storage engine ready");

    // 6. Load policies from config.policies.dir.
    let default_decision = config::parse_default_decision(&cfg.policies.default_decision)?;
    let policy_set = shroudb_sentry_core::policy::PolicySet::load_dir(&cfg.policies.dir)?;
    let policy_count = policy_set.policies().len();
    let policy_set = Arc::new(std::sync::RwLock::new(policy_set));
    tracing::info!(
        count = policy_count,
        dir = %cfg.policies.dir.display(),
        watch = cfg.policies.watch,
        "policies loaded"
    );

    // 7. Create signing keyring.
    tracing::info!(mode = %cfg.signing.mode, algorithm = %cfg.signing.algorithm, "signing config");
    let signing_algorithm = config::parse_algorithm(&cfg.signing.algorithm)?;
    let jwt_algorithm = match signing_algorithm {
        shroudb_sentry_core::signing::SigningAlgorithm::Jwt(alg) => alg,
        shroudb_sentry_core::signing::SigningAlgorithm::HmacSha256 => {
            // HMAC mode: use ES256 as a placeholder algorithm for the keyring struct,
            // but actual signing will use HMAC-SHA256 via the signing mode.
            shroudb_crypto::JwtAlgorithm::ES256
        }
    };
    let signing_mode = match signing_algorithm {
        shroudb_sentry_core::signing::SigningAlgorithm::HmacSha256 => {
            shroudb_sentry_core::signing::SigningMode::Hmac
        }
        _ => shroudb_sentry_core::signing::SigningMode::Jwt,
    };
    let keyring_name = "sentry-signing".to_string();
    let keyring = SigningKeyring {
        name: keyring_name.clone(),
        algorithm: jwt_algorithm,
        rotation_days: cfg.signing.rotation_days,
        drain_days: cfg.signing.drain_days,
        decision_ttl_secs: cfg.signing.decision_ttl_secs,
        key_versions: vec![],
    };
    let signing_index = Arc::new(shroudb_sentry_protocol::signing_index::SigningIndex::new(
        keyring,
        signing_mode,
    ));

    // 8. WAL replay for signing keys.
    let replayed = shroudb_sentry_protocol::recovery::replay_sentry_wal(
        &engine,
        &signing_index,
        &keyring_name,
    )
    .await?;
    if replayed > 0 {
        tracing::info!(entries = replayed, "sentry WAL replay complete");
    }

    // 9. Seed initial signing key if needed.
    let seeded =
        shroudb_sentry_protocol::recovery::seed_signing_key(&engine, &signing_index, &keyring_name)
            .await?;
    if seeded {
        tracing::info!("seeded initial signing key");
    }
    tracing::info!("signing keyring ready");

    // 10. Build auth registry from config.
    let auth_registry = Arc::new(config::build_auth_registry(&cfg));

    // 11. Create Sentry dispatcher.
    let policies_dir = cfg.policies.dir.clone();
    let mut dispatcher = shroudb_sentry_protocol::CommandDispatcher::new(
        Arc::clone(&engine),
        Arc::clone(&policy_set),
        Arc::clone(&signing_index),
        Arc::clone(&auth_registry),
        default_decision,
        policies_dir.clone(),
    );
    if cfg.evaluation.cache_enabled {
        dispatcher = dispatcher.with_decision_cache(cfg.evaluation.cache_ttl_secs);
        tracing::info!(
            cache_ttl = cfg.evaluation.cache_ttl_secs,
            max_batch = cfg.evaluation.max_batch_size,
            "evaluation caching enabled"
        );
    }
    let dispatcher = Arc::new(dispatcher);

    // 12. Install Prometheus metrics recorder.
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install metrics recorder");

    // 13. Set up shutdown signal (SIGTERM + SIGINT).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // 14. Start key lifecycle scheduler (drain→retire, auto-rotation).
    {
        let engine = Arc::clone(&engine);
        let si = Arc::clone(&signing_index);
        let kn = keyring_name.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(shroudb_sentry_protocol::scheduler::run_scheduler(
            engine, si, kn, rx,
        ));
    }
    tracing::info!("background scheduler started");

    // 14b. Start file watcher for hot policy reload.
    if cfg.policies.watch {
        let watch_disp = Arc::clone(&dispatcher);
        let watch_dir = policies_dir.clone();
        let watch_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            run_policy_watcher(watch_dir, watch_disp, watch_rx).await;
        });
        tracing::info!(dir = %policies_dir.display(), "policy file watcher started");
    }

    // 15. Start HTTP server (metrics + JWKS only).
    {
        let http_config = http::HttpConfig {
            bind: cfg.server.http_bind,
            signing_index: Arc::clone(&signing_index),
            metrics_handle: metrics_handle.clone(),
        };
        let http_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = http::run_http_server(http_config, http_rx).await {
                tracing::error!(error = %e, "HTTP server failed");
            }
        });
    }

    // 16. Run RESP3 server (blocks until shutdown).
    tracing::info!(bind = %cfg.server.bind, "shroudb-sentry ready");
    server::run(&cfg.server, dispatcher, metrics_handle, shutdown_rx).await?;

    // 17. Shut down storage engine (flush WAL, fsync).
    engine.shutdown().await?;

    tracing::info!("shroudb-sentry shut down cleanly");
    Ok(())
}

fn resolve_master_key() -> anyhow::Result<Box<dyn MasterKeySource>> {
    if std::env::var("SHROUDB_MASTER_KEY").is_ok()
        || std::env::var("SHROUDB_MASTER_KEY_FILE").is_ok()
    {
        return Ok(Box::new(ChainedMasterKeySource::default_chain()));
    }

    tracing::warn!(
        "no master key configured (set SHROUDB_MASTER_KEY or SHROUDB_MASTER_KEY_FILE for persistence)"
    );
    tracing::warn!("using ephemeral master key — data will NOT survive restart");
    Ok(Box::new(EphemeralMasterKey::generate()))
}

struct EphemeralMasterKey {
    key: SecretBytes,
}

impl EphemeralMasterKey {
    fn generate() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; 32];
        rng.fill(&mut bytes).expect("CSPRNG fill failed");
        Self {
            key: SecretBytes::new(bytes),
        }
    }
}

impl MasterKeySource for EphemeralMasterKey {
    fn load(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<SecretBytes, shroudb_storage::StorageError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(self.key.clone()) })
    }

    fn source_name(&self) -> &str {
        "ephemeral"
    }
}

fn init_logging(data_dir: &std::path::Path) -> anyhow::Result<()> {
    use tracing_subscriber::filter::Targets;

    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("audit.log"))
        .map_err(|e| anyhow::anyhow!("failed to open audit.log: {e}"))?;

    let audit_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::sync::Mutex::new(audit_file))
        .with_filter(Targets::new().with_target("sentry::audit", tracing::Level::INFO));

    let env_filter = resolve_log_filter();
    let console_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_filter(env_filter);

    tracing_subscriber::registry()
        .with(console_layer)
        .with(audit_layer)
        .init();

    Ok(())
}

fn resolve_log_filter() -> tracing_subscriber::EnvFilter {
    if let Ok(level) = std::env::var("LOG_LEVEL") {
        return tracing_subscriber::EnvFilter::new(level);
    }
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

async fn run_policy_watcher(
    dir: PathBuf,
    dispatcher: Arc<shroudb_sentry_protocol::CommandDispatcher>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    use notify::{RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                // Only trigger on .toml file changes.
                let has_toml = event
                    .paths
                    .iter()
                    .any(|p| p.extension().is_some_and(|ext| ext == "toml"));
                if has_toml {
                    let _ = tx.blocking_send(());
                }
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "failed to create file watcher");
                return;
            }
        };

    if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
        tracing::error!(error = %e, dir = %dir.display(), "failed to watch policies directory");
        return;
    }

    let debounce = tokio::time::Duration::from_secs(1);
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(()) = rx.recv() => {
                // Debounce: drain any events that arrive within 1 second.
                tokio::time::sleep(debounce).await;
                while rx.try_recv().is_ok() {}

                match dispatcher.reload_policies() {
                    Ok(count) => {
                        tracing::info!(count, "policies hot-reloaded by file watcher");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "policy hot-reload failed");
                    }
                }
            }
        }
    }

    drop(watcher);
}

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
