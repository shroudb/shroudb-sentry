use std::sync::Arc;
use std::time::Duration;

use shroudb_store::Store;

use crate::engine::SentryEngine;

/// Start a background scheduler that auto-rotates and retires signing keys.
pub fn start_scheduler<S: Store + 'static>(
    engine: Arc<SentryEngine<S>>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // skip first immediate tick

        loop {
            interval.tick().await;
            if let Err(e) = run_cycle(&engine).await {
                tracing::warn!(error = %e, "scheduler cycle failed");
            }
        }
    })
}

async fn run_cycle<S: Store>(engine: &SentryEngine<S>) -> Result<(), String> {
    let signing = engine.signing_manager();
    let keyring = match signing.get("default") {
        Ok(kr) => kr,
        Err(_) => return Ok(()), // No keyring configured
    };

    // Auto-rotate if active key has exceeded rotation_days
    if let Some(active) = keyring.active_key()
        && let Some(activated_at) = active.activated_at
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_days = now.saturating_sub(activated_at) / 86400;
        if age_days >= u64::from(keyring.rotation_days) {
            match signing.rotate("default", true, false).await {
                Ok(result) if result.rotated => {
                    tracing::info!(
                        new_version = result.key_version,
                        "scheduler: auto-rotated signing key"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "scheduler: auto-rotation failed");
                }
            }
        }
    }

    // Auto-retire expired draining keys
    match signing.retire_expired("default").await {
        Ok(retired) if !retired.is_empty() => {
            tracing::info!(?retired, "scheduler: retired draining keys");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "scheduler: retirement check failed");
        }
    }

    Ok(())
}
