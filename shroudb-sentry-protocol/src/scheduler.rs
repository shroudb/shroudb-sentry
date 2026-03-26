//! Background scheduler for signing key drain-to-retired transitions and auto-rotation.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shroudb_storage::{OpType, StorageEngine, WalPayload};

use shroudb_sentry_core::key_state::KeyState;
use shroudb_sentry_core::signing::SigningKeyVersion;

use crate::signing_index::SigningIndex;

/// Start the background scheduler. Runs until the shutdown signal is received.
pub async fn run_scheduler(
    engine: Arc<StorageEngine>,
    signing_index: Arc<SigningIndex>,
    keyring_name: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(30);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if let Err(e) = tick(&engine, &signing_index, &keyring_name).await {
                    tracing::error!(error = %e, "scheduler tick failed");
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("scheduler shutting down");
                break;
            }
        }
    }
}

async fn tick(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
    keyring_name: &str,
) -> Result<(), crate::error::CommandError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Phase 1: Collect keys to retire (read-only scan).
    let keys_to_retire: Vec<u32> = {
        let kr = signing_index.read();
        let drain_days = kr.drain_days;
        kr.key_versions
            .iter()
            .filter(|kv| {
                kv.state == KeyState::Draining
                    && kv
                        .draining_since
                        .map(|ds| (now.saturating_sub(ds)) / 86400 >= u64::from(drain_days))
                        .unwrap_or(false)
            })
            .map(|kv| kv.version)
            .collect()
    };

    // Phase 2: Apply retire transitions (one at a time, dropping lock between awaits).
    for version in keys_to_retire {
        // Write WAL first (no lock held).
        let wal_result = engine
            .apply_wal_only(
                keyring_name,
                OpType::KeyVersionStateChanged,
                WalPayload::KeyVersionStateChanged {
                    keyring: keyring_name.to_string(),
                    version,
                    new_state: "Retired".into(),
                    timestamp: now,
                },
            )
            .await;

        match wal_result {
            Ok(()) => {
                // Update in-memory state.
                let mut kr = signing_index.write();
                if let Some(kv) = kr.key_versions.iter_mut().find(|k| k.version == version) {
                    kv.state = KeyState::Retired;
                    kv.retired_at = Some(now);
                }
                tracing::info!(version = version, "signing key retired by scheduler");
            }
            Err(e) => {
                tracing::error!(version = version, error = %e, "failed to retire key");
            }
        }
    }

    // Phase 3: Check if auto-rotation is needed.
    let rotation_info = {
        let kr = signing_index.read();
        let rotation_days = kr.rotation_days;
        let algorithm = kr.algorithm;
        let needs_rotation = kr
            .active_key()
            .map(|active| {
                let age_days = (now.saturating_sub(active.created_at)) / 86400;
                age_days >= u64::from(rotation_days)
            })
            .unwrap_or(false);
        let next_version = kr.next_version();
        let active_version = kr.active_key().map(|k| k.version);
        (needs_rotation, algorithm, next_version, active_version)
    };

    if rotation_info.0 {
        let (_, algorithm, next_version, active_version) = rotation_info;

        let kp = match shroudb_crypto::generate_signing_key(algorithm) {
            Ok(kp) => kp,
            Err(e) => {
                tracing::error!(error = %e, "failed to generate rotated signing key");
                return Ok(());
            }
        };

        let encrypted =
            match engine.encrypt_private_key(keyring_name, kp.private_key_pkcs8.as_bytes()) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error = %e, "failed to encrypt rotated key");
                    return Ok(());
                }
            };

        // Demote current Active to Draining via WAL.
        if let Some(av) = active_version {
            let _ = engine
                .apply_wal_only(
                    keyring_name,
                    OpType::KeyVersionStateChanged,
                    WalPayload::KeyVersionStateChanged {
                        keyring: keyring_name.to_string(),
                        version: av,
                        new_state: "Draining".into(),
                        timestamp: now,
                    },
                )
                .await;

            let mut kr = signing_index.write();
            if let Some(active) = kr.active_key_mut() {
                active.state = KeyState::Draining;
                active.draining_since = Some(now);
            }
        }

        // Write new key to WAL.
        let wal_result = engine
            .apply_wal_only(
                keyring_name,
                OpType::KeyVersionCreated,
                WalPayload::KeyVersionCreated {
                    keyring: keyring_name.to_string(),
                    version: next_version,
                    state: "Active".into(),
                    encrypted_key_material: encrypted,
                    created_at: now,
                },
            )
            .await;

        match wal_result {
            Ok(()) => {
                let kid = format!("{}-v{}", keyring_name, next_version);
                let mut kr = signing_index.write();
                kr.key_versions.push(SigningKeyVersion {
                    version: next_version,
                    state: KeyState::Active,
                    algorithm,
                    private_key: Some(kp.private_key_pkcs8),
                    public_key: kp.public_key_der,
                    kid,
                    created_at: now,
                    activated_at: Some(now),
                    draining_since: None,
                    retired_at: None,
                });

                tracing::info!(
                    version = next_version,
                    "signing key auto-rotated by scheduler"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to write rotated key to WAL");
            }
        }
    }

    Ok(())
}
