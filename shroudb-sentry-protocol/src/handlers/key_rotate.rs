//! KEY_ROTATE handler: generate a new signing key, demote Active to Draining.

use std::time::{SystemTime, UNIX_EPOCH};

use shroudb_storage::{OpType, StorageEngine, WalPayload};

use shroudb_sentry_core::key_state::KeyState;
use shroudb_sentry_core::signing::SigningKeyVersion;

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

pub async fn handle_key_rotate(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
    keyring_name: &str,
    force: bool,
    dryrun: bool,
) -> Result<ResponseMap, CommandError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check if rotation is needed.
    let (needs_rotation, algorithm, next_version, active_version) = {
        let kr = signing_index.read();
        let rotation_days = kr.rotation_days;
        let needs_rotation = force
            || kr
                .active_key()
                .map(|active| {
                    let age_days = (now.saturating_sub(active.created_at)) / 86400;
                    age_days >= u64::from(rotation_days)
                })
                .unwrap_or(true); // No active key means we need one.
        let next_version = kr.next_version();
        let active_version = kr.active_key().map(|k| k.version);
        (needs_rotation, kr.algorithm, next_version, active_version)
    };

    if !needs_rotation {
        return Ok(ResponseMap::ok()
            .with("rotated", ResponseValue::Boolean(false))
            .with("message", ResponseValue::String("rotation not due".into())));
    }

    if dryrun {
        return Ok(ResponseMap::ok()
            .with("rotated", ResponseValue::Boolean(false))
            .with("dryrun", ResponseValue::Boolean(true))
            .with(
                "would_create_version",
                ResponseValue::Integer(i64::from(next_version)),
            ));
    }

    // Generate new key.
    let kp = shroudb_crypto::generate_signing_key(algorithm)
        .map_err(|e| CommandError::Internal(e.to_string()))?;

    let encrypted = engine
        .encrypt_private_key(keyring_name, kp.private_key_pkcs8.as_bytes())
        .map_err(|e| CommandError::Storage(e.to_string()))?;

    // Demote current Active to Draining.
    if let Some(av) = active_version {
        engine
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
            .await
            .map_err(|e| CommandError::Storage(e.to_string()))?;

        let mut kr = signing_index.write();
        if let Some(active) = kr.active_key_mut() {
            active.state = KeyState::Draining;
            active.draining_since = Some(now);
        }
    }

    // Write new key to WAL.
    engine
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
        .await
        .map_err(|e| CommandError::Storage(e.to_string()))?;

    // Update in-memory.
    let kid = format!("{}-v{}", keyring_name, next_version);
    {
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
    }

    tracing::info!(version = next_version, "signing key rotated");

    Ok(ResponseMap::ok()
        .with("rotated", ResponseValue::Boolean(true))
        .with(
            "new_version",
            ResponseValue::Integer(i64::from(next_version)),
        ))
}
