//! WAL replay for Sentry signing key versions.
//!
//! On startup, this module replays WAL entries to restore signing key state:
//! - `KeyVersionCreated` — new signing key versions
//! - `KeyVersionStateChanged` — state transitions (Active -> Draining -> Retired)
//!
//! If the keyring has no key versions after replay (fresh start), an initial Active
//! key is generated.

use std::time::{SystemTime, UNIX_EPOCH};

use shroudb_storage::wal::reader::RecoveryMode;
use shroudb_storage::{OpType, StorageEngine, WalPayload};

use shroudb_sentry_core::key_state::KeyState;
use shroudb_sentry_core::signing::SigningKeyVersion;

use crate::error::CommandError;
use crate::signing_index::SigningIndex;

/// Replay Sentry WAL entries to restore signing key versions.
///
/// Returns the number of entries replayed.
pub async fn replay_sentry_wal(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
    keyring_name: &str,
) -> Result<u64, CommandError> {
    let reader = shroudb_storage::wal::WalReader::new(
        engine.data_dir().to_path_buf(),
        engine.namespace().clone(),
    );

    let (entries, _corrupt) = reader
        .entries_after_checkpoint(None, RecoveryMode::Recover)
        .await
        .map_err(|e| CommandError::Storage(e.to_string()))?;

    let mut replayed = 0u64;

    for entry in &entries {
        match entry.header.op_type {
            OpType::KeyVersionCreated | OpType::KeyVersionStateChanged => {
                let ks_key = engine
                    .keyspace_key(&entry.header.keyspace_id)
                    .map_err(|e| CommandError::Storage(e.to_string()))?;
                let payload = entry
                    .decrypt_payload(ks_key.as_bytes())
                    .map_err(|e| CommandError::Storage(e.to_string()))?;
                replay_key_payload(engine, signing_index, keyring_name, &payload)?;
                replayed += 1;
            }
            _ => {
                // Not a Sentry signing entry — skip.
            }
        }
    }

    Ok(replayed)
}

/// Apply a key version WAL payload to the signing index.
fn replay_key_payload(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
    expected_keyring: &str,
    payload: &WalPayload,
) -> Result<(), CommandError> {
    match payload {
        WalPayload::KeyVersionCreated {
            keyring,
            version,
            state,
            encrypted_key_material,
            created_at,
        } => {
            if keyring != expected_keyring {
                return Ok(()); // Not our keyring.
            }

            let key_bytes = engine
                .decrypt_private_key(keyring, encrypted_key_material)
                .map_err(|e| CommandError::Storage(e.to_string()))?;
            let key_material = shroudb_crypto::SecretBytes::new(key_bytes);
            let key_state = KeyState::from_str_lossy(state);

            // Derive public key.
            let public_key =
                derive_public_key_from_pkcs8(key_material.as_bytes()).unwrap_or_default();

            let mut kr = signing_index.write();

            // Remove existing version (idempotent replay).
            kr.key_versions.retain(|v| v.version != *version);

            let kid = format!("{}-v{}", keyring, version);
            let algorithm = kr.algorithm;

            kr.key_versions.push(SigningKeyVersion {
                version: *version,
                state: key_state,
                algorithm,
                private_key: Some(key_material),
                public_key,
                kid,
                created_at: *created_at,
                activated_at: if key_state == KeyState::Active {
                    Some(*created_at)
                } else {
                    None
                },
                draining_since: None,
                retired_at: None,
            });
        }
        WalPayload::KeyVersionStateChanged {
            keyring,
            version,
            new_state,
            timestamp,
        } => {
            if keyring != expected_keyring {
                return Ok(());
            }

            let mut kr = signing_index.write();
            if let Some(kv) = kr.key_versions.iter_mut().find(|v| v.version == *version) {
                let new = KeyState::from_str_lossy(new_state);
                kv.state = new;
                match new {
                    KeyState::Active => kv.activated_at = Some(*timestamp),
                    KeyState::Draining => kv.draining_since = Some(*timestamp),
                    KeyState::Retired => kv.retired_at = Some(*timestamp),
                    KeyState::Staged => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// After WAL replay, generate an initial signing key if the keyring is empty.
pub async fn seed_signing_key(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
    keyring_name: &str,
) -> Result<bool, CommandError> {
    {
        let kr = signing_index.read();
        if !kr.key_versions.is_empty() {
            return Ok(false);
        }
    }

    let algorithm = {
        let kr = signing_index.read();
        kr.algorithm
    };

    let kp = shroudb_crypto::generate_signing_key(algorithm)
        .map_err(|e| CommandError::Internal(e.to_string()))?;

    let encrypted = engine
        .encrypt_private_key(keyring_name, kp.private_key_pkcs8.as_bytes())
        .map_err(|e| CommandError::Storage(e.to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Write to WAL.
    engine
        .apply_wal_only(
            keyring_name,
            OpType::KeyVersionCreated,
            WalPayload::KeyVersionCreated {
                keyring: keyring_name.to_string(),
                version: 1,
                state: "Active".into(),
                encrypted_key_material: encrypted,
                created_at: now,
            },
        )
        .await
        .map_err(|e| CommandError::Storage(e.to_string()))?;

    // Update in-memory.
    let kid = format!("{}-v1", keyring_name);
    let mut kr = signing_index.write();
    kr.key_versions.push(SigningKeyVersion {
        version: 1,
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

    Ok(true)
}

/// Extract public key from PKCS#8 DER private key.
fn derive_public_key_from_pkcs8(private_key_der: &[u8]) -> Option<Vec<u8>> {
    if let Ok(pk) = shroudb_crypto::ecdsa_p256_public_key_from_private(private_key_der) {
        return Some(pk);
    }
    if let Ok(pk) = shroudb_crypto::ed25519_public_key_from_private(private_key_der) {
        return Some(pk);
    }
    None
}
