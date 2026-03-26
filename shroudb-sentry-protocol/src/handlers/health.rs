use shroudb_storage::{HealthState, NodeRole, StorageEngine};

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

pub fn handle_health(
    engine: &StorageEngine,
    signing_index: &SigningIndex,
) -> Result<ResponseMap, CommandError> {
    let health = engine.health();
    let status = match health {
        HealthState::Ready => "ok",
        _ => "degraded",
    };

    let keyring = signing_index.read();
    let has_active_key = keyring.active_key().is_some();

    let mut resp = ResponseMap::ok()
        .with("health", ResponseValue::String(status.into()))
        .with("has_active_key", ResponseValue::Boolean(has_active_key))
        .with(
            "policy_count",
            ResponseValue::Integer(0), // Updated by dispatch
        );

    // Replication info
    let role = engine.role();
    match &*role {
        NodeRole::Primary { .. } => {
            resp = resp.with("role", ResponseValue::String("primary".into()));
        }
        NodeRole::Replica { primary_addr, .. } => {
            resp = resp.with("role", ResponseValue::String("replica".into()));
            resp = resp.with("primary", ResponseValue::String(primary_addr.clone()));
            if let Some(lag) = engine.replication_lag_seconds() {
                resp = resp.with("lag_seconds", ResponseValue::String(format!("{lag:.3}")));
            }
            if let Some(lag) = engine.replication_lag_entry_count() {
                resp = resp.with("lag_entries", ResponseValue::Integer(lag as i64));
            }
        }
        NodeRole::Standalone => {
            resp = resp.with("role", ResponseValue::String("standalone".into()));
        }
    }

    Ok(resp)
}
