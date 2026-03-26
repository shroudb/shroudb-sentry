use shroudb_storage::{HealthState, StorageEngine};

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

    Ok(ResponseMap::ok()
        .with("health", ResponseValue::String(status.into()))
        .with("has_active_key", ResponseValue::Boolean(has_active_key))
        .with(
            "policy_count",
            ResponseValue::Integer(0), // Updated by dispatch
        ))
}
