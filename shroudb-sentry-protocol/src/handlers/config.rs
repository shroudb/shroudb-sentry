use std::sync::Arc;

use shroudb_storage::{
    ConfigKeyDef, ConfigSource, ConfigValueType, OpType, StorageEngine, WalPayload,
};

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};

const MUTABLE_KEYS: &[ConfigKeyDef] = &[
    ConfigKeyDef {
        key: "decision_ttl_secs",
        description: "Decision cache TTL in seconds",
        mutable: true,
        value_type: ConfigValueType::U64,
    },
    ConfigKeyDef {
        key: "cache.enabled",
        description: "Whether the decision cache is enabled",
        mutable: true,
        value_type: ConfigValueType::Bool,
    },
    ConfigKeyDef {
        key: "cache.ttl_secs",
        description: "Decision cache TTL in seconds",
        mutable: true,
        value_type: ConfigValueType::U64,
    },
    ConfigKeyDef {
        key: "default_decision",
        description: "Default decision when no policy matches (permit or deny)",
        mutable: true,
        value_type: ConfigValueType::String,
    },
    ConfigKeyDef {
        key: "snapshot_entry_threshold",
        description: "WAL entries before automatic snapshot",
        mutable: true,
        value_type: ConfigValueType::U64,
    },
    ConfigKeyDef {
        key: "snapshot_time_threshold_secs",
        description: "Seconds between automatic snapshots",
        mutable: true,
        value_type: ConfigValueType::U64,
    },
];

pub async fn handle_config_get(
    engine: &StorageEngine,
    key: &str,
) -> Result<ResponseMap, CommandError> {
    if let Some(entry) = engine.config_store().get(key) {
        return Ok(ResponseMap::ok()
            .with("value", ResponseValue::String(entry.value))
            .with("source", ResponseValue::String(entry.source.to_string())));
    }

    match key {
        "fsync_mode" => Ok(ResponseMap::ok().with(
            "value",
            ResponseValue::String(format!("{:?}", engine.fsync_mode())),
        )),
        "health" => {
            Ok(ResponseMap::ok().with("value", ResponseValue::String(engine.health().to_string())))
        }
        "snapshot_entry_threshold" => Ok(ResponseMap::ok().with(
            "value",
            ResponseValue::String(engine.snapshot_entry_threshold().to_string()),
        )),
        "snapshot_time_threshold_secs" => Ok(ResponseMap::ok().with(
            "value",
            ResponseValue::String(engine.snapshot_time_threshold_secs().to_string()),
        )),
        _ => Err(CommandError::NotFound {
            entity: "config".into(),
            id: key.into(),
        }),
    }
}

pub async fn handle_config_set(
    engine: &Arc<StorageEngine>,
    key: &str,
    value: &str,
) -> Result<ResponseMap, CommandError> {
    if key.starts_with("server.") || key.starts_with("storage.") || key.starts_with("tls.") {
        return Err(CommandError::BadArg {
            message: format!("config key '{key}' is immutable (requires restart)"),
        });
    }

    if let Some(def) = MUTABLE_KEYS.iter().find(|k| k.key == key) {
        validate_value(value, def.value_type)?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    engine
        .apply(
            "_config",
            OpType::ConfigChanged,
            WalPayload::ConfigChanged {
                key: key.to_string(),
                value: value.to_string(),
            },
        )
        .await
        .map_err(|e| CommandError::Internal(format!("failed to persist config: {e}")))?;

    engine.config_store().set(
        key.to_string(),
        value.to_string(),
        now,
        ConfigSource::Runtime,
    );

    tracing::info!(key = key, value = value, "config updated");
    Ok(ResponseMap::ok())
}

pub async fn handle_config_list(engine: &StorageEngine) -> Result<ResponseMap, CommandError> {
    let mut fields = Vec::new();

    for (key, entry) in engine.config_store().list() {
        fields.push((
            key,
            ResponseValue::Map(
                ResponseMap::ok()
                    .with("value", ResponseValue::String(entry.value))
                    .with("source", ResponseValue::String(entry.source.to_string()))
                    .with("mutable", ResponseValue::Boolean(true)),
            ),
        ));
    }

    for def in MUTABLE_KEYS {
        if engine.config_store().get(def.key).is_none() {
            let value = match def.key {
                "snapshot_entry_threshold" => engine.snapshot_entry_threshold().to_string(),
                "snapshot_time_threshold_secs" => engine.snapshot_time_threshold_secs().to_string(),
                _ => continue,
            };
            fields.push((
                def.key.to_string(),
                ResponseValue::Map(
                    ResponseMap::ok()
                        .with("value", ResponseValue::String(value))
                        .with("source", ResponseValue::String("default".into()))
                        .with("mutable", ResponseValue::Boolean(true)),
                ),
            ));
        }
    }

    Ok(ResponseMap { fields })
}

fn validate_value(value: &str, expected: ConfigValueType) -> Result<(), CommandError> {
    match expected {
        ConfigValueType::U64 => {
            value.parse::<u64>().map_err(|_| CommandError::BadArg {
                message: format!("expected u64 value, got: {value}"),
            })?;
        }
        ConfigValueType::Bool => {
            if !matches!(value, "true" | "false") {
                return Err(CommandError::BadArg {
                    message: format!("expected true/false, got: {value}"),
                });
            }
        }
        ConfigValueType::String => {
            // For default_decision, validate permit/deny
        }
        _ => {}
    }
    Ok(())
}
