use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

pub fn handle_key_info(signing_index: &SigningIndex) -> Result<ResponseMap, CommandError> {
    let keyring = signing_index.read();

    let versions: Vec<ResponseValue> = keyring
        .key_versions
        .iter()
        .map(|kv| {
            ResponseValue::Map(
                ResponseMap::ok()
                    .with("version", ResponseValue::Integer(i64::from(kv.version)))
                    .with("state", ResponseValue::String(kv.state.to_string()))
                    .with("kid", ResponseValue::String(kv.kid.clone()))
                    .with("created_at", ResponseValue::Integer(kv.created_at as i64)),
            )
        })
        .collect();

    Ok(ResponseMap::ok()
        .with("name", ResponseValue::String(keyring.name.clone()))
        .with(
            "algorithm",
            ResponseValue::String(format!("{:?}", keyring.algorithm)),
        )
        .with(
            "rotation_days",
            ResponseValue::Integer(i64::from(keyring.rotation_days)),
        )
        .with(
            "drain_days",
            ResponseValue::Integer(i64::from(keyring.drain_days)),
        )
        .with(
            "decision_ttl_secs",
            ResponseValue::Integer(keyring.decision_ttl_secs as i64),
        )
        .with("key_versions", ResponseValue::Array(versions)))
}
