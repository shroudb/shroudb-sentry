use shroudb_sentry_core::policy::PolicySet;

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};

pub fn handle_policy_list(policy_set: &PolicySet) -> Result<ResponseMap, CommandError> {
    let names: Vec<ResponseValue> = policy_set
        .policies()
        .iter()
        .map(|p| ResponseValue::String(p.name.clone()))
        .collect();

    Ok(ResponseMap::ok()
        .with("count", ResponseValue::Integer(names.len() as i64))
        .with("policies", ResponseValue::Array(names)))
}
