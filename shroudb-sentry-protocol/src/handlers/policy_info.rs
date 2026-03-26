use shroudb_sentry_core::policy::PolicySet;

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};

pub fn handle_policy_info(policy_set: &PolicySet, name: &str) -> Result<ResponseMap, CommandError> {
    let policy = policy_set
        .get(name)
        .ok_or_else(|| CommandError::PolicyNotFound(name.into()))?;

    let mut resp = ResponseMap::ok()
        .with("name", ResponseValue::String(policy.name.clone()))
        .with("effect", ResponseValue::String(policy.effect.to_string()))
        .with(
            "priority",
            ResponseValue::Integer(i64::from(policy.priority)),
        );

    if let Some(ref desc) = policy.description {
        resp = resp.with("description", ResponseValue::String(desc.clone()));
    }

    Ok(resp)
}
