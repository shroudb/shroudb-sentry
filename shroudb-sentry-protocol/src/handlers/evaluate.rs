use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::policy::{Effect, PolicySet};

use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

pub fn handle_evaluate(
    policy_set: &PolicySet,
    signing_index: &SigningIndex,
    json: &str,
    default_decision: Effect,
) -> Result<ResponseMap, CommandError> {
    let request: EvaluationRequest =
        serde_json::from_str(json).map_err(|e| CommandError::BadArg {
            message: format!("invalid evaluation request JSON: {e}"),
        })?;

    let decision = policy_set.evaluate(&request, default_decision);

    let signed = signing_index
        .sign_decision(&decision, &request)
        .map_err(|e| CommandError::Internal(e.to_string()))?;

    let mut resp = ResponseMap::ok()
        .with(
            "decision",
            ResponseValue::String(signed.decision.to_string()),
        )
        .with("token", ResponseValue::String(signed.token));

    if let Some(ref policy_name) = signed.matched_policy {
        resp = resp.with("policy", ResponseValue::String(policy_name.clone()));
    }

    resp = resp.with(
        "cache_until",
        ResponseValue::Integer(signed.cache_until as i64),
    );

    Ok(resp)
}
