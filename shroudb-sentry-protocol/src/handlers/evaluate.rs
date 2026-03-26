use shroudb_sentry_core::decision::SignedDecision;
use shroudb_sentry_core::evaluation::EvaluationRequest;
use shroudb_sentry_core::policy::{Effect, PolicySet};

use crate::decision_cache::DecisionCache;
use crate::error::CommandError;
use crate::response::{ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

pub fn handle_evaluate(
    policy_set: &PolicySet,
    signing_index: &SigningIndex,
    json: &str,
    default_decision: Effect,
    cache: Option<&DecisionCache>,
) -> Result<ResponseMap, CommandError> {
    let request: EvaluationRequest =
        serde_json::from_str(json).map_err(|e| CommandError::BadArg {
            message: format!("invalid evaluation request JSON: {e}"),
        })?;

    // Check cache first.
    if let Some(cache) = cache
        && let Some(cached) = cache.get(&request)
    {
        return Ok(signed_to_response(cached));
    }

    let decision = policy_set.evaluate(&request, default_decision);

    let signed = signing_index
        .sign_decision(&decision, &request)
        .map_err(|e| CommandError::Internal(e.to_string()))?;

    // Store in cache.
    if let Some(cache) = cache {
        cache.put(&request, &signed);
    }

    Ok(signed_to_response(signed))
}

fn signed_to_response(signed: SignedDecision) -> ResponseMap {
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

    resp
}
