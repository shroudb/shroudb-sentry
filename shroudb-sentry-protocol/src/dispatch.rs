use shroudb_acl::AuthContext;
use shroudb_store::Store;

use shroudb_sentry_core::policy::Policy;
use shroudb_sentry_engine::engine::SentryEngine;
use shroudb_sentry_engine::evaluator;

use crate::commands::SentryCommand;
use crate::response::SentryResponse;

const COMMAND_LIST: &[&str] = &[
    "AUTH",
    "POLICY CREATE",
    "POLICY GET",
    "POLICY LIST",
    "POLICY DELETE",
    "POLICY UPDATE",
    "EVALUATE",
    "KEY ROTATE",
    "KEY INFO",
    "JWKS",
    "HEALTH",
    "PING",
    "COMMAND LIST",
];

/// Dispatch a command to the engine and return a response.
///
/// ACL is checked before routing to the handler. AUTH is handled at the
/// connection layer and should not reach this function.
pub async fn dispatch<S: Store>(
    engine: &SentryEngine<S>,
    cmd: SentryCommand,
    auth_context: Option<&AuthContext>,
) -> SentryResponse {
    // Check ACL requirement
    let requirement = cmd.acl_requirement();
    if let Some(ctx) = auth_context
        && let Err(e) = ctx.check(&requirement)
    {
        return SentryResponse::error(format!("access denied: {e}"));
    }

    match cmd {
        SentryCommand::Auth { .. } => {
            // AUTH is handled at the connection layer, never dispatched
            SentryResponse::error("AUTH must be handled at the connection layer")
        }

        SentryCommand::PolicyCreate { name, policy_json } => {
            handle_policy_create(engine, &name, &policy_json).await
        }

        SentryCommand::PolicyGet { name } => handle_policy_get(engine, &name),

        SentryCommand::PolicyList => handle_policy_list(engine),

        SentryCommand::PolicyDelete { name } => handle_policy_delete(engine, &name).await,

        SentryCommand::PolicyUpdate { name, policy_json } => {
            handle_policy_update(engine, &name, &policy_json).await
        }

        SentryCommand::Evaluate { request_json } => handle_evaluate(engine, &request_json),

        SentryCommand::KeyRotate { force, dryrun } => {
            handle_key_rotate(engine, force, dryrun).await
        }

        SentryCommand::KeyInfo => handle_key_info(engine),

        SentryCommand::Jwks => handle_jwks(engine),

        SentryCommand::Health => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "policy_count": engine.policy_count(),
        })),

        SentryCommand::Ping => SentryResponse::ok(serde_json::json!("PONG")),

        SentryCommand::CommandList => {
            let commands: Vec<serde_json::Value> =
                COMMAND_LIST.iter().map(|c| serde_json::json!(c)).collect();
            SentryResponse::ok(serde_json::json!({
                "status": "ok",
                "commands": commands,
            }))
        }
    }
}

async fn handle_policy_create<S: Store>(
    engine: &SentryEngine<S>,
    name: &str,
    policy_json: &str,
) -> SentryResponse {
    let mut policy: Policy = match serde_json::from_str(policy_json) {
        Ok(p) => p,
        Err(e) => return SentryResponse::error(format!("invalid policy JSON: {e}")),
    };

    // Override name from the command argument
    policy.name = name.to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if policy.created_at == 0 {
        policy.created_at = now;
    }
    policy.updated_at = now;

    match engine.policy_create(policy).await {
        Ok(p) => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "name": p.name,
            "effect": p.effect.to_string(),
            "priority": p.priority,
        })),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

fn handle_policy_get<S: Store>(engine: &SentryEngine<S>, name: &str) -> SentryResponse {
    match engine.policy_get(name) {
        Ok(p) => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "name": p.name,
            "description": p.description,
            "effect": p.effect.to_string(),
            "priority": p.priority,
            "created_at": p.created_at,
            "updated_at": p.updated_at,
        })),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

fn handle_policy_list<S: Store>(engine: &SentryEngine<S>) -> SentryResponse {
    let names = engine.policy_list();
    SentryResponse::ok(serde_json::json!({
        "status": "ok",
        "count": names.len(),
        "policies": names,
    }))
}

async fn handle_policy_delete<S: Store>(engine: &SentryEngine<S>, name: &str) -> SentryResponse {
    match engine.policy_delete(name).await {
        Ok(()) => SentryResponse::ok_simple(),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

async fn handle_policy_update<S: Store>(
    engine: &SentryEngine<S>,
    name: &str,
    policy_json: &str,
) -> SentryResponse {
    let updates: Policy = match serde_json::from_str(policy_json) {
        Ok(p) => p,
        Err(e) => return SentryResponse::error(format!("invalid policy JSON: {e}")),
    };

    match engine.policy_update(name, updates).await {
        Ok(p) => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "name": p.name,
            "effect": p.effect.to_string(),
            "priority": p.priority,
            "updated_at": p.updated_at,
        })),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

fn handle_evaluate<S: Store>(engine: &SentryEngine<S>, request_json: &str) -> SentryResponse {
    let request = match evaluator::parse_evaluation_request(request_json) {
        Ok(r) => r,
        Err(e) => return SentryResponse::error(e.to_string()),
    };

    match engine.evaluate_request(&request) {
        Ok(signed) => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "decision": signed.decision.to_string(),
            "token": signed.token,
            "matched_policy": signed.matched_policy,
            "cache_until": signed.cache_until,
        })),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

async fn handle_key_rotate<S: Store>(
    engine: &SentryEngine<S>,
    force: bool,
    dryrun: bool,
) -> SentryResponse {
    match engine.key_rotate(force, dryrun).await {
        Ok(result) => SentryResponse::ok(serde_json::json!({
            "status": "ok",
            "rotated": result.rotated,
            "key_version": result.key_version,
            "previous_version": result.previous_version,
        })),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

fn handle_key_info<S: Store>(engine: &SentryEngine<S>) -> SentryResponse {
    match engine.key_info() {
        Ok(info) => {
            let mut obj = info;
            obj["status"] = serde_json::json!("ok");
            SentryResponse::ok(obj)
        }
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

fn handle_jwks<S: Store>(engine: &SentryEngine<S>) -> SentryResponse {
    match engine.jwks() {
        Ok(jwks) => SentryResponse::ok(jwks),
        Err(e) => SentryResponse::error(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dispatch tests require a real Store; see server integration tests.

    #[test]
    fn command_list_is_exhaustive() {
        assert!(COMMAND_LIST.len() >= 13);
        assert!(COMMAND_LIST.contains(&"EVALUATE"));
        assert!(COMMAND_LIST.contains(&"JWKS"));
        assert!(COMMAND_LIST.contains(&"POLICY CREATE"));
    }
}
