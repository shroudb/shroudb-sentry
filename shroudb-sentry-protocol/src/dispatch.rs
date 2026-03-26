use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, histogram};
use shroudb_storage::{HealthState, StorageEngine};

use shroudb_sentry_core::policy::{Effect, PolicySet};

use crate::auth::{AuthPolicy, AuthRegistry};
use crate::command::{Command, command_verb};
use crate::error::CommandError;
use crate::handlers;
use crate::response::{CommandResponse, ResponseMap, ResponseValue};
use crate::signing_index::SigningIndex;

/// Routes parsed Sentry commands to the appropriate handler.
pub struct CommandDispatcher {
    engine: Arc<StorageEngine>,
    policy_set: Arc<std::sync::RwLock<PolicySet>>,
    signing_index: Arc<SigningIndex>,
    auth_registry: Arc<AuthRegistry>,
    default_decision: Effect,
}

impl CommandDispatcher {
    pub fn new(
        engine: Arc<StorageEngine>,
        policy_set: Arc<std::sync::RwLock<PolicySet>>,
        signing_index: Arc<SigningIndex>,
        auth_registry: Arc<AuthRegistry>,
        default_decision: Effect,
    ) -> Self {
        Self {
            engine,
            policy_set,
            signing_index,
            auth_registry,
            default_decision,
        }
    }

    pub fn auth_registry(&self) -> &AuthRegistry {
        &self.auth_registry
    }

    pub fn engine(&self) -> &StorageEngine {
        &self.engine
    }

    pub fn policy_set(&self) -> &std::sync::RwLock<PolicySet> {
        &self.policy_set
    }

    pub fn signing_index(&self) -> &SigningIndex {
        &self.signing_index
    }

    pub async fn execute(&self, cmd: Command, auth: Option<&AuthPolicy>) -> CommandResponse {
        // Handle pipeline recursively.
        if let Command::Pipeline(commands) = cmd {
            let mut results = Vec::with_capacity(commands.len());
            for c in commands {
                results.push(Box::pin(self.execute(c, auth)).await);
            }
            return CommandResponse::Array(results);
        }

        // Check auth policy if auth is required.
        if self.auth_registry.is_required()
            && !matches!(cmd, Command::Auth { .. } | Command::Health)
        {
            match auth {
                None => {
                    return CommandResponse::Error(CommandError::AuthRequired);
                }
                Some(policy) => {
                    if let Err(e) = policy.check(&cmd) {
                        return CommandResponse::Error(e);
                    }
                }
            }
        }

        // Check engine health (allow Health commands through).
        if !matches!(cmd, Command::Health) && self.engine.health() != HealthState::Ready {
            return CommandResponse::Error(CommandError::NotReady(
                self.engine.health().to_string(),
            ));
        }

        let verb = command_verb(&cmd);
        let is_read = cmd.is_read();

        let start = Instant::now();
        let result = self.dispatch(cmd).await;
        let duration = start.elapsed();

        let result_label = match &result {
            Ok(_) => "ok",
            Err(_) => "error",
        };

        counter!("sentry_commands_total", "command" => verb, "result" => result_label).increment(1);
        histogram!("sentry_command_duration_seconds", "command" => verb)
            .record(duration.as_secs_f64());

        let behavior = if is_read { "read" } else { "write" };
        counter!("sentry_commands_by_behavior_total", "behavior" => behavior).increment(1);

        // Audit log for write operations.
        if !is_read {
            let actor = auth.map(|a| a.name.as_str()).unwrap_or("anonymous");
            tracing::info!(
                target: "sentry::audit",
                op = verb,
                result = result_label,
                duration_ms = duration.as_millis() as u64,
                actor = actor,
                "command executed"
            );
        }

        match result {
            Ok(resp) => CommandResponse::Success(resp),
            Err(e) => CommandResponse::Error(e),
        }
    }

    async fn dispatch(&self, cmd: Command) -> Result<ResponseMap, CommandError> {
        match cmd {
            Command::PolicyReload => {
                // Reloading from disk is done at the server layer; this just confirms.
                Ok(ResponseMap::ok())
            }

            Command::PolicyList => {
                let ps = self.policy_set.read().expect("policy set lock poisoned");
                handlers::policy_list::handle_policy_list(&ps)
            }

            Command::PolicyInfo { name } => {
                let ps = self.policy_set.read().expect("policy set lock poisoned");
                handlers::policy_info::handle_policy_info(&ps, &name)
            }

            Command::KeyRotate {
                force: _,
                dryrun: _,
            } => {
                // Key rotation is handled by the server layer / scheduler.
                Ok(ResponseMap::ok().with(
                    "message",
                    ResponseValue::String("key rotation scheduled".into()),
                ))
            }

            Command::KeyInfo => handlers::key_info::handle_key_info(&self.signing_index),

            Command::Evaluate { json } => {
                let ps = self.policy_set.read().expect("policy set lock poisoned");
                handlers::evaluate::handle_evaluate(
                    &ps,
                    &self.signing_index,
                    &json,
                    self.default_decision,
                )
            }

            Command::Health => {
                let policy_count = {
                    let ps = self.policy_set.read().expect("policy set lock poisoned");
                    ps.policies().len()
                };

                let mut resp = handlers::health::handle_health(&self.engine, &self.signing_index)?;
                // Overwrite the placeholder policy_count.
                resp.fields.retain(|(k, _)| k != "policy_count");
                resp = resp.with("policy_count", ResponseValue::Integer(policy_count as i64));
                Ok(resp)
            }

            Command::Auth { .. } => Ok(ResponseMap::ok()),

            Command::Pipeline(_) => unreachable!("pipeline handled above"),
        }
    }
}
