//! Authentication and authorization for Sentry connections.
//!
//! Tokens map to policies that scope access to specific commands.

use std::collections::HashMap;

use crate::command::{Command, command_verb};
use crate::error::CommandError;

/// A resolved auth policy for a connection.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub name: String,
    /// Allowed command verbs. `["*"]` means all commands.
    pub commands: Vec<String>,
}

impl AuthPolicy {
    /// System-level policy that allows everything.
    pub fn system() -> Self {
        Self {
            name: "system".into(),
            commands: vec!["*".into()],
        }
    }

    pub fn allows_command(&self, verb: &str) -> bool {
        self.commands
            .iter()
            .any(|c| c == "*" || c.eq_ignore_ascii_case(verb))
    }

    /// Check if this policy allows the given command.
    pub fn check(&self, command: &Command) -> Result<(), CommandError> {
        let verb = command_verb(command);

        // AUTH and HEALTH are always allowed.
        if verb == "AUTH" || verb == "HEALTH" {
            return Ok(());
        }

        if !self.allows_command(verb) {
            return Err(CommandError::Denied {
                reason: format!("command {verb} not allowed by policy '{}'", self.name),
            });
        }

        Ok(())
    }
}

/// Registry of auth tokens to policies. Built from config at startup.
pub struct AuthRegistry {
    policies: HashMap<String, AuthPolicy>,
    required: bool,
}

impl AuthRegistry {
    pub fn new(policies: HashMap<String, AuthPolicy>, required: bool) -> Self {
        Self { policies, required }
    }

    /// No auth configured — everything is allowed.
    pub fn permissive() -> Self {
        Self {
            policies: HashMap::new(),
            required: false,
        }
    }

    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Look up a token and return the associated policy.
    pub fn authenticate(&self, token: &str) -> Result<&AuthPolicy, CommandError> {
        self.policies
            .get(token)
            .ok_or_else(|| CommandError::Denied {
                reason: "invalid token".into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(commands: Vec<&str>) -> AuthPolicy {
        AuthPolicy {
            name: "test".into(),
            commands: commands.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn wildcard_allows_all_commands() {
        let policy = make_policy(vec!["*"]);
        assert!(policy.allows_command("EVALUATE"));
        assert!(policy.allows_command("POLICY_LIST"));
    }

    #[test]
    fn specific_commands_only() {
        let policy = make_policy(vec!["EVALUATE", "POLICY_LIST"]);
        assert!(policy.allows_command("EVALUATE"));
        assert!(policy.allows_command("POLICY_LIST"));
        assert!(!policy.allows_command("KEY_ROTATE"));
    }

    #[test]
    fn authenticate_valid_token() {
        let policy = make_policy(vec!["*"]);
        let mut policies = HashMap::new();
        policies.insert("secret123".to_string(), policy);
        let registry = AuthRegistry::new(policies, true);

        let result = registry.authenticate("secret123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test");
    }

    #[test]
    fn authenticate_invalid_token() {
        let registry = AuthRegistry::new(HashMap::new(), true);
        assert!(registry.authenticate("bad").is_err());
    }
}
