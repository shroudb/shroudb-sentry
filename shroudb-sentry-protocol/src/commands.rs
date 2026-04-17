use shroudb_acl::{AclRequirement, Scope};

/// Commands supported by the Sentry authorization engine.
#[derive(Debug, Clone)]
pub enum SentryCommand {
    /// Authenticate the connection.
    Auth { token: String },

    /// Create a new authorization policy.
    PolicyCreate { name: String, policy_json: String },

    /// Get a policy by name.
    PolicyGet { name: String },

    /// List all policy names.
    PolicyList,

    /// Delete a policy.
    PolicyDelete { name: String },

    /// Get version history of a policy.
    PolicyHistory { name: String },

    /// Update an existing policy.
    PolicyUpdate { name: String, policy_json: String },

    /// Evaluate an authorization request.
    Evaluate { request_json: String },

    /// Rotate the signing key.
    KeyRotate { force: bool, dryrun: bool },

    /// Get signing key metadata.
    KeyInfo,

    /// Get the JSON Web Key Set.
    Jwks,

    /// Health check.
    Health,

    /// Ping (connectivity check).
    Ping,

    /// List supported commands.
    CommandList,

    /// Engine identity handshake. Pre-auth; returns engine name, version,
    /// wire protocol, supported commands, and capability tags so a client
    /// can detect SDK/engine version mismatches before issuing any real
    /// command.
    Hello,
}

impl SentryCommand {
    /// Declare the ACL requirement for this command.
    pub fn acl_requirement(&self) -> AclRequirement {
        match self {
            // Pre-auth / public
            SentryCommand::Auth { .. }
            | SentryCommand::Health
            | SentryCommand::Ping
            | SentryCommand::CommandList
            | SentryCommand::Hello
            | SentryCommand::KeyInfo
            | SentryCommand::Jwks => AclRequirement::None,

            // Admin-only (structural)
            SentryCommand::PolicyCreate { .. }
            | SentryCommand::PolicyDelete { .. }
            | SentryCommand::PolicyUpdate { .. }
            | SentryCommand::KeyRotate { .. } => AclRequirement::Admin,

            // Read on sentry.policies.*
            SentryCommand::PolicyGet { .. }
            | SentryCommand::PolicyHistory { .. }
            | SentryCommand::PolicyList => AclRequirement::Namespace {
                ns: "sentry.policies.*".into(),
                scope: Scope::Read,
                tenant_override: None,
            },

            // Read on sentry.evaluate.*
            SentryCommand::Evaluate { .. } => AclRequirement::Namespace {
                ns: "sentry.evaluate.*".into(),
                scope: Scope::Read,
                tenant_override: None,
            },
        }
    }
}

/// Parse a RESP3 command from string arguments.
pub fn parse_command(args: &[&str]) -> Result<SentryCommand, String> {
    if args.is_empty() {
        return Err("empty command".into());
    }

    match args[0].to_uppercase().as_str() {
        "AUTH" => {
            if args.len() < 2 {
                return Err("usage: AUTH <token>".into());
            }
            Ok(SentryCommand::Auth {
                token: args[1].to_string(),
            })
        }
        "POLICY" => parse_policy_subcommand(args),
        "EVALUATE" => {
            if args.len() < 2 {
                return Err("usage: EVALUATE <json>".into());
            }
            Ok(SentryCommand::Evaluate {
                request_json: args[1].to_string(),
            })
        }
        "KEY" => parse_key_subcommand(args),
        "JWKS" => Ok(SentryCommand::Jwks),
        "HEALTH" => Ok(SentryCommand::Health),
        "PING" => Ok(SentryCommand::Ping),
        "COMMAND" => Ok(SentryCommand::CommandList),
        "HELLO" => Ok(SentryCommand::Hello),
        _ => Err(format!("unknown command: {}", args[0])),
    }
}

fn parse_policy_subcommand(args: &[&str]) -> Result<SentryCommand, String> {
    if args.len() < 2 {
        return Err("usage: POLICY <CREATE|GET|LIST|DELETE|UPDATE> ...".into());
    }

    match args[1].to_uppercase().as_str() {
        "CREATE" => {
            if args.len() < 4 {
                return Err("usage: POLICY CREATE <name> <json>".into());
            }
            Ok(SentryCommand::PolicyCreate {
                name: args[2].to_string(),
                policy_json: args[3].to_string(),
            })
        }
        "GET" => {
            if args.len() < 3 {
                return Err("usage: POLICY GET <name>".into());
            }
            Ok(SentryCommand::PolicyGet {
                name: args[2].to_string(),
            })
        }
        "LIST" => Ok(SentryCommand::PolicyList),
        "HISTORY" => {
            if args.len() < 3 {
                return Err("usage: POLICY HISTORY <name>".into());
            }
            Ok(SentryCommand::PolicyHistory {
                name: args[2].to_string(),
            })
        }
        "DELETE" => {
            if args.len() < 3 {
                return Err("usage: POLICY DELETE <name>".into());
            }
            Ok(SentryCommand::PolicyDelete {
                name: args[2].to_string(),
            })
        }
        "UPDATE" => {
            if args.len() < 4 {
                return Err("usage: POLICY UPDATE <name> <json>".into());
            }
            Ok(SentryCommand::PolicyUpdate {
                name: args[2].to_string(),
                policy_json: args[3].to_string(),
            })
        }
        _ => Err(format!("unknown POLICY subcommand: {}", args[1])),
    }
}

fn parse_key_subcommand(args: &[&str]) -> Result<SentryCommand, String> {
    if args.len() < 2 {
        return Err("usage: KEY <ROTATE|INFO>".into());
    }

    match args[1].to_uppercase().as_str() {
        "ROTATE" => {
            let force = has_flag(args, "FORCE");
            let dryrun = has_flag(args, "DRYRUN");
            Ok(SentryCommand::KeyRotate { force, dryrun })
        }
        "INFO" => Ok(SentryCommand::KeyInfo),
        _ => Err(format!("unknown KEY subcommand: {}", args[1])),
    }
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth() {
        let cmd = parse_command(&["AUTH", "my-token"]).unwrap();
        assert!(matches!(cmd, SentryCommand::Auth { token } if token == "my-token"));
    }

    #[test]
    fn parse_policy_create() {
        let cmd = parse_command(&["POLICY", "CREATE", "test", "{}"]).unwrap();
        assert!(matches!(cmd, SentryCommand::PolicyCreate { name, .. } if name == "test"));
    }

    #[test]
    fn parse_policy_list() {
        let cmd = parse_command(&["POLICY", "LIST"]).unwrap();
        assert!(matches!(cmd, SentryCommand::PolicyList));
    }

    #[test]
    fn parse_evaluate() {
        let cmd = parse_command(&["EVALUATE", r#"{"principal":{"id":"x"}}"#]).unwrap();
        assert!(matches!(cmd, SentryCommand::Evaluate { .. }));
    }

    #[test]
    fn parse_key_rotate() {
        let cmd = parse_command(&["KEY", "ROTATE", "FORCE"]).unwrap();
        assert!(matches!(
            cmd,
            SentryCommand::KeyRotate {
                force: true,
                dryrun: false
            }
        ));
    }

    #[test]
    fn parse_jwks() {
        let cmd = parse_command(&["JWKS"]).unwrap();
        assert!(matches!(cmd, SentryCommand::Jwks));
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(&["HEALTH"]).unwrap();
        assert!(matches!(cmd, SentryCommand::Health));
    }

    #[test]
    fn parse_unknown() {
        assert!(parse_command(&["FOOBAR"]).is_err());
    }

    #[test]
    fn acl_requirements() {
        use shroudb_acl::AclRequirement;

        let auth = SentryCommand::Auth { token: "x".into() };
        assert_eq!(auth.acl_requirement(), AclRequirement::None);

        let create = SentryCommand::PolicyCreate {
            name: "x".into(),
            policy_json: "{}".into(),
        };
        assert_eq!(create.acl_requirement(), AclRequirement::Admin);

        let eval = SentryCommand::Evaluate {
            request_json: "{}".into(),
        };
        assert!(matches!(
            eval.acl_requirement(),
            AclRequirement::Namespace { .. }
        ));
    }

    #[test]
    fn parse_empty_args() {
        assert!(parse_command(&[]).is_err());
    }

    #[test]
    fn parse_auth_missing_token() {
        assert!(parse_command(&["AUTH"]).is_err());
    }

    #[test]
    fn parse_policy_missing_subcommand() {
        assert!(parse_command(&["POLICY"]).is_err());
    }

    #[test]
    fn parse_policy_unknown_subcommand() {
        assert!(parse_command(&["POLICY", "UNKNOWN"]).is_err());
    }

    #[test]
    fn parse_policy_get_missing_name() {
        assert!(parse_command(&["POLICY", "GET"]).is_err());
    }

    #[test]
    fn parse_policy_delete_missing_name() {
        assert!(parse_command(&["POLICY", "DELETE"]).is_err());
    }

    #[test]
    fn parse_policy_create_missing_json() {
        assert!(parse_command(&["POLICY", "CREATE", "name"]).is_err());
    }

    #[test]
    fn parse_policy_update_missing_args() {
        assert!(parse_command(&["POLICY", "UPDATE"]).is_err());
        assert!(parse_command(&["POLICY", "UPDATE", "name"]).is_err());
    }

    #[test]
    fn parse_evaluate_missing_json() {
        assert!(parse_command(&["EVALUATE"]).is_err());
    }

    #[test]
    fn parse_key_missing_subcommand() {
        assert!(parse_command(&["KEY"]).is_err());
    }

    #[test]
    fn parse_key_unknown_subcommand() {
        assert!(parse_command(&["KEY", "UNKNOWN"]).is_err());
    }

    #[test]
    fn parse_key_rotate_dryrun() {
        let cmd = parse_command(&["KEY", "ROTATE", "DRYRUN"]).unwrap();
        assert!(matches!(
            cmd,
            SentryCommand::KeyRotate {
                force: false,
                dryrun: true
            }
        ));
    }

    #[test]
    fn parse_key_rotate_force_and_dryrun() {
        let cmd = parse_command(&["KEY", "ROTATE", "FORCE", "DRYRUN"]).unwrap();
        assert!(matches!(
            cmd,
            SentryCommand::KeyRotate {
                force: true,
                dryrun: true
            }
        ));
    }

    #[test]
    fn parse_key_rotate_no_flags() {
        let cmd = parse_command(&["KEY", "ROTATE"]).unwrap();
        assert!(matches!(
            cmd,
            SentryCommand::KeyRotate {
                force: false,
                dryrun: false
            }
        ));
    }

    #[test]
    fn parse_ping() {
        let cmd = parse_command(&["PING"]).unwrap();
        assert!(matches!(cmd, SentryCommand::Ping));
    }

    #[test]
    fn parse_command_list() {
        let cmd = parse_command(&["COMMAND"]).unwrap();
        assert!(matches!(cmd, SentryCommand::CommandList));
    }

    #[test]
    fn parse_hello() {
        let cmd = parse_command(&["HELLO"]).unwrap();
        assert!(matches!(cmd, SentryCommand::Hello));
    }

    #[test]
    fn parse_policy_history() {
        let cmd = parse_command(&["POLICY", "HISTORY", "my-policy"]).unwrap();
        assert!(matches!(cmd, SentryCommand::PolicyHistory { name } if name == "my-policy"));
    }

    #[test]
    fn parse_policy_history_missing_name() {
        assert!(parse_command(&["POLICY", "HISTORY"]).is_err());
    }

    #[test]
    fn parse_case_insensitive() {
        assert!(parse_command(&["health"]).is_ok());
        assert!(parse_command(&["Health"]).is_ok());
        assert!(parse_command(&["policy", "list"]).is_ok());
        assert!(parse_command(&["key", "info"]).is_ok());
        assert!(parse_command(&["jwks"]).is_ok());
        assert!(parse_command(&["evaluate", "{}"]).is_ok());
        assert!(parse_command(&["policy", "history", "x"]).is_ok());
    }

    #[test]
    fn acl_all_commands_covered() {
        // Verify every command variant has an ACL requirement
        let commands = vec![
            SentryCommand::Auth { token: "x".into() },
            SentryCommand::PolicyCreate {
                name: "x".into(),
                policy_json: "{}".into(),
            },
            SentryCommand::PolicyGet { name: "x".into() },
            SentryCommand::PolicyList,
            SentryCommand::PolicyDelete { name: "x".into() },
            SentryCommand::PolicyHistory { name: "x".into() },
            SentryCommand::PolicyUpdate {
                name: "x".into(),
                policy_json: "{}".into(),
            },
            SentryCommand::Evaluate {
                request_json: "{}".into(),
            },
            SentryCommand::KeyRotate {
                force: false,
                dryrun: false,
            },
            SentryCommand::KeyInfo,
            SentryCommand::Jwks,
            SentryCommand::Health,
            SentryCommand::Ping,
            SentryCommand::CommandList,
            SentryCommand::Hello,
        ];

        for cmd in commands {
            // Just ensure it doesn't panic — ACL is declared for all variants
            let _ = cmd.acl_requirement();
        }
    }
}
