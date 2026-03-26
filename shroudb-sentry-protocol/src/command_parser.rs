//! Parse a list of string tokens into a Sentry `Command`.

use crate::command::Command;
use crate::error::CommandError;

pub fn parse_command(strings: Vec<String>) -> Result<Command, CommandError> {
    if strings.is_empty() {
        return Err(CommandError::BadArg {
            message: "empty command".into(),
        });
    }

    let verb = strings[0].to_ascii_uppercase();
    let args = &strings[1..];

    match verb.as_str() {
        "POLICY_RELOAD" => Ok(Command::PolicyReload),
        "POLICY_LIST" => Ok(Command::PolicyList),
        "POLICY_INFO" => parse_policy_info(args),
        "KEY_ROTATE" => parse_key_rotate(args),
        "KEY_INFO" => Ok(Command::KeyInfo),
        "EVALUATE" => parse_evaluate(args),
        "HEALTH" => Ok(Command::Health),
        "CONFIG" => parse_config(args),
        "AUTH" => parse_auth(args),
        "PIPELINE" => parse_pipeline(&strings),
        _ => Err(CommandError::BadArg {
            message: format!("unknown command: {verb}"),
        }),
    }
}

fn parse_policy_info(args: &[String]) -> Result<Command, CommandError> {
    require_arg(args, "POLICY_INFO", 1)?;
    Ok(Command::PolicyInfo {
        name: args[0].clone(),
    })
}

fn parse_key_rotate(args: &[String]) -> Result<Command, CommandError> {
    let flags: Vec<String> = args.iter().map(|s| s.to_ascii_uppercase()).collect();
    Ok(Command::KeyRotate {
        force: flags.contains(&"FORCE".to_string()),
        dryrun: flags.contains(&"DRYRUN".to_string()),
    })
}

fn parse_evaluate(args: &[String]) -> Result<Command, CommandError> {
    require_arg(args, "EVALUATE", 1)?;
    Ok(Command::Evaluate {
        json: args[0].clone(),
    })
}

fn parse_auth(args: &[String]) -> Result<Command, CommandError> {
    require_arg(args, "AUTH", 1)?;
    Ok(Command::Auth {
        token: args[0].clone(),
    })
}

fn parse_config(args: &[String]) -> Result<Command, CommandError> {
    require_arg(args, "CONFIG", 1)?;
    let sub = args[0].to_ascii_uppercase();
    match sub.as_str() {
        "GET" => {
            require_arg(args, "CONFIG GET", 2)?;
            Ok(Command::ConfigGet {
                key: args[1].clone(),
            })
        }
        "SET" => {
            require_arg(args, "CONFIG SET", 3)?;
            Ok(Command::ConfigSet {
                key: args[1].clone(),
                value: args[2].clone(),
            })
        }
        "LIST" => Ok(Command::ConfigList),
        other => Err(CommandError::BadArg {
            message: format!("unknown CONFIG subcommand: {other}"),
        }),
    }
}

fn parse_pipeline(strings: &[String]) -> Result<Command, CommandError> {
    let tokens = &strings[1..];
    let mut commands = Vec::new();
    let mut current = Vec::new();

    for token in tokens {
        if token.eq_ignore_ascii_case("END") {
            if current.is_empty() {
                continue;
            }
            commands.push(parse_command(std::mem::take(&mut current))?);
        } else {
            current.push(token.clone());
        }
    }

    if !current.is_empty() {
        commands.push(parse_command(current)?);
    }

    if commands.is_empty() {
        return Err(CommandError::BadArg {
            message: "PIPELINE contains no commands".into(),
        });
    }

    Ok(Command::Pipeline(commands))
}

fn require_arg(args: &[String], cmd: &str, min: usize) -> Result<(), CommandError> {
    if args.len() < min {
        return Err(CommandError::BadArg {
            message: format!("{cmd} requires at least {min} argument(s)"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(strings: &[&str]) -> Vec<String> {
        strings.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_policy_list() {
        let cmd = parse_command(s(&["POLICY_LIST"])).unwrap();
        assert!(matches!(cmd, Command::PolicyList));
    }

    #[test]
    fn parse_policy_info_basic() {
        let cmd = parse_command(s(&["POLICY_INFO", "my-policy"])).unwrap();
        match cmd {
            Command::PolicyInfo { name } => assert_eq!(name, "my-policy"),
            _ => panic!("expected PolicyInfo"),
        }
    }

    #[test]
    fn parse_evaluate_json() {
        let json =
            r#"{"principal":{"id":"u1"},"resource":{"id":"r1","type":"doc"},"action":"read"}"#;
        let cmd = parse_command(s(&["EVALUATE", json])).unwrap();
        match cmd {
            Command::Evaluate { json: j } => assert_eq!(j, json),
            _ => panic!("expected Evaluate"),
        }
    }

    #[test]
    fn parse_key_rotate_with_flags() {
        let cmd = parse_command(s(&["KEY_ROTATE", "FORCE", "DRYRUN"])).unwrap();
        match cmd {
            Command::KeyRotate { force, dryrun } => {
                assert!(force);
                assert!(dryrun);
            }
            _ => panic!("expected KeyRotate"),
        }
    }

    #[test]
    fn parse_health() {
        let cmd = parse_command(s(&["HEALTH"])).unwrap();
        assert!(matches!(cmd, Command::Health));
    }

    #[test]
    fn parse_config_get() {
        let cmd = parse_command(s(&["CONFIG", "GET", "decision_ttl_secs"])).unwrap();
        match cmd {
            Command::ConfigGet { key } => assert_eq!(key, "decision_ttl_secs"),
            _ => panic!("expected ConfigGet"),
        }
    }

    #[test]
    fn parse_config_set() {
        let cmd = parse_command(s(&["CONFIG", "SET", "decision_ttl_secs", "300"])).unwrap();
        match cmd {
            Command::ConfigSet { key, value } => {
                assert_eq!(key, "decision_ttl_secs");
                assert_eq!(value, "300");
            }
            _ => panic!("expected ConfigSet"),
        }
    }

    #[test]
    fn parse_config_list() {
        let cmd = parse_command(s(&["CONFIG", "LIST"])).unwrap();
        assert!(matches!(cmd, Command::ConfigList));
    }

    #[test]
    fn parse_config_missing_subcommand() {
        let result = parse_command(s(&["CONFIG"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_command() {
        let result = parse_command(s(&["BOGUS"]));
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_command() {
        let result = parse_command(vec![]);
        assert!(result.is_err());
    }
}
