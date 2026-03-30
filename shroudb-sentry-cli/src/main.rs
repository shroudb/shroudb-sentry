use std::io::BufRead;

use anyhow::Context;
use clap::Parser;
use shroudb_sentry_client::SentryClient;

#[derive(Parser)]
#[command(
    name = "shroudb-sentry-cli",
    about = "CLI for the Sentry authorization engine"
)]
struct Cli {
    /// Server address
    #[arg(long, default_value = "127.0.0.1:6799", env = "SENTRY_ADDR")]
    addr: String,

    /// Command to execute (omit for interactive mode)
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut client = SentryClient::connect(&cli.addr)
        .await
        .context("failed to connect to Sentry server")?;

    if cli.command.is_empty() {
        interactive(&mut client).await
    } else {
        let args: Vec<&str> = cli.command.iter().map(|s| s.as_str()).collect();
        execute(&mut client, &args).await
    }
}

async fn execute(client: &mut SentryClient, args: &[&str]) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!("empty command");
    }

    match args[0].to_uppercase().as_str() {
        "HEALTH" => {
            client.health().await?;
            println!("OK");
        }
        "PING" => {
            println!("PONG");
        }
        "AUTH" => {
            if args.len() < 2 {
                anyhow::bail!("usage: AUTH <token>");
            }
            client.auth(args[1]).await?;
            println!("OK");
        }
        "EVALUATE" => {
            if args.len() < 2 {
                anyhow::bail!("usage: EVALUATE <json>");
            }
            let result = client.evaluate(args[1]).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "decision": result.decision,
                    "token": result.token,
                    "matched_policy": result.matched_policy,
                    "cache_until": result.cache_until,
                }))?
            );
        }
        "POLICY" => {
            if args.len() < 2 {
                anyhow::bail!("usage: POLICY <CREATE|GET|LIST|DELETE|UPDATE> ...");
            }
            match args[1].to_uppercase().as_str() {
                "CREATE" => {
                    if args.len() < 4 {
                        anyhow::bail!("usage: POLICY CREATE <name> <json>");
                    }
                    let resp = client.policy_create(args[2], args[3]).await?;
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                "GET" => {
                    if args.len() < 3 {
                        anyhow::bail!("usage: POLICY GET <name>");
                    }
                    let info = client.policy_get(args[2]).await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "name": info.name,
                            "description": info.description,
                            "effect": info.effect,
                            "priority": info.priority,
                            "created_at": info.created_at,
                            "updated_at": info.updated_at,
                        }))?
                    );
                }
                "LIST" => {
                    let policies = client.policy_list().await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "count": policies.len(),
                            "policies": policies,
                        }))?
                    );
                }
                "DELETE" => {
                    if args.len() < 3 {
                        anyhow::bail!("usage: POLICY DELETE <name>");
                    }
                    client.policy_delete(args[2]).await?;
                    println!("OK");
                }
                "UPDATE" => {
                    if args.len() < 4 {
                        anyhow::bail!("usage: POLICY UPDATE <name> <json>");
                    }
                    let resp = client.policy_update(args[2], args[3]).await?;
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
                sub => anyhow::bail!("unknown POLICY subcommand: {sub}"),
            }
        }
        "KEY" => {
            if args.len() < 2 {
                anyhow::bail!("usage: KEY <ROTATE|INFO>");
            }
            match args[1].to_uppercase().as_str() {
                "ROTATE" => {
                    let force = has_flag(args, "FORCE");
                    let dryrun = has_flag(args, "DRYRUN");
                    let result = client.key_rotate(force, dryrun).await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "rotated": result.rotated,
                            "key_version": result.key_version,
                            "previous_version": result.previous_version,
                        }))?
                    );
                }
                "INFO" => {
                    let info = client.key_info().await?;
                    println!("{}", serde_json::to_string_pretty(&info)?);
                }
                sub => anyhow::bail!("unknown KEY subcommand: {sub}"),
            }
        }
        "JWKS" => {
            let jwks = client.jwks().await?;
            println!("{}", serde_json::to_string_pretty(&jwks)?);
        }
        other => anyhow::bail!("unknown command: {other}"),
    }

    Ok(())
}

async fn interactive(client: &mut SentryClient) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    eprint!("sentry> ");
    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            eprint!("sentry> ");
            continue;
        }
        if line == "quit" || line == "exit" {
            break;
        }

        let args = shell_split(line);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        match execute(client, &arg_refs).await {
            Ok(()) => {}
            Err(e) => eprintln!("error: {e}"),
        }
        eprint!("sentry> ");
    }
    Ok(())
}

fn shell_split(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_braces: usize = 0;
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' if in_braces == 0 => {
                in_quotes = !in_quotes;
            }
            '{' if !in_quotes => {
                in_braces += 1;
                current.push(ch);
            }
            '}' if !in_quotes && in_braces > 0 => {
                in_braces -= 1;
                current.push(ch);
            }
            ' ' | '\t' if in_braces == 0 && !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn has_flag(args: &[&str], flag: &str) -> bool {
    let upper = flag.to_uppercase();
    args.iter().any(|a| a.to_uppercase() == upper)
}
