mod connection;
mod error;

pub use error::ClientError;

use connection::Connection;

/// Result types for Sentry client operations.
#[derive(Debug, Clone)]
pub struct EvaluateResult {
    pub decision: String,
    pub token: String,
    pub matched_policy: Option<String>,
    pub cache_until: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyInfo {
    pub name: String,
    pub description: String,
    pub effect: String,
    pub priority: i32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct RotateResult {
    pub key_version: u32,
    pub previous_version: Option<u32>,
    pub rotated: bool,
}

/// Typed async client for the Sentry authorization engine.
pub struct SentryClient {
    conn: Connection,
}

impl SentryClient {
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    pub async fn evaluate(&mut self, request_json: &str) -> Result<EvaluateResult, ClientError> {
        let resp = self.command(&["EVALUATE", request_json]).await?;
        check_status(&resp)?;
        Ok(EvaluateResult {
            decision: resp["decision"].as_str().unwrap_or("deny").to_string(),
            token: resp["token"].as_str().unwrap_or("").to_string(),
            matched_policy: resp["matched_policy"].as_str().map(String::from),
            cache_until: resp["cache_until"].as_u64().unwrap_or(0),
        })
    }

    pub async fn policy_create(
        &mut self,
        name: &str,
        policy_json: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resp = self
            .command(&["POLICY", "CREATE", name, policy_json])
            .await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn policy_get(&mut self, name: &str) -> Result<PolicyInfo, ClientError> {
        let resp = self.command(&["POLICY", "GET", name]).await?;
        check_status(&resp)?;
        Ok(PolicyInfo {
            name: resp["name"].as_str().unwrap_or("").to_string(),
            description: resp["description"].as_str().unwrap_or("").to_string(),
            effect: resp["effect"].as_str().unwrap_or("").to_string(),
            priority: resp["priority"].as_i64().unwrap_or(0) as i32,
            created_at: resp["created_at"].as_u64().unwrap_or(0),
            updated_at: resp["updated_at"].as_u64().unwrap_or(0),
        })
    }

    pub async fn policy_list(&mut self) -> Result<Vec<String>, ClientError> {
        let resp = self.command(&["POLICY", "LIST"]).await?;
        check_status(&resp)?;
        resp["policies"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected policies array".into()))
    }

    pub async fn policy_delete(&mut self, name: &str) -> Result<(), ClientError> {
        let resp = self.command(&["POLICY", "DELETE", name]).await?;
        check_status(&resp)
    }

    pub async fn policy_update(
        &mut self,
        name: &str,
        policy_json: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resp = self
            .command(&["POLICY", "UPDATE", name, policy_json])
            .await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn key_rotate(
        &mut self,
        force: bool,
        dryrun: bool,
    ) -> Result<RotateResult, ClientError> {
        let mut args = vec!["KEY", "ROTATE"];
        if force {
            args.push("FORCE");
        }
        if dryrun {
            args.push("DRYRUN");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(RotateResult {
            key_version: resp["key_version"].as_u64().unwrap_or(0) as u32,
            previous_version: resp["previous_version"].as_u64().map(|v| v as u32),
            rotated: resp["rotated"].as_bool().unwrap_or(false),
        })
    }

    pub async fn key_info(&mut self) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["KEY", "INFO"]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn jwks(&mut self) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["JWKS"]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    // If the response is a valid object or array, treat as success
    if resp.is_object() || resp.is_array() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat(
        "unexpected response format".into(),
    ))
}
