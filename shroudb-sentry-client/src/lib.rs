mod connection;
mod error;
pub mod policy_evaluator;

pub use error::ClientError;

use connection::Connection;
use tokio::sync::Mutex;

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
    pub version: u64,
    pub principal: serde_json::Value,
    pub resource: serde_json::Value,
    pub action: serde_json::Value,
    pub conditions: serde_json::Value,
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
///
/// The TCP connection lives behind a `Mutex` so methods take `&self` (not
/// `&mut self`). This lets `SentryClient` satisfy
/// [`shroudb_acl::PolicyEvaluator`] as a trait object, and lets consumers
/// share a single client across tasks via `Arc<SentryClient>`.
pub struct SentryClient {
    conn: Mutex<Connection>,
}

impl SentryClient {
    /// Connect directly to a standalone Sentry server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Connect to a Sentry engine through a Moat gateway.
    ///
    /// Commands are automatically prefixed with `SENTRY` for Moat routing.
    /// Meta-commands (AUTH, HEALTH, PING) are sent without prefix.
    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect_moat(addr).await?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn auth(&self, token: &str) -> Result<(), ClientError> {
        let resp = self.meta_command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    pub async fn health(&self) -> Result<(), ClientError> {
        let resp = self.meta_command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    pub async fn evaluate(&self, request_json: &str) -> Result<EvaluateResult, ClientError> {
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
        &self,
        name: &str,
        policy_json: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resp = self
            .command(&["POLICY", "CREATE", name, policy_json])
            .await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn policy_get(&self, name: &str) -> Result<PolicyInfo, ClientError> {
        let resp = self.command(&["POLICY", "GET", name]).await?;
        check_status(&resp)?;
        Ok(PolicyInfo {
            name: resp["name"].as_str().unwrap_or("").to_string(),
            description: resp["description"].as_str().unwrap_or("").to_string(),
            effect: resp["effect"].as_str().unwrap_or("").to_string(),
            priority: resp["priority"].as_i64().unwrap_or(0) as i32,
            version: resp["version"].as_u64().unwrap_or(0),
            principal: resp["principal"].clone(),
            resource: resp["resource"].clone(),
            action: resp["action"].clone(),
            conditions: resp["conditions"].clone(),
            created_at: resp["created_at"].as_u64().unwrap_or(0),
            updated_at: resp["updated_at"].as_u64().unwrap_or(0),
        })
    }

    pub async fn policy_history(&self, name: &str) -> Result<Vec<PolicyInfo>, ClientError> {
        let resp = self.command(&["POLICY", "HISTORY", name]).await?;
        check_status(&resp)?;
        resp["versions"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| PolicyInfo {
                        name: v["name"].as_str().unwrap_or("").to_string(),
                        description: v["description"].as_str().unwrap_or("").to_string(),
                        effect: v["effect"].as_str().unwrap_or("").to_string(),
                        priority: v["priority"].as_i64().unwrap_or(0) as i32,
                        version: v["version"].as_u64().unwrap_or(0),
                        principal: v["principal"].clone(),
                        resource: v["resource"].clone(),
                        action: v["action"].clone(),
                        conditions: v["conditions"].clone(),
                        created_at: v["created_at"].as_u64().unwrap_or(0),
                        updated_at: v["updated_at"].as_u64().unwrap_or(0),
                    })
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected versions array".into()))
    }

    pub async fn policy_list(&self) -> Result<Vec<String>, ClientError> {
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

    pub async fn policy_delete(&self, name: &str) -> Result<(), ClientError> {
        let resp = self.command(&["POLICY", "DELETE", name]).await?;
        check_status(&resp)
    }

    pub async fn policy_update(
        &self,
        name: &str,
        policy_json: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resp = self
            .command(&["POLICY", "UPDATE", name, policy_json])
            .await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn key_rotate(&self, force: bool, dryrun: bool) -> Result<RotateResult, ClientError> {
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

    pub async fn key_info(&self) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["KEY", "INFO"]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    pub async fn jwks(&self) -> Result<serde_json::Value, ClientError> {
        let resp = self.command(&["JWKS"]).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    async fn command(&self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.lock().await.send_command(args).await
    }

    async fn meta_command(&self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.lock().await.send_meta_command(args).await
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

#[cfg(test)]
mod surface_tests {
    //! Pin the publicly-reachable API surface of the sentry client.

    use super::SentryClient;
    use shroudb_acl::PolicyEvaluator;
    use std::sync::Arc;

    #[test]
    fn sentry_client_pub_type_reachable_from_crate_root() {
        fn _accepts(_c: SentryClient) {}
    }

    #[test]
    fn sentry_client_satisfies_policy_evaluator_as_trait_object() {
        // Compile-only: pins the `policy_evaluator` module providing an
        // impl of `PolicyEvaluator` for `SentryClient`, usable as a trait
        // object.
        fn _accepts_policy(_p: Arc<dyn PolicyEvaluator>) {}
        fn _would_accept(c: SentryClient) {
            _accepts_policy(Arc::new(c));
        }
    }
}
