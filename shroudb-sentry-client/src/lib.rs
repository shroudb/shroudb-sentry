//! `shroudb-sentry-client` — typed Rust client library for ShrouDB Sentry.
//!
//! Provides a high-level async API for interacting with a Sentry server over TCP.
//! The RESP3 protocol is handled internally — callers never deal with raw frames.
//!
//! # Example
//!
//! ```no_run
//! use shroudb_sentry_client::SentryClient;
//!
//! # async fn example() -> Result<(), shroudb_sentry_client::ClientError> {
//! let mut client = SentryClient::connect("127.0.0.1:6799").await?;
//!
//! // List policies
//! let list = client.policy_list().await?;
//! println!("Policies: {:?}", list.policies);
//!
//! // Evaluate an authorization request
//! let result = client.evaluate(r#"{"principal":{"id":"u1"},"resource":{"id":"r1","type":"doc"},"action":"read"}"#).await?;
//! println!("Decision: {}", result.decision);
//! # Ok(())
//! # }
//! ```

pub mod connection;
pub mod error;
pub mod response;

pub use error::ClientError;
pub use response::{
    EvaluateResult, HealthResult, KeyInfoResult, KeyRotateResult, PolicyInfoResult,
    PolicyListResult, Response,
};

use connection::Connection;

/// Default Sentry server port.
const DEFAULT_PORT: u16 = 6799;

/// Parsed components of a Sentry connection URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub auth_token: Option<String>,
}

/// Parse a Sentry connection URI.
///
/// Format: `shroudb-sentry://[token@]host[:port]`
///         `shroudb-sentry+tls://[token@]host[:port]`
///
/// # Examples
///
/// ```
/// use shroudb_sentry_client::parse_uri;
///
/// let cfg = parse_uri("shroudb-sentry://localhost").unwrap();
/// assert_eq!(cfg.host, "localhost");
/// assert_eq!(cfg.port, 6799);
/// assert!(!cfg.tls);
///
/// let cfg = parse_uri("shroudb-sentry+tls://mytoken@prod.example.com:7000").unwrap();
/// assert!(cfg.tls);
/// assert_eq!(cfg.auth_token.as_deref(), Some("mytoken"));
/// assert_eq!(cfg.host, "prod.example.com");
/// assert_eq!(cfg.port, 7000);
/// ```
pub fn parse_uri(uri: &str) -> Result<ConnectionConfig, ClientError> {
    let (tls, rest) = if let Some(rest) = uri.strip_prefix("shroudb-sentry+tls://") {
        (true, rest)
    } else if let Some(rest) = uri.strip_prefix("shroudb-sentry://") {
        (false, rest)
    } else {
        return Err(ClientError::Protocol(format!("invalid URI scheme: {uri}")));
    };

    let (auth_token, hostport) = if let Some(at_pos) = rest.find('@') {
        (Some(rest[..at_pos].to_string()), &rest[at_pos + 1..])
    } else {
        (None, rest)
    };

    // Strip trailing path if present
    let hostport = hostport.split('/').next().unwrap_or(hostport);

    let (host, port) = if let Some(colon_pos) = hostport.rfind(':') {
        let port_str = &hostport[colon_pos + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (hostport[..colon_pos].to_string(), p),
            Err(_) => (hostport.to_string(), DEFAULT_PORT),
        }
    } else {
        (hostport.to_string(), DEFAULT_PORT)
    };

    Ok(ConnectionConfig {
        host,
        port,
        tls,
        auth_token,
    })
}

/// A client for interacting with a ShrouDB Sentry server.
pub struct SentryClient {
    connection: Connection,
}

impl SentryClient {
    /// Connect to a Sentry server at the given address (e.g. `"127.0.0.1:6799"`).
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let connection = Connection::connect(addr).await?;
        Ok(Self { connection })
    }

    /// Connect to a Sentry server over TLS.
    pub async fn connect_tls(addr: &str) -> Result<Self, ClientError> {
        let connection = Connection::connect_tls(addr).await?;
        Ok(Self { connection })
    }

    /// Connect using a URI string.
    ///
    /// Format: `shroudb-sentry://[token@]host[:port]`
    ///         `shroudb-sentry+tls://[token@]host[:port]`
    pub async fn from_uri(uri: &str) -> Result<Self, ClientError> {
        let config = parse_uri(uri)?;
        let addr = format!("{}:{}", config.host, config.port);
        let mut client = if config.tls {
            Self::connect_tls(&addr).await?
        } else {
            Self::connect(&addr).await?
        };
        if let Some(token) = &config.auth_token {
            client.auth(token).await?;
        }
        Ok(client)
    }

    /// Authenticate the connection with a bearer token.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.connection.send_command_strs(&["AUTH", token]).await?;
        check_ok_status(resp)
    }

    /// Evaluate an authorization request.
    pub async fn evaluate(&mut self, json: &str) -> Result<EvaluateResult, ClientError> {
        let resp = self
            .connection
            .send_command_strs(&["EVALUATE", json])
            .await?;
        EvaluateResult::from_response(resp)
    }

    /// List all loaded policies.
    pub async fn policy_list(&mut self) -> Result<PolicyListResult, ClientError> {
        let resp = self.connection.send_command_strs(&["POLICY_LIST"]).await?;
        PolicyListResult::from_response(resp)
    }

    /// Get information about a specific policy.
    pub async fn policy_info(&mut self, name: &str) -> Result<PolicyInfoResult, ClientError> {
        let resp = self
            .connection
            .send_command_strs(&["POLICY_INFO", name])
            .await?;
        PolicyInfoResult::from_response(resp)
    }

    /// Reload all policies from disk.
    pub async fn policy_reload(&mut self) -> Result<(), ClientError> {
        let resp = self
            .connection
            .send_command_strs(&["POLICY_RELOAD"])
            .await?;
        check_ok_status(resp)
    }

    /// Rotate the signing key.
    pub async fn key_rotate(
        &mut self,
        force: bool,
        dryrun: bool,
    ) -> Result<KeyRotateResult, ClientError> {
        let mut args: Vec<&str> = vec!["KEY_ROTATE"];
        if force {
            args.push("FORCE");
        }
        if dryrun {
            args.push("DRYRUN");
        }
        let resp = self.connection.send_command_strs(&args).await?;
        KeyRotateResult::from_response(resp)
    }

    /// Get signing key information.
    pub async fn key_info(&mut self) -> Result<KeyInfoResult, ClientError> {
        let resp = self.connection.send_command_strs(&["KEY_INFO"]).await?;
        KeyInfoResult::from_response(resp)
    }

    /// Check server health.
    pub async fn health(&mut self) -> Result<HealthResult, ClientError> {
        let resp = self.connection.send_command_strs(&["HEALTH"]).await?;
        HealthResult::from_response(resp)
    }

    /// Send an arbitrary command and return the raw RESP3 response.
    pub async fn raw_command(&mut self, args: &[&str]) -> Result<Response, ClientError> {
        self.connection.send_command_strs(args).await
    }
}

/// Check that a response indicates success (must be a Map, not an error or other type).
fn check_ok_status(resp: Response) -> Result<(), ClientError> {
    match &resp {
        Response::Error(e) => {
            if e.contains("DENIED") {
                Err(ClientError::AuthRequired)
            } else {
                Err(ClientError::Server(e.clone()))
            }
        }
        Response::Map(_) => Ok(()),
        other => Err(ClientError::Protocol(format!(
            "expected Map response, got {}",
            other.type_name()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_plain_host() {
        let cfg = parse_uri("shroudb-sentry://localhost").unwrap();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 6799);
        assert!(!cfg.tls);
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn parse_uri_with_port() {
        let cfg = parse_uri("shroudb-sentry://localhost:7000").unwrap();
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 7000);
    }

    #[test]
    fn parse_uri_tls() {
        let cfg = parse_uri("shroudb-sentry+tls://prod.example.com").unwrap();
        assert!(cfg.tls);
        assert_eq!(cfg.host, "prod.example.com");
        assert_eq!(cfg.port, 6799);
    }

    #[test]
    fn parse_uri_with_auth() {
        let cfg = parse_uri("shroudb-sentry://mytoken@localhost:6799").unwrap();
        assert_eq!(cfg.auth_token.as_deref(), Some("mytoken"));
        assert_eq!(cfg.host, "localhost");
        assert_eq!(cfg.port, 6799);
    }

    #[test]
    fn parse_uri_full_form() {
        let cfg = parse_uri("shroudb-sentry+tls://tok@host:7000").unwrap();
        assert!(cfg.tls);
        assert_eq!(cfg.auth_token.as_deref(), Some("tok"));
        assert_eq!(cfg.host, "host");
        assert_eq!(cfg.port, 7000);
    }

    #[test]
    fn parse_uri_invalid_scheme() {
        assert!(parse_uri("redis://localhost").is_err());
        assert!(parse_uri("http://localhost").is_err());
        assert!(parse_uri("shroudb-mint://localhost").is_err());
    }

    #[test]
    fn parse_uri_default_port_on_invalid_port() {
        let cfg = parse_uri("shroudb-sentry://localhost:notaport").unwrap();
        assert_eq!(cfg.port, 6799);
    }
}
