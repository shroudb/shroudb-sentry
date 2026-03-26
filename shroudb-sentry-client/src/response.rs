//! Parsed response types and typed result structs for Sentry.

use std::collections::HashMap;

use crate::error::ClientError;

// ---------------------------------------------------------------------------
// Raw response
// ---------------------------------------------------------------------------

/// A parsed response value.
#[derive(Debug, Clone)]
pub enum Response {
    /// Simple string or bulk string.
    String(String),
    /// Error response.
    Error(String),
    /// Integer response.
    Integer(i64),
    /// Null value.
    Null,
    /// Array of responses.
    Array(Vec<Response>),
    /// Map of key-value pairs.
    Map(Vec<(Response, Response)>),
}

impl Response {
    /// Return the string value, or `None` if this is not a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Response::String(s) => Some(s),
            _ => None,
        }
    }

    /// Return the integer value, or `None`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Response::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Return `true` if this is an error response.
    pub fn is_error(&self) -> bool {
        matches!(self, Response::Error(_))
    }

    /// Return `true` if this is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Response::Null)
    }

    /// For display/debug: human-readable type name.
    pub fn type_name(&self) -> &'static str {
        match self {
            Response::String(_) => "String",
            Response::Error(_) => "Error",
            Response::Integer(_) => "Integer",
            Response::Null => "Null",
            Response::Array(_) => "Array",
            Response::Map(_) => "Map",
        }
    }

    /// Convert a response to a display string.
    pub fn to_display_string(&self) -> String {
        match self {
            Response::String(s) => s.clone(),
            Response::Error(e) => format!("(error) {e}"),
            Response::Integer(n) => n.to_string(),
            Response::Null => "(nil)".to_string(),
            Response::Array(_) => "(array)".to_string(),
            Response::Map(_) => "(map)".to_string(),
        }
    }

    /// Convert to `serde_json::Value`.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Response::String(s) => serde_json::Value::String(s.clone()),
            Response::Error(e) => serde_json::json!({ "error": e }),
            Response::Integer(n) => serde_json::json!(n),
            Response::Null => serde_json::Value::Null,
            Response::Array(items) => {
                serde_json::Value::Array(items.iter().map(|r| r.to_json()).collect())
            }
            Response::Map(entries) => {
                let obj: serde_json::Map<String, serde_json::Value> = entries
                    .iter()
                    .map(|(k, v)| (k.to_display_string(), v.to_json()))
                    .collect();
                serde_json::Value::Object(obj)
            }
        }
    }

    /// Reconstruct the raw wire format from a parsed Response.
    pub fn to_raw(&self) -> String {
        let mut buf = String::new();
        write_raw(self, &mut buf);
        buf
    }

    /// Print in human-readable format.
    pub fn print(&self, indent: usize) {
        let pad = "  ".repeat(indent);
        match self {
            Response::String(s) => println!("{pad}{s}"),
            Response::Error(e) => println!("{pad}(error) {e}"),
            Response::Integer(n) => println!("{pad}(integer) {n}"),
            Response::Null => println!("{pad}(nil)"),
            Response::Array(items) => {
                if items.is_empty() {
                    println!("{pad}(empty array)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        print!("{pad}{}. ", i + 1);
                        print_response_inline(item, indent + 1);
                    }
                }
            }
            Response::Map(entries) => {
                if entries.is_empty() {
                    println!("{pad}(empty map)");
                } else {
                    for (key, val) in entries {
                        let key_str = key.to_display_string();
                        match val {
                            Response::Map(_) | Response::Array(_) => {
                                println!("{pad}{key_str}:");
                                val.print(indent + 1);
                            }
                            _ => {
                                let val_str = response_to_inline_string(val);
                                println!("{pad}{key_str}: {val_str}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// Look up a key in a map response, returning the value.
    fn get_field(&self, key: &str) -> Option<&Response> {
        match self {
            Response::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.to_display_string() == key)
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Get a string field from a map response.
    fn get_string_field(&self, key: &str) -> Option<String> {
        self.get_field(key)
            .and_then(|v| v.as_str().map(String::from))
    }

    /// Get an integer field from a map response.
    fn get_int_field(&self, key: &str) -> Option<i64> {
        self.get_field(key).and_then(|v| match v {
            Response::Integer(n) => Some(*n),
            Response::String(s) => s.parse().ok(),
            _ => None,
        })
    }
}

fn print_response_inline(resp: &Response, indent: usize) {
    match resp {
        Response::Map(_) | Response::Array(_) => {
            println!();
            resp.print(indent);
        }
        _ => {
            println!("{}", response_to_inline_string(resp));
        }
    }
}

fn response_to_inline_string(resp: &Response) -> String {
    match resp {
        Response::String(s) => s.clone(),
        Response::Error(e) => format!("(error) {e}"),
        Response::Integer(n) => format!("(integer) {n}"),
        Response::Null => "(nil)".to_string(),
        Response::Array(items) => format!("(array, {} items)", items.len()),
        Response::Map(entries) => format!("(map, {} entries)", entries.len()),
    }
}

fn write_raw(resp: &Response, buf: &mut String) {
    match resp {
        Response::String(s) => {
            buf.push_str(&format!("${}\r\n{s}\r\n", s.len()));
        }
        Response::Error(e) => {
            buf.push('-');
            buf.push_str(e);
            buf.push_str("\r\n");
        }
        Response::Integer(n) => {
            buf.push(':');
            buf.push_str(&n.to_string());
            buf.push_str("\r\n");
        }
        Response::Null => {
            buf.push_str("_\r\n");
        }
        Response::Array(items) => {
            buf.push_str(&format!("*{}\r\n", items.len()));
            for item in items {
                write_raw(item, buf);
            }
        }
        Response::Map(entries) => {
            buf.push_str(&format!("%{}\r\n", entries.len()));
            for (k, v) in entries {
                write_raw(k, buf);
                write_raw(v, buf);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Response validation helpers
// ---------------------------------------------------------------------------

/// Check for error responses and ensure the response is a Map.
fn check_map_response(resp: &Response, command: &'static str) -> Result<(), ClientError> {
    if let Response::Error(e) = resp {
        if e.contains("DENIED") {
            return Err(ClientError::AuthRequired);
        }
        return Err(ClientError::Server(e.clone()));
    }
    if !matches!(resp, Response::Map(_)) {
        return Err(ClientError::Protocol(format!(
            "expected Map response for {command}, got {}",
            resp.type_name()
        )));
    }
    Ok(())
}

/// Require a string field, returning `MissingField` if absent.
fn require_string(
    resp: &Response,
    field: &'static str,
    command: &'static str,
) -> Result<String, ClientError> {
    resp.get_string_field(field)
        .ok_or(ClientError::MissingField { command, field })
}

/// Require an integer field, returning `MissingField` if absent.
fn require_int(
    resp: &Response,
    field: &'static str,
    command: &'static str,
) -> Result<i64, ClientError> {
    resp.get_int_field(field)
        .ok_or(ClientError::MissingField { command, field })
}

// ---------------------------------------------------------------------------
// Typed result structs
// ---------------------------------------------------------------------------

/// Result from an EVALUATE command.
#[derive(Debug, Clone)]
pub struct EvaluateResult {
    pub decision: String,
    pub token: String,
    pub policy: Option<String>,
    pub cache_until: i64,
}

impl EvaluateResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "EVALUATE")?;
        Ok(Self {
            decision: require_string(&resp, "decision", "EVALUATE")?,
            token: require_string(&resp, "token", "EVALUATE")?,
            policy: resp.get_string_field("policy"),
            cache_until: require_int(&resp, "cache_until", "EVALUATE")?,
        })
    }
}

/// Result from a POLICY_LIST command.
#[derive(Debug, Clone)]
pub struct PolicyListResult {
    pub count: i64,
    pub policies: Vec<String>,
}

impl PolicyListResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "POLICY_LIST")?;
        let count = require_int(&resp, "count", "POLICY_LIST")?;
        let policies = resp
            .get_field("policies")
            .and_then(|v| match v {
                Response::Array(items) => Some(
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(String::from))
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        Ok(Self { count, policies })
    }
}

/// Result from a POLICY_INFO command.
#[derive(Debug, Clone)]
pub struct PolicyInfoResult {
    pub name: String,
    pub effect: String,
    pub priority: i64,
    pub description: Option<String>,
}

impl PolicyInfoResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "POLICY_INFO")?;
        Ok(Self {
            name: require_string(&resp, "name", "POLICY_INFO")?,
            effect: require_string(&resp, "effect", "POLICY_INFO")?,
            priority: require_int(&resp, "priority", "POLICY_INFO")?,
            description: resp.get_string_field("description"),
        })
    }
}

/// Result from a KEY_INFO command.
#[derive(Debug, Clone)]
pub struct KeyInfoResult {
    pub name: String,
    pub algorithm: String,
    pub rotation_days: i64,
    pub drain_days: i64,
    pub decision_ttl_secs: i64,
    /// All fields from the response, for forward-compatibility.
    pub fields: HashMap<String, serde_json::Value>,
}

impl KeyInfoResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "KEY_INFO")?;
        let mut fields = HashMap::new();
        if let Response::Map(entries) = &resp {
            for (k, v) in entries {
                fields.insert(k.to_display_string(), v.to_json());
            }
        }
        Ok(Self {
            name: require_string(&resp, "name", "KEY_INFO")?,
            algorithm: require_string(&resp, "algorithm", "KEY_INFO")?,
            rotation_days: require_int(&resp, "rotation_days", "KEY_INFO")?,
            drain_days: require_int(&resp, "drain_days", "KEY_INFO")?,
            decision_ttl_secs: require_int(&resp, "decision_ttl_secs", "KEY_INFO")?,
            fields,
        })
    }
}

/// Result from a KEY_ROTATE command.
#[derive(Debug, Clone)]
pub struct KeyRotateResult {
    pub rotated: bool,
    pub new_version: Option<i64>,
    /// All fields from the response, for forward-compatibility.
    pub fields: HashMap<String, serde_json::Value>,
}

impl KeyRotateResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "KEY_ROTATE")?;
        let mut fields = HashMap::new();
        if let Response::Map(entries) = &resp {
            for (k, v) in entries {
                fields.insert(k.to_display_string(), v.to_json());
            }
        }
        Ok(Self {
            rotated: resp
                .get_field("rotated")
                .and_then(|v| match v {
                    Response::String(s) => Some(s == "true"),
                    _ => None,
                })
                .unwrap_or(false),
            new_version: resp.get_int_field("new_version"),
            fields,
        })
    }
}

/// Result from a HEALTH command.
#[derive(Debug, Clone)]
pub struct HealthResult {
    pub health: String,
    /// All fields from the response, for forward-compatibility.
    pub fields: HashMap<String, serde_json::Value>,
}

impl HealthResult {
    pub fn from_response(resp: Response) -> Result<Self, ClientError> {
        check_map_response(&resp, "HEALTH")?;
        let mut fields = HashMap::new();
        if let Response::Map(entries) = &resp {
            for (k, v) in entries {
                fields.insert(k.to_display_string(), v.to_json());
            }
        }
        Ok(Self {
            health: require_string(&resp, "health", "HEALTH")?,
            fields,
        })
    }
}
