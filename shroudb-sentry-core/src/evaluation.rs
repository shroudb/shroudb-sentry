use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// An authorization evaluation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub principal: Principal,
    pub resource: Resource,
    pub action: String,
}

/// The identity requesting access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,
}

/// The resource being accessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}
