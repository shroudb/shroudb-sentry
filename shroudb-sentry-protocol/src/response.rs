/// Response type for the Sentry protocol.
#[derive(Debug)]
pub enum SentryResponse {
    /// Successful response with JSON data.
    Ok(serde_json::Value),
    /// Error response.
    Error(String),
}

impl SentryResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self::Ok(data)
    }

    pub fn ok_simple() -> Self {
        Self::Ok(serde_json::json!({"status": "ok"}))
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error(msg.into())
    }
}
