//! Error types for the Sentry client library.

/// Errors that can occur when using the Sentry client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// TCP connection or I/O error.
    #[error("connection failed: {0}")]
    Connection(#[from] std::io::Error),

    /// The server returned an error response.
    #[error("server error: {0}")]
    Server(String),

    /// Protocol-level error (malformed response, unexpected type, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A required field was missing or had the wrong type in the server response.
    #[error("missing required field '{field}' in {command} response")]
    MissingField {
        command: &'static str,
        field: &'static str,
    },

    /// The server requires authentication but none was provided.
    #[error("authentication required")]
    AuthRequired,
}
