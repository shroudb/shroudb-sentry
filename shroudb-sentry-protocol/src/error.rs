use thiserror::Error;

/// Errors returned by command execution.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("bad argument: {message}")]
    BadArg { message: String },

    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    #[error("{entity} not found: {id}")]
    NotFound { entity: String, id: String },

    #[error("no active signing key")]
    NoActiveKey,

    #[error("authentication required")]
    AuthRequired,

    #[error("access denied: {reason}")]
    Denied { reason: String },

    #[error("server not ready: {0}")]
    NotReady(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("read-only: this node is a replica")]
    ReadOnly,

    #[error(transparent)]
    Sentry(#[from] shroudb_sentry_core::error::SentryError),
}

impl CommandError {
    /// RESP3 error prefix for wire serialization.
    pub fn error_code(&self) -> &'static str {
        match self {
            CommandError::BadArg { .. } => "BADARG",
            CommandError::PolicyNotFound(_) => "NOTFOUND",
            CommandError::NotFound { .. } => "NOTFOUND",
            CommandError::NoActiveKey => "NOKEY",
            CommandError::AuthRequired => "DENIED",
            CommandError::Denied { .. } => "DENIED",
            CommandError::NotReady(_) => "NOTREADY",
            CommandError::Internal(_) => "INTERNAL",
            CommandError::Storage(_) => "STORAGE",
            CommandError::ReadOnly => "READONLY",
            CommandError::Sentry(_) => "SENTRY",
        }
    }
}
