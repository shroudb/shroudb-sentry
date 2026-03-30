/// Errors produced by the Sentry authorization engine.
#[derive(Debug, thiserror::Error)]
pub enum SentryError {
    /// A policy with this name already exists.
    #[error("policy already exists: {0}")]
    PolicyExists(String),

    /// The requested policy was not found.
    #[error("policy not found: {0}")]
    PolicyNotFound(String),

    /// No active signing key is available.
    #[error("no active signing key")]
    NoActiveKey,

    /// Signing failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// An invalid argument was provided.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// A Store operation failed.
    #[error("store error: {0}")]
    Store(String),

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}
