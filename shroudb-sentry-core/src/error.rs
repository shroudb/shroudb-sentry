use thiserror::Error;

use crate::key_state::KeyState;

#[derive(Debug, Error)]
pub enum SentryError {
    #[error("policy parse error: {0}")]
    PolicyParse(String),

    #[error("policy conflict: {0}")]
    PolicyConflict(String),

    #[error("invalid condition: {0}")]
    InvalidCondition(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: KeyState, to: KeyState },

    #[error("no active key")]
    NoActiveKey,
}
