use serde::{Deserialize, Serialize};

use crate::error::SentryError;

/// Key lifecycle state machine: Staged -> Active -> Draining -> Retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Staged,
    Active,
    Draining,
    Retired,
}

impl KeyState {
    /// Returns whether this state can transition to the target state.
    pub fn can_transition_to(self, target: KeyState) -> bool {
        matches!(
            (self, target),
            (KeyState::Staged, KeyState::Active)
                | (KeyState::Active, KeyState::Draining)
                | (KeyState::Draining, KeyState::Retired)
        )
    }

    /// Attempt to transition to the target state.
    pub fn transition_to(self, target: KeyState) -> Result<KeyState, SentryError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(SentryError::InvalidStateTransition {
                from: self,
                to: target,
            })
        }
    }

    /// Parse from string (for WAL replay).
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "Staged" => KeyState::Staged,
            "Active" => KeyState::Active,
            "Draining" => KeyState::Draining,
            "Retired" => KeyState::Retired,
            other => {
                tracing::warn!(
                    state = other,
                    "unrecognized key state in WAL, defaulting to Active"
                );
                KeyState::Active
            }
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Staged => write!(f, "Staged"),
            KeyState::Active => write!(f, "Active"),
            KeyState::Draining => write!(f, "Draining"),
            KeyState::Retired => write!(f, "Retired"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions() {
        assert!(KeyState::Staged.can_transition_to(KeyState::Active));
        assert!(KeyState::Active.can_transition_to(KeyState::Draining));
        assert!(KeyState::Draining.can_transition_to(KeyState::Retired));
    }

    #[test]
    fn invalid_transitions() {
        assert!(!KeyState::Staged.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Staged.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Staged));
        assert!(!KeyState::Draining.can_transition_to(KeyState::Active));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Active.can_transition_to(KeyState::Active));
    }

    #[test]
    fn transition_to_ok() {
        let state = KeyState::Staged.transition_to(KeyState::Active).unwrap();
        assert_eq!(state, KeyState::Active);
    }

    #[test]
    fn transition_to_err() {
        let err = KeyState::Staged
            .transition_to(KeyState::Retired)
            .unwrap_err();
        assert!(matches!(
            err,
            SentryError::InvalidStateTransition {
                from: KeyState::Staged,
                to: KeyState::Retired,
            }
        ));
    }
}
