//! EngineHandler implementation for Sentry.
//!
//! Routes WAL entries for signing key versions to the signing index
//! during replay and replication.

use std::sync::Arc;

use shroudb_storage::{EngineHandler, OpType, StorageEngine, StorageError, WalPayload};

use crate::recovery;
use crate::signing_index::SigningIndex;

/// Sentry engine handler for WAL replay and replication.
pub struct SentryEngineHandler {
    engine: Arc<StorageEngine>,
    signing_index: Arc<SigningIndex>,
    keyring_name: String,
}

impl SentryEngineHandler {
    pub fn new(
        engine: Arc<StorageEngine>,
        signing_index: Arc<SigningIndex>,
        keyring_name: String,
    ) -> Self {
        Self {
            engine,
            signing_index,
            keyring_name,
        }
    }
}

impl EngineHandler for SentryEngineHandler {
    fn name(&self) -> &str {
        "sentry"
    }

    fn handles_op_type(&self, op: OpType) -> bool {
        matches!(
            op,
            OpType::KeyVersionCreated | OpType::KeyVersionStateChanged
        )
    }

    fn apply_wal_payload(
        &self,
        _keyspace_id: &str,
        _op: OpType,
        payload: &WalPayload,
    ) -> Result<(), StorageError> {
        recovery::replay_key_payload(
            &self.engine,
            &self.signing_index,
            &self.keyring_name,
            payload,
        )
        .map_err(|e| StorageError::Deserialization(e.to_string()))
    }
}
