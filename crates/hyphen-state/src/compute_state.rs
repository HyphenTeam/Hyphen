use hyphen_compute::ComputeState;
use thiserror::Error;

use crate::compress::CompressedTree;

pub const COMPUTE_STATE_KEY: &[u8] = b"aether_compute_snapshot_v1";

#[derive(Debug, Error)]
pub enum ComputeStateStoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("encoding: {0}")]
    Encoding(String),
}

/// Canonical AetherCompute snapshot. Mutations are persisted by the block
/// atomic transaction; this wrapper owns the checked in-memory copy.
pub struct ComputeStateStore {
    pub(crate) tree: CompressedTree,
    committed: ComputeState,
}

impl ComputeStateStore {
    pub fn open(db: &sled::Db) -> Result<Self, ComputeStateStoreError> {
        let tree = CompressedTree::new(
            db.open_tree("aether_compute_state_v1")
                .map_err(|error| ComputeStateStoreError::Storage(error.to_string()))?,
        );
        let committed = match tree
            .get(COMPUTE_STATE_KEY)
            .map_err(|error| ComputeStateStoreError::Storage(error.to_string()))?
        {
            Some(bytes) => hyphen_codec::deserialize(&bytes)
                .map_err(|error| ComputeStateStoreError::Encoding(error.to_string()))?,
            None => ComputeState::default(),
        };
        Ok(Self { tree, committed })
    }

    pub fn snapshot(&self) -> ComputeState {
        self.committed.clone()
    }

    pub fn root(&self) -> hyphen_crypto::Hash256 {
        self.committed.root()
    }

    pub(crate) fn replace_committed(&mut self, state: ComputeState) {
        self.committed = state;
    }
}
