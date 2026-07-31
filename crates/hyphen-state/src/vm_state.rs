use hyphen_vm::VmLedger;
use thiserror::Error;

use crate::compress::CompressedTree;

pub const VM_STATE_KEY: &[u8] = b"wasm_ledger_snapshot_v1";

#[derive(Debug, Error)]
pub enum VmStateStoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("encoding: {0}")]
    Encoding(String),
}

pub struct VmStateStore {
    pub(crate) tree: CompressedTree,
    committed: VmLedger,
}

impl VmStateStore {
    pub fn open(db: &sled::Db) -> Result<Self, VmStateStoreError> {
        let tree = CompressedTree::new(
            db.open_tree("wasm_ledger_state_v1")
                .map_err(|error| VmStateStoreError::Storage(error.to_string()))?,
        );
        let committed = match tree
            .get(VM_STATE_KEY)
            .map_err(|error| VmStateStoreError::Storage(error.to_string()))?
        {
            Some(bytes) => crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .deserialize(&bytes)
                .map_err(|error| VmStateStoreError::Encoding(error.to_string()))?,
            None => VmLedger::default(),
        };
        Ok(Self { tree, committed })
    }

    pub fn snapshot(&self) -> VmLedger {
        self.committed.clone()
    }

    pub fn root(&self) -> hyphen_crypto::Hash256 {
        self.committed.root()
    }

    pub(crate) fn replace_committed(&mut self, state: VmLedger) {
        self.committed = state;
    }
}
