use std::collections::HashMap;
use thiserror::Error;

use crate::types::ContractAddress;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression: {0}")]
    Compress(String),
}

pub struct ContractState {
    tree: sled::Tree,
}

impl ContractState {
    pub fn open(db: &sled::Db) -> Result<Self, StateError> {
        Ok(Self {
            tree: db.open_tree("contract_state")?,
        })
    }

    fn storage_key(contract: &ContractAddress, key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(32 + key.len());
        k.extend_from_slice(contract.as_bytes());
        k.extend_from_slice(key);
        k
    }

    pub fn get(
        &self,
        contract: &ContractAddress,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StateError> {
        let sk = Self::storage_key(contract, key);
        self.tree
            .get(&sk)?
            .map(|bytes| {
                zstd::stream::decode_all(bytes.as_ref())
                    .map_err(|error| StateError::Compress(error.to_string()))
            })
            .transpose()
    }

    pub fn set(
        &self,
        contract: &ContractAddress,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        let sk = Self::storage_key(contract, key);
        let compressed = zstd::bulk::compress(value, 3)
            .map_err(|error| StateError::Compress(error.to_string()))?;
        self.tree.insert(&sk, compressed)?;
        Ok(())
    }

    pub fn delete(&self, contract: &ContractAddress, key: &[u8]) -> Result<(), StateError> {
        let sk = Self::storage_key(contract, key);
        self.tree.remove(&sk)?;
        Ok(())
    }
}

pub struct OverlayState {
    base: ContractState,
    writes: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl OverlayState {
    pub fn new(base: ContractState) -> Self {
        Self {
            base,
            writes: HashMap::new(),
        }
    }

    pub fn get(
        &self,
        contract: &ContractAddress,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StateError> {
        let sk = ContractState::storage_key(contract, key);
        if let Some(entry) = self.writes.get(&sk) {
            return Ok(entry.clone());
        }
        self.base.get(contract, key)
    }

    pub fn set(&mut self, contract: &ContractAddress, key: &[u8], value: Vec<u8>) {
        let sk = ContractState::storage_key(contract, key);
        self.writes.insert(sk, Some(value));
    }

    pub fn delete(&mut self, contract: &ContractAddress, key: &[u8]) {
        let sk = ContractState::storage_key(contract, key);
        self.writes.insert(sk, None);
    }

    pub fn commit(self) -> Result<(), StateError> {
        let Self { base, writes } = self;
        for (sk, value) in writes {
            match value {
                Some(v) => {
                    let compressed = zstd::bulk::compress(&v, 3)
                        .map_err(|error| StateError::Compress(error.to_string()))?;
                    base.tree.insert(&sk, compressed)?;
                }
                None => {
                    base.tree.remove(&sk)?;
                }
            }
        }
        Ok(())
    }
}
