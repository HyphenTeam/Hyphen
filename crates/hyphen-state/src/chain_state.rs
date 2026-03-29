use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compress::CompressedTree;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression: {0}")]
    Compress(#[from] crate::compress::CompressError),
    #[error("deserialisation: {0}")]
    Serde(String),
    #[error("state not initialised")]
    NotInitialised,
}

type Result<T> = std::result::Result<T, StateError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub hash: Hash256,
    pub cumulative_difficulty: u128,
    pub total_outputs: u64,
}

pub struct ChainState {
    tree: CompressedTree,
}

const TIP_KEY: &[u8] = b"chain_tip";
const EPOCH_SEED_PREFIX: &[u8] = b"epoch_seed:";

impl ChainState {
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            tree: CompressedTree::new(db.open_tree("chain_state")?),
        })
    }

    pub fn get_tip(&self) -> Result<Option<ChainTip>> {
        match self.tree.get(TIP_KEY)? {
            Some(data) => {
                let tip: ChainTip =
                    bincode::deserialize(&data).map_err(|e| StateError::Serde(e.to_string()))?;
                Ok(Some(tip))
            }
            None => Ok(None),
        }
    }

    pub fn set_tip(&self, tip: &ChainTip) -> Result<()> {
        let data = bincode::serialize(tip).map_err(|e| StateError::Serde(e.to_string()))?;
        self.tree.insert(TIP_KEY, &data)?;
        Ok(())
    }

    pub fn get_epoch_seed(&self, epoch: u64) -> Result<Option<Hash256>> {
        let mut key = EPOCH_SEED_PREFIX.to_vec();
        key.extend_from_slice(&epoch.to_be_bytes());
        match self.tree.get(&key)? {
            Some(data) => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&data);
                Ok(Some(Hash256::from_bytes(h)))
            }
            None => Ok(None),
        }
    }

    pub fn set_epoch_seed(&self, epoch: u64, seed: &Hash256) -> Result<()> {
        let mut key = EPOCH_SEED_PREFIX.to_vec();
        key.extend_from_slice(&epoch.to_be_bytes());
        self.tree.insert(&key, seed.as_bytes())?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.tree.flush()?;
        Ok(())
    }
}
