use hyphen_crypto::merkle::MerkleTree;
use hyphen_crypto::Hash256;
use thiserror::Error;

use crate::compress::CompressedTree;

#[derive(Debug, Error)]
pub enum CommitmentTreeError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression: {0}")]
    Compress(#[from] crate::compress::CompressError),
    #[error("serialisation: {0}")]
    Serde(String),
}

type Result<T> = std::result::Result<T, CommitmentTreeError>;

const TREE_STATE_KEY: &[u8] = b"merkle_tree_state";

pub struct PersistentCommitmentTree {
    tree_data: CompressedTree,
    inner: MerkleTree,
}

impl PersistentCommitmentTree {
    pub fn open(db: &sled::Db) -> Result<Self> {
        let tree_data = CompressedTree::new(db.open_tree("commitment_tree")?);
        let inner = match tree_data.get(TREE_STATE_KEY)? {
            Some(data) => bincode::deserialize(&data)
                .map_err(|e| CommitmentTreeError::Serde(e.to_string()))?,
            None => MerkleTree::new(),
        };
        Ok(Self { tree_data, inner })
    }

    pub fn root(&self) -> Hash256 {
        self.inner.root()
    }

    pub fn count(&self) -> u64 {
        self.inner.count()
    }

    pub fn append(&mut self, leaf: Hash256) -> Result<u64> {
        let idx = self.inner.append(leaf);
        self.persist()?;
        Ok(idx)
    }

    pub fn prove(&self, index: u64) -> Option<hyphen_crypto::merkle::MerkleProof> {
        self.inner.prove(index)
    }

    fn persist(&self) -> Result<()> {
        let data = bincode::serialize(&self.inner)
            .map_err(|e| CommitmentTreeError::Serde(e.to_string()))?;
        self.tree_data.insert(TREE_STATE_KEY, &data)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.tree_data.flush()?;
        Ok(())
    }
}
