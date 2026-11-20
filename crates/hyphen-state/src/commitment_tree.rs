use hyphen_crypto::Hash256;
use hyphen_crypto::merkle::MerkleTree;
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

pub(crate) const TREE_STATE_KEY: &[u8] = b"merkle_tree_state";

pub(crate) fn snapshot_codec() -> rustbinary::CompactConfig {
    // Every stored node needs two position integers and a 32-byte hash.
    crate::wire_config(crate::DEFAULT_WIRE_BYTES)
        .base_config()
        .with_collection_limit((crate::DEFAULT_WIRE_BYTES / 34) as u64)
        .with_compact_format()
}

pub struct PersistentCommitmentTree {
    pub(crate) tree_data: CompressedTree,
    inner: MerkleTree,
}

impl PersistentCommitmentTree {
    pub fn open(db: &sled::Db) -> Result<Self> {
        let tree_data = CompressedTree::new(db.open_tree("commitment_tree")?);
        let inner = match tree_data.get_raw(TREE_STATE_KEY)? {
            Some(frame) => {
                // Snapshots are written with zstd bulk compression. Decode into a
                // size-bounded buffer, then release the page before building the map.
                let data = zstd::bulk::decompress(&frame, crate::DEFAULT_WIRE_BYTES)
                    .map_err(|e| crate::compress::CompressError::Decompress(e.to_string()))?;
                drop(frame);
                snapshot_codec()
                    .deserialize(&data)
                    .map_err(|e| CommitmentTreeError::Serde(e.to_string()))?
            }
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
        let mut next = self.inner.clone();
        let idx = next.append(leaf);
        let data = snapshot_codec()
            .serialize(&next)
            .map_err(|e| CommitmentTreeError::Serde(e.to_string()))?;
        self.tree_data
            .inner()
            .insert(TREE_STATE_KEY, crate::compress::compress(&data)?)?;
        self.inner = next;
        Ok(idx)
    }

    pub fn prove(&self, index: u64) -> Option<hyphen_crypto::merkle::MerkleProof> {
        self.inner.prove(index)
    }

    pub fn snapshot(&self) -> MerkleTree {
        self.inner.clone()
    }

    pub(crate) fn replace_committed(&mut self, inner: MerkleTree) {
        self.inner = inner;
    }

    pub fn flush(&self) -> Result<()> {
        self.tree_data.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopens_tree_above_the_network_collection_budget() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let mut stored = PersistentCommitmentTree::open(&db).unwrap();
        for index in 0..500_000u64 {
            stored
                .inner
                .append(hyphen_crypto::blake3_hash(&index.to_le_bytes()));
        }
        let last = hyphen_crypto::blake3_hash(b"next");
        let index = stored.append(last).unwrap();
        let root = stored.root();
        drop(stored);
        let reopened = PersistentCommitmentTree::open(&db).unwrap();
        assert_eq!(reopened.count(), index + 1);
        assert_eq!(reopened.root(), root);
        assert!(reopened.prove(index).unwrap().verify(&last, &root));
    }
}
