//! Immutable storage for non-canonical block bodies.

use hyphen_core::block::Block;
use hyphen_crypto::Hash256;
use thiserror::Error;

use crate::compress::{compress, decompress};

#[derive(Debug, Error)]
pub enum BranchArchiveError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression error: {0}")]
    Compress(#[from] crate::compress::CompressError),
    #[error("block serialisation error: {0}")]
    Serialize(String),
    #[error("block is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("archived bytes do not hash to requested block {0}")]
    HashMismatch(Hash256),
    #[error("different block bytes already exist at hash {0}")]
    ImmutableConflict(Hash256),
    #[error("branch block not found: {0}")]
    NotFound(Hash256),
}

pub struct BranchBlockArchive {
    blocks: sled::Tree,
}

impl BranchBlockArchive {
    pub fn open(db: &sled::Db) -> Result<Self, BranchArchiveError> {
        Ok(Self {
            blocks: db.open_tree("branch_block_archive")?,
        })
    }

    /// Archive untrusted block bytes by their content hash without making the
    /// block canonical or implying any validation status.
    pub fn archive(&self, block: &Block, max_size: usize) -> Result<Hash256, BranchArchiveError> {
        let encoded = hyphen_codec::serialize(block)
            .map_err(|error| BranchArchiveError::Serialize(error.to_string()))?;
        enforce_size(encoded.len(), max_size)?;
        let hash = block.hash();
        let compressed = compress(&encoded)?;
        match self.blocks.compare_and_swap(
            hash.as_bytes(),
            None as Option<&[u8]>,
            Some(compressed.as_slice()),
        )? {
            Ok(()) => Ok(hash),
            Err(error) => {
                let existing = error
                    .current
                    .ok_or(BranchArchiveError::ImmutableConflict(hash))?;
                let existing = decompress(&existing)?;
                if existing == encoded {
                    Ok(hash)
                } else {
                    Err(BranchArchiveError::ImmutableConflict(hash))
                }
            }
        }
    }

    pub fn get(&self, hash: &Hash256, max_size: usize) -> Result<Block, BranchArchiveError> {
        let compressed = self
            .blocks
            .get(hash.as_bytes())?
            .ok_or(BranchArchiveError::NotFound(*hash))?;
        let encoded = decompress(&compressed)?;
        enforce_size(encoded.len(), max_size)?;
        let block = Block::deserialise_limited(&encoded, max_size)
            .map_err(|error| BranchArchiveError::Serialize(error.to_string()))?;
        if block.hash() != *hash {
            return Err(BranchArchiveError::HashMismatch(*hash));
        }
        Ok(block)
    }

    pub fn contains(&self, hash: &Hash256) -> Result<bool, BranchArchiveError> {
        Ok(self.blocks.contains_key(hash.as_bytes())?)
    }

    pub fn flush(&self) -> Result<(), BranchArchiveError> {
        self.blocks.flush()?;
        Ok(())
    }
}

fn enforce_size(actual: usize, maximum: usize) -> Result<(), BranchArchiveError> {
    if actual > maximum {
        Err(BranchArchiveError::TooLarge { actual, maximum })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::block::{Block, BlockHeader};

    fn block(marker: u8) -> Block {
        Block {
            header: BlockHeader {
                version: 2,
                height: 1,
                timestamp: 1,
                prev_hash: Hash256::ZERO,
                tx_root: Hash256::ZERO,
                commitment_root: Hash256::ZERO,
                nullifier_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
                receipt_root: Hash256::ZERO,
                uncle_root: Hash256::ZERO,
                pow_commitment: Hash256::from_bytes([marker; 32]),
                epoch_seed: Hash256::ZERO,
                difficulty: 1,
                nonce: marker as u64,
                extra_nonce: [marker; 32],
                miner_pubkey: [marker; 32],
                total_fee: 0,
                reward: 0,
                view_tag: 0,
                block_size: 0,
            },
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: Vec::new(),
        }
    }

    #[test]
    fn archive_is_idempotent_hash_bound_and_size_limited() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let archive = BranchBlockArchive::open(&db).unwrap();
        let block = block(7);
        let hash = archive.archive(&block, 4_096).unwrap();
        assert_eq!(archive.archive(&block, 4_096).unwrap(), hash);
        assert_eq!(archive.get(&hash, 4_096).unwrap().hash(), hash);
        assert!(archive.contains(&hash).unwrap());
        assert!(matches!(
            archive.archive(&block, 1),
            Err(BranchArchiveError::TooLarge { .. })
        ));
    }
}
