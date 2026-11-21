//! Immutable storage for non-canonical block bodies.

use hyphen_core::block::Block;
use hyphen_crypto::Hash256;
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use thiserror::Error;

use crate::compress::{compress, decompress};

#[derive(Debug, Error)]
pub enum BranchArchiveError {
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
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
    positions: sled::Tree,
}

impl BranchBlockArchive {
    pub fn open(db: &sled::Db) -> Result<Self, BranchArchiveError> {
        Ok(Self {
            blocks: db.open_tree("branch_block_archive")?,
            positions: db.open_tree("branch_positions_v1")?,
        })
    }

    /// Archive untrusted block bytes by their content hash without making the
    /// block canonical or implying any validation status.
    pub fn archive(&self, block: &Block, max_size: usize) -> Result<Hash256, BranchArchiveError> {
        let encoded = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(block)
            .map_err(|error| BranchArchiveError::Serialize(error.to_string()))?;
        enforce_size(encoded.len(), max_size)?;
        let hash = block.hash();
        let compressed = compress(&encoded)?;
        let key = position_key(block.header.height, hash);
        let result = (&self.blocks, &self.positions).transaction(|(bodies, positions)| {
            if let Some(existing) = bodies.get(hash.as_bytes())? {
                if existing.as_ref() != compressed
                    && decompress(&existing).as_deref().ok() != Some(&encoded)
                {
                    return Err(ConflictableTransactionError::Abort(
                        BranchArchiveError::ImmutableConflict(hash),
                    ));
                }
            } else {
                bodies.insert(hash.as_bytes().as_slice(), compressed.as_slice())?;
            }
            positions.insert(key.as_slice(), block.header.prev_hash.as_bytes().as_slice())?;
            Ok(hash)
        });
        result.map_err(|error| match error {
            TransactionError::Abort(error) => error,
            TransactionError::Storage(error) => error.into(),
        })
    }

    pub fn index_position(&self, block: &Block) -> Result<(), BranchArchiveError> {
        self.positions.insert(
            position_key(block.header.height, block.hash()),
            block.header.prev_hash.as_bytes().as_slice(),
        )?;
        Ok(())
    }

    /// Older databases retain detached bodies and their undo records without a height index.
    pub fn index_existing_branches(
        &self,
        store: &crate::store::BlockStore,
        max_size: usize,
    ) -> Result<(), BranchArchiveError> {
        if self.positions.contains_key(b"ready")? {
            return Ok(());
        }
        for key in store.undo_index.inner().iter().keys() {
            let hash = stored_hash(&key?)?;
            let block = store.get_block_by_hash(&hash)?;
            match store.get_block_hash_at_height(block.header.height) {
                Ok(canonical) if canonical == hash => continue,
                Ok(_) | Err(crate::store::StoreError::NotFound(_)) => {
                    self.index_position(&block)?
                }
                Err(err) => return Err(err.into()),
            }
        }
        for key in self.blocks.iter().keys() {
            self.index_position(&self.get(&stored_hash(&key?)?, max_size)?)?;
        }
        self.positions.insert(b"ready", &[])?;
        self.positions.flush()?;
        Ok(())
    }

    pub fn at_height(
        &self,
        height: u64,
        limit: usize,
    ) -> Result<Vec<(Hash256, Hash256)>, BranchArchiveError> {
        self.positions
            .scan_prefix(height.to_be_bytes())
            .take(limit)
            .map(|entry| {
                let (key, parent) = entry?;
                Ok((stored_hash(&key[8..])?, stored_hash(&parent)?))
            })
            .collect()
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
        self.positions.flush()?;
        Ok(())
    }
}

fn stored_hash(bytes: &[u8]) -> Result<Hash256, BranchArchiveError> {
    Ok(Hash256::from_bytes(bytes.try_into().map_err(|_| {
        BranchArchiveError::Serialize("invalid branch index hash".into())
    })?))
}

fn position_key(height: u64, hash: Hash256) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(hash.as_bytes());
    key
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
            pow_witnesses: Vec::new(),
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
