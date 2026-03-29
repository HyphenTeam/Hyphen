use hyphen_core::block::Block;
use hyphen_crypto::Hash256;
use thiserror::Error;

use crate::compress::CompressedTree;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression: {0}")]
    Compress(#[from] crate::compress::CompressError),
    #[error("serialisation: {0}")]
    Serde(String),
    #[error("block not found: {0}")]
    NotFound(String),
}

type Result<T> = std::result::Result<T, StoreError>;

pub struct BlockStore {
    blocks: CompressedTree,
    height_index: sled::Tree,
    tx_index: sled::Tree,
}

impl BlockStore {
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            blocks: CompressedTree::new(db.open_tree("blocks")?),
            height_index: db.open_tree("height_index")?,
            tx_index: db.open_tree("tx_index")?,
        })
    }

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let data = bincode::serialize(block).map_err(|e| StoreError::Serde(e.to_string()))?;

        self.blocks.insert(hash.as_bytes(), &data)?;
        self.height_index
            .insert(block.header.height.to_be_bytes(), hash.as_bytes().as_ref())?;

        for (idx, tx_blob) in block.transactions.iter().enumerate() {
            let tx_hash = hyphen_crypto::blake3_hash(tx_blob);
            let mut val = [0u8; 36];
            val[..32].copy_from_slice(hash.as_bytes());
            val[32..36].copy_from_slice(&(idx as u32).to_le_bytes());
            self.tx_index.insert(tx_hash.as_bytes(), &val[..])?;
        }

        Ok(())
    }

    pub fn get_block_by_hash(&self, hash: &Hash256) -> Result<Block> {
        let data = self
            .blocks
            .get(hash.as_bytes())?
            .ok_or_else(|| StoreError::NotFound(hash.to_string()))?;
        bincode::deserialize(&data).map_err(|e| StoreError::Serde(e.to_string()))
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Block> {
        let hash_bytes = self
            .height_index
            .get(height.to_be_bytes())?
            .ok_or_else(|| StoreError::NotFound(format!("height {height}")))?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);
        self.get_block_by_hash(&Hash256::from_bytes(h))
    }

    pub fn get_block_hash_at_height(&self, height: u64) -> Result<Hash256> {
        let hash_bytes = self
            .height_index
            .get(height.to_be_bytes())?
            .ok_or_else(|| StoreError::NotFound(format!("height {height}")))?;
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash_bytes);
        Ok(Hash256::from_bytes(h))
    }

    pub fn has_block(&self, hash: &Hash256) -> Result<bool> {
        Ok(self.blocks.contains_key(hash.as_bytes())?)
    }

    pub fn get_tx_location(&self, tx_hash: &Hash256) -> Result<(Hash256, u32)> {
        let val = self
            .tx_index
            .get(tx_hash.as_bytes())?
            .ok_or_else(|| StoreError::NotFound(tx_hash.to_string()))?;
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&val[..32]);
        let idx = u32::from_le_bytes(val[32..36].try_into().unwrap());
        Ok((Hash256::from_bytes(block_hash), idx))
    }

    pub fn flush(&self) -> Result<()> {
        self.blocks.flush()?;
        self.height_index.flush()?;
        self.tx_index.flush()?;
        Ok(())
    }
}
