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
    output_index: sled::Tree,
    coinbase_index: sled::Tree,
}

impl BlockStore {
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            blocks: CompressedTree::new(db.open_tree("blocks")?),
            height_index: db.open_tree("height_index")?,
            tx_index: db.open_tree("tx_index")?,
            output_index: db.open_tree("output_index")?,
            coinbase_index: db.open_tree("coinbase_index")?,
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
        self.output_index.flush()?;
        self.coinbase_index.flush()?;
        Ok(())
    }

    /// Store the serialised coinbase transaction for a given block height.
    pub fn insert_coinbase(&self, height: u64, data: &[u8]) -> Result<()> {
        self.coinbase_index
            .insert(height.to_be_bytes(), data)?;
        Ok(())
    }

    /// Retrieve the serialised coinbase transaction at a given height.
    pub fn get_coinbase(&self, height: u64) -> Result<Vec<u8>> {
        let data = self
            .coinbase_index
            .get(height.to_be_bytes())?
            .ok_or_else(|| StoreError::NotFound(format!("coinbase at height {height}")))?;
        Ok(data.to_vec())
    }

    /// Store an output by its global index.
    /// Value layout: `[one_time_pubkey: 32] [commitment: 32]`
    pub fn insert_output(
        &self,
        global_index: u64,
        one_time_pubkey: &[u8; 32],
        commitment: &[u8; 32],
    ) -> Result<()> {
        let mut val = [0u8; 64];
        val[..32].copy_from_slice(one_time_pubkey);
        val[32..64].copy_from_slice(commitment);
        self.output_index
            .insert(global_index.to_be_bytes(), &val[..])?;
        Ok(())
    }

    /// Get an output (one_time_pubkey, commitment) by global index.
    pub fn get_output(&self, global_index: u64) -> Result<([u8; 32], [u8; 32])> {
        let val = self
            .output_index
            .get(global_index.to_be_bytes())?
            .ok_or_else(|| StoreError::NotFound(format!("output index {global_index}")))?;
        let mut pk = [0u8; 32];
        let mut cm = [0u8; 32];
        pk.copy_from_slice(&val[..32]);
        cm.copy_from_slice(&val[32..64]);
        Ok((pk, cm))
    }

    /// Get `count` random outputs below `ceiling` global index.
    /// Returns (one_time_pubkey, commitment, global_index) tuples.
    pub fn get_random_outputs(
        &self,
        count: usize,
        ceiling: u64,
    ) -> Result<Vec<([u8; 32], [u8; 32], u64)>> {
        use rand::Rng;
        if ceiling == 0 {
            return Ok(Vec::new());
        }
        let mut rng = rand::thread_rng();
        let mut result = Vec::with_capacity(count);
        let mut attempts = 0;
        let max_attempts = count * 10;
        while result.len() < count && attempts < max_attempts {
            attempts += 1;
            let idx: u64 = rng.gen_range(0..ceiling);
            if let Ok((pk, cm)) = self.get_output(idx) {
                result.push((pk, cm, idx));
            }
        }
        Ok(result)
    }
}
