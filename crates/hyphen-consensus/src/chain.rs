use parking_lot::RwLock;
use std::sync::Arc;

use hyphen_core::block::Block;
use hyphen_core::config::ChainConfig;
use hyphen_core::error::CoreError;
use hyphen_core::timestamp::ntp_adjusted_timestamp_ms;
use hyphen_crypto::Hash256;
use hyphen_pow::difficulty::next_difficulty;
use hyphen_pow::solver::verify_pow;
use hyphen_pow::EpochArena;
use hyphen_state::chain_state::{ChainState, ChainTip};
use hyphen_state::commitment_tree::PersistentCommitmentTree;
use hyphen_state::nullifier_set::NullifierSet;
use hyphen_state::store::BlockStore;
use hyphen_tx::builder::build_coinbase_tx;
use hyphen_tx::transaction::Transaction;

use crate::genesis::build_genesis_block;
use crate::validator::BlockValidator;

pub struct Blockchain {
    pub cfg: ChainConfig,
    pub db: sled::Db,
    pub blocks: BlockStore,
    pub chain_state: ChainState,
    pub nullifiers: NullifierSet,
    pub commitment_tree: RwLock<PersistentCommitmentTree>,
    arena: RwLock<Option<Arc<EpochArena>>>,
}

impl Blockchain {
    pub fn open(path: &str, cfg: ChainConfig) -> Result<Self, CoreError> {
        let db = sled::open(path).map_err(|e| CoreError::Storage(e.to_string()))?;
        let blocks = BlockStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let chain_state = ChainState::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let nullifiers = NullifierSet::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let commitment_tree =
            PersistentCommitmentTree::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;

        let bc = Self {
            cfg,
            db,
            blocks,
            chain_state,
            nullifiers,
            commitment_tree: RwLock::new(commitment_tree),
            arena: RwLock::new(None),
        };

        if bc
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .is_none()
        {
            let genesis = build_genesis_block(&bc.cfg);
            bc.apply_block_unchecked(&genesis)?;
        }

        Ok(bc)
    }

    pub fn tip(&self) -> Result<ChainTip, CoreError> {
        self.chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .ok_or_else(|| CoreError::Validation("chain not initialised".into()))
    }

    pub fn height(&self) -> Result<u64, CoreError> {
        Ok(self.tip()?.height)
    }

    pub fn store(&self) -> &BlockStore {
        &self.blocks
    }

    pub fn arena_for_epoch(&self, epoch_seed: Hash256) -> Arc<EpochArena> {
        {
            let guard = self.arena.read();
            if let Some(ref arena) = *guard {
                if arena.params.epoch_seed == epoch_seed {
                    return Arc::clone(arena);
                }
            }
        }
        let new_arena = Arc::new(EpochArena::generate(
            epoch_seed,
            self.cfg.arena_size,
            self.cfg.page_size,
        ));
        *self.arena.write() = Some(Arc::clone(&new_arena));
        new_arena
    }

    pub fn epoch_seed_for_height(&self, height: u64) -> Result<Hash256, CoreError> {
        let epoch = height / self.cfg.epoch_length;
        if epoch == 0 {
            return Ok(hyphen_crypto::blake3_hash(b"Hyphen_genesis_epoch_seed"));
        }
        let prev_epoch_end = epoch * self.cfg.epoch_length - 1;
        let hash = self
            .blocks
            .get_block_hash_at_height(prev_epoch_end)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(hyphen_crypto::blake3_hash(hash.as_bytes()))
    }

    pub fn next_difficulty(&self) -> Result<u64, CoreError> {
        let tip = self.tip()?;
        let window = self.cfg.difficulty_window.min(tip.height) as usize;
        if window < 2 {
            return Ok(self.cfg.genesis_difficulty);
        }

        let start = tip.height + 1 - window as u64;
        let mut timestamps = Vec::with_capacity(window);
        let mut difficulties = Vec::with_capacity(window);

        for h in start..=tip.height {
            let block = self
                .blocks
                .get_block_by_height(h)
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            timestamps.push(block.header.timestamp);
            difficulties.push(block.header.difficulty);
        }

        Ok(next_difficulty(&timestamps, &difficulties, &self.cfg))
    }

    fn apply_block_unchecked(&self, block: &Block) -> Result<(), CoreError> {
        let hash = block.hash();
        self.blocks
            .insert_block(block)
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        {
            let mut ct = self.commitment_tree.write();
            for tx_blob in &block.transactions {
                if let Ok(tx) = bincode::deserialize::<Transaction>(tx_blob) {
                    for out in &tx.outputs {
                        let nh = out.note_hash();
                        let global_idx = ct
                            .append(nh)
                            .map_err(|e| CoreError::Storage(e.to_string()))?;
                        let _ = self.blocks.insert_output(
                            global_idx,
                            &out.one_time_pubkey,
                            out.commitment.as_bytes(),
                        );
                    }
                    for inp in &tx.inputs {
                        self.nullifiers
                            .insert(&inp.key_image, block.header.height)
                            .map_err(|e| CoreError::Storage(e.to_string()))?;
                    }
                }
            }

            // Create coinbase transaction if miner address is available
            if block.header.reward > 0 && block.pq_signature.len() == 32 {
                let mut view_public = [0u8; 32];
                view_public.copy_from_slice(&block.pq_signature);
                let coinbase_tx = build_coinbase_tx(
                    view_public,
                    block.header.miner_pubkey,
                    block.header.reward,
                    block.header.height,
                )
                .map_err(|e| CoreError::Validation(format!("coinbase build error: {e}")))?;

                for out in &coinbase_tx.outputs {
                    let nh = out.note_hash();
                    let global_idx = ct
                        .append(nh)
                        .map_err(|e| CoreError::Storage(e.to_string()))?;
                    let _ = self.blocks.insert_output(
                        global_idx,
                        &out.one_time_pubkey,
                        out.commitment.as_bytes(),
                    );
                }

                // Store serialized coinbase TX so RPC can serve it to wallets
                let coinbase_blob = coinbase_tx.serialise();
                self.blocks
                    .insert_coinbase(block.header.height, &coinbase_blob)
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
            }
        }

        let prev_tip = self
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let cum_diff = prev_tip.map(|t| t.cumulative_difficulty).unwrap_or(0)
            + block.header.difficulty as u128;

        let total_outputs = {
            let ct = self.commitment_tree.read();
            ct.count()
        };

        self.chain_state
            .set_tip(&ChainTip {
                height: block.header.height,
                hash,
                cumulative_difficulty: cum_diff,
                total_outputs,
            })
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        if (block.header.height + 1).is_multiple_of(self.cfg.epoch_length) {
            let next_epoch = (block.header.height + 1) / self.cfg.epoch_length;
            let seed = hyphen_crypto::blake3_hash(hash.as_bytes());
            self.chain_state
                .set_epoch_seed(next_epoch, &seed)
                .map_err(|e| CoreError::Storage(e.to_string()))?;
        }

        Ok(())
    }

    pub fn accept_block(&self, block: &Block) -> Result<(), CoreError> {
        let tip = self.tip()?;
        let now_ms = ntp_adjusted_timestamp_ms();

        let validator = BlockValidator::new(&self.cfg);

        validator
            .validate_header(&block.header, tip.height, &tip.hash, now_ms)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_tx_root(block)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_uncle_root(block)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        let blocks_ref = &self.blocks;
        validator
            .validate_uncles(block, &|height| {
                blocks_ref
                    .get_block_by_height(height)
                    .ok()
                    .map(|b| b.header)
            })
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        let epoch_seed = self.epoch_seed_for_height(block.header.height)?;
        let arena = self.arena_for_epoch(epoch_seed);
        if !verify_pow(&block.header, &arena, &self.cfg) {
            return Err(CoreError::PowFailed);
        }

        let block_bytes =
            bincode::serialize(block).map_err(|e| CoreError::Serialisation(e.to_string()))?;
        if block_bytes.len() > self.cfg.max_block_size {
            return Err(CoreError::BlockTooLarge);
        }

        for tx_blob in &block.transactions {
            let tx: Transaction = bincode::deserialize(tx_blob)
                .map_err(|e| CoreError::Serialisation(e.to_string()))?;

            for inp in &tx.inputs {
                if self
                    .nullifiers
                    .contains(&inp.key_image)
                    .map_err(|e| CoreError::Storage(e.to_string()))?
                {
                    return Err(CoreError::DuplicateNullifier(hex::encode(inp.key_image)));
                }
            }
        }

        self.apply_block_unchecked(block)
    }
}
