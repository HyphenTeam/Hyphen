use parking_lot::RwLock;
use std::sync::Arc;
use tracing::info;

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
                        let _ = self.blocks.insert_output_with_height(
                            global_idx,
                            &out.one_time_pubkey,
                            out.commitment.as_bytes(),
                            block.header.height,
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
                info!(
                    "Coinbase: height={} view_public={} spend_public={} reward={}",
                    block.header.height,
                    hex::encode(view_public),
                    hex::encode(block.header.miner_pubkey),
                    block.header.reward,
                );
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
                    let _ = self.blocks.insert_output_with_height(
                        global_idx,
                        &out.one_time_pubkey,
                        out.commitment.as_bytes(),
                        block.header.height,
                    );
                }

                // Store serialized coinbase TX so RPC can serve it to wallets
                let coinbase_blob = coinbase_tx.serialise();
                self.blocks
                    .insert_coinbase(block.header.height, &coinbase_blob)
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
            } else if block.header.reward > 0 {
                info!(
                    "Coinbase SKIPPED: height={} pq_signature_len={} reward={}",
                    block.header.height,
                    block.pq_signature.len(),
                    block.header.reward,
                );
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

        // Get previous block timestamp for minimum-timestamp validation
        let prev_timestamp = if tip.height > 0 {
            self.blocks
                .get_block_by_height(tip.height)
                .map(|b| b.header.timestamp)
                .unwrap_or(0)
        } else {
            0
        };

        let validator = BlockValidator::new(&self.cfg);

        validator
            .validate_header(&block.header, tip.height, &tip.hash, prev_timestamp, now_ms)
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

        // C2 fix: Verify declared difficulty matches expected value
        let expected_difficulty = self.next_difficulty()?;
        if block.header.difficulty != expected_difficulty {
            return Err(CoreError::Validation(format!(
                "difficulty mismatch: expected {}, got {}",
                expected_difficulty, block.header.difficulty
            )));
        }

        let epoch_seed = self.epoch_seed_for_height(block.header.height)?;
        let arena = self.arena_for_epoch(epoch_seed);
        if !verify_pow(&block.header, &arena, &self.cfg) {
            return Err(CoreError::PowFailed);
        }

        // C3 fix: Verify declared reward matches emission formula
        let expected_reward = hyphen_economics::emission::lcd_base_reward(
            block.header.height,
            &self.cfg,
        );
        if block.header.reward != expected_reward {
            return Err(CoreError::Validation(format!(
                "reward mismatch: expected {}, got {}",
                expected_reward, block.header.reward
            )));
        }

        let block_bytes =
            bincode::serialize(block).map_err(|e| CoreError::Serialisation(e.to_string()))?;
        if block_bytes.len() > self.cfg.max_block_size {
            return Err(CoreError::BlockTooLarge);
        }

        // ── TERA: build set of valid epoch contexts ──
        // Accept epoch_context derived from the current epoch and up to
        // tera_epoch_tolerance past epochs.
        let valid_epoch_contexts = self.build_valid_epoch_contexts(block.header.height)?;
        let total_outputs = {
            let ct = self.commitment_tree.read();
            ct.count()
        };

        // C5 fix: Track key images seen within this block to prevent
        // intra-block double spends
        let mut block_key_images = std::collections::HashSet::new();

        for tx_blob in &block.transactions {
            let tx: Transaction = bincode::deserialize(tx_blob)
                .map_err(|e| CoreError::Serialisation(e.to_string()))?;

            for inp in &tx.inputs {
                // Check against persistent nullifier set
                if self
                    .nullifiers
                    .contains(&inp.key_image)
                    .map_err(|e| CoreError::Storage(e.to_string()))?
                {
                    return Err(CoreError::DuplicateNullifier(hex::encode(inp.key_image)));
                }
                // Check against other transactions in this block
                if !block_key_images.insert(inp.key_image) {
                    return Err(CoreError::DuplicateNullifier(hex::encode(inp.key_image)));
                }
            }

            // Full transaction validation including TERA + MD-VRE
            let store = &self.blocks;
            validator
                .validate_transaction(
                    &tx,
                    |global_index| {
                        store.resolve_ring_member(global_index).map_err(|e| {
                            crate::validator::ValidationError::Core(
                                CoreError::Storage(e.to_string()),
                            )
                        })
                    },
                    &valid_epoch_contexts,
                    total_outputs,
                )
                .map_err(|e| CoreError::Validation(e.to_string()))?;
        }

        self.apply_block_unchecked(block)
    }

    /// Build the set of valid TERA epoch contexts for the given height.
    /// Returns blake3("TERA_v1_context__Hyphen_2025_ctx" keyed, epoch_seed)
    /// for the current epoch and the previous `tera_epoch_tolerance` epochs.
    pub fn build_valid_epoch_contexts(&self, height: u64) -> Result<Vec<[u8; 32]>, CoreError> {
        let current_epoch = height / self.cfg.epoch_length;
        let tolerance = self.cfg.tera_epoch_tolerance;
        let first_epoch = current_epoch.saturating_sub(tolerance);

        let mut contexts = Vec::with_capacity((current_epoch - first_epoch + 1) as usize);
        for e in first_epoch..=current_epoch {
            let seed = if e == 0 {
                hyphen_crypto::blake3_hash(b"Hyphen_genesis_epoch_seed")
            } else {
                let prev_end = e * self.cfg.epoch_length - 1;
                let hash = self
                    .blocks
                    .get_block_hash_at_height(prev_end)
                    .map_err(|err| CoreError::Storage(err.to_string()))?;
                hyphen_crypto::blake3_hash(hash.as_bytes())
            };
            let ctx = *hyphen_crypto::hash::blake3_keyed(
                b"TERA_v1_context__Hyphen_2025_ctx",
                seed.as_bytes(),
            )
            .as_bytes();
            contexts.push(ctx);
        }
        Ok(contexts)
    }
}
