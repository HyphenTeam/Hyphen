use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use tracing::info;

use hyphen_compute::{ComputeTransaction, ProofVerifier, RejectingVerifier, TaskRecord};
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
use hyphen_state::{
    commit_block_update, consensus_state_root, revert_block_update, AtomicBlockUpdate,
    AtomicStateStores, AuthenticatedBlobStore, BranchBlockArchive, ComputeStateStore,
    IndexedOutput, PersistentSparseMerkleTree, ReorgBackend, ReorgCoordinator, ReorgOutcome,
    ReorgPlan, VmStateStore, WesStateStore, WesTransaction,
};
use hyphen_tx::builder::build_coinbase_tx;
use hyphen_tx::transaction::Transaction;
use hyphen_vm::{Contract, ContractAddress, VmTransaction};

use crate::genesis::{build_genesis_block, genesis_epoch_seed};
use crate::validator::BlockValidator;

pub struct Blockchain {
    pub cfg: ChainConfig,
    pub db: sled::Db,
    pub blocks: BlockStore,
    pub chain_state: ChainState,
    pub nullifiers: NullifierSet,
    pub commitment_tree: RwLock<PersistentCommitmentTree>,
    pub branch_blocks: BranchBlockArchive,
    /// Legacy H-WES latest-state tree exposed by the bounded proof service.
    pub wes_latest: PersistentSparseMerkleTree,
    /// Content-addressed storage used by the proof/blob request protocol.
    pub proof_blobs: AuthenticatedBlobStore,
    pub compute_state: RwLock<ComputeStateStore>,
    pub vm_state: RwLock<VmStateStore>,
    pub wes_state: RwLock<WesStateStore>,
    pub reorg: ReorgCoordinator,
    compute_verifier: Arc<dyn ProofVerifier>,
    transition: Mutex<()>,
    arena: RwLock<Option<Arc<EpochArena>>>,
}

impl Blockchain {
    pub fn open(path: &str, cfg: ChainConfig) -> Result<Self, CoreError> {
        let db = sled::open(path).map_err(|e| CoreError::Storage(e.to_string()))?;
        Self::open_db_with_verifier(db, cfg, Arc::new(RejectingVerifier))
    }

    #[cfg(test)]
    fn open_db(db: sled::Db, cfg: ChainConfig) -> Result<Self, CoreError> {
        Self::open_db_with_verifier(db, cfg, Arc::new(RejectingVerifier))
    }

    pub fn open_with_compute_verifier(
        path: &str,
        cfg: ChainConfig,
        verifier: Arc<dyn ProofVerifier>,
    ) -> Result<Self, CoreError> {
        let db = sled::open(path).map_err(|e| CoreError::Storage(e.to_string()))?;
        Self::open_db_with_verifier(db, cfg, verifier)
    }

    fn open_db_with_verifier(
        db: sled::Db,
        cfg: ChainConfig,
        compute_verifier: Arc<dyn ProofVerifier>,
    ) -> Result<Self, CoreError> {
        let blocks = BlockStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let chain_state = ChainState::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let nullifiers = NullifierSet::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let commitment_tree =
            PersistentCommitmentTree::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let branch_blocks =
            BranchBlockArchive::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let reorg = ReorgCoordinator::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let chain_namespace = Hash256::from_bytes(cfg.consensus_params_hash());
        let wes_namespace = hyphen_crypto::blake3_hash(
            &[
                b"HYPHEN_WES_LATEST_NAMESPACE_V1".as_slice(),
                chain_namespace.as_bytes(),
            ]
            .concat(),
        );
        let wes_latest = PersistentSparseMerkleTree::open(&db, "wes_latest_smt_v1", wes_namespace)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let proof_blobs =
            AuthenticatedBlobStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let compute_state =
            ComputeStateStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let vm_state = VmStateStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let wes_state = WesStateStore::open(&db, build_genesis_block(&cfg).hash())
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        // ── Genesis config immutability check ──────────────────────
        let meta_tree = db
            .open_tree("consensus_meta")
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let current_hash = cfg.consensus_params_hash();
        if let Some(stored) = meta_tree
            .get(b"params_hash")
            .map_err(|e| CoreError::Storage(e.to_string()))?
        {
            if stored.as_ref() != current_hash.as_slice() {
                return Err(CoreError::Validation(
                    "consensus parameters differ from genesis — \
                     the chain database was created with different rules; \
                     refusing to open to prevent fork"
                        .into(),
                ));
            }
        } else {
            meta_tree
                .insert(b"params_hash", current_hash.as_slice())
                .map_err(|e| CoreError::Storage(e.to_string()))?;
        }

        let bc = Self {
            cfg,
            db,
            blocks,
            chain_state,
            nullifiers,
            commitment_tree: RwLock::new(commitment_tree),
            branch_blocks,
            wes_latest,
            proof_blobs,
            compute_state: RwLock::new(compute_state),
            vm_state: RwLock::new(vm_state),
            wes_state: RwLock::new(wes_state),
            reorg,
            compute_verifier,
            transition: Mutex::new(()),
            arena: RwLock::new(None),
        };

        let expected_genesis = build_genesis_block(&bc.cfg);
        let expected_genesis_hash = expected_genesis.hash();
        if bc
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .is_none()
        {
            bc.apply_block_unchecked(&expected_genesis)?;
            meta_tree
                .insert(b"genesis_hash", expected_genesis_hash.as_bytes().as_slice())
                .map_err(|e| CoreError::Storage(e.to_string()))?;
        } else {
            let stored_genesis = bc
                .blocks
                .get_block_by_height(0)
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            if stored_genesis.hash() != expected_genesis_hash {
                return Err(CoreError::Validation(format!(
                    "genesis hash mismatch: database={}, expected={}; refusing to join a different chain",
                    stored_genesis.hash(), expected_genesis_hash
                )));
            }

            if let Some(stored_hash) = meta_tree
                .get(b"genesis_hash")
                .map_err(|e| CoreError::Storage(e.to_string()))?
            {
                if stored_hash.as_ref() != expected_genesis_hash.as_bytes() {
                    return Err(CoreError::Validation(
                        "stored genesis metadata does not match block zero".into(),
                    ));
                }
            } else {
                meta_tree
                    .insert(b"genesis_hash", expected_genesis_hash.as_bytes().as_slice())
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
            }
        }

        bc.recover_pending_reorg()?;
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

    pub fn chain_id(&self) -> Hash256 {
        build_genesis_block(&self.cfg).hash()
    }

    pub fn compute_root(&self) -> Hash256 {
        let _transition = self.transition.lock();
        self.compute_state.read().root()
    }

    pub fn compute_task(&self, task_id: Hash256) -> Option<TaskRecord> {
        let _transition = self.transition.lock();
        self.compute_state.read().snapshot().task(task_id).cloned()
    }

    pub fn compute_tasks(
        &self,
        offset: usize,
        limit: usize,
    ) -> (Vec<(Hash256, TaskRecord)>, usize) {
        let _transition = self.transition.lock();
        let state = self.compute_state.read().snapshot();
        (state.tasks_page(offset, limit), state.task_count())
    }

    pub fn vm_contract(&self, address: ContractAddress) -> Option<Contract> {
        let _transition = self.transition.lock();
        self.vm_state.read().snapshot().contract(address).cloned()
    }

    pub fn vm_storage(&self, address: ContractAddress, key: &[u8]) -> Option<Vec<u8>> {
        let _transition = self.transition.lock();
        self.vm_state
            .read()
            .snapshot()
            .storage(address, key)
            .map(ToOwned::to_owned)
    }

    pub fn h_wes_roots(&self) -> (hyphen_state::StateRoots, Hash256) {
        let _transition = self.transition.lock();
        let state = self.wes_state.read();
        (state.roots(), state.root())
    }

    pub fn state_root(&self) -> Hash256 {
        let _transition = self.transition.lock();
        consensus_state_root(
            self.compute_state.read().root(),
            self.vm_state.read().root(),
            self.wes_state.read().root(),
        )
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
            return Ok(genesis_epoch_seed(&self.cfg));
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
        let prev_tip = self
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let cum_diff = prev_tip.map(|t| t.cumulative_difficulty).unwrap_or(0)
            + block.header.difficulty as u128;

        let mut commitment_tree = self.commitment_tree.write();
        let mut compute_store = self.compute_state.write();
        let mut vm_store = self.vm_state.write();
        let mut wes_store = self.wes_state.write();
        let mut prepared_tree = commitment_tree.snapshot();
        let mut prepared_compute = compute_store.snapshot();
        let mut prepared_vm = vm_store.snapshot();
        let mut prepared_wes = wes_store.snapshot();
        prepared_wes.expire_due(block.header.height, 1024);
        let mut outputs = Vec::new();
        let mut nullifiers = Vec::new();
        for tx_blob in &block.transactions {
            if let Some(transaction) = ComputeTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                prepared_compute
                    .apply(
                        self.chain_id(),
                        block.header.height,
                        &transaction,
                        self.compute_verifier.as_ref(),
                    )
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = VmTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                prepared_vm
                    .apply(self.chain_id(), block.header.height, &transaction)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = WesTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                transaction
                    .apply(&mut prepared_wes, self.chain_id(), block.header.height)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            let tx = Transaction::deserialise_limited(tx_blob)
                .map_err(|error| CoreError::Serialisation(error.to_string()))?;
            for output in &tx.outputs {
                let global_index = prepared_tree.append(output.note_hash());
                outputs.push(IndexedOutput {
                    global_index,
                    one_time_pubkey: output.one_time_pubkey,
                    commitment: *output.commitment.as_bytes(),
                    block_height: block.header.height,
                });
            }
            nullifiers.extend(tx.inputs.iter().map(|input| input.key_image));
        }

        let coinbase = if block.header.reward > 0 && block.header.height > 0 {
            let authorization = block.decode_authorization().map_err(|error| {
                CoreError::Validation(format!("cannot apply unauthorized block: {error}"))
            })?;
            info!(
                "Coinbase: height={} view_public={} spend_public={} reward={}",
                block.header.height,
                hex::encode(authorization.reward_view_public),
                hex::encode(authorization.reward_spend_public),
                block.header.reward,
            );
            let coinbase_tx = build_coinbase_tx(
                authorization.reward_view_public,
                authorization.reward_spend_public,
                block.header.reward,
                block.header.height,
                hash,
            )
            .map_err(|error| CoreError::Validation(format!("coinbase build error: {error}")))?;
            for output in &coinbase_tx.outputs {
                let global_index = prepared_tree.append(output.note_hash());
                outputs.push(IndexedOutput {
                    global_index,
                    one_time_pubkey: output.one_time_pubkey,
                    commitment: *output.commitment.as_bytes(),
                    block_height: block.header.height,
                });
            }
            Some(coinbase_tx.serialise())
        } else {
            None
        };

        let next_epoch_seed = if (block.header.height + 1).is_multiple_of(self.cfg.epoch_length) {
            let next_epoch = (block.header.height + 1) / self.cfg.epoch_length;
            let seed = hyphen_crypto::blake3_hash(hash.as_bytes());
            Some((next_epoch, seed))
        } else {
            None
        };
        let total_outputs = prepared_tree.count();

        commit_block_update(
            AtomicStateStores {
                blocks: &self.blocks,
                chain_state: &self.chain_state,
                nullifiers: &self.nullifiers,
                commitment_tree: &mut commitment_tree,
                compute_state: &mut compute_store,
                vm_state: &mut vm_store,
                wes_state: &mut wes_store,
            },
            AtomicBlockUpdate {
                block,
                commitment_tree: prepared_tree,
                outputs,
                nullifiers,
                coinbase,
                tip: ChainTip {
                    height: block.header.height,
                    hash,
                    cumulative_difficulty: cum_diff,
                    total_outputs,
                },
                next_epoch_seed,
                compute_state: prepared_compute,
                vm_state: prepared_vm,
                wes_state: prepared_wes,
            },
        )
        .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn accept_block(&self, block: &Block) -> Result<(), CoreError> {
        let _transition = self.transition.lock();
        self.accept_block_locked(block)
    }

    fn accept_block_locked(&self, block: &Block) -> Result<(), CoreError> {
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
            .validate_block_authorization(block, build_genesis_block(&self.cfg).hash())
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_tx_root(block)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_transaction_order(block)
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
        let expected_reward =
            hyphen_economics::emission::lcd_base_reward(block.header.height, &self.cfg);
        if block.header.reward != expected_reward {
            return Err(CoreError::Validation(format!(
                "reward mismatch: expected {}, got {}",
                expected_reward, block.header.reward
            )));
        }

        let block_bytes =
            hyphen_codec::serialize(block).map_err(|e| CoreError::Serialisation(e.to_string()))?;
        if block_bytes.len() > self.cfg.max_block_size {
            return Err(CoreError::BlockTooLarge);
        }

        // ── TERA: build set of valid epoch contexts ──
        // Accept epoch_context derived from the current epoch and up to
        // tera_epoch_tolerance past epochs.
        let total_fee = self.validate_transaction_blobs_for_height_locked(
            &block.transactions,
            block.header.height,
        )?;
        let state_root = self.state_root_after_locked(&block.transactions, block.header.height)?;
        if block.header.state_root != state_root {
            return Err(CoreError::Validation(format!(
                "state root mismatch: expected {state_root}, got {}",
                block.header.state_root
            )));
        }
        if self
            .cfg
            .feature_enabled(hyphen_core::FEATURE_CANONICAL_TX_ORDER)
            && block.header.total_fee != total_fee
        {
            return Err(CoreError::Validation(format!(
                "total fee mismatch: expected {total_fee}, got {}",
                block.header.total_fee
            )));
        }

        self.apply_block_unchecked(block)
    }

    /// Fully validates an ordered transaction candidate against current
    /// canonical state and returns its checked fee sum.
    pub fn validate_transaction_blobs_for_height(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<u64, CoreError> {
        let _transition = self.transition.lock();
        self.validate_transaction_blobs_for_height_locked(transaction_blobs, block_height)
    }

    fn validate_transaction_blobs_for_height_locked(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<u64, CoreError> {
        let tip = self.tip()?;
        let expected_height = tip
            .height
            .checked_add(1)
            .ok_or_else(|| CoreError::Validation("chain height exhausted".into()))?;
        if block_height != expected_height {
            return Err(CoreError::HeightMismatch {
                expected: expected_height,
                got: block_height,
            });
        }
        let total_size = transaction_blobs.iter().try_fold(0usize, |total, blob| {
            total
                .checked_add(blob.len())
                .ok_or(CoreError::BlockTooLarge)
        })?;
        if total_size > self.cfg.max_block_size {
            return Err(CoreError::BlockTooLarge);
        }

        let valid_epoch_contexts = self.build_valid_epoch_contexts(block_height)?;
        let total_outputs = self.commitment_tree.read().count();
        let validator = BlockValidator::new(&self.cfg);
        let mut block_key_images = std::collections::HashSet::new();
        let mut transaction_hashes = std::collections::HashSet::new();
        let mut compute_state = self.compute_state.read().snapshot();
        let mut vm_state = self.vm_state.read().snapshot();
        let mut wes_state = self.wes_state.read().snapshot();
        wes_state.expire_due(block_height, 1024);
        let mut total_fee = 0u64;

        for tx_blob in transaction_blobs {
            let transaction_hash = hyphen_crypto::blake3_hash(tx_blob);
            if !transaction_hashes.insert(transaction_hash) {
                return Err(CoreError::Validation(
                    "duplicate transaction in block candidate".into(),
                ));
            }
            if let Some(transaction) = ComputeTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_USEFUL_WORK) {
                    return Err(CoreError::Validation(
                        "AetherCompute transactions are not active on this chain profile".into(),
                    ));
                }
                compute_state
                    .apply(
                        self.chain_id(),
                        block_height,
                        &transaction,
                        self.compute_verifier.as_ref(),
                    )
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = VmTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_WASM) {
                    return Err(CoreError::Validation(
                        "WASM transactions are not active on this chain profile".into(),
                    ));
                }
                vm_state
                    .apply(self.chain_id(), block_height, &transaction)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = WesTransaction::decode(tx_blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_H_WES) {
                    return Err(CoreError::Validation(
                        "H-WES transactions are not active on this chain profile".into(),
                    ));
                }
                transaction
                    .apply(&mut wes_state, self.chain_id(), block_height)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            let tx = Transaction::deserialise_limited(tx_blob)
                .map_err(|error| CoreError::Serialisation(error.to_string()))?;
            total_fee = total_fee
                .checked_add(tx.fee)
                .ok_or_else(|| CoreError::Validation("transaction fee sum overflow".into()))?;

            for input in &tx.inputs {
                if self
                    .nullifiers
                    .contains(&input.key_image)
                    .map_err(|error| CoreError::Storage(error.to_string()))?
                    || !block_key_images.insert(input.key_image)
                {
                    return Err(CoreError::DuplicateNullifier(hex::encode(input.key_image)));
                }
            }

            let store = &self.blocks;
            validator
                .validate_transaction(
                    &tx,
                    |global_index| {
                        store.resolve_ring_member(global_index).map_err(|error| {
                            crate::validator::ValidationError::Core(CoreError::Storage(
                                error.to_string(),
                            ))
                        })
                    },
                    &valid_epoch_contexts,
                    total_outputs,
                    block_height,
                )
                .map_err(|error| CoreError::Validation(error.to_string()))?;
        }

        Ok(total_fee)
    }

    /// Computes the unified AetherCompute, WASM and H-WES post-state root for
    /// an ordered block candidate without mutating canonical state.
    pub fn state_root_after(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<Hash256, CoreError> {
        let _transition = self.transition.lock();
        self.state_root_after_locked(transaction_blobs, block_height)
    }

    fn state_root_after_locked(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<Hash256, CoreError> {
        let mut state = self.compute_state.read().snapshot();
        let mut vm_state = self.vm_state.read().snapshot();
        let mut wes_state = self.wes_state.read().snapshot();
        wes_state.expire_due(block_height, 1024);
        for blob in transaction_blobs {
            if let Some(transaction) = ComputeTransaction::decode(blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_USEFUL_WORK) {
                    return Err(CoreError::Validation(
                        "AetherCompute transactions are not active on this chain profile".into(),
                    ));
                }
                state
                    .apply(
                        self.chain_id(),
                        block_height,
                        &transaction,
                        self.compute_verifier.as_ref(),
                    )
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = VmTransaction::decode(blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_WASM) {
                    return Err(CoreError::Validation(
                        "WASM transactions are not active on this chain profile".into(),
                    ));
                }
                vm_state
                    .apply(self.chain_id(), block_height, &transaction)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
                continue;
            }
            if let Some(transaction) = WesTransaction::decode(blob)
                .map_err(|error| CoreError::Validation(error.to_string()))?
            {
                if !self.cfg.feature_enabled(hyphen_core::FEATURE_H_WES) {
                    return Err(CoreError::Validation(
                        "H-WES transactions are not active on this chain profile".into(),
                    ));
                }
                transaction
                    .apply(&mut wes_state, self.chain_id(), block_height)
                    .map_err(|error| CoreError::Validation(error.to_string()))?;
            }
        }
        let wes_root = if wes_state.is_empty() {
            Hash256::ZERO
        } else {
            wes_state.roots().combined()
        };
        Ok(consensus_state_root(
            state.root(),
            vm_state.root(),
            wes_root,
        ))
    }

    /// Persist a competing block body without assigning it validation status.
    /// Every block is fully revalidated if a reorg later attempts to attach it.
    pub fn stage_reorg_block(&self, block: &Block) -> Result<Hash256, CoreError> {
        self.branch_blocks
            .archive(block, self.cfg.max_block_size)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn execute_reorg(&self, plan: ReorgPlan) -> Result<ReorgOutcome, CoreError> {
        let _transition = self.transition.lock();
        self.validate_reorg_plan(&plan)?;
        let mut backend = BlockchainReorgBackend { chain: self };
        self.reorg
            .execute(&mut backend, plan)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn recover_pending_reorg(&self) -> Result<Option<ReorgOutcome>, CoreError> {
        let _transition = self.transition.lock();
        let mut backend = BlockchainReorgBackend { chain: self };
        self.reorg
            .recover(&mut backend)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn validate_reorg_plan(&self, plan: &ReorgPlan) -> Result<(), CoreError> {
        let tip = self.tip()?;
        let expected_tip = plan.detach.first().copied().unwrap_or(plan.common_ancestor);
        if expected_tip != tip.hash || plan.old_work != tip.cumulative_difficulty {
            return Err(CoreError::Validation(
                "reorg plan does not start at the current canonical tip".into(),
            ));
        }

        let mut cursor = tip.hash;
        let mut cursor_height = tip.height;
        let mut detached_work = 0u128;
        for expected in &plan.detach {
            if *expected != cursor {
                return Err(CoreError::Validation(
                    "reorg detach path is not contiguous".into(),
                ));
            }
            let block = self
                .blocks
                .get_block_by_hash(expected)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if block.header.height != cursor_height {
                return Err(CoreError::Validation(
                    "reorg detach height does not match canonical history".into(),
                ));
            }
            detached_work = detached_work
                .checked_add(block.header.difficulty as u128)
                .ok_or_else(|| CoreError::Validation("reorg work overflow".into()))?;
            cursor = block.header.prev_hash;
            cursor_height = cursor_height
                .checked_sub(1)
                .ok_or_else(|| CoreError::Validation("reorg attempts to detach genesis".into()))?;
        }
        if cursor != plan.common_ancestor
            || self
                .blocks
                .get_block_hash_at_height(cursor_height)
                .map_err(|error| CoreError::Storage(error.to_string()))?
                != plan.common_ancestor
        {
            return Err(CoreError::Validation(
                "reorg common ancestor is not canonical".into(),
            ));
        }

        let ancestor_work = plan
            .old_work
            .checked_sub(detached_work)
            .ok_or_else(|| CoreError::Validation("reorg old work is inconsistent".into()))?;
        let mut candidate_work = ancestor_work;
        let mut parent = plan.common_ancestor;
        let mut height = cursor_height;
        for expected in &plan.attach {
            height = height
                .checked_add(1)
                .ok_or_else(|| CoreError::Validation("reorg height overflow".into()))?;
            let block = self.load_reorg_block(expected)?;
            if block.header.prev_hash != parent || block.header.height != height {
                return Err(CoreError::Validation(
                    "reorg attach path is not contiguous".into(),
                ));
            }
            candidate_work = candidate_work
                .checked_add(block.header.difficulty as u128)
                .ok_or_else(|| CoreError::Validation("reorg work overflow".into()))?;
            parent = *expected;
        }
        if candidate_work != plan.new_work || candidate_work <= plan.old_work {
            return Err(CoreError::Validation(
                "reorg candidate work is not the declared strictly-heavier work".into(),
            ));
        }
        Ok(())
    }

    fn load_reorg_block(&self, hash: &Hash256) -> Result<Block, CoreError> {
        let block = match self.blocks.get_block_by_hash(hash) {
            Ok(block) => Ok(block),
            Err(_) => self
                .branch_blocks
                .get(hash, self.cfg.max_block_size)
                .map_err(|error| CoreError::Storage(error.to_string())),
        }?;
        if block.hash() != *hash {
            return Err(CoreError::Validation(
                "reorg block archive key does not match block hash".into(),
            ));
        }
        Ok(block)
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
                genesis_epoch_seed(&self.cfg)
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

struct BlockchainReorgBackend<'a> {
    chain: &'a Blockchain,
}

impl ReorgBackend for BlockchainReorgBackend<'_> {
    type Error = CoreError;

    fn tip(&self) -> Result<Hash256, Self::Error> {
        Ok(self.chain.tip()?.hash)
    }

    fn detach_tip(&mut self, expected: Hash256) -> Result<(), Self::Error> {
        let mut commitments = self.chain.commitment_tree.write();
        let mut compute = self.chain.compute_state.write();
        let mut vm = self.chain.vm_state.write();
        let mut wes = self.chain.wes_state.write();
        revert_block_update(
            AtomicStateStores {
                blocks: &self.chain.blocks,
                chain_state: &self.chain.chain_state,
                nullifiers: &self.chain.nullifiers,
                commitment_tree: &mut commitments,
                compute_state: &mut compute,
                vm_state: &mut vm,
                wes_state: &mut wes,
            },
            &expected,
        )
        .map_err(|error| CoreError::Storage(error.to_string()))
    }

    fn attach(&mut self, block: Hash256) -> Result<(), Self::Error> {
        let block = self.chain.load_reorg_block(&block)?;
        self.chain.accept_block_locked(&block)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.chain
            .db
            .flush()
            .map(|_| ())
            .map_err(|error| CoreError::Storage(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_compute::{
        ArithmeticProfile, ComputeTransaction, DataCommitment, ScientificDomain, SignedTask,
        TaskSpec, MIN_CHALLENGE_BLOCKS, MIN_RETENTION_BLOCKS,
    };
    use hyphen_core::{BlockAuthorization, BlockHeader, FROZEN_BLOCK_VERSION};
    use hyphen_crypto::{SecretKey, SpendKey, ViewKey};
    use hyphen_vm::ledger::{SignedCall, SignedDeploy};
    use hyphen_vm::types::{ContractCall, DeployParams};

    fn test_config() -> ChainConfig {
        let mut cfg = ChainConfig::devnet();
        cfg.genesis_difficulty = 1;
        cfg.arena_size = 4_096;
        cfg.scratchpad_size = 4_096;
        cfg.page_size = 4_096;
        cfg.pow_rounds = 1;
        cfg.writeback_interval = 1;
        cfg.kernel_count = 1;
        cfg.difficulty_window = 2;
        cfg.epoch_length = 100;
        cfg
    }

    fn remine_and_authorize(cfg: &ChainConfig, block: &mut Block, marker: u8) {
        let miner = SecretKey([marker; 32]);
        let view_public = ViewKey([marker.wrapping_add(1); 32])
            .public_point()
            .compress()
            .to_bytes();
        let spend_public = SpendKey([marker.wrapping_add(2); 32])
            .public_point()
            .compress()
            .to_bytes();
        block.header.nonce = 0;
        let arena = EpochArena::generate(block.header.epoch_seed, cfg.arena_size, cfg.page_size);
        hyphen_pow::solver::mine_block(&mut block.header, &arena, cfg);
        let authorization = BlockAuthorization::sign(
            &block.header,
            cfg.network_magic,
            cfg.consensus_params_hash(),
            build_genesis_block(cfg).hash(),
            view_public,
            spend_public,
            &miner,
        )
        .unwrap();
        block.block_authorization = hyphen_codec::serialize(&authorization).unwrap();
    }

    fn child(cfg: &ChainConfig, parent: &Block, marker: u8, timestamp_offset: u64) -> Block {
        let miner = SecretKey([marker; 32]);
        let view_public = ViewKey([marker.wrapping_add(1); 32])
            .public_point()
            .compress()
            .to_bytes();
        let spend_public = SpendKey([marker.wrapping_add(2); 32])
            .public_point()
            .compress()
            .to_bytes();
        let height = parent.header.height + 1;
        let epoch_seed = genesis_epoch_seed(cfg);
        let mut header = BlockHeader {
            version: FROZEN_BLOCK_VERSION,
            height,
            timestamp: parent.header.timestamp + timestamp_offset,
            prev_hash: parent.hash(),
            tx_root: Hash256::ZERO,
            commitment_root: Hash256::ZERO,
            nullifier_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: hyphen_crypto::blake3_hash(epoch_seed.as_bytes()),
            epoch_seed,
            difficulty: if height >= 3 { 3 } else { 1 },
            nonce: marker as u64,
            extra_nonce: [marker; 32],
            miner_pubkey: *miner.public_key().as_bytes(),
            total_fee: 0,
            reward: hyphen_economics::emission::lcd_base_reward(height, cfg),
            view_tag: 0,
            block_size: 0,
        };
        let arena = EpochArena::generate(epoch_seed, cfg.arena_size, cfg.page_size);
        hyphen_pow::solver::mine_block(&mut header, &arena, cfg);
        let authorization = BlockAuthorization::sign(
            &header,
            cfg.network_magic,
            cfg.consensus_params_hash(),
            build_genesis_block(cfg).hash(),
            view_public,
            spend_public,
            &miner,
        )
        .unwrap();
        Block {
            header,
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: hyphen_codec::serialize(&authorization).unwrap(),
        }
    }

    fn competing_branches(cfg: &ChainConfig) -> (Block, Vec<Block>, Vec<Block>) {
        let genesis = build_genesis_block(cfg);
        let old_one = child(cfg, &genesis, 11, 1);
        let old_two = child(cfg, &old_one, 12, 1);
        let new_one = child(cfg, &genesis, 21, 2);
        let new_two = child(cfg, &new_one, 22, 1);
        let new_three = child(cfg, &new_two, 23, 1);
        (
            genesis,
            vec![old_one, old_two],
            vec![new_one, new_two, new_three],
        )
    }

    fn plan(genesis: &Block, old: &[Block], new: &[Block]) -> ReorgPlan {
        ReorgPlan {
            common_ancestor: genesis.hash(),
            detach: old.iter().rev().map(Block::hash).collect(),
            attach: new.iter().map(Block::hash).collect(),
            old_work: 3,
            new_work: 6,
        }
    }

    #[test]
    fn real_backend_revalidates_and_applies_strictly_heavier_branch() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let (genesis, old, new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        for block in &new {
            chain.stage_reorg_block(block).unwrap();
        }

        let outcome = chain.execute_reorg(plan(&genesis, &old, &new)).unwrap();

        assert_eq!(
            outcome,
            ReorgOutcome::AppliedCandidate {
                new_tip: new[2].hash()
            }
        );
        let tip = chain.tip().unwrap();
        assert_eq!(tip.hash, new[2].hash());
        assert_eq!(tip.height, 3);
        assert_eq!(tip.cumulative_difficulty, 6);
        assert_eq!(tip.total_outputs, 3);
        assert!(chain.reorg.pending().unwrap().is_none());
    }

    #[test]
    fn invalid_candidate_restores_exact_original_chain() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let (genesis, old, mut new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        let old_tip = chain.tip().unwrap();
        let old_root = chain.commitment_tree.read().root();
        let old_coinbase = [
            chain.blocks.get_coinbase(1).unwrap(),
            chain.blocks.get_coinbase(2).unwrap(),
        ];
        *new[1].block_authorization.last_mut().unwrap() ^= 0x80;
        for block in &new {
            chain.stage_reorg_block(block).unwrap();
        }

        let outcome = chain.execute_reorg(plan(&genesis, &old, &new)).unwrap();

        assert!(matches!(
            outcome,
            ReorgOutcome::RestoredOriginal { old_tip: restored, ref reason }
                if restored == old_tip.hash && reason.contains("authorization")
        ));
        assert_eq!(chain.tip().unwrap(), old_tip);
        assert_eq!(chain.commitment_tree.read().root(), old_root);
        assert_eq!(chain.blocks.get_coinbase(1).unwrap(), old_coinbase[0]);
        assert_eq!(chain.blocks.get_coinbase(2).unwrap(), old_coinbase[1]);
        assert!(chain.reorg.pending().unwrap().is_none());
    }

    #[test]
    fn forged_reorg_work_is_rejected_without_mutation() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let (genesis, old, new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        for block in &new {
            chain.stage_reorg_block(block).unwrap();
        }
        let original = chain.tip().unwrap();
        let mut forged = plan(&genesis, &old, &new);
        forged.new_work = 400;

        assert!(matches!(
            chain.execute_reorg(forged),
            Err(CoreError::Validation(message)) if message.contains("work")
        ));
        assert_eq!(chain.tip().unwrap(), original);
        assert!(chain.reorg.pending().unwrap().is_none());
    }

    struct InterruptingBackend<'a> {
        inner: BlockchainReorgBackend<'a>,
        detach_calls: usize,
    }

    impl ReorgBackend for InterruptingBackend<'_> {
        type Error = CoreError;

        fn tip(&self) -> Result<Hash256, Self::Error> {
            self.inner.tip()
        }

        fn detach_tip(&mut self, expected: Hash256) -> Result<(), Self::Error> {
            self.detach_calls += 1;
            if self.detach_calls == 2 {
                return Err(CoreError::Storage("simulated process interruption".into()));
            }
            self.inner.detach_tip(expected)
        }

        fn attach(&mut self, block: Hash256) -> Result<(), Self::Error> {
            self.inner.attach(block)
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.inner.flush()
        }
    }

    #[test]
    fn blockchain_open_resumes_a_persisted_partial_reorg() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let (genesis, old, new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        for block in &new {
            chain.stage_reorg_block(block).unwrap();
        }
        let reorg_plan = plan(&genesis, &old, &new);
        chain.validate_reorg_plan(&reorg_plan).unwrap();
        {
            let _transition = chain.transition.lock();
            let mut backend = InterruptingBackend {
                inner: BlockchainReorgBackend { chain: &chain },
                detach_calls: 0,
            };
            assert!(chain.reorg.execute(&mut backend, reorg_plan).is_err());
        }
        assert_eq!(chain.tip().unwrap().hash, old[0].hash());
        assert!(chain.reorg.pending().unwrap().is_some());
        drop(chain);

        let reopened = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(reopened.tip().unwrap().hash, new[2].hash());
        assert_eq!(reopened.tip().unwrap().cumulative_difficulty, 6);
        assert!(reopened.reorg.pending().unwrap().is_none());
    }

    #[test]
    fn useful_work_post_state_root_is_checked_and_persisted_atomically() {
        let mut cfg = test_config();
        cfg.consensus_features |= hyphen_core::FEATURE_USEFUL_WORK;
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();
        let scientist = SecretKey([91; 32]);
        let task = SignedTask::sign(
            TaskSpec {
                chain_id: chain.chain_id(),
                scientist: scientist.public_key(),
                nonce: 1,
                domain: ScientificDomain::QuantumChromodynamics,
                arithmetic: ArithmeticProfile::DeterministicFixedPointV1,
                circuit_id: Hash256::from_bytes([92; 32]),
                program_hash: Hash256::from_bytes([93; 32]),
                input: DataCommitment {
                    object_hash: Hash256::from_bytes([94; 32]),
                    byte_len: 4096,
                    chunk_size: 4096,
                    chunk_count: 1,
                    chunk_root: Hash256::from_bytes([95; 32]),
                    locator: "ar://qcd-input".into(),
                },
                max_operations: 1_000_000,
                challenge_blocks: MIN_CHALLENGE_BLOCKS,
                retention_blocks: MIN_RETENTION_BLOCKS,
                reward: 1000,
                publish_deadline: 50,
            },
            &scientist,
        )
        .unwrap();
        let blob = ComputeTransaction::Publish(task).encode().unwrap();
        let mut block = child(&cfg, &genesis, 96, 1);
        block.transactions = vec![blob];
        block.header.tx_root = block.compute_tx_root();
        block.header.state_root = chain.state_root_after(&block.transactions, 1).unwrap();
        let expected_root = block.header.state_root;
        remine_and_authorize(&cfg, &mut block, 96);
        chain.accept_block(&block).unwrap();
        assert_eq!(chain.state_root(), expected_root);
        drop(chain);

        let reopened = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(reopened.state_root(), expected_root);
        assert_eq!(reopened.tip().unwrap().height, 1);
    }

    #[test]
    fn wasm_state_survives_reopen_and_is_removed_by_reorg() {
        let mut cfg = test_config();
        cfg.consensus_features |= hyphen_core::FEATURE_WASM;
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();
        let owner = SecretKey([97; 32]);
        let code = wasmer::wat2wasm(
            br#"(module
                (import "env" "h_storage_write" (func $write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1 1)
                (data (i32.const 0) "keyvalue")
                (func (export "set")
                    (drop (call $write (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 5))))
            )"#,
        )
        .unwrap()
        .into_owned();
        let address = ContractAddress::from_deployer_and_nonce(owner.public_key().as_bytes(), 0);
        let deploy = VmTransaction::Deploy(
            SignedDeploy::sign(
                chain.chain_id(),
                DeployParams {
                    deployer: *owner.public_key().as_bytes(),
                    code,
                    constructor_args: Vec::new(),
                    gas_limit: 1_000_000,
                    nonce: 0,
                },
                &owner,
            )
            .unwrap(),
        )
        .encode()
        .unwrap();
        let mut old_one = child(&cfg, &genesis, 97, 1);
        old_one.transactions = vec![deploy];
        old_one.header.tx_root = old_one.compute_tx_root();
        old_one.header.state_root = chain
            .state_root_after(&old_one.transactions, old_one.header.height)
            .unwrap();
        remine_and_authorize(&cfg, &mut old_one, 97);
        chain.accept_block(&old_one).unwrap();

        let call = VmTransaction::Call(
            SignedCall::sign(
                chain.chain_id(),
                1,
                ContractCall {
                    caller: *owner.public_key().as_bytes(),
                    contract: address,
                    function: "set".into(),
                    args: Vec::new(),
                    gas_limit: 100_000,
                    value: 0,
                },
                &owner,
            )
            .unwrap(),
        )
        .encode()
        .unwrap();
        let mut old_two = child(&cfg, &old_one, 98, 1);
        old_two.transactions = vec![call];
        old_two.header.tx_root = old_two.compute_tx_root();
        old_two.header.state_root = chain
            .state_root_after(&old_two.transactions, old_two.header.height)
            .unwrap();
        remine_and_authorize(&cfg, &mut old_two, 98);
        chain.accept_block(&old_two).unwrap();
        let persisted_root = chain.state_root();
        assert_eq!(chain.vm_storage(address, b"key"), Some(b"value".to_vec()));
        drop(chain);

        let reopened = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        assert_eq!(reopened.state_root(), persisted_root);
        assert!(reopened.vm_contract(address).is_some());
        assert_eq!(
            reopened.vm_storage(address, b"key"),
            Some(b"value".to_vec())
        );

        let new_one = child(&cfg, &genesis, 21, 2);
        let new_two = child(&cfg, &new_one, 22, 1);
        let new_three = child(&cfg, &new_two, 23, 1);
        let old = vec![old_one, old_two];
        let new = vec![new_one, new_two, new_three];
        for block in &new {
            reopened.stage_reorg_block(block).unwrap();
        }
        assert!(matches!(
            reopened.execute_reorg(plan(&genesis, &old, &new)).unwrap(),
            ReorgOutcome::AppliedCandidate { .. }
        ));
        assert_eq!(reopened.h_wes_roots().1, Hash256::ZERO);
        assert!(reopened.vm_contract(address).is_none());
        assert_eq!(reopened.state_root(), Hash256::ZERO);
        drop(reopened);

        let reopened_after_reorg = Blockchain::open_db(db, cfg).unwrap();
        assert!(reopened_after_reorg.vm_contract(address).is_none());
        assert_eq!(reopened_after_reorg.state_root(), Hash256::ZERO);
    }

    #[test]
    fn h_wes_five_root_state_expires_in_the_atomic_block_transition() {
        let mut cfg = test_config();
        cfg.consensus_features |= hyphen_core::FEATURE_H_WES;
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();
        let owner = SecretKey([101; 32]);
        let record = hyphen_state::StateRecord {
            chain_id: chain.chain_id(),
            class: hyphen_state::StateClass::ContractStorage,
            key: Hash256::from_bytes([102; 32]),
            version: 0,
            value_hash: Hash256::from_bytes([103; 32]),
            owner_policy: hyphen_state::wes_owner_policy(owner.public_key()),
            created_at: 1,
            lease_end: 2,
            status: hyphen_state::StateStatus::Live,
        };
        let create = hyphen_state::SignedStateCreate::sign(record, &owner).unwrap();
        let blob = hyphen_state::WesTransaction::Create(create)
            .encode()
            .unwrap();
        let mut first = child(&cfg, &genesis, 104, 1);
        first.transactions = vec![blob];
        first.header.tx_root = first.compute_tx_root();
        first.header.state_root = chain.state_root_after(&first.transactions, 1).unwrap();
        remine_and_authorize(&cfg, &mut first, 104);
        chain.accept_block(&first).unwrap();
        let live_roots = chain.wes_state.read().roots();

        let mut second = child(&cfg, &first, 105, 1);
        second.header.state_root = chain.state_root_after(&[], 2).unwrap();
        remine_and_authorize(&cfg, &mut second, 105);
        chain.accept_block(&second).unwrap();
        let expired_roots = chain.wes_state.read().roots();
        assert_ne!(live_roots.live, expired_roots.live);
        assert_ne!(live_roots.archive, expired_roots.archive);
        assert_eq!(chain.state_root(), second.header.state_root);
    }
}
