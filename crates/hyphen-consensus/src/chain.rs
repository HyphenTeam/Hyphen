use parking_lot::{Mutex, RwLock};
use std::sync::Arc;
use tracing::info;

use hyphen_compute::inline::{
    InlineNeuralVerifier, MAX_INLINE_ENVELOPE, MAX_INLINE_TASKS, MAX_INLINE_TRANSITIONS_PER_BLOCK,
    inline_circuit_id,
};
use hyphen_compute::{ComputeTransaction, NeuralWorkVerifier, ProofVerifier, TaskRecord};
use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::ChainConfig;
use hyphen_core::config::FEATURE_INLINE_COMPUTE;
use hyphen_core::error::CoreError;
use hyphen_core::timestamp::ntp_adjusted_timestamp_ms;
use hyphen_crypto::Hash256;
use hyphen_pow::difficulty::next_difficulty;
use hyphen_pow::{MAX_WITNESSES_PER_BLOCK, verify_witnesses};
use hyphen_state::chain_state::{ChainState, ChainTip};
use hyphen_state::commitment_tree::PersistentCommitmentTree;
use hyphen_state::nullifier_set::NullifierSet;
use hyphen_state::store::BlockStore;
use hyphen_state::witness_set::WitnessSet;
use hyphen_state::{
    AtomicBlockUpdate, AtomicStateStores, AuthenticatedBlobStore, BranchBlockArchive,
    ComputeStateStore, IndexedOutput, PersistentSparseMerkleTree, ReorgBackend, ReorgCoordinator,
    ReorgOutcome, ReorgPlan, VmStateStore, WesStateStore, WesTransaction, commit_block_update,
    consensus_state_root, revert_block_update,
};
use hyphen_tx::builder::build_coinbase_tx;
use hyphen_tx::transaction::Transaction;
use hyphen_vm::{Contract, ContractAddress, VmTransaction};

use crate::validator::BlockValidator;
use hyphen_core::genesis::{build_genesis_block, genesis_epoch_seed};

/// Page cache a node gives its storage engine.
///
/// `sled` defaults to one gigabyte, which is larger than the entire memory of a
/// small host. 64 MiB keeps the hot index resident while leaving room for the
/// runtime, the explorer and whatever else shares the machine; the node exposes
/// the knob as `--db-cache-mb`.
pub const DEFAULT_DB_CACHE_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_DB_CACHE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PEER_BRANCH_BYTES: usize = 16 * 1024 * 1024;

fn ordinary_difficulty(history: &[BlockHeader], cfg: &ChainConfig) -> u64 {
    let count = (cfg.difficulty_window as usize).min(history.len()).min(
        history.last().map_or(0, |header| {
            usize::try_from(header.height).unwrap_or(usize::MAX)
        }),
    );
    if count < 2 {
        return cfg.genesis_difficulty;
    }
    let tail = &history[history.len() - count..];
    let timestamps = tail
        .iter()
        .map(|header| header.timestamp)
        .collect::<Vec<_>>();
    let difficulties = tail
        .iter()
        .map(|header| header.difficulty)
        .collect::<Vec<_>>();
    next_difficulty(&timestamps, &difficulties, cfg).clamp(1, MAX_WITNESSES_PER_BLOCK)
}

fn open_db(path: &str, cache_bytes: u64) -> Result<sled::Db, CoreError> {
    sled::Config::new()
        .path(path)
        .cache_capacity(cache_bytes.max(MIN_DB_CACHE_BYTES))
        .open()
        .map_err(|e| CoreError::Storage(e.to_string()))
}

pub struct Blockchain {
    pub cfg: ChainConfig,
    pub db: sled::Db,
    pub blocks: BlockStore,
    pub chain_state: ChainState,
    pub nullifiers: NullifierSet,
    pub commitment_tree: RwLock<PersistentCommitmentTree>,
    pub branch_blocks: BranchBlockArchive,
    pub wes_latest: PersistentSparseMerkleTree,
    pub proof_blobs: AuthenticatedBlobStore,
    pub compute_state: RwLock<ComputeStateStore>,
    pub vm_state: RwLock<VmStateStore>,
    pub wes_state: RwLock<WesStateStore>,
    pub witnesses: WitnessSet,
    pub reorg: ReorgCoordinator,
    compute_verifier: Arc<dyn ProofVerifier>,
    transition: Mutex<()>,
    reorg_visibility: RwLock<()>,
    peer_candidate: sled::Tree,
}

pub struct CandidateTemplate {
    pub height: u64,
    pub parent: BlockHeader,
    pub difficulty: u64,
    pub epoch_seed: Hash256,
    pub commitment_root: Hash256,
    pub nullifier_root: Hash256,
    pub state_root: Hash256,
    pub total_fee: u64,
}

pub struct CanonicalOutput {
    pub tip: ChainTip,
    pub block_hash: Hash256,
    pub block_height: u64,
    pub transaction: Transaction,
    pub output_index: u32,
}

pub struct OfflineSpend {
    pub transaction: Vec<u8>,
    pub block: Hash256,
    pub height: u64,
    pub source: IndexedOutput,
}

/// Protocol envelopes occupy block positions but do not create shielded outputs.
pub fn protocol_envelope(blob: &[u8]) -> bool {
    [
        hyphen_compute::ENVELOPE_MAGIC,
        hyphen_vm::VM_ENVELOPE_MAGIC,
        hyphen_state::wes_state::WES_ENVELOPE_MAGIC,
    ]
    .iter()
    .any(|magic| blob.starts_with(*magic))
}

struct ProtocolState {
    compute: hyphen_compute::ComputeState,
    vm: hyphen_vm::VmLedger,
    wes: hyphen_state::ReferenceExpiringState,
}

impl ProtocolState {
    fn root(&self) -> Result<Hash256, CoreError> {
        let wes_root = if self.wes.is_empty() {
            Hash256::ZERO
        } else {
            self.wes.roots().combined()
        };
        Ok(consensus_state_root(
            self.compute.root(),
            self.vm
                .root()
                .map_err(|e| CoreError::Serialisation(e.to_string()))?,
            wes_root,
        ))
    }
}

impl Blockchain {
    pub fn open(path: &str, cfg: ChainConfig) -> Result<Self, CoreError> {
        Self::open_with_cache(path, cfg, DEFAULT_DB_CACHE_BYTES)
    }

    /// Open with an explicit page-cache budget.
    ///
    /// `sled`'s default is one gigabyte. A node that shares a 2 GiB host with a
    /// pool, a tunnel and a shell cannot afford to let the storage engine decide
    /// the process's memory ceiling, so the caller sets it.
    pub fn open_with_cache(
        path: &str,
        cfg: ChainConfig,
        cache_bytes: u64,
    ) -> Result<Self, CoreError> {
        let db = open_db(path, cache_bytes)?;
        Self::open_db(db, cfg)
    }

    pub(crate) fn open_db(db: sled::Db, cfg: ChainConfig) -> Result<Self, CoreError> {
        let verifier: Arc<dyn ProofVerifier> = if cfg.feature_enabled(FEATURE_INLINE_COMPUTE) {
            Arc::new(InlineNeuralVerifier)
        } else if cfg.feature_enabled(hyphen_core::FEATURE_USEFUL_WORK) {
            Arc::new(NeuralWorkVerifier)
        } else {
            Arc::new(hyphen_compute::RejectingVerifier)
        };
        Self::open_db_with_verifier(db, cfg, verifier)
    }

    pub fn open_with_compute_verifier(
        path: &str,
        cfg: ChainConfig,
        verifier: Arc<dyn ProofVerifier>,
    ) -> Result<Self, CoreError> {
        if cfg.feature_enabled(FEATURE_INLINE_COMPUTE | hyphen_core::FEATURE_USEFUL_WORK) {
            return Err(CoreError::Validation(
                "compute-enabled network requires its profile verifier".into(),
            ));
        }
        let db = open_db(path, DEFAULT_DB_CACHE_BYTES)?;
        Self::open_db_with_verifier(db, cfg, verifier)
    }

    fn open_db_with_verifier(
        db: sled::Db,
        cfg: ChainConfig,
        compute_verifier: Arc<dyn ProofVerifier>,
    ) -> Result<Self, CoreError> {
        let meta_tree = ensure_chain_identity(&db, &cfg)?;
        let blocks = BlockStore::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let chain_state = ChainState::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let nullifiers = NullifierSet::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let commitment_tree =
            PersistentCommitmentTree::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        let branch_blocks =
            BranchBlockArchive::open(&db).map_err(|e| CoreError::Storage(e.to_string()))?;
        branch_blocks
            .index_existing_branches(&blocks, cfg.max_block_size)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
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
        let witnesses = WitnessSet::open(&db, chain_namespace)
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        let peer_candidate = db
            .open_tree("peer_reorg_candidate")
            .map_err(|e| CoreError::Storage(e.to_string()))?;
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
            witnesses,
            reorg,
            compute_verifier,
            transition: Mutex::new(()),
            reorg_visibility: RwLock::new(()),
            peer_candidate,
        };

        let expected_genesis = build_genesis_block(&bc.cfg);
        let expected_genesis_hash = expected_genesis.hash();
        if bc
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .is_none()
        {
            bc.apply_block_unchecked(&expected_genesis, bc.protocol_snapshot(0))?;
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
                    stored_genesis.hash(),
                    expected_genesis_hash
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

        if !bc.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            bc.witnesses
                .reconcile_canonical(&bc.blocks, bc.height()?, &meta_tree)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
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
        self.compute_state.read().committed().task(task_id).cloned()
    }

    pub fn compute_tasks(
        &self,
        offset: usize,
        limit: usize,
    ) -> (Vec<(Hash256, TaskRecord)>, usize) {
        self.with_compute_state(|state| (state.tasks_page(offset, limit), state.task_count()))
    }

    pub fn with_compute_state<R>(
        &self,
        read: impl FnOnce(&hyphen_compute::ComputeState) -> R,
    ) -> R {
        let _transition = self.transition.lock();
        let store = self.compute_state.read();
        read(store.committed())
    }

    pub fn vm_contract(&self, address: ContractAddress) -> Option<Contract> {
        let _transition = self.transition.lock();
        self.vm_state.read().ledger().contract(address).cloned()
    }

    pub fn vm_query_snapshot(
        &self,
        address: ContractAddress,
    ) -> Result<(Hash256, Option<hyphen_vm::ledger::ContractSnapshot>), CoreError> {
        if !self
            .cfg
            .feature_enabled(hyphen_core::config::FEATURE_ASSET_RULES_V1)
        {
            return Err(CoreError::Validation(
                "bounded contract snapshots are inactive".into(),
            ));
        }
        let _transition = self.transition.lock();
        Ok((
            self.tip()?.hash,
            self.vm_state.read().ledger().contract_snapshot(address),
        ))
    }

    pub fn vm_contracts(&self, offset: usize, limit: usize) -> (Vec<Contract>, usize) {
        let _transition = self.transition.lock();
        let store = self.vm_state.read();
        let state = store.ledger();
        (
            state
                .contracts_page(offset, limit)
                .into_iter()
                .cloned()
                .collect(),
            state.contract_count(),
        )
    }

    pub fn vm_storage(&self, address: ContractAddress, key: &[u8]) -> Option<Vec<u8>> {
        let _transition = self.transition.lock();
        self.vm_state
            .read()
            .ledger()
            .storage(address, key)
            .map(ToOwned::to_owned)
    }

    pub fn h_wes_roots(&self) -> (hyphen_state::StateRoots, Hash256) {
        let _transition = self.transition.lock();
        let state = self.wes_state.read();
        (state.roots(), state.root())
    }

    pub fn state_root(&self) -> Result<Hash256, CoreError> {
        let _transition = self.transition.lock();
        Ok(consensus_state_root(
            self.compute_state.read().root(),
            self.vm_state
                .read()
                .ledger()
                .root()
                .map_err(|e| CoreError::Serialisation(e.to_string()))?,
            self.wes_state.read().root(),
        ))
    }

    pub fn store(&self) -> &BlockStore {
        &self.blocks
    }

    /// Resolve the exact transaction and ordinal, including the reward appended last in a block.
    pub fn canonical_output(&self, index: u64) -> Result<CanonicalOutput, CoreError> {
        let _view = self.canonical_view()?;
        let _transition = self.transition.lock();
        self.canonical_output_locked(index)
    }

    /// Resolve a reserve spend and its source against one committed tip, including during peer reorgs.
    pub fn offline_spend(
        &self,
        image: Hash256,
    ) -> Result<(ChainTip, Option<OfflineSpend>), CoreError> {
        use hyphen_tx::offline::{CLAIM_VERSION, SPENT_PREFIX};
        if !self
            .cfg
            .feature_enabled(hyphen_core::config::FEATURE_OFFLINE_CLAIMS)
            || !image.as_bytes().starts_with(SPENT_PREFIX)
        {
            return Err(CoreError::Validation(
                "expected an offline reserve marker on an active network".into(),
            ));
        }
        let _transition = self.transition.lock();
        self.ensure_reorg_complete()?;
        let tip = self.tip()?;
        let Some(height) = self
            .nullifiers
            .spent_height(image.as_bytes())
            .map_err(|e| CoreError::Storage(e.to_string()))?
        else {
            return Ok((tip, None));
        };
        let block = self
            .blocks
            .get_block_by_height(height)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let hash = block.hash();
        for blob in block.transactions {
            if blob.first() != Some(&CLAIM_VERSION) {
                continue;
            }
            let tx = Transaction::deserialise_limited(&blob)
                .map_err(|e| CoreError::Serialisation(e.to_string()))?;
            let [input] = tx.inputs.as_slice() else {
                continue;
            };
            if input.key_image != image.0 {
                continue;
            }
            let [reference] = input.ring.as_slice() else {
                return Err(CoreError::Storage(
                    "malformed canonical reserve spend".into(),
                ));
            };
            let entry = self.canonical_output_locked(reference.global_index)?;
            let output = &entry.transaction.outputs[entry.output_index as usize];
            return Ok((
                tip,
                Some(OfflineSpend {
                    transaction: blob,
                    block: hash,
                    height,
                    source: IndexedOutput {
                        global_index: reference.global_index,
                        one_time_pubkey: output.one_time_pubkey,
                        commitment: *output.commitment.as_bytes(),
                        block_height: entry.block_height,
                    },
                }),
            ));
        }
        Err(CoreError::Storage(
            "canonical spend missing from indexed block".into(),
        ))
    }

    fn canonical_output_locked(&self, index: u64) -> Result<CanonicalOutput, CoreError> {
        let tip = self.tip()?;
        if index >= tip.total_outputs {
            return Err(CoreError::Validation(
                "output is outside the canonical ledger".into(),
            ));
        }
        let storage = |e: hyphen_state::store::StoreError| CoreError::Storage(e.to_string());
        let (key, commitment, _, height) = self.blocks.output_record(index).map_err(storage)?;
        let block = self.blocks.get_block_by_height(height).map_err(storage)?;
        let mut first = 0;
        let mut end = index;
        while first < end {
            let mid = first + (end - first) / 2;
            if self.blocks.output_record(mid).map_err(storage)?.3 < height {
                first = mid + 1;
            } else {
                end = mid;
            }
        }
        let reward = (height > 0 && block.header.reward > 0)
            .then(|| self.blocks.get_coinbase(height))
            .transpose()
            .map_err(storage)?;
        let mut ordinal = index - first;
        for blob in block
            .transactions
            .iter()
            .filter(|blob| !protocol_envelope(blob))
            .chain(reward.iter())
        {
            let tx = Transaction::deserialise_limited(blob)
                .map_err(|e| CoreError::Serialisation(e.to_string()))?;
            if ordinal < tx.outputs.len() as u64 {
                let output = &tx.outputs[ordinal as usize];
                if output.one_time_pubkey != key || *output.commitment.as_bytes() != commitment {
                    return Err(CoreError::Storage(
                        "canonical output index disagrees with block".into(),
                    ));
                }
                return Ok(CanonicalOutput {
                    tip,
                    block_hash: block.hash(),
                    block_height: height,
                    transaction: tx,
                    output_index: ordinal as u32,
                });
            }
            ordinal -= tx.outputs.len() as u64;
        }
        Err(CoreError::Storage(
            "canonical output missing from indexed block".into(),
        ))
    }

    /// Read the canonical block and its separately indexed reward in one chain state.
    pub fn block_with_coinbase(
        &self,
        hash: &Hash256,
    ) -> Result<(Block, Option<Vec<u8>>), hyphen_state::store::StoreError> {
        let _transition = self.transition.lock();
        let block = self.blocks.get_block_by_hash(hash)?;
        let coinbase = if block.header.height > 0 && block.header.reward > 0 {
            if self.blocks.get_block_hash_at_height(block.header.height)? != *hash {
                return Err(hyphen_state::store::StoreError::NotFound(hash.to_string()));
            }
            Some(self.blocks.get_coinbase(block.header.height)?)
        } else {
            None
        };
        Ok((block, coinbase))
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

    /// Headers of up to `count` most recent canonical blocks, oldest first.
    fn recent_headers(&self, count: usize) -> Result<Vec<BlockHeader>, CoreError> {
        let tip = self.tip()?;
        let count = count.max(1) as u64;
        let start = tip.height.saturating_sub(count - 1);
        let mut headers = Vec::with_capacity((tip.height - start + 1) as usize);
        for height in start..=tip.height {
            headers.push(
                self.blocks
                    .get_block_by_height(height)
                    .map_err(|error| CoreError::Storage(error.to_string()))?
                    .header,
            );
        }
        Ok(headers)
    }

    fn difficulty_history(&self) -> Result<Vec<BlockHeader>, CoreError> {
        let count = if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            crate::neural_work::WORK_RETARGET_WINDOW as usize + 1
        } else {
            self.cfg.difficulty_window as usize
        };
        self.recent_headers(count)
    }

    fn difficulty_from_history(&self, history: &[BlockHeader]) -> u64 {
        if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            crate::neural_work::expected_threshold(
                history,
                &crate::neural_work::neural_work_params(&self.cfg),
            )
        } else {
            ordinary_difficulty(history, &self.cfg)
        }
    }

    pub fn next_difficulty(&self) -> Result<u64, CoreError> {
        Ok(self.difficulty_from_history(&self.difficulty_history()?))
    }

    /// Fork-choice weight of one block under this profile.
    ///
    /// Witness-count profiles add the header field directly. The neural profile
    /// stores a threshold there, so it must add the expected number of attempts
    /// instead — the two scales are not comparable and mixing them would invert
    /// the choice between branches.
    fn block_weight(&self, header: &BlockHeader) -> u128 {
        if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            // Genesis is not mined, so it must not carry work weight. Its
            // `difficulty` is a profile constant, not a threshold, and reading
            // it as one would let the genesis value dominate fork choice.
            if header.height == 0 {
                return 0;
            }
            crate::neural_work::block_weight(header.difficulty)
        } else {
            header.difficulty as u128
        }
    }

    /// Checks a block's mathematical witnesses and its chained commitment.
    ///
    /// Order matters: the pure predicate is checked first so a malformed list is
    /// rejected without touching storage, then single-use membership is checked
    /// against the node's claimed set, and only then is the commitment compared.
    fn validate_witnesses(
        &self,
        block: &Block,
        parent_commitment: &Hash256,
        required: u64,
        history: &[BlockHeader],
    ) -> Result<(), CoreError> {
        if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            return crate::neural_work::verify(
                block,
                &block.header.prev_hash,
                history,
                &crate::neural_work::neural_work_params(&self.cfg),
            )
            .map_err(|error| CoreError::Validation(format!("neural work rejected: {error:?}")));
        }

        verify_witnesses(&block.pow_witnesses, self.cfg.pouw_chain_length, required)
            .map_err(|error| CoreError::Validation(format!("proof of work rejected: {error}")))?;

        for witness in &block.pow_witnesses {
            let claimed = self
                .witnesses
                .contains(*witness)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if claimed {
                return Err(CoreError::Validation(format!(
                    "proof of work rejected: witness {witness} was already claimed"
                )));
            }
        }

        let expected = hyphen_pow::vms::witness_commitment(
            parent_commitment,
            block.header.height,
            &block.pow_witnesses,
        );
        if expected != block.header.pow_commitment {
            return Err(CoreError::Validation(
                "work commitment does not match the claimed witness list".into(),
            ));
        }
        Ok(())
    }

    fn protocol_snapshot(&self, height: u64) -> ProtocolState {
        let mut wes = self.wes_state.read().snapshot();
        wes.expire_due(height, 1024);
        ProtocolState {
            compute: self.compute_state.read().snapshot(),
            vm: self.vm_state.read().snapshot(),
            wes,
        }
    }

    fn apply_block_unchecked(&self, block: &Block, state: ProtocolState) -> Result<(), CoreError> {
        let hash = block.hash();
        let prev_tip = self
            .chain_state
            .get_tip()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let cum_diff = prev_tip
            .map(|t| t.cumulative_difficulty)
            .unwrap_or(0)
            .checked_add(self.block_weight(&block.header))
            .ok_or_else(|| CoreError::Validation("cumulative work overflow".into()))?;

        let mut commitment_tree = self.commitment_tree.write();
        let mut compute_store = self.compute_state.write();
        let mut vm_store = self.vm_state.write();
        let mut wes_store = self.wes_state.write();
        let mut prepared_tree = commitment_tree.snapshot();
        let mut outputs = Vec::new();
        let mut nullifiers = Vec::new();
        for tx_blob in &block.transactions {
            if protocol_envelope(tx_blob) {
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
                hyphen_crypto::hex_encode(authorization.reward_view_public),
                hyphen_crypto::hex_encode(authorization.reward_spend_public),
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

        let next_epoch_seed = block
            .header
            .height
            .checked_add(1)
            .filter(|height| height.is_multiple_of(self.cfg.epoch_length))
            .map(|height| {
                (
                    height / self.cfg.epoch_length,
                    hyphen_crypto::blake3_hash(hash.as_bytes()),
                )
            });
        let total_outputs = prepared_tree.count();

        commit_block_update(
            AtomicStateStores {
                blocks: &self.blocks,
                chain_state: &self.chain_state,
                nullifiers: &self.nullifiers,
                witnesses: &self.witnesses,
                index_pow_witnesses: !self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK),
                commitment_tree: &mut commitment_tree,
                compute_state: &mut compute_store,
                vm_state: &mut vm_store,
                wes_state: &mut wes_store,
            },
            AtomicBlockUpdate {
                block,
                block_weight: self.block_weight(&block.header),
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
                compute_state: state.compute,
                vm_state: state.vm,
                wes_state: state.wes,
            },
        )
        .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn accept_block(&self, block: &Block) -> Result<(), CoreError> {
        self.accept_block_at(block, ntp_adjusted_timestamp_ms())
    }

    pub(crate) fn accept_block_at(
        &self,
        block: &Block,
        observation_ms: u64,
    ) -> Result<(), CoreError> {
        let _visibility = self.reorg_visibility.write();
        let _transition = self.transition.lock();
        self.ensure_reorg_complete()?;
        self.check_arrival_time(block, observation_ms)?;
        self.accept_block_locked(block)
    }

    fn check_arrival_time(&self, block: &Block, now_ms: u64) -> Result<(), CoreError> {
        BlockValidator::new(&self.cfg)
            .check_arrival_time(&block.header, now_ms)
            .map_err(|_| CoreError::FutureTimestamp)
    }

    /// A template-provider client may retry after the acknowledgement is lost.
    /// Only an exact copy of a canonical post-genesis block qualifies as a retry.
    pub fn accept_submitted_block(&self, block: &Block) -> Result<(), CoreError> {
        let _visibility = self.reorg_visibility.write();
        let _transition = self.transition.lock();
        self.ensure_reorg_complete()?;
        if block.header.height > 0
            && self
                .blocks
                .get_block_hash_at_height(block.header.height)
                .ok()
                == Some(block.hash())
            && self
                .blocks
                .get_block_by_height(block.header.height)
                .is_ok_and(|stored| &stored == block)
        {
            return Ok(());
        }
        self.check_arrival_time(block, ntp_adjusted_timestamp_ms())?;
        self.accept_block_locked(block)
    }

    fn accept_block_locked(&self, block: &Block) -> Result<(), CoreError> {
        let tip = self.tip()?;
        let encoded_size = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialized_size(block)
            .map_err(|e| CoreError::Serialisation(e.to_string()))?;
        if encoded_size > self.cfg.max_block_size.min(crate::DEFAULT_WIRE_BYTES) as u64 {
            return Err(CoreError::BlockTooLarge);
        }
        let parent_header = self
            .blocks
            .get_block_by_height(tip.height)
            .map_err(|error| CoreError::Storage(error.to_string()))?
            .header;
        if parent_header.hash() != tip.hash {
            return Err(CoreError::Storage(
                "stored parent differs from canonical tip".into(),
            ));
        }
        let prev_timestamp = parent_header.timestamp;
        let parent_commitment = parent_header.pow_commitment;

        let validator = BlockValidator::new(&self.cfg);

        validator
            .validate_history_header(&block.header, tip.height, &tip.hash, prev_timestamp)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_block_authorization(block, build_genesis_block(&self.cfg).hash())
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_tx_root(block)
            .map_err(|e| CoreError::Validation(e.to_string()))?;

        validator
            .validate_receipt_root(block)
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

        let history = self.difficulty_history()?;
        let expected_difficulty = self.difficulty_from_history(&history);
        if block.header.difficulty != expected_difficulty {
            return Err(CoreError::Validation(format!(
                "difficulty mismatch: expected {}, got {}",
                expected_difficulty, block.header.difficulty
            )));
        }

        let epoch_seed = self.epoch_seed_for_height(block.header.height)?;
        if block.header.epoch_seed != epoch_seed {
            return Err(CoreError::Validation(format!(
                "epoch seed mismatch: expected {epoch_seed}, got {}",
                block.header.epoch_seed
            )));
        }
        self.validate_witnesses(block, &parent_commitment, expected_difficulty, &history)?;

        let expected_reward =
            hyphen_economics::emission::lcd_base_reward(block.header.height, &self.cfg);
        if block.header.reward != expected_reward {
            return Err(CoreError::Validation(format!(
                "reward mismatch: expected {}, got {}",
                expected_reward, block.header.reward
            )));
        }

        if self
            .cfg
            .feature_enabled(hyphen_core::config::FEATURE_ASSET_RULES_V1)
            && (block.header.commitment_root != self.commitment_tree.read().root()
                || block.header.nullifier_root
                    != self
                        .nullifiers
                        .root_hash()
                        .map_err(|e| CoreError::Storage(e.to_string()))?)
        {
            return Err(CoreError::Validation(
                "payment roots differ from canonical parent state".into(),
            ));
        }
        let (total_fee, prepared) = self.validate_transaction_blobs_for_height_locked(
            &block.transactions,
            block.header.height,
            None,
        )?;
        let state_root = prepared.root()?;
        if block.header.state_root != state_root {
            return Err(CoreError::Validation(format!(
                "state root mismatch: expected {state_root}, got {}",
                block.header.state_root
            )));
        }
        if self.cfg.feature_enabled(
            hyphen_core::FEATURE_CANONICAL_TX_ORDER | hyphen_core::config::FEATURE_ASSET_RULES_V1,
        ) && block.header.total_fee != total_fee
        {
            return Err(CoreError::Validation(format!(
                "total fee mismatch: expected {total_fee}, got {}",
                block.header.total_fee
            )));
        }

        self.apply_block_unchecked(block, prepared)
    }

    /// Fully validates an ordered transaction candidate against current
    /// canonical state and returns its checked fee sum.
    pub fn validate_transaction_blobs_for_height(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<u64, CoreError> {
        let _transition = self.transition.lock();
        self.validate_transaction_blobs_for_height_locked(transaction_blobs, block_height, None)
            .map(|(fee, _)| fee)
    }

    pub fn candidate_fee_and_root(
        &self,
        blobs: &[Vec<u8>],
        height: u64,
        parent: Hash256,
    ) -> Result<(u64, Hash256), CoreError> {
        let _transition = self.transition.lock();
        if self.tip()?.hash != parent {
            return Err(CoreError::Validation(
                "candidate parent is no longer canonical".into(),
            ));
        }
        let (fee, state) =
            self.validate_transaction_blobs_for_height_locked(blobs, height, None)?;
        Ok((fee, state.root()?))
    }

    pub fn prepare_template(
        &self,
        blobs: &mut Vec<Vec<u8>>,
    ) -> Result<CandidateTemplate, CoreError> {
        let _transition = self.transition.lock();
        self.ensure_reorg_complete()?;
        let tip = self.tip()?;
        let height = tip
            .height
            .checked_add(1)
            .ok_or_else(|| CoreError::Validation("chain height exhausted".into()))?;
        let parent = self
            .blocks
            .get_block_by_hash(&tip.hash)
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .header;
        let mut selected = Vec::with_capacity(blobs.len());
        let (total_fee, state) =
            self.validate_transaction_blobs_for_height_locked(blobs, height, Some(&mut selected))?;
        let template = CandidateTemplate {
            height,
            parent,
            difficulty: self.next_difficulty()?,
            epoch_seed: self.epoch_seed_for_height(height)?,
            commitment_root: self.commitment_tree.read().root(),
            nullifier_root: self
                .nullifiers
                .root_hash()
                .map_err(|e| CoreError::Storage(e.to_string()))?,
            state_root: state.root()?,
            total_fee,
        };
        let mut keep = selected.into_iter();
        blobs.retain(|_| keep.next().expect("one selection per candidate"));
        Ok(template)
    }

    fn validate_transaction_blobs_for_height_locked(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
        mut selection: Option<&mut Vec<bool>>,
    ) -> Result<(u64, ProtocolState), CoreError> {
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
        let mut state = self.protocol_snapshot(block_height);
        let mut vm_budget = hyphen_vm::ledger::VmBlockBudget::new(
            &state.vm,
            self.cfg
                .feature_enabled(hyphen_core::config::FEATURE_ASSET_RULES_V1),
        );
        let mut total_fee = 0u64;

        let inline = self.cfg.feature_enabled(FEATURE_INLINE_COMPUTE);
        let mut compute_count = 0;

        for tx_blob in transaction_blobs {
            let transaction_hash = hyphen_crypto::blake3_hash(tx_blob);
            let result = (|| {
                if transaction_hashes.contains(&transaction_hash) {
                    return Err(CoreError::Validation(
                        "duplicate transaction in block candidate".into(),
                    ));
                }
                if inline
                    && tx_blob.starts_with(hyphen_compute::ENVELOPE_MAGIC)
                    && (tx_blob.len() > MAX_INLINE_ENVELOPE
                        || compute_count >= MAX_INLINE_TRANSITIONS_PER_BLOCK)
                {
                    return Err(CoreError::Validation(
                        "inline compute block or envelope limit exceeded".into(),
                    ));
                }
                if let Some(transaction) = ComputeTransaction::decode(tx_blob)
                    .map_err(|error| CoreError::Validation(error.to_string()))?
                {
                    if !self.cfg.feature_enabled(hyphen_core::FEATURE_USEFUL_WORK) {
                        return Err(CoreError::Validation(
                            "AetherCompute transactions are not active on this chain profile"
                                .into(),
                        ));
                    }
                    if inline
                        && let ComputeTransaction::Publish(task) = &transaction
                        && (task.spec.circuit_id != inline_circuit_id()
                            || state.compute.task_count() >= MAX_INLINE_TASKS)
                    {
                        return Err(CoreError::Validation(
                            "unsupported inline circuit or task capacity exhausted".into(),
                        ));
                    }
                    state
                        .compute
                        .apply(
                            self.chain_id(),
                            block_height,
                            &transaction,
                            self.compute_verifier.as_ref(),
                        )
                        .map_err(|error| CoreError::Validation(error.to_string()))?;
                    compute_count += 1;
                    return Ok(());
                }
                if let Some(transaction) = VmTransaction::decode(tx_blob)
                    .map_err(|error| CoreError::Validation(error.to_string()))?
                {
                    if !self.cfg.feature_enabled(hyphen_core::FEATURE_WASM) {
                        return Err(CoreError::Validation(
                            "WASM transactions are not active on this chain profile".into(),
                        ));
                    }
                    state
                        .vm
                        .apply_in_block(self.chain_id(), block_height, &transaction, &mut vm_budget)
                        .map_err(|error| CoreError::Validation(error.to_string()))?;
                    return Ok(());
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
                        .apply(&mut state.wes, self.chain_id(), block_height)
                        .map_err(|error| CoreError::Validation(error.to_string()))?;
                    return Ok(());
                }
                let tx = validator.decode_payment(tx_blob)?;
                let next_fee = total_fee
                    .checked_add(tx.fee)
                    .ok_or_else(|| CoreError::Validation("transaction fee sum overflow".into()))?;

                for input in &tx.inputs {
                    if self
                        .nullifiers
                        .contains(&input.key_image)
                        .map_err(|error| CoreError::Storage(error.to_string()))?
                        || block_key_images.contains(&input.key_image)
                    {
                        return Err(CoreError::DuplicateNullifier(hyphen_crypto::hex_encode(
                            input.key_image,
                        )));
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
                    .map_err(|error| match error {
                        crate::validator::ValidationError::Core(e) => e,
                        e => CoreError::Validation(e.to_string()),
                    })?;
                block_key_images.extend(tx.inputs.iter().map(|input| input.key_image));
                total_fee = next_fee;
                Ok(())
            })();
            match (&mut selection, result) {
                (keep, Ok(())) => {
                    transaction_hashes.insert(transaction_hash);
                    if let Some(keep) = keep {
                        keep.push(true);
                    }
                }
                (
                    Some(keep),
                    Err(
                        CoreError::Validation(_)
                        | CoreError::DuplicateNullifier(_)
                        | CoreError::Serialisation(_),
                    ),
                ) => keep.push(false),
                (_, result) => result?,
            }
        }

        Ok((total_fee, state))
    }

    /// Computes the unified AetherCompute, WASM and H-WES post-state root for
    /// an ordered block candidate without mutating canonical state.
    pub fn state_root_after(
        &self,
        transaction_blobs: &[Vec<u8>],
        block_height: u64,
    ) -> Result<Hash256, CoreError> {
        let _transition = self.transition.lock();
        self.validate_transaction_blobs_for_height_locked(transaction_blobs, block_height, None)?
            .1
            .root()
    }

    /// Persist a competing block body without assigning it validation status.
    /// Every block is fully revalidated if a reorg later attempts to attach it.
    pub fn stage_reorg_block(&self, block: &Block) -> Result<Hash256, CoreError> {
        self.branch_blocks
            .archive(block, self.cfg.max_block_size)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn execute_reorg(&self, plan: ReorgPlan) -> Result<ReorgOutcome, CoreError> {
        let _visibility = self.reorg_visibility.write();
        let _transition = self.transition.lock();
        self.execute_reorg_locked(plan, ntp_adjusted_timestamp_ms())
    }

    pub fn canonical_view(&self) -> Result<parking_lot::RwLockReadGuard<'_, ()>, CoreError> {
        let guard = self.reorg_visibility.read();
        self.ensure_reorg_complete()?;
        Ok(guard)
    }

    fn ensure_reorg_complete(&self) -> Result<(), CoreError> {
        if self
            .reorg
            .pending()
            .map_err(|e| CoreError::Storage(e.to_string()))?
            .is_some()
        {
            return Err(CoreError::Storage(
                "reorganisation recovery is pending".into(),
            ));
        }
        Ok(())
    }

    fn execute_reorg_locked(
        &self,
        plan: ReorgPlan,
        observation_ms: u64,
    ) -> Result<ReorgOutcome, CoreError> {
        self.validate_reorg_plan(&plan, observation_ms)?;
        let mut backend = BlockchainReorgBackend { chain: self };
        self.reorg
            .execute(&mut backend, plan)
            .map_err(|error| CoreError::Storage(error.to_string()))
    }

    pub fn recover_pending_reorg(&self) -> Result<Option<ReorgOutcome>, CoreError> {
        let _visibility = self.reorg_visibility.write();
        let _transition = self.transition.lock();
        let mut backend = BlockchainReorgBackend { chain: self };
        let outcome = self
            .reorg
            .recover(&mut backend)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.peer_candidate
            .clear()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        Ok(outcome)
    }

    /// The peer supplies bodies in ancestor-first order. The journal checks
    /// the claimed cumulative work and validates each complete transition.
    pub fn accept_peer_branch(
        &self,
        blocks: &[Block],
        claimed_work: u128,
    ) -> Result<Vec<Hash256>, CoreError> {
        self.accept_peer_branch_at(blocks, claimed_work, ntp_adjusted_timestamp_ms())
    }

    pub(crate) fn accept_peer_branch_at(
        &self,
        blocks: &[Block],
        claimed_work: u128,
        observation_ms: u64,
    ) -> Result<Vec<Hash256>, CoreError> {
        let _visibility = self.reorg_visibility.write();
        let _transition = self.transition.lock();
        self.ensure_reorg_complete()?;
        let tip = self.tip()?;
        let first = blocks
            .first()
            .ok_or_else(|| CoreError::Validation("empty candidate branch".into()))?;
        let base = first
            .header
            .height
            .checked_sub(1)
            .ok_or_else(|| CoreError::Validation("cannot replace genesis".into()))?;
        let depth = tip
            .height
            .checked_sub(base)
            .ok_or_else(|| CoreError::Validation("candidate ancestor ahead of tip".into()))?;
        if depth.saturating_add(blocks.len() as u64) > hyphen_state::MAX_REORG_PATH_BLOCKS as u64
            || claimed_work <= tip.cumulative_difficulty
        {
            return Err(CoreError::Validation(
                "candidate exceeds recovery depth or lacks cumulative work".into(),
            ));
        }
        let ancestor = self
            .blocks
            .get_block_by_height(base)
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        if first.header.prev_hash != ancestor.hash() {
            return Err(CoreError::Validation(
                "candidate ancestor is no longer canonical".into(),
            ));
        }
        let mut history = Vec::new();
        let window = (crate::neural_work::WORK_RETARGET_WINDOW as usize + 1)
            .max(self.cfg.difficulty_window as usize)
            .max(1);
        for height in base.saturating_sub(window as u64 - 1)..=base {
            history.push(
                self.blocks
                    .get_block_by_height(height)
                    .map_err(|e| CoreError::Storage(e.to_string()))?
                    .header,
            );
        }
        let mut detach = Vec::with_capacity(depth as usize);
        for offset in 0..depth {
            detach.push(
                self.blocks
                    .get_block_hash_at_height(tip.height - offset)
                    .map_err(|e| CoreError::Storage(e.to_string()))?,
            );
        }
        let validator = BlockValidator::new(&self.cfg);
        let mut batch = sled::Batch::default();
        let mut size = 0usize;
        let mut attach = Vec::with_capacity(blocks.len());
        for block in blocks {
            let bytes = crate::wire_config(self.cfg.max_block_size)
                .serialize(block)
                .map_err(|_| CoreError::BlockTooLarge)?;
            size = size
                .checked_add(bytes.len())
                .ok_or(CoreError::BlockTooLarge)?;
            if size > MAX_PEER_BRANCH_BYTES {
                return Err(CoreError::BlockTooLarge);
            }
            let parent = history.last().expect("ancestor header is present");
            validator
                .validate_history_header(
                    &block.header,
                    parent.height,
                    &parent.hash(),
                    parent.timestamp,
                )
                .and_then(|_| validator.validate_block_authorization(block, self.chain_id()))
                .and_then(|_| validator.validate_tx_root(block))
                .and_then(|_| validator.validate_uncle_root(block))
                .map_err(|e| CoreError::Validation(e.to_string()))?;
            if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
                crate::neural_work::verify(
                    block,
                    &parent.hash(),
                    &history,
                    &crate::neural_work::neural_work_params(&self.cfg),
                )
                .map_err(|e| CoreError::Validation(format!("invalid branch work: {e:?}")))?;
            } else {
                let difficulty = ordinary_difficulty(&history, &self.cfg);
                if difficulty != block.header.difficulty
                    || hyphen_pow::vms::witness_commitment(
                        &parent.pow_commitment,
                        block.header.height,
                        &block.pow_witnesses,
                    ) != block.header.pow_commitment
                {
                    return Err(CoreError::DifficultyFailed);
                }
                verify_witnesses(&block.pow_witnesses, self.cfg.pouw_chain_length, difficulty)
                    .map_err(|e| CoreError::Validation(e.to_string()))?;
            }
            let hash = block.hash();
            batch.insert(hash.as_bytes().as_slice(), bytes);
            attach.push(hash);
            if history.len() == window {
                history.remove(0);
            }
            history.push(block.header.clone());
        }
        let plan = ReorgPlan {
            common_ancestor: ancestor.hash(),
            old_work: tip.cumulative_difficulty,
            new_work: claimed_work,
            detach: detach.clone(),
            attach,
        };
        self.peer_candidate
            .clear()
            .and_then(|_| self.peer_candidate.apply_batch(batch))
            .and_then(|_| self.peer_candidate.flush())
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        let outcome = self.execute_reorg_locked(plan, observation_ms);
        self.ensure_reorg_complete()?;
        self.peer_candidate
            .clear()
            .map_err(|e| CoreError::Storage(e.to_string()))?;
        match outcome? {
            ReorgOutcome::AppliedCandidate { .. } => Ok(detach),
            ReorgOutcome::RestoredOriginal { reason, .. } => Err(CoreError::Validation(reason)),
        }
    }

    fn validate_reorg_plan(&self, plan: &ReorgPlan, observation_ms: u64) -> Result<(), CoreError> {
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
                .checked_add(self.block_weight(&block.header))
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
            // Admission happens before the journal is persisted. Recovery may
            // subsequently run with a different clock, including during rollback.
            self.check_arrival_time(&block, observation_ms)?;
            if block.header.prev_hash != parent || block.header.height != height {
                return Err(CoreError::Validation(
                    "reorg attach path is not contiguous".into(),
                ));
            }
            candidate_work = candidate_work
                .checked_add(self.block_weight(&block.header))
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
            Err(hyphen_state::store::StoreError::NotFound(_)) => match self
                .peer_candidate
                .get(hash.as_bytes())
                .map_err(|e| CoreError::Storage(e.to_string()))?
            {
                Some(bytes) => Block::deserialise_limited(&bytes, self.cfg.max_block_size)
                    .map_err(|e| CoreError::Storage(e.to_string())),
                None => self
                    .branch_blocks
                    .get(hash, self.cfg.max_block_size)
                    .map_err(|e| CoreError::Storage(e.to_string())),
            },
            Err(error) => Err(CoreError::Storage(error.to_string())),
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
        let block = self
            .chain
            .blocks
            .get_block_by_hash(&expected)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        self.chain
            .branch_blocks
            .index_position(&block)
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let mut commitments = self.chain.commitment_tree.write();
        let mut compute = self.chain.compute_state.write();
        let mut vm = self.chain.vm_state.write();
        let mut wes = self.chain.wes_state.write();
        revert_block_update(
            AtomicStateStores {
                blocks: &self.chain.blocks,
                chain_state: &self.chain.chain_state,
                nullifiers: &self.chain.nullifiers,
                witnesses: &self.chain.witnesses,
                index_pow_witnesses: !self
                    .chain
                    .cfg
                    .feature_enabled(hyphen_core::FEATURE_NEURAL_WORK),
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

/// Refuses to open a database written under different consensus parameters.
///
/// Every state tree is namespaced by `consensus_params_hash`, so a directory
/// from another network or profile would otherwise fail with an SMT namespace
/// error that says nothing about the actual cause. This runs first so the
/// operator sees the reason, and returns the metadata tree for the genesis
/// checks that follow.
fn ensure_chain_identity(db: &sled::Db, cfg: &ChainConfig) -> Result<sled::Tree, CoreError> {
    let meta_tree = db
        .open_tree("consensus_meta")
        .map_err(|e| CoreError::Storage(e.to_string()))?;
    let current_hash = cfg.consensus_params_hash();
    match meta_tree
        .get(b"params_hash")
        .map_err(|e| CoreError::Storage(e.to_string()))?
    {
        Some(stored) if stored.as_ref() != current_hash.as_slice() => Err(CoreError::Validation(
            "consensus parameters differ from genesis — \
             the chain database was created with different rules; \
             refusing to open to prevent fork"
                .into(),
        )),
        Some(_) => Ok(meta_tree),
        None => {
            meta_tree
                .insert(b"params_hash", current_hash.as_slice())
                .map_err(|e| CoreError::Storage(e.to_string()))?;
            Ok(meta_tree)
        }
    }
}

#[cfg(test)]
#[path = "transition_vectors.rs"]
mod transition_vectors;

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_compute::{
        ArithmeticProfile, ComputeTransaction, DataCommitment, MIN_CHALLENGE_BLOCKS,
        MIN_RETENTION_BLOCKS, ScientificDomain, SignedTask, TaskSpec,
    };
    use hyphen_core::{BlockAuthorization, BlockHeader, FROZEN_BLOCK_VERSION};
    use hyphen_crypto::{SecretKey, SpendKey, ViewKey};
    use hyphen_vm::ledger::{SignedCall, SignedDeploy};
    use hyphen_vm::types::{ContractCall, DeployParams};

    fn test_config() -> ChainConfig {
        let mut cfg = ChainConfig::archived_devnet_v2();
        cfg.genesis_difficulty = 1;
        cfg.pouw_chain_length = 3;
        cfg.difficulty_window = 2;
        cfg.epoch_length = 100;
        cfg
    }

    #[test]
    fn legacy_consensus_database_is_rejected_before_genesis_mutation() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        db.open_tree("consensus_meta")
            .unwrap()
            .insert(b"params_hash", [0x42u8; 32].as_slice())
            .unwrap();

        assert!(matches!(
            Blockchain::open_db(db, cfg),
            Err(CoreError::Validation(message))
                if message.contains("different rules") && message.contains("refusing to open")
        ));
    }

    /// A real directory opened under one profile must reject another profile
    /// with the identity message. Before the check was moved ahead of the state
    /// trees, this surfaced as "persisted sparse Merkle tree namespace does not
    /// match", which tells an operator nothing.
    #[test]
    fn database_from_another_profile_is_rejected_with_the_identity_error() {
        for previous in [
            ChainConfig::archived_devnet_v2(),
            ChainConfig::archived_neural_devnet_v1(),
        ] {
            let db = sled::Config::new().temporary(true).open().unwrap();
            let previous_genesis = build_genesis_block(&previous).hash();
            drop(Blockchain::open_db(db.clone(), previous.clone()).unwrap());
            let error = Blockchain::open_db(db.clone(), ChainConfig::neural_devnet())
                .err()
                .expect("HYN3 must reject databases from earlier genesis blocks");
            assert!(
                error.to_string().contains("consensus parameters differ"),
                "{error}"
            );
            let reopened = Blockchain::open_db(db, previous).unwrap();
            assert_eq!(reopened.tip().unwrap().hash, previous_genesis);
        }
    }

    /// Test-only mining. Each marker owns a disjoint residue class, so blocks
    /// built for different branches can never claim the same witness and a
    /// re-attached branch is accepted without spurious collisions.
    fn mine_witnesses(
        cfg: &ChainConfig,
        block: &mut Block,
        parent_commitment: Hash256,
        marker: u8,
    ) {
        let required = block.header.difficulty;
        let claimed_never = |_: u64| false;
        let outcome = hyphen_pow::search(&hyphen_pow::SearchParams {
            length: cfg.pouw_chain_length,
            offset: 3 + 2 * u64::from(marker % 64),
            stride: 128,
            count: required,
            max_candidates: 20_000_000,
            is_claimed: &claimed_never,
        })
        .expect("valid test search parameters");
        assert_eq!(
            outcome.witnesses.len() as u64,
            required,
            "test search budget exhausted for marker {marker}"
        );
        block.pow_witnesses = outcome.witnesses;
        block.header.pow_commitment = hyphen_pow::vms::witness_commitment(
            &parent_commitment,
            block.header.height,
            &block.pow_witnesses,
        );
    }

    fn authorize_block(cfg: &ChainConfig, block: &mut Block, marker: u8) {
        let miner = SecretKey([marker; 32]);
        let view_public = ViewKey([marker.wrapping_add(1); 32])
            .public_point()
            .compress()
            .to_bytes();
        let spend_public = SpendKey([marker.wrapping_add(2); 32])
            .public_point()
            .compress()
            .to_bytes();
        if cfg.feature_enabled(hyphen_core::config::FEATURE_ASSET_RULES_V1) {
            block.header.extra_nonce =
                hyphen_core::authorization::reward_commitment(&view_public, &spend_public);
        }
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
        block.block_authorization = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&authorization)
            .unwrap();
    }

    fn child(cfg: &ChainConfig, parent: &Block, marker: u8, timestamp_offset: u64) -> Block {
        let miner = SecretKey([marker; 32]);
        let height = parent.header.height + 1;
        let epoch_seed = genesis_epoch_seed(cfg);
        let header = BlockHeader {
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
            pow_commitment: Hash256::ZERO,
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
        let mut block = Block {
            header,
            pow_witnesses: Vec::new(),
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: Vec::new(),
        };
        mine_witnesses(cfg, &mut block, parent.header.pow_commitment, marker);
        authorize_block(cfg, &mut block, marker);
        block
    }

    #[test]
    fn template_retry_acknowledges_only_the_exact_canonical_block() {
        let cfg = test_config();
        let genesis = build_genesis_block(&cfg);
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let mut block = child(&cfg, &genesis, 11, 1);
        chain.accept_submitted_block(&block).unwrap();
        chain.accept_submitted_block(&block).unwrap();
        block.block_authorization.clear();
        assert!(chain.accept_submitted_block(&block).is_err());
        assert!(chain.accept_submitted_block(&genesis).is_err());
        assert_eq!(chain.tip().unwrap().height, 1);
    }

    #[test]
    fn future_block_can_be_resubmitted_at_exact_clock_boundary() {
        let cfg = ChainConfig::archived_devnet_v2();
        let chain = Blockchain::open_db(
            sled::Config::new().temporary(true).open().unwrap(),
            cfg.clone(),
        )
        .unwrap();
        let genesis = build_genesis_block(&cfg);
        let first = child(&cfg, &genesis, 11, 30_000);
        let earliest = first.header.timestamp - cfg.timestamp_future_limit_ms;
        assert!(matches!(
            chain.accept_block_at(&first, earliest - 1),
            Err(CoreError::FutureTimestamp)
        ));
        assert_eq!(chain.tip().unwrap().hash, genesis.hash());
        chain.accept_block_at(&first, earliest).unwrap();
        let second = child(&cfg, &first, 12, 0);
        assert!(
            chain
                .accept_block_at(&second, u64::MAX)
                .unwrap_err()
                .to_string()
                .contains("timestamp too old")
        );
        let mut future = first;
        future.header.timestamp = ntp_adjusted_timestamp_ms() + 86_400_000;
        authorize_block(&cfg, &mut future, 11);
        let mut archive = crate::export_archive(&chain).unwrap();
        archive.blocks = vec![future.clone()];
        assert_eq!(
            crate::verify_historical_archive(&cfg, &archive)
                .unwrap()
                .final_hash,
            future.hash()
        );
        let live = Blockchain::open_db(
            sled::Config::new().temporary(true).open().unwrap(),
            cfg.clone(),
        )
        .unwrap();
        assert!(
            crate::replay_archive(&live, &archive)
                .unwrap_err()
                .contains("archive admission")
        );
        assert_eq!(live.height().unwrap(), 0);
        archive.blocks.push(second);
        assert!(crate::verify_historical_archive(&cfg, &archive).is_err());
    }

    #[test]
    fn offline_conflicts_consume_one_reserve_through_reorg_and_reopen() {
        use hyphen_tx::offline::{Funding, Invoice, Reserve, Voucher, redeem, spent_image};
        let cfg = ChainConfig::archived_offline_devnet_v1();
        let chain_id = build_genesis_block(&cfg).hash();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let branch = Blockchain::open_db(
            sled::Config::new().temporary(true).open().unwrap(),
            cfg.clone(),
        )
        .unwrap();
        let owner = SecretKey([1; 32]);
        let reserve = Reserve {
            chain: chain_id,
            owner: owner.public_key(),
            amount: hyphen_economics::emission::lcd_base_reward(1, &cfg),
            fee: 1_000_000,
            nonce: [5; 32],
        };
        let recipient = hyphen_crypto::stealth::generate_keys().2;
        let build = |chain: &Blockchain,
                     marker: u8,
                     mut blobs: Vec<Vec<u8>>,
                     reward_addr: hyphen_crypto::StealthAddress| {
            let parent = chain
                .store()
                .get_block_by_height(chain.tip().unwrap().height)
                .unwrap();
            let template = chain.prepare_template(&mut blobs).unwrap();
            let mut block = child(&cfg, &parent, marker, 30_000);
            block.transactions = blobs;
            block.header.tx_root = block.compute_tx_root();
            block.header.state_root = template.state_root;
            block.header.commitment_root = template.commitment_root;
            block.header.nullifier_root = template.nullifier_root;
            block.header.total_fee = template.total_fee;
            block.header.difficulty = template.difficulty;
            mine_witnesses(&cfg, &mut block, parent.header.pow_commitment, marker);
            block.header.extra_nonce = hyphen_core::authorization::reward_commitment(
                &reward_addr.view_public,
                &reward_addr.spend_public,
            );
            let auth = BlockAuthorization::sign(
                &block.header,
                cfg.network_magic,
                cfg.consensus_params_hash(),
                chain_id,
                reward_addr.view_public,
                reward_addr.spend_public,
                &SecretKey([marker; 32]),
            )
            .unwrap();
            block.block_authorization = crate::wire_config(1024).serialize(&auth).unwrap();
            chain.accept_block(&block).unwrap();
            block
        };
        let funded = build(&chain, 1, vec![], reserve.address().unwrap());
        branch.accept_block(&funded).unwrap();
        let note = chain
            .canonical_output(0)
            .unwrap()
            .transaction
            .outputs
            .remove(0);
        let voucher = Voucher {
            funding: Funding {
                reserve,
                index: 0,
                ephemeral: note.ephemeral_pubkey,
                ordinal: 0,
            },
            transfers: vec![],
        };
        let image = spent_image(chain_id, &note);
        // A valid holder signature is independent of whether that holder's reserve was funded.
        let mut unfunded = voucher.clone();
        let other_owner = SecretKey([91; 32]);
        unfunded.funding.reserve.owner = other_owner.public_key();
        let unbacked = redeem(unfunded, chain_id, &other_owner, recipient).unwrap();
        let mut proposed = vec![unbacked.serialise()];
        assert!(
            chain
                .validate_transaction_blobs_for_height(&proposed, 2)
                .is_err()
        );
        chain.prepare_template(&mut proposed).unwrap();
        assert!(proposed.is_empty());
        assert!(!chain.nullifiers.contains(image.as_bytes()).unwrap());
        let withdrawal = |seed| {
            let mut copy = voucher.clone();
            let receiver = SecretKey([seed; 32]);
            let invoice = Invoice::new(copy.funding.id(), &receiver, [seed; 32]);
            copy.transfer(chain_id, &owner, invoice).unwrap();
            redeem(copy, chain_id, &receiver, recipient).unwrap()
        };
        let a = withdrawal(2);
        let b = withdrawal(3);
        let both = vec![a.serialise(), b.serialise()];
        assert!(matches!(
            chain.validate_transaction_blobs_for_height(&both, 2),
            Err(CoreError::DuplicateNullifier(_))
        ));
        let first = build(&chain, 4, both, recipient);
        assert_eq!(first.transactions, vec![a.serialise()]);
        let alt = build(&branch, 5, vec![b.serialise()], recipient);
        let extended = build(&branch, 6, vec![], recipient);
        chain
            .accept_peer_branch(
                &[alt, extended],
                branch.tip().unwrap().cumulative_difficulty,
            )
            .unwrap();
        drop(chain);
        let reopened = Blockchain::open_db(db, cfg.clone()).unwrap();
        assert_eq!(reopened.tip().unwrap().hash, branch.tip().unwrap().hash);
        assert_eq!(
            reopened.canonical_output(1).unwrap().transaction.hash(),
            b.hash()
        );
        assert!(reopened.nullifiers.contains(image.as_bytes()).unwrap());
        assert_eq!(
            reopened
                .nullifiers
                .with_prefix(hyphen_tx::offline::SPENT_PREFIX)
                .count(),
            1
        );
        assert!(matches!(
            reopened.validate_transaction_blobs_for_height(&[a.serialise()], 4),
            Err(CoreError::DuplicateNullifier(_))
        ));
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
    fn upgrading_recovers_witness_claims_from_canonical_blocks() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let first = child(&cfg, &build_genesis_block(&cfg), 11, 1);
        let next = child(&cfg, &first, 12, 1);
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        chain.accept_block(&first).unwrap();

        db.open_tree("consensus_meta")
            .unwrap()
            .remove(b"atomic_witness_index_v1")
            .unwrap();
        chain.witnesses.remove(first.pow_witnesses[0]).unwrap();
        chain
            .witnesses
            .insert(next.pow_witnesses[0], next.header.height)
            .unwrap();
        drop(chain);

        let chain = Blockchain::open_db(db, cfg).unwrap();
        assert!(chain.witnesses.contains(first.pow_witnesses[0]).unwrap());
        assert!(!chain.witnesses.contains(next.pow_witnesses[0]).unwrap());
        chain.accept_block(&next).unwrap();
        assert_eq!(chain.tip().unwrap().hash, next.hash());
    }

    #[test]
    fn real_backend_revalidates_and_applies_strictly_heavier_branch() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let (genesis, old, new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        let detached = chain.canonical_output(0).unwrap();
        assert_eq!(detached.block_hash, old[0].hash());
        assert!(chain.canonical_output(2).is_err());
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
        let replacement = chain.canonical_output(0).unwrap();
        assert_eq!(replacement.block_hash, new[0].hash());
        assert_eq!(replacement.tip.hash, tip.hash);
        assert_ne!(detached.transaction.hash(), replacement.transaction.hash());
        assert!(chain.reorg.pending().unwrap().is_none());
        let positions = chain.branch_blocks.at_height(1, 8).unwrap();
        assert_eq!(positions.len(), 2);
        for hash in [old[0].hash(), new[0].hash()] {
            assert!(positions.contains(&(hash, genesis.hash())));
        }
        drop(chain);
        db.drop_tree("branch_positions_v1").unwrap();
        let upgraded = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(upgraded.branch_blocks.at_height(1, 8).unwrap(), positions);
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
    fn peer_branch_recomputes_work_and_restores_on_invalid_state() {
        let cfg = test_config();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let (_, old, new) = competing_branches(&cfg);
        for block in &old {
            chain.accept_block(block).unwrap();
        }
        assert!(chain.accept_peer_branch(&new, 7).is_err());
        let mut rejected = new.clone();
        rejected[2].header.state_root = Hash256::from_bytes([5; 32]);
        authorize_block(&cfg, &mut rejected[2], 23);
        assert!(chain.accept_peer_branch(&rejected, 6).is_err());
        assert_eq!(chain.tip().unwrap().hash, old[1].hash());
        assert!(chain.peer_candidate.is_empty());
        assert_eq!(
            chain.accept_peer_branch(&new, 6).unwrap(),
            [old[1].hash(), old[0].hash()]
        );
        drop(chain);
        let reopened = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(reopened.tip().unwrap().hash, new[2].hash());
        assert!(reopened.peer_candidate.is_empty());
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
        chain
            .validate_reorg_plan(&reorg_plan, ntp_adjusted_timestamp_ms())
            .unwrap();
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
    fn durable_reorg_stages_match_genesis_replay() {
        use std::{cell::Cell, process::Command};
        struct StopAt<'a> {
            inner: BlockchainReorgBackend<'a>,
            calls: Cell<usize>,
            stop: usize,
        }
        impl StopAt<'_> {
            fn boundary(&self, stage: &str) {
                let at = self.calls.replace(self.calls.get() + 1);
                if at == self.stop {
                    eprintln!("cut={at} stage={stage}");
                    std::process::exit(if at == 0 { 85 } else { 86 });
                }
            }
        }
        impl ReorgBackend for StopAt<'_> {
            type Error = CoreError;
            fn tip(&self) -> Result<Hash256, CoreError> {
                self.boundary("before_tip_read");
                self.inner.tip()
            }
            fn detach_tip(&mut self, hash: Hash256) -> Result<(), CoreError> {
                self.boundary("before_detach");
                self.inner.detach_tip(hash)
            }
            fn attach(&mut self, hash: Hash256) -> Result<(), CoreError> {
                self.boundary("before_attach");
                self.inner.attach(hash)
            }
            fn flush(&mut self) -> Result<(), CoreError> {
                self.boundary("before_backend_flush");
                self.inner.flush()
            }
            fn journal_changed(&self) {
                self.boundary("after_journal_cas_before_flush");
            }
        }
        let cfg = test_config();
        let (genesis, old, mut candidate) = competing_branches(&cfg);
        if let Ok(path) = std::env::var("HYPHEN_REORG_TEST_DB") {
            if std::env::var("HYPHEN_REORG_TEST_RESTORE").unwrap() == "true" {
                candidate[2].header.state_root = Hash256::from_bytes([4; 32]);
                authorize_block(&cfg, &mut candidate[2], 23);
            }
            let chain = Blockchain::open(&path, cfg).unwrap();
            for b in &old {
                chain.accept_block(b).unwrap();
            }
            for b in &candidate {
                chain.stage_reorg_block(b).unwrap();
            }
            chain.db.flush().unwrap();
            let plan = plan(&genesis, &old, &candidate);
            chain
                .validate_reorg_plan(&plan, ntp_adjusted_timestamp_ms())
                .unwrap();
            let mut backend = StopAt {
                inner: BlockchainReorgBackend { chain: &chain },
                calls: Cell::new(0),
                stop: std::env::var("HYPHEN_REORG_TEST_CUT")
                    .unwrap()
                    .parse()
                    .unwrap(),
            };
            chain.reorg.execute(&mut backend, plan).unwrap();
            backend.boundary("after_journal_cleanup_flush");
            return;
        }
        let reference = |blocks: &[Block]| {
            let chain = Blockchain::open_db(
                sled::Config::new().temporary(true).open().unwrap(),
                cfg.clone(),
            )
            .unwrap();
            for b in blocks {
                chain.accept_block(b).unwrap();
            }
            chain
        };
        let original = reference(&old);
        let winner = reference(&candidate);
        let stem = std::env::temp_dir().join(format!(
            "hyphen-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&stem).unwrap();
        for restore in [false, true] {
            for cut in 0..100 {
                let path = stem.join(format!("{restore}-{cut}"));
                let child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "chain::tests::durable_reorg_stages_match_genesis_replay",
                        "--nocapture",
                    ])
                    .env("HYPHEN_REORG_TEST_DB", &path)
                    .env("HYPHEN_REORG_TEST_RESTORE", restore.to_string())
                    .env("HYPHEN_REORG_TEST_CUT", cut.to_string())
                    .output()
                    .unwrap();
                let code = child.status.code().unwrap();
                assert!(
                    matches!(code, 0 | 85 | 86),
                    "{cut} {} {}",
                    String::from_utf8_lossy(&child.stdout),
                    String::from_utf8_lossy(&child.stderr)
                );
                let actual = Blockchain::open(path.to_str().unwrap(), cfg.clone()).unwrap();
                // At cut 1 the intent entered sled's cache. Either durable
                // result is legal until the initial journal flush returns.
                let initial_intent_lost =
                    cut == 1 && actual.tip().unwrap().hash == original.tip().unwrap().hash;
                let expected = if restore || code == 85 || initial_intent_lost {
                    &original
                } else {
                    &winner
                };
                assert!(actual.reorg.pending().unwrap().is_none());
                assert_eq!(actual.tip().unwrap(), expected.tip().unwrap());
                assert_eq!(actual.state_root().unwrap(), expected.state_root().unwrap());
                assert_eq!(
                    actual.commitment_tree.read().root(),
                    expected.commitment_tree.read().root()
                );
                assert_eq!(
                    actual.nullifiers.root_hash().unwrap(),
                    expected.nullifiers.root_hash().unwrap()
                );
                assert_eq!(
                    actual.witnesses.claimed_count(),
                    expected.witnesses.claimed_count()
                );
                // Compare every stored (origin, claiming height) byte pair,
                // including any unexpected records outside the two paths.
                let claims = |chain: &Blockchain| {
                    let index = chain
                        .db
                        .tree_names()
                        .into_iter()
                        .find(|name| name.starts_with(b"pow_witness_index_v2_"))
                        .unwrap();
                    chain
                        .db
                        .open_tree(index)
                        .unwrap()
                        .iter()
                        .collect::<sled::Result<Vec<_>>>()
                        .unwrap()
                };
                assert_eq!(claims(&actual), claims(expected));
                if code != 0 {
                    eprintln!(
                        "restore={restore} {} recovered_height={}",
                        String::from_utf8_lossy(&child.stderr).trim(),
                        actual.height().unwrap()
                    );
                }
                drop(actual);
                std::fs::remove_dir_all(path).unwrap();
                if code == 0 {
                    assert!(cut > 10);
                    eprintln!(
                        "restore={restore} process_cuts={cut} tip={} height={}",
                        expected.tip().unwrap().hash,
                        expected.height().unwrap()
                    );
                    break;
                }
                assert!(cut < 99, "all recovery stages must be reached");
            }
        }
        std::fs::remove_dir(stem).unwrap();
    }

    /// Builds a block that satisfies the neural work rule for `parent`.
    fn neural_child(chain: &Blockchain, cfg: &ChainConfig, parent: &Block, marker: u8) -> Block {
        let params = crate::neural_work::neural_work_params(cfg);
        let miner = SecretKey([marker; 32]);
        let miner_pubkey = *miner.public_key().as_bytes();
        let height = parent.header.height + 1;
        let parent_hash = parent.hash();
        let threshold = params.initial_threshold;
        let seed = crate::neural_work::work_seed(&parent_hash, height, &miner_pubkey);
        let descriptor = hyphen_neural::WorkDescriptor {
            epoch: height,
            spec: params.spec,
            threshold,
            chain_seed: *seed.as_bytes(),
        };
        let mut weights = vec![0_i64; params.spec.weight_count()];
        descriptor.derive_weights(&mut weights).unwrap();
        let nonce = (0..1_000_000)
            .find(|&n| {
                let score =
                    hyphen_neural::block_work::nonce_score(&descriptor, &weights, n).unwrap();
                hyphen_neural::block_work::qualifies(&descriptor, n, score).unwrap()
            })
            .unwrap();
        let witnesses = vec![nonce];
        let header = BlockHeader {
            version: FROZEN_BLOCK_VERSION,
            height,
            timestamp: parent.header.timestamp + 1,
            prev_hash: parent_hash,
            tx_root: Hash256::ZERO,
            commitment_root: chain.commitment_tree.read().root(),
            nullifier_root: chain.nullifiers.root_hash().unwrap(),
            state_root: chain.state_root_after(&[], height).unwrap(),
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: crate::neural_work::work_commitment(
                &parent_hash,
                height,
                threshold,
                &miner_pubkey,
                &witnesses,
            ),
            epoch_seed: genesis_epoch_seed(cfg),
            difficulty: threshold,
            nonce: 0,
            extra_nonce: [marker; 32],
            miner_pubkey,
            total_fee: 0,
            reward: hyphen_economics::emission::lcd_base_reward(height, cfg),
            view_tag: 0,
            block_size: 0,
        };
        let mut block = Block {
            header,
            pow_witnesses: witnesses,
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: Vec::new(),
        };
        authorize_block(cfg, &mut block, marker);
        block
    }

    #[test]
    fn the_neural_profile_accepts_neural_work_and_weighs_it_by_attempts() {
        let cfg = ChainConfig::neural_devnet();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();

        let block = neural_child(&chain, &cfg, &genesis, 11);
        chain.accept_block(&block).unwrap();

        let tip = chain.tip().unwrap();
        assert_eq!(tip.height, 1);
        assert_eq!(
            tip.cumulative_difficulty,
            crate::neural_work::block_weight(
                crate::neural_work::neural_work_params(&cfg).initial_threshold
            ),
            "fork-choice weight must be the expected attempt count, not the threshold"
        );
    }

    #[test]
    fn the_neural_profile_rejects_a_cunningham_witness_list() {
        let cfg = ChainConfig::neural_devnet();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();

        let mut block = neural_child(&chain, &cfg, &genesis, 12);
        block.pow_witnesses = vec![3, 5, 11];
        let error = chain.accept_block(&block).unwrap_err();
        assert!(
            error.to_string().contains("neural work rejected"),
            "unexpected error: {error}"
        );
        assert_eq!(chain.tip().unwrap().height, 0);
    }

    #[test]
    fn the_neural_profile_rejects_work_mined_for_another_miner() {
        let cfg = ChainConfig::neural_devnet();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();

        let mut block = neural_child(&chain, &cfg, &genesis, 13);
        let thief = SecretKey([14; 32]);
        block.header.miner_pubkey = *thief.public_key().as_bytes();
        block.header.pow_commitment = crate::neural_work::work_commitment(
            &genesis.hash(),
            block.header.height,
            block.header.difficulty,
            &block.header.miner_pubkey,
            &block.pow_witnesses,
        );
        authorize_block(&cfg, &mut block, 14);
        let error = chain.accept_block(&block).unwrap_err();
        assert!(
            error.to_string().contains("neural work rejected"),
            "unexpected error: {error}"
        );
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
        authorize_block(&cfg, &mut block, 96);
        chain.accept_block(&block).unwrap();
        assert_eq!(chain.state_root().unwrap(), expected_root);
        drop(chain);

        let reopened = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(reopened.state_root().unwrap(), expected_root);
        assert_eq!(reopened.tip().unwrap().height, 1);
    }

    #[test]
    fn fee_roots_and_reward_binding_at_genesis_follow_profile() {
        for cfg in [
            ChainConfig::archived_devnet_v2(),
            ChainConfig::archived_contract_devnet_v1(),
        ] {
            let strict = cfg.feature_enabled(hyphen_core::config::FEATURE_ASSET_RULES_V1);
            for field in ["fee", "commitment", "nullifier", "reward"] {
                let db = sled::Config::new().temporary(true).open().unwrap();
                let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
                let genesis = build_genesis_block(&cfg);
                let mut block = child(&cfg, &genesis, 77, 1);
                let template = chain.prepare_template(&mut vec![]).unwrap();
                block.header.commitment_root = template.commitment_root;
                block.header.nullifier_root = template.nullifier_root;
                match field {
                    "fee" => block.header.total_fee += 1,
                    "commitment" => block.header.commitment_root = Hash256::from_bytes([1; 32]),
                    "nullifier" => block.header.nullifier_root = Hash256::from_bytes([2; 32]),
                    _ => (),
                }
                authorize_block(&cfg, &mut block, 77);
                if field == "reward" {
                    let alternative = SpendKey([84; 32]).public_point().compress().to_bytes();
                    let auth = BlockAuthorization::sign(
                        &block.header,
                        cfg.network_magic,
                        cfg.consensus_params_hash(),
                        genesis.hash(),
                        alternative,
                        alternative,
                        &SecretKey([77; 32]),
                    )
                    .unwrap();
                    block.block_authorization = crate::wire_config(4096).serialize(&auth).unwrap();
                }
                let result = chain.accept_block(&block);
                assert_eq!(result.is_err(), strict, "{field}: {result:?}");
                assert_eq!(chain.height().unwrap(), u64::from(!strict));
            }
        }
    }

    #[test]
    fn candidate_conflicting_payments_keep_the_first_valid_spend() {
        use hyphen_crypto::stealth::{
            StealthAddress, derive_commitment_blinding, derive_consensus_one_time_key,
        };
        use hyphen_tx::{
            builder::{InputSpec, TransactionBuilder},
            note::{Note, OwnedNote},
        };

        let mut cfg = test_config();
        cfg.ring_size = 2;
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg.clone()).unwrap();
        let genesis = build_genesis_block(&cfg);
        let first = child(&cfg, &genesis, 11, 1);
        chain.accept_block(&first).unwrap();
        let second = child(&cfg, &first, 12, 1);
        chain.accept_block(&second).unwrap();
        let spend = SpendKey([13; 32]);
        let recipient = StealthAddress {
            view_public: ViewKey([12; 32]).public_point().compress().to_bytes(),
            spend_public: spend.public_point().compress().to_bytes(),
        };
        let (_, _, shared) =
            derive_consensus_one_time_key(&recipient, 0, first.hash().as_bytes()).unwrap();
        let reward =
            Transaction::deserialise_limited(&chain.blocks.get_coinbase(1).unwrap()).unwrap();
        let output = &reward.outputs[0];
        let owned = OwnedNote {
            note: Note {
                commitment: output.commitment,
                one_time_pubkey: output.one_time_pubkey,
                ephemeral_pubkey: output.ephemeral_pubkey,
                encrypted_amount: output.encrypted_amount,
                global_index: 0,
                block_height: 1,
            },
            value: first.header.reward,
            blinding: derive_commitment_blinding(&shared).to_bytes(),
            spend_sk: (shared + spend.as_scalar()).to_bytes(),
        };
        let (key, commitment, _) = chain.blocks.resolve_ring_member(1).unwrap();
        let payment = |fee| {
            let mut builder = TransactionBuilder::new();
            builder.add_input(InputSpec {
                owned: owned.clone(),
                decoys: vec![(key, commitment, 1)],
                real_index: 0,
            });
            builder
                .add_output(recipient, owned.value - fee)
                .set_fee(fee);
            builder.build().unwrap().serialise()
        };
        let original = payment(1_000_000);
        let alternative = payment(2_000_000);
        for (first, second, fee) in [
            (&original, &alternative, 1_000_000),
            (&alternative, &original, 2_000_000),
        ] {
            let mut both = vec![first.clone(), second.clone()];
            assert!(matches!(
                chain.candidate_fee_and_root(&both, 3, chain.tip().unwrap().hash),
                Err(CoreError::DuplicateNullifier(_))
            ));
            let template = chain.prepare_template(&mut both).unwrap();
            assert_eq!(template.total_fee, fee);
            assert_eq!(both.as_slice(), std::slice::from_ref(first));
        }
        let mut block = child(&cfg, &second, 13, 1);
        block.transactions.push(original.clone());
        block.header.total_fee = 1_000_000;
        block.header.tx_root = block.compute_tx_root();
        authorize_block(&cfg, &mut block, 13);
        chain.accept_block(&block).unwrap();
        let payment = Transaction::deserialise_limited(&original).unwrap();
        for (ordinal, _) in payment.outputs.iter().enumerate() {
            let found = chain.canonical_output(2 + ordinal as u64).unwrap();
            assert_eq!((found.block_height, found.block_hash), (3, block.hash()));
            assert_eq!(found.transaction.hash(), payment.hash());
            assert_eq!(found.output_index as usize, ordinal);
        }
        let reward = chain
            .canonical_output(2 + payment.outputs.len() as u64)
            .unwrap();
        assert!(reward.transaction.is_coinbase());
        assert_eq!(reward.output_index, 0);
    }

    #[test]
    fn template_keeps_only_successful_in_order_transitions() {
        let cfg = ChainConfig::archived_contract_devnet_v1();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db, cfg).unwrap();
        let key = SecretKey([14; 32]);
        let deploy = |nonce, gas_limit| {
            VmTransaction::Deploy(
                SignedDeploy::sign(
                    chain.chain_id(),
                    DeployParams {
                        nonce,
                        gas_limit,
                        code: wat::parse_str("(module (memory (export \"memory\") 1 1))").unwrap(),
                        constructor_args: vec![],
                        deployer: *key.public_key().as_bytes(),
                    },
                    &key,
                )
                .unwrap(),
            )
            .encode()
            .unwrap()
        };
        let first = deploy(0, hyphen_vm::gas::MAX_TRANSACTION_GAS);
        let second = deploy(1, hyphen_vm::gas::MAX_TRANSACTION_GAS);
        let third = deploy(2, hyphen_vm::gas::MIN_TRANSACTION_GAS);
        let mut blobs = vec![
            second.clone(),
            vec![0xff],
            first.clone(),
            first.clone(),
            second.clone(),
            third,
        ];
        let before = chain.state_root().unwrap();
        let candidate = chain.prepare_template(&mut blobs).unwrap();
        assert_eq!(blobs, [first, second]);
        assert_eq!(
            chain
                .candidate_fee_and_root(&blobs, 1, candidate.parent.hash())
                .unwrap(),
            (0, candidate.state_root)
        );
        assert!(
            chain
                .candidate_fee_and_root(&blobs, 1, Hash256::ZERO)
                .is_err()
        );
        assert_ne!(candidate.state_root, before);
        assert_eq!(chain.state_root().unwrap(), before);
    }

    #[test]
    #[ignore = "requires Rust and Clang Wasm artifacts from scripts/test-contract-toolchains.ps1"]
    fn compiled_contract_toolchains() {
        let directory =
            std::path::PathBuf::from(std::env::var_os("HYPHEN_CONTRACT_TOOLCHAINS").unwrap());
        let cfg = ChainConfig::archived_contract_devnet_v1();
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let genesis = build_genesis_block(&cfg);
        let mut block = child(&cfg, &genesis, 77, 1);
        let mut rows = Vec::new();
        for (i, language) in ["c", "cpp", "s", "limit-orders", "collection"]
            .into_iter()
            .enumerate()
        {
            let code = std::fs::read(directory.join(format!("{language}.wasm"))).unwrap();
            let owner = SecretKey([i as u8 + 1; 32]);
            let public = *owner.public_key().as_bytes();
            let address = ContractAddress::from_deployer_and_nonce(&public, 0);
            let (constructor_args, args, query_args, key, expected) = if language == "limit-orders"
            {
                assert_eq!(
                    hyphen_vm::application::application_manifest(&code)
                        .unwrap()
                        .unwrap()
                        .category,
                    hyphen_vm::application::AppCategory::Defi
                );
                let supplies = [100u64.to_le_bytes(), 200u64.to_le_bytes()].concat();
                let recipient = SecretKey([44; 32]).public_key();
                let key = [&[0][..], recipient.as_bytes()].concat();
                let query = [&[1][..], &key].concat();
                let units = 25u64.to_le_bytes();
                (
                    supplies,
                    [query.as_slice(), &units].concat(),
                    query,
                    key,
                    units.to_vec(),
                )
            } else if language == "collection" {
                let recipient = SecretKey([45; 32]).public_key();
                let metadata = [0x91; 32];
                let mint = [&[1][..], recipient.as_bytes(), &metadata].concat();
                let key = 1u64.to_le_bytes().to_vec();
                let query = [&[1][..], &key].concat();
                let token = [
                    recipient.as_bytes().as_slice(),
                    &[0; 32],
                    &metadata,
                    &[0; 8],
                ]
                .concat();
                (1u64.to_le_bytes().to_vec(), mint, query, key, token)
            } else {
                let value = b"contract ABI\0\xff".to_vec();
                (vec![], value.clone(), vec![], b"key".to_vec(), value)
            };
            let params = DeployParams {
                deployer: public,
                code,
                constructor_args,
                nonce: 0,
                gas_limit: 4_000_000,
            };
            let call = ContractCall {
                caller: public,
                contract: address,
                args,
                function: "hyphen_execute".into(),
                value: 0,
                gas_limit: 100_000,
            };
            let mut engine = hyphen_vm::VmEngine::new();
            let (contract, _) = engine.deploy(&params, 1).unwrap();
            assert!(engine.call(&contract, &call).unwrap().success);
            let query = ContractCall {
                function: "hyphen_query".into(),
                args: query_args,
                ..call.clone()
            };
            let result = engine.call(&contract, &query).unwrap();
            assert!(result.success && result.state_changes.is_empty());
            assert_eq!(result.return_data, expected);
            block.transactions.push(
                VmTransaction::Deploy(
                    SignedDeploy::sign(chain.chain_id(), params, &owner).unwrap(),
                )
                .encode()
                .unwrap(),
            );
            block.transactions.push(
                VmTransaction::Call(SignedCall::sign(chain.chain_id(), 1, call, &owner).unwrap())
                    .encode()
                    .unwrap(),
            );
            rows.push((address, key, expected));
        }
        block.header.tx_root = block.compute_tx_root();
        block.header.commitment_root = chain.commitment_tree.read().root();
        block.header.nullifier_root = chain.nullifiers.root_hash().unwrap();
        block.header.state_root = chain.state_root_after(&block.transactions, 1).unwrap();
        authorize_block(&cfg, &mut block, 77);
        chain.accept_block(&block).unwrap();
        drop(chain);
        let chain = Blockchain::open_db(db, cfg).unwrap();
        assert_eq!(chain.state_root().unwrap(), block.header.state_root);
        for (address, key, expected) in rows {
            assert_eq!(chain.vm_storage(address, &key).unwrap(), expected);
        }
    }

    #[test]
    fn wasm_state_survives_reopen_and_is_removed_by_reorg() {
        let mut cfg = test_config();
        cfg.consensus_features |= hyphen_core::FEATURE_WASM;
        let db = sled::Config::new().temporary(true).open().unwrap();
        let chain = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        let genesis = chain.blocks.get_block_by_height(0).unwrap();
        let owner = SecretKey([97; 32]);
        let code = wat::parse_bytes(
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
        authorize_block(&cfg, &mut old_one, 97);
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
        authorize_block(&cfg, &mut old_two, 98);
        chain.accept_block(&old_two).unwrap();
        let persisted_root = chain.state_root().unwrap();
        assert_eq!(chain.vm_storage(address, b"key"), Some(b"value".to_vec()));
        drop(chain);

        let reopened = Blockchain::open_db(db.clone(), cfg.clone()).unwrap();
        assert_eq!(reopened.state_root().unwrap(), persisted_root);
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
        assert_eq!(reopened.state_root().unwrap(), Hash256::ZERO);
        drop(reopened);

        let reopened_after_reorg = Blockchain::open_db(db, cfg).unwrap();
        assert!(reopened_after_reorg.vm_contract(address).is_none());
        assert_eq!(reopened_after_reorg.state_root().unwrap(), Hash256::ZERO);
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
        authorize_block(&cfg, &mut first, 104);
        chain.accept_block(&first).unwrap();
        let live_roots = chain.wes_state.read().roots();

        let mut second = child(&cfg, &first, 105, 1);
        second.header.state_root = chain.state_root_after(&[], 2).unwrap();
        authorize_block(&cfg, &mut second, 105);
        chain.accept_block(&second).unwrap();
        let expired_roots = chain.wes_state.read().roots();
        assert_ne!(live_roots.live, expired_roots.live);
        assert_ne!(live_roots.archive, expired_roots.archive);
        assert_eq!(chain.state_root().unwrap(), second.header.state_root);
    }
}
