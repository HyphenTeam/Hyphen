pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::CompactConfig {
    rustbinary::options()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
        .with_compact_format()
}

pub mod atomic;
pub mod branch_archive;
pub mod branch_store;
pub mod chain_state;
pub mod commitment_tree;
pub mod compress;
pub mod compute_state;
pub mod expiring_state;
pub mod nullifier_set;
pub mod persistent_smt;
pub mod proof_store;
pub mod reorg_journal;
pub mod store;
pub mod vm_state;
pub mod wes_state;
pub mod witness_set;

pub use atomic::{
    AtomicBlockUpdate, AtomicStateError, AtomicStateStores, IndexedOutput, commit_block_update,
    consensus_state_root, revert_block_update,
};
pub use branch_archive::{BranchArchiveError, BranchBlockArchive};
pub use branch_store::{
    BranchMetadata, BranchStore, BranchStoreError, BranchValidation, ReorgPlan,
};
pub use chain_state::ChainState;
pub use commitment_tree::PersistentCommitmentTree;
pub use compress::CompressedTree;
pub use compute_state::{COMPUTE_STATE_KEY, ComputeStateStore};
pub use expiring_state::{
    AuthorizationAction, AuthorizationRequest, ConsumeWitness, LifecycleEvent, LifecycleReceipt,
    LifecycleTransition, ReferenceExpiringState, RestoreOutcome, RestorePolicy, RestoreWitness,
    StateClass, StateRecord, StateRoots, StateStatus, WesError, verify_consume_witness,
    verify_lifecycle_receipt, verify_restore_witness,
};
pub use nullifier_set::NullifierSet;
pub use persistent_smt::{
    PersistentSmtError, PersistentSparseMerkleTree, SmtMutation, SparseMerkleProof,
    verify_sparse_merkle_proof,
};
pub use proof_store::{
    AuthenticatedBlobStore, BlobChunkProof, BlobMetadata, MAX_BLOB_CHUNK_SIZE, MAX_BLOB_CHUNKS,
    MAX_PROOF_BLOB_SIZE, MIN_BLOB_CHUNK_SIZE, ProofStoreError, blob_hash, describe_blob,
    verify_blob_chunk_proof, verify_blob_metadata,
};
pub use reorg_journal::{
    MAX_REJECTION_REASON_BYTES, MAX_REORG_PATH_BLOCKS, ReorgBackend, ReorgCoordinator,
    ReorgCoordinatorError, ReorgJournal, ReorgMode, ReorgOutcome,
};
pub use store::BlockStore;
pub use vm_state::{VM_STATE_KEY, VmStateStore};
pub use wes_state::{
    SignedStateCreate, WES_STATE_KEY, WesStateStore, WesTransaction, WesTransactionError,
    owner_policy as wes_owner_policy,
};
pub use witness_set::{WitnessSet, WitnessSetError};
