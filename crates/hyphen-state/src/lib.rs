pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::Config {
    rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
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

pub use atomic::{
    commit_block_update, consensus_state_root, revert_block_update, AtomicBlockUpdate,
    AtomicStateError, AtomicStateStores, IndexedOutput,
};
pub use branch_archive::{BranchArchiveError, BranchBlockArchive};
pub use branch_store::{
    BranchMetadata, BranchStore, BranchStoreError, BranchValidation, ReorgPlan,
};
pub use chain_state::ChainState;
pub use commitment_tree::PersistentCommitmentTree;
pub use compress::CompressedTree;
pub use compute_state::{ComputeStateStore, COMPUTE_STATE_KEY};
pub use expiring_state::{
    verify_consume_witness, verify_lifecycle_receipt, verify_restore_witness, AuthorizationAction,
    AuthorizationRequest, ConsumeWitness, LifecycleEvent, LifecycleReceipt, LifecycleTransition,
    ReferenceExpiringState, RestoreOutcome, RestorePolicy, RestoreWitness, StateClass, StateRecord,
    StateRoots, StateStatus, WesError,
};
pub use nullifier_set::NullifierSet;
pub use persistent_smt::{
    verify_sparse_merkle_proof, PersistentSmtError, PersistentSparseMerkleTree, SmtMutation,
    SparseMerkleProof,
};
pub use proof_store::{
    blob_hash, describe_blob, verify_blob_chunk_proof, verify_blob_metadata,
    AuthenticatedBlobStore, BlobChunkProof, BlobMetadata, ProofStoreError, MAX_BLOB_CHUNKS,
    MAX_BLOB_CHUNK_SIZE, MAX_PROOF_BLOB_SIZE, MIN_BLOB_CHUNK_SIZE,
};
pub use reorg_journal::{
    ReorgBackend, ReorgCoordinator, ReorgCoordinatorError, ReorgJournal, ReorgMode, ReorgOutcome,
    MAX_REJECTION_REASON_BYTES, MAX_REORG_PATH_BLOCKS,
};
pub use store::BlockStore;
pub use vm_state::{VmStateStore, VM_STATE_KEY};
pub use wes_state::{
    owner_policy as wes_owner_policy, SignedStateCreate, WesStateStore, WesTransaction,
    WesTransactionError, WES_STATE_KEY,
};
