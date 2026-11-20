pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::CompactConfig {
    rustbinary::options()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
        .with_compact_format()
}

pub mod availability;
pub mod chain;
pub mod fair_finality;
pub mod fairness_receipts;
pub mod fast_ordering;
pub mod fusion;
pub mod neural_work;
pub mod private_fair_ordering;
pub mod replay;
pub mod validator;

pub use availability::{
    AvailabilityCertificate, AvailabilityError, AvailabilityStatement, AvailabilityVote,
    HonestAvailabilityVoter,
};
pub use chain::Blockchain;
pub use fair_finality::{
    DualHandoffCertificate, FairFinalityError, FairFinalityProposal, FairFinalityValue,
    FinalityPhase, HandoffRole, HandoffStatement, HandoffVote, HonestFinalityVoter,
    HonestHandoffVoter, PhaseCertificate, PhaseVote, PhaseVoteStatement, TimeoutCertificate,
    TimeoutStatement, TimeoutVote, verify_phase_certificate, verify_proposal,
    verify_timeout_certificate,
};
pub use fairness_receipts::{
    HonestReceiptVoter, InclusionReceiptError, InclusionReceiptStatement, InclusionReceiptVote,
    InclusionReceiptVoteGossip, MAX_RECEIPT_VOTES, QuorumInclusionReceipt,
    QuorumInclusionReceiptGossip, ReceiptObligationSet,
};
pub use fast_ordering::{
    Committee, CommitteeSeat, FastOrderingError, HonestVoter, OrderingCertificate,
    OrderingStatement, OrderingVote, WorkContribution, committee_capture_probability,
};
pub use fusion::{
    ConflictKey, FrontierTip, FusionBlock, FusionError, FusionInput, FusionResult,
    FusionTransaction, TransactionReceipt as FusionTransactionReceipt, fuse_certified_frontier,
};
pub use hyphen_core::genesis::{build_genesis_block, genesis_epoch_seed};
pub use neural_work::{
    NeuralWorkError, NeuralWorkParams, WORK_MAX_ADJUST, WORK_MEDIAN_WINDOW, WORK_RETARGET_WINDOW,
    WORK_TARGET_SECS, block_weight, expected_threshold, median_time_past, retarget_threshold,
    work_commitment, work_seed,
};
pub use private_fair_ordering::{
    FairBatch, FairOrderingContext, FairOrderingError, ReceptionObservation, ReceptionStatement,
    VisibleFairOrder, VisibleMetadata, build_visible_fair_order, sign_reception,
    visible_metadata_root,
};
pub use replay::{
    CHAIN_ARCHIVE_VERSION, ChainArchive, ReplayReport, export_archive, replay_archive,
    verify_archive_envelopes,
};
pub use validator::BlockValidator;
