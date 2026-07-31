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

pub mod availability;
pub mod chain;
pub mod fair_finality;
pub mod fairness_receipts;
pub mod fast_ordering;
pub mod fusion;
pub mod genesis;
pub mod private_fair_ordering;
pub mod replay;
pub mod validator;

pub use availability::{
    AvailabilityCertificate, AvailabilityError, AvailabilityStatement, AvailabilityVote,
    HonestAvailabilityVoter,
};
pub use chain::Blockchain;
pub use fair_finality::{
    verify_phase_certificate, verify_proposal, verify_timeout_certificate, DualHandoffCertificate,
    FairFinalityError, FairFinalityProposal, FairFinalityValue, FinalityPhase, HandoffRole,
    HandoffStatement, HandoffVote, HonestFinalityVoter, HonestHandoffVoter, PhaseCertificate,
    PhaseVote, PhaseVoteStatement, TimeoutCertificate, TimeoutStatement, TimeoutVote,
};
pub use fairness_receipts::{
    HonestReceiptVoter, InclusionReceiptError, InclusionReceiptStatement, InclusionReceiptVote,
    InclusionReceiptVoteGossip, QuorumInclusionReceipt, QuorumInclusionReceiptGossip,
    ReceiptObligationSet, MAX_RECEIPT_VOTES,
};
pub use fast_ordering::{
    committee_capture_probability, Committee, CommitteeSeat, FastOrderingError, HonestVoter,
    OrderingCertificate, OrderingStatement, OrderingVote, WorkContribution,
};
pub use fusion::{
    fuse_certified_frontier, ConflictKey, FrontierTip, FusionBlock, FusionError, FusionInput,
    FusionResult, FusionTransaction, TransactionReceipt as FusionTransactionReceipt,
};
pub use genesis::{build_genesis_block, genesis_epoch_seed};
pub use private_fair_ordering::{
    build_visible_fair_order, sign_reception, visible_metadata_root, FairBatch,
    FairOrderingContext, FairOrderingError, ReceptionObservation, ReceptionStatement,
    VisibleFairOrder, VisibleMetadata,
};
pub use replay::{
    export_archive, replay_archive, verify_archive_envelopes, ChainArchive, ReplayReport,
    CHAIN_ARCHIVE_VERSION,
};
pub use validator::BlockValidator;
