//! Locked two-phase fair-order finality and dual-committee epoch handoff.
//!
//! This module is inactive. It provides deterministic certificate validation
//! and crash-durable honest-voter guards; networking, leader election and
//! timeout scheduling must still be supplied before activation.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{Hash256, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fairness_receipts::ReceiptObligationSet;
use crate::fast_ordering::Committee;
use crate::private_fair_ordering::VisibleFairOrder;

const FINALITY_VERSION: u8 = 0;
const D_VALUE: &[u8] = b"HYPHEN_FOC_FINALITY_VALUE_V0";
const D_VOTE: &[u8] = b"HYPHEN_FOC_PHASE_VOTE_V0";
const D_TIMEOUT: &[u8] = b"HYPHEN_FOC_TIMEOUT_VOTE_V0";
const D_HANDOFF: &[u8] = b"HYPHEN_FOC_HANDOFF_V0";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FinalityPhase {
    Prepare = 0,
    Commit = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FairFinalityValue {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub slot: u64,
    pub parent_checkpoint: Hash256,
    pub metadata_root: Hash256,
    pub evidence_root: Hash256,
    pub order_root: Hash256,
}

impl FairFinalityValue {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(217);
        bytes.push(FINALITY_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(self.parent_checkpoint.as_bytes());
        bytes.extend_from_slice(self.metadata_root.as_bytes());
        bytes.extend_from_slice(self.evidence_root.as_bytes());
        bytes.extend_from_slice(self.order_root.as_bytes());
        bytes
    }

    pub fn hash(&self) -> Hash256 {
        hash_parts(D_VALUE, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseVoteStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub slot: u64,
    pub view: u64,
    pub phase: FinalityPhase,
    pub value_hash: Hash256,
}

impl PhaseVoteStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(130);
        bytes.push(FINALITY_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(self.value_hash.as_bytes());
        bytes
    }

    pub fn digest(&self) -> Hash256 {
        hash_parts(D_VOTE, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseVote {
    pub seat: u16,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseCertificate {
    pub statement: PhaseVoteStatement,
    pub votes: Vec<PhaseVote>,
}

impl PhaseCertificate {
    pub fn digest(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(32 + self.votes.len() * 66);
        bytes.extend_from_slice(self.statement.digest().as_bytes());
        let mut votes = self.votes.clone();
        votes.sort_by_key(|vote| vote.seat);
        for vote in votes {
            bytes.extend_from_slice(&vote.seat.to_be_bytes());
            bytes.extend_from_slice(vote.signature.as_bytes());
        }
        hash_parts(b"HYPHEN_FOC_PHASE_QC_V0", &[&bytes])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub slot: u64,
    pub view: u64,
    pub highest_prepare: Option<PhaseCertificate>,
}

impl TimeoutStatement {
    pub fn digest(&self) -> Hash256 {
        let high = self
            .highest_prepare
            .as_ref()
            .map(PhaseCertificate::digest)
            .unwrap_or(Hash256::ZERO);
        hash_parts(
            D_TIMEOUT,
            &[
                &[FINALITY_VERSION],
                self.chain_id.as_bytes(),
                &self.epoch.to_be_bytes(),
                self.committee_id.as_bytes(),
                &self.slot.to_be_bytes(),
                &self.view.to_be_bytes(),
                high.as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutVote {
    pub seat: u16,
    pub statement: TimeoutStatement,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutCertificate {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub slot: u64,
    pub view: u64,
    pub votes: Vec<TimeoutVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FairFinalityProposal {
    pub view: u64,
    pub value: FairFinalityValue,
    pub timeout: Option<TimeoutCertificate>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FairFinalityError {
    #[error("finality object belongs to another chain, committee, epoch or slot")]
    WrongContext,
    #[error("certificate has the wrong phase, view or value")]
    WrongCertificate,
    #[error("certificate does not contain 2f+1 distinct seats")]
    NoQuorum,
    #[error("certificate repeats a committee seat")]
    DuplicateSeat,
    #[error("certificate references an unknown committee seat")]
    UnknownSeat,
    #[error("certificate signature is invalid")]
    InvalidSignature,
    #[error("secret key does not own the requested committee seat")]
    WrongSigner,
    #[error("proposal lacks the required timeout certificate")]
    MissingTimeout,
    #[error("timeout certificate contains conflicting highest prepare QCs")]
    ConflictingHighPrepare,
    #[error("proposal does not preserve the highest prepared value")]
    ViolatesHighestPrepare,
    #[error("honest voter is locked on another value")]
    LockedValue,
    #[error("honest voter refuses phase equivocation")]
    Equivocation,
    #[error("honest voter refuses a stale view or a proposal after timing out")]
    StaleView,
    #[error("proposal order commitment does not match the supplied order")]
    WrongOrder,
    #[error("proposal omits a quorum-receipted transaction")]
    ReceiptOmission,
    #[error("handoff does not bind adjacent epochs and expected committees")]
    InvalidHandoff,
    #[error("handoff does not bind the expected finalized PoW checkpoint")]
    WrongCheckpoint,
    #[error("honest voter refuses a conflicting epoch handoff")]
    HandoffEquivocation,
    #[error("durable voter state changed concurrently")]
    StorageConflict,
    #[error("durable voter state failed: {0}")]
    Storage(String),
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SlotState {
    revision: u64,
    locked: Option<(u64, Hash256)>,
    highest_prepare: Option<PhaseCertificate>,
    decisions: BTreeMap<(u64, FinalityPhase), Hash256>,
    timeout_statements: BTreeMap<u64, TimeoutStatement>,
    highest_voted_view: Option<u64>,
}

pub struct HonestFinalityVoter {
    secret: SecretKey,
    chain_id: Hash256,
    slots: BTreeMap<(u64, u64), SlotState>,
    storage: Option<sled::Tree>,
}

impl HonestFinalityVoter {
    pub fn new_in_memory(secret: SecretKey, chain_id: Hash256) -> Self {
        Self {
            secret,
            chain_id,
            slots: BTreeMap::new(),
            storage: None,
        }
    }

    pub fn open(
        database: &sled::Db,
        secret: SecretKey,
        chain_id: Hash256,
    ) -> Result<Self, FairFinalityError> {
        let storage = database
            .open_tree("h_foc_finality_voter_v0")
            .map_err(storage_error)?;
        Ok(Self {
            secret,
            chain_id,
            slots: BTreeMap::new(),
            storage: Some(storage),
        })
    }

    pub fn prepare(
        &mut self,
        committee: &Committee,
        seat: u16,
        proposal: &FairFinalityProposal,
        order: &VisibleFairOrder,
        obligations: &ReceiptObligationSet,
    ) -> Result<PhaseVote, FairFinalityError> {
        verify_proposal(committee, self.chain_id, proposal)?;
        verify_order(&proposal.value, order, obligations)?;
        verify_seat(committee, seat, &self.secret)?;
        let value_hash = proposal.value.hash();
        let slot_key = (proposal.value.epoch, proposal.value.slot);
        let previous = self.load_slot(slot_key)?;
        let mut state = previous.clone();
        if state.timeout_statements.contains_key(&proposal.view)
            || state
                .highest_voted_view
                .is_some_and(|highest| proposal.view < highest)
        {
            return Err(FairFinalityError::StaleView);
        }
        if let Some((locked_view, locked_value)) = state.locked {
            if locked_value != value_hash {
                let high = proposal
                    .timeout
                    .as_ref()
                    .map(highest_prepare)
                    .transpose()?
                    .flatten();
                if high.is_none_or(|qc| qc.statement.view <= locked_view) {
                    return Err(FairFinalityError::LockedValue);
                }
            }
        }
        let statement = record_phase(
            committee,
            &proposal.value,
            proposal.view,
            FinalityPhase::Prepare,
            &mut state,
        )?;
        state.highest_voted_view = Some(
            state
                .highest_voted_view
                .map_or(proposal.view, |highest| highest.max(proposal.view)),
        );
        self.persist_slot(slot_key, &previous, &mut state)?;
        Ok(sign_phase(&self.secret, seat, &statement))
    }

    pub fn commit(
        &mut self,
        committee: &Committee,
        seat: u16,
        value: &FairFinalityValue,
        prepare_qc: &PhaseCertificate,
    ) -> Result<PhaseVote, FairFinalityError> {
        verify_value_context(committee, self.chain_id, value)?;
        verify_phase_certificate(committee, prepare_qc)?;
        if prepare_qc.statement.phase != FinalityPhase::Prepare
            || prepare_qc.statement.chain_id != self.chain_id
            || prepare_qc.statement.committee_id != committee.id()
            || prepare_qc.statement.epoch != value.epoch
            || prepare_qc.statement.slot != value.slot
            || prepare_qc.statement.value_hash != value.hash()
        {
            return Err(FairFinalityError::WrongCertificate);
        }
        verify_seat(committee, seat, &self.secret)?;
        let slot_key = (value.epoch, value.slot);
        let previous = self.load_slot(slot_key)?;
        let mut state = previous.clone();
        let view = prepare_qc.statement.view;
        if state
            .highest_voted_view
            .is_some_and(|highest| view < highest)
        {
            return Err(FairFinalityError::StaleView);
        }
        if let Some((locked_view, locked_value)) = state.locked {
            if locked_value != value.hash() && view <= locked_view {
                return Err(FairFinalityError::LockedValue);
            }
            if view >= locked_view {
                state.locked = Some((view, value.hash()));
            }
        } else {
            state.locked = Some((view, value.hash()));
        }
        if state
            .highest_prepare
            .as_ref()
            .is_none_or(|previous| previous.statement.view < view)
        {
            state.highest_prepare = Some(prepare_qc.clone());
        }
        let statement = record_phase(committee, value, view, FinalityPhase::Commit, &mut state)?;
        state.highest_voted_view = Some(
            state
                .highest_voted_view
                .map_or(view, |highest| highest.max(view)),
        );
        self.persist_slot(slot_key, &previous, &mut state)?;
        Ok(sign_phase(&self.secret, seat, &statement))
    }

    pub fn timeout(
        &mut self,
        committee: &Committee,
        seat: u16,
        epoch: u64,
        slot: u64,
        view: u64,
    ) -> Result<TimeoutVote, FairFinalityError> {
        verify_epoch(committee, epoch)?;
        verify_seat(committee, seat, &self.secret)?;
        let slot_key = (epoch, slot);
        let previous = self.load_slot(slot_key)?;
        if let Some(statement) = previous.timeout_statements.get(&view) {
            return Ok(TimeoutVote {
                seat,
                signature: self.secret.sign(statement.digest().as_bytes()),
                statement: statement.clone(),
            });
        }
        if previous
            .highest_voted_view
            .is_some_and(|highest| view < highest)
        {
            return Err(FairFinalityError::StaleView);
        }
        let mut state = previous.clone();
        let statement = TimeoutStatement {
            chain_id: self.chain_id,
            epoch,
            committee_id: committee.id(),
            slot,
            view,
            highest_prepare: state.highest_prepare.clone(),
        };
        state.timeout_statements.insert(view, statement.clone());
        state.highest_voted_view = Some(
            state
                .highest_voted_view
                .map_or(view, |highest| highest.max(view)),
        );
        self.persist_slot(slot_key, &previous, &mut state)?;
        Ok(TimeoutVote {
            seat,
            signature: self.secret.sign(statement.digest().as_bytes()),
            statement,
        })
    }

    fn load_slot(&mut self, key: (u64, u64)) -> Result<SlotState, FairFinalityError> {
        if let Some(state) = self.slots.get(&key) {
            return Ok(state.clone());
        }
        let Some(storage) = &self.storage else {
            return Ok(SlotState::default());
        };
        let storage_key = voter_slot_key(
            self.chain_id,
            self.secret.public_key().as_bytes(),
            key.0,
            key.1,
        );
        let state = match storage.get(storage_key).map_err(storage_error)? {
            Some(bytes) => hyphen_codec::deserialize(&bytes).map_err(storage_error)?,
            None => SlotState::default(),
        };
        self.slots.insert(key, state.clone());
        Ok(state)
    }

    fn persist_slot(
        &mut self,
        key: (u64, u64),
        previous: &SlotState,
        next: &mut SlotState,
    ) -> Result<(), FairFinalityError> {
        next.revision = previous
            .revision
            .checked_add(1)
            .ok_or_else(|| FairFinalityError::Storage("state revision overflow".into()))?;
        if let Some(storage) = &self.storage {
            let storage_key = voter_slot_key(
                self.chain_id,
                self.secret.public_key().as_bytes(),
                key.0,
                key.1,
            );
            let expected = if previous.revision == 0 {
                None
            } else {
                Some(hyphen_codec::serialize(previous).map_err(storage_error)?)
            };
            let encoded = hyphen_codec::serialize(next).map_err(storage_error)?;
            storage
                .compare_and_swap(storage_key, expected.as_deref(), Some(encoded))
                .map_err(storage_error)?
                .map_err(|_| FairFinalityError::StorageConflict)?;
            storage.flush().map_err(storage_error)?;
        }
        self.slots.insert(key, next.clone());
        Ok(())
    }
}

pub fn verify_phase_certificate(
    committee: &Committee,
    certificate: &PhaseCertificate,
) -> Result<(), FairFinalityError> {
    verify_epoch(committee, certificate.statement.epoch)?;
    if certificate.statement.committee_id != committee.id() {
        return Err(FairFinalityError::WrongContext);
    }
    verify_votes(
        committee,
        certificate.statement.digest(),
        certificate
            .votes
            .iter()
            .map(|vote| (vote.seat, vote.signature)),
    )
}

pub fn verify_timeout_certificate(
    committee: &Committee,
    certificate: &TimeoutCertificate,
) -> Result<Option<PhaseCertificate>, FairFinalityError> {
    verify_epoch(committee, certificate.epoch)?;
    if certificate.committee_id != committee.id()
        || certificate.votes.len() < committee.quorum()
        || certificate.votes.len() > committee.seats.len()
    {
        return Err(FairFinalityError::NoQuorum);
    }
    let mut seats = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.statement.chain_id != certificate.chain_id
            || vote.statement.epoch != certificate.epoch
            || vote.statement.committee_id != certificate.committee_id
            || vote.statement.slot != certificate.slot
            || vote.statement.view != certificate.view
        {
            return Err(FairFinalityError::WrongContext);
        }
        if !seats.insert(vote.seat) {
            return Err(FairFinalityError::DuplicateSeat);
        }
        let seat = committee
            .seat(vote.seat)
            .ok_or(FairFinalityError::UnknownSeat)?;
        seat.public_key
            .verify(vote.statement.digest().as_bytes(), &vote.signature)
            .map_err(|_| FairFinalityError::InvalidSignature)?;
        if let Some(qc) = &vote.statement.highest_prepare {
            verify_phase_certificate(committee, qc)?;
            if qc.statement.phase != FinalityPhase::Prepare
                || qc.statement.chain_id != certificate.chain_id
                || qc.statement.epoch != certificate.epoch
                || qc.statement.committee_id != certificate.committee_id
                || qc.statement.slot != certificate.slot
                || qc.statement.view > certificate.view
            {
                return Err(FairFinalityError::WrongCertificate);
            }
        }
    }
    highest_prepare(certificate)
}

pub fn verify_proposal(
    committee: &Committee,
    expected_chain_id: Hash256,
    proposal: &FairFinalityProposal,
) -> Result<(), FairFinalityError> {
    verify_value_context(committee, expected_chain_id, &proposal.value)?;
    if proposal.view == 0 {
        if proposal.timeout.is_some() {
            return Err(FairFinalityError::WrongCertificate);
        }
        return Ok(());
    }
    let timeout = proposal
        .timeout
        .as_ref()
        .ok_or(FairFinalityError::MissingTimeout)?;
    if timeout.chain_id != expected_chain_id
        || timeout.epoch != proposal.value.epoch
        || timeout.slot != proposal.value.slot
        || timeout.view.checked_add(1) != Some(proposal.view)
    {
        return Err(FairFinalityError::WrongContext);
    }
    let high = verify_timeout_certificate(committee, timeout)?;
    if high
        .as_ref()
        .is_some_and(|qc| qc.statement.value_hash != proposal.value.hash())
    {
        return Err(FairFinalityError::ViolatesHighestPrepare);
    }
    Ok(())
}

fn highest_prepare(
    certificate: &TimeoutCertificate,
) -> Result<Option<PhaseCertificate>, FairFinalityError> {
    let max_view = certificate
        .votes
        .iter()
        .filter_map(|vote| {
            vote.statement
                .highest_prepare
                .as_ref()
                .map(|qc| qc.statement.view)
        })
        .max();
    let Some(max_view) = max_view else {
        return Ok(None);
    };
    let mut candidates = certificate.votes.iter().filter_map(|vote| {
        vote.statement
            .highest_prepare
            .as_ref()
            .filter(|qc| qc.statement.view == max_view)
    });
    let first = candidates.next().cloned().expect("maximum came from a QC");
    if candidates.any(|candidate| candidate.statement.value_hash != first.statement.value_hash) {
        return Err(FairFinalityError::ConflictingHighPrepare);
    }
    Ok(Some(first))
}

fn verify_order(
    value: &FairFinalityValue,
    order: &VisibleFairOrder,
    obligations: &ReceiptObligationSet,
) -> Result<(), FairFinalityError> {
    if value.metadata_root != order.metadata_root
        || value.evidence_root != order.evidence_root
        || value.order_root != order.order_root
    {
        return Err(FairFinalityError::WrongOrder);
    }
    obligations
        .validate_order(value.slot, order)
        .map_err(|_| FairFinalityError::ReceiptOmission)
}

fn record_phase(
    committee: &Committee,
    value: &FairFinalityValue,
    view: u64,
    phase: FinalityPhase,
    state: &mut SlotState,
) -> Result<PhaseVoteStatement, FairFinalityError> {
    let statement = PhaseVoteStatement {
        chain_id: value.chain_id,
        epoch: value.epoch,
        committee_id: committee.id(),
        slot: value.slot,
        view,
        phase,
        value_hash: value.hash(),
    };
    let digest = statement.digest();
    if let Some(previous) = state.decisions.get(&(view, phase)) {
        if *previous != digest {
            return Err(FairFinalityError::Equivocation);
        }
    } else {
        state.decisions.insert((view, phase), digest);
    }
    Ok(statement)
}

fn sign_phase(secret: &SecretKey, seat: u16, statement: &PhaseVoteStatement) -> PhaseVote {
    PhaseVote {
        seat,
        signature: secret.sign(statement.digest().as_bytes()),
    }
}

fn verify_value_context(
    committee: &Committee,
    expected_chain_id: Hash256,
    value: &FairFinalityValue,
) -> Result<(), FairFinalityError> {
    if value.chain_id != expected_chain_id || value.committee_id != committee.id() {
        return Err(FairFinalityError::WrongContext);
    }
    verify_epoch(committee, value.epoch)
}

fn verify_epoch(committee: &Committee, epoch: u64) -> Result<(), FairFinalityError> {
    if committee.source_epoch.checked_add(1) != Some(epoch) {
        return Err(FairFinalityError::WrongContext);
    }
    Ok(())
}

fn verify_seat(
    committee: &Committee,
    seat: u16,
    secret: &SecretKey,
) -> Result<(), FairFinalityError> {
    let committee_seat = committee.seat(seat).ok_or(FairFinalityError::UnknownSeat)?;
    if committee_seat.public_key != secret.public_key() {
        return Err(FairFinalityError::WrongSigner);
    }
    Ok(())
}

fn verify_votes(
    committee: &Committee,
    digest: Hash256,
    votes: impl Iterator<Item = (u16, Signature)>,
) -> Result<(), FairFinalityError> {
    let votes = votes.collect::<Vec<_>>();
    if votes.len() < committee.quorum() || votes.len() > committee.seats.len() {
        return Err(FairFinalityError::NoQuorum);
    }
    let mut seen = BTreeSet::new();
    for (seat_index, signature) in votes {
        if !seen.insert(seat_index) {
            return Err(FairFinalityError::DuplicateSeat);
        }
        let seat = committee
            .seat(seat_index)
            .ok_or(FairFinalityError::UnknownSeat)?;
        seat.public_key
            .verify(digest.as_bytes(), &signature)
            .map_err(|_| FairFinalityError::InvalidSignature)?;
    }
    Ok(())
}

fn voter_slot_key(chain_id: Hash256, public_key: &[u8; 32], epoch: u64, slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(88);
    key.extend_from_slice(b"HFOC_SLOT_V0");
    key.extend_from_slice(chain_id.as_bytes());
    key.extend_from_slice(public_key);
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

fn storage_error(error: impl std::fmt::Display) -> FairFinalityError {
    FairFinalityError::Storage(error.to_string())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum HandoffRole {
    Old = 0,
    New = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffStatement {
    pub chain_id: Hash256,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub old_committee_id: Hash256,
    pub new_committee_id: Hash256,
    pub checkpoint_height: u64,
    pub checkpoint_hash: Hash256,
    pub previous_handoff: Hash256,
}

impl HandoffStatement {
    pub fn digest(&self, role: HandoffRole) -> Hash256 {
        hash_parts(
            D_HANDOFF,
            &[
                &[FINALITY_VERSION, role as u8],
                self.chain_id.as_bytes(),
                &self.from_epoch.to_be_bytes(),
                &self.to_epoch.to_be_bytes(),
                self.old_committee_id.as_bytes(),
                self.new_committee_id.as_bytes(),
                &self.checkpoint_height.to_be_bytes(),
                self.checkpoint_hash.as_bytes(),
                self.previous_handoff.as_bytes(),
            ],
        )
    }

    pub fn hash(&self) -> Hash256 {
        hash_parts(
            b"HYPHEN_FOC_HANDOFF_ID_V0",
            &[self.digest(HandoffRole::Old).as_bytes()],
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandoffVote {
    pub seat: u16,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DualHandoffCertificate {
    pub statement: HandoffStatement,
    pub old_votes: Vec<HandoffVote>,
    pub new_votes: Vec<HandoffVote>,
}

pub struct HonestHandoffVoter {
    secret: SecretKey,
    chain_id: Hash256,
    decisions: BTreeMap<(u64, HandoffRole), Hash256>,
    storage: Option<sled::Tree>,
}

impl HonestHandoffVoter {
    pub fn new_in_memory(secret: SecretKey, chain_id: Hash256) -> Self {
        Self {
            secret,
            chain_id,
            decisions: BTreeMap::new(),
            storage: None,
        }
    }

    pub fn open(
        database: &sled::Db,
        secret: SecretKey,
        chain_id: Hash256,
    ) -> Result<Self, FairFinalityError> {
        let storage = database
            .open_tree("h_foc_handoff_voter_v0")
            .map_err(storage_error)?;
        Ok(Self {
            secret,
            chain_id,
            decisions: BTreeMap::new(),
            storage: Some(storage),
        })
    }

    pub fn vote(
        &mut self,
        committee: &Committee,
        seat: u16,
        role: HandoffRole,
        statement: &HandoffStatement,
    ) -> Result<HandoffVote, FairFinalityError> {
        if statement.chain_id != self.chain_id
            || statement.from_epoch.checked_add(1) != Some(statement.to_epoch)
            || match role {
                HandoffRole::Old => {
                    committee.source_epoch.checked_add(1) != Some(statement.from_epoch)
                        || committee.id() != statement.old_committee_id
                }
                HandoffRole::New => {
                    committee.source_epoch.checked_add(1) != Some(statement.to_epoch)
                        || committee.id() != statement.new_committee_id
                }
            }
        {
            return Err(FairFinalityError::InvalidHandoff);
        }
        verify_seat(committee, seat, &self.secret)?;
        let digest = statement.digest(role);
        let key = (statement.from_epoch, role);
        if let Some(previous) = self.decisions.get(&key) {
            if *previous != digest {
                return Err(FairFinalityError::HandoffEquivocation);
            }
        }
        if let Some(storage) = &self.storage {
            let storage_key = handoff_voter_key(
                self.chain_id,
                self.secret.public_key().as_bytes(),
                statement.from_epoch,
                role,
            );
            match storage.get(&storage_key).map_err(storage_error)? {
                Some(previous) if previous.as_ref() != digest.as_bytes() => {
                    return Err(FairFinalityError::HandoffEquivocation);
                }
                Some(_) => {}
                None => {
                    storage
                        .compare_and_swap(
                            &storage_key,
                            None as Option<&[u8]>,
                            Some(digest.as_bytes()),
                        )
                        .map_err(storage_error)?
                        .map_err(|_| FairFinalityError::StorageConflict)?;
                    storage.flush().map_err(storage_error)?;
                }
            }
        }
        self.decisions.insert(key, digest);
        Ok(HandoffVote {
            seat,
            signature: self.secret.sign(digest.as_bytes()),
        })
    }
}

fn handoff_voter_key(
    chain_id: Hash256,
    public_key: &[u8; 32],
    from_epoch: u64,
    role: HandoffRole,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(85);
    key.extend_from_slice(b"HFOC_HANDOFF_V0");
    key.extend_from_slice(chain_id.as_bytes());
    key.extend_from_slice(public_key);
    key.extend_from_slice(&from_epoch.to_be_bytes());
    key.push(role as u8);
    key
}

impl DualHandoffCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        old_committee: &Committee,
        new_committee: &Committee,
        expected_chain_id: Hash256,
        expected_checkpoint_height: u64,
        expected_checkpoint_hash: Hash256,
        expected_previous_handoff: Hash256,
    ) -> Result<(), FairFinalityError> {
        let statement = &self.statement;
        if statement.chain_id != expected_chain_id
            || statement.from_epoch.checked_add(1) != Some(statement.to_epoch)
            || old_committee.source_epoch.checked_add(1) != Some(statement.from_epoch)
            || new_committee.source_epoch.checked_add(1) != Some(statement.to_epoch)
            || statement.old_committee_id != old_committee.id()
            || statement.new_committee_id != new_committee.id()
        {
            return Err(FairFinalityError::InvalidHandoff);
        }
        if statement.checkpoint_height != expected_checkpoint_height
            || statement.checkpoint_hash != expected_checkpoint_hash
            || statement.previous_handoff != expected_previous_handoff
        {
            return Err(FairFinalityError::WrongCheckpoint);
        }
        verify_votes(
            old_committee,
            statement.digest(HandoffRole::Old),
            self.old_votes
                .iter()
                .map(|vote| (vote.seat, vote.signature)),
        )?;
        verify_votes(
            new_committee,
            statement.digest(HandoffRole::New),
            self.new_votes
                .iter()
                .map(|vote| (vote.seat, vote.signature)),
        )
    }
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut bytes =
        Vec::with_capacity(domain.len() + 1 + parts.iter().map(|part| part.len()).sum::<usize>());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for part in parts {
        bytes.extend_from_slice(part);
    }
    hyphen_crypto::blake3_hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fast_ordering::WorkContribution;
    use crate::private_fair_ordering::FairBatch;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn committee(source_epoch: u64, seed: u8) -> (Committee, BTreeMap<[u8; 32], SecretKey>) {
        let secrets = [
            SecretKey([1; 32]),
            SecretKey([2; 32]),
            SecretKey([3; 32]),
            SecretKey([4; 32]),
        ];
        let work = secrets
            .iter()
            .map(|secret| WorkContribution {
                public_key: secret.public_key(),
                work: 1,
            })
            .collect::<Vec<_>>();
        let committee = Committee::from_finalized_work(source_epoch, hash(seed), 1, &work).unwrap();
        let secrets = secrets
            .into_iter()
            .map(|secret| (*secret.public_key().as_bytes(), secret))
            .collect();
        (committee, secrets)
    }

    fn value(committee: &Committee, order_root: u8) -> FairFinalityValue {
        FairFinalityValue {
            chain_id: hash(0x11),
            epoch: committee.source_epoch + 1,
            committee_id: committee.id(),
            slot: 7,
            parent_checkpoint: hash(0x22),
            metadata_root: hash(0x31),
            evidence_root: hash(0x32),
            order_root: hash(order_root),
        }
    }

    fn order(root: u8) -> VisibleFairOrder {
        VisibleFairOrder {
            metadata_root: hash(0x31),
            evidence_root: hash(0x32),
            batches: vec![FairBatch {
                transactions: vec![hash(0x44)],
            }],
            order_root: hash(root),
        }
    }

    fn voters(secrets: &BTreeMap<[u8; 32], SecretKey>) -> BTreeMap<[u8; 32], HonestFinalityVoter> {
        secrets
            .iter()
            .map(|(key, secret)| {
                (
                    *key,
                    HonestFinalityVoter::new_in_memory(secret.clone(), hash(0x11)),
                )
            })
            .collect()
    }

    fn prepare_qc(
        committee: &Committee,
        voters: &mut BTreeMap<[u8; 32], HonestFinalityVoter>,
        value: &FairFinalityValue,
    ) -> PhaseCertificate {
        let proposal = FairFinalityProposal {
            view: 0,
            value: value.clone(),
            timeout: None,
        };
        let obligations = ReceiptObligationSet::default();
        let votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .prepare(committee, seat.index, &proposal, &order(0x33), &obligations)
                    .unwrap()
            })
            .collect();
        PhaseCertificate {
            statement: PhaseVoteStatement {
                chain_id: value.chain_id,
                epoch: value.epoch,
                committee_id: committee.id(),
                slot: value.slot,
                view: 0,
                phase: FinalityPhase::Prepare,
                value_hash: value.hash(),
            },
            votes,
        }
    }

    #[test]
    fn prepare_then_commit_qc_verifies_and_locks_honest_voters() {
        let (committee, secrets) = committee(8, 6);
        let mut voters = voters(&secrets);
        let finality_value = value(&committee, 0x33);
        let prepare = prepare_qc(&committee, &mut voters, &finality_value);
        verify_phase_certificate(&committee, &prepare).unwrap();
        let commit_votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .commit(&committee, seat.index, &finality_value, &prepare)
                    .unwrap()
            })
            .collect();
        let commit = PhaseCertificate {
            statement: PhaseVoteStatement {
                phase: FinalityPhase::Commit,
                ..prepare.statement.clone()
            },
            votes: commit_votes,
        };
        verify_phase_certificate(&committee, &commit).unwrap();

        let conflicting = FairFinalityProposal {
            view: 1,
            value: value(&committee, 0x34),
            timeout: None,
        };
        let seat = committee.seats[0];
        assert_eq!(
            voters.get_mut(seat.public_key.as_bytes()).unwrap().prepare(
                &committee,
                seat.index,
                &conflicting,
                &order(0x34),
                &ReceiptObligationSet::default()
            ),
            Err(FairFinalityError::MissingTimeout)
        );
    }

    #[test]
    fn dual_handoff_requires_both_quorums_and_exact_checkpoint() {
        let (old, secrets) = committee(8, 6);
        let (new, _) = committee(9, 7);
        let statement = HandoffStatement {
            chain_id: hash(0x11),
            from_epoch: 9,
            to_epoch: 10,
            old_committee_id: old.id(),
            new_committee_id: new.id(),
            checkpoint_height: 1000,
            checkpoint_hash: hash(0x55),
            previous_handoff: hash(0x54),
        };
        let mut old_voters = secrets
            .values()
            .cloned()
            .map(|secret| {
                (
                    *secret.public_key().as_bytes(),
                    HonestHandoffVoter::new_in_memory(secret, hash(0x11)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut new_voters = secrets
            .values()
            .cloned()
            .map(|secret| {
                (
                    *secret.public_key().as_bytes(),
                    HonestHandoffVoter::new_in_memory(secret, hash(0x11)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let old_votes = old
            .seats
            .iter()
            .take(old.quorum())
            .map(|seat| {
                old_voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .vote(&old, seat.index, HandoffRole::Old, &statement)
                    .unwrap()
            })
            .collect();
        let new_votes = new
            .seats
            .iter()
            .take(new.quorum())
            .map(|seat| {
                new_voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .vote(&new, seat.index, HandoffRole::New, &statement)
                    .unwrap()
            })
            .collect();
        let certificate = DualHandoffCertificate {
            statement,
            old_votes,
            new_votes,
        };
        certificate
            .verify(&old, &new, hash(0x11), 1000, hash(0x55), hash(0x54))
            .unwrap();
        assert_eq!(
            certificate.verify(&old, &new, hash(0x11), 1000, hash(0x56), hash(0x54)),
            Err(FairFinalityError::WrongCheckpoint)
        );
    }

    #[test]
    fn phase_equivocation_guard_survives_restart() {
        let database = sled::Config::new().temporary(true).open().unwrap();
        let (committee, secrets) = committee(8, 6);
        let seat = committee.seats[0];
        let secret = secrets.get(seat.public_key.as_bytes()).unwrap().clone();
        let first_value = value(&committee, 0x33);
        let first = FairFinalityProposal {
            view: 0,
            value: first_value,
            timeout: None,
        };
        let mut voter = HonestFinalityVoter::open(&database, secret.clone(), hash(0x11)).unwrap();
        voter
            .prepare(
                &committee,
                seat.index,
                &first,
                &order(0x33),
                &ReceiptObligationSet::default(),
            )
            .unwrap();
        drop(voter);

        let conflicting = FairFinalityProposal {
            view: 0,
            value: value(&committee, 0x34),
            timeout: None,
        };
        let mut reopened = HonestFinalityVoter::open(&database, secret, hash(0x11)).unwrap();
        assert_eq!(
            reopened.prepare(
                &committee,
                seat.index,
                &conflicting,
                &order(0x34),
                &ReceiptObligationSet::default(),
            ),
            Err(FairFinalityError::Equivocation)
        );
    }

    #[test]
    fn handoff_equivocation_guard_survives_restart() {
        let database = sled::Config::new().temporary(true).open().unwrap();
        let (old, secrets) = committee(8, 6);
        let (new, _) = committee(9, 7);
        let seat = old.seats[0];
        let secret = secrets.get(seat.public_key.as_bytes()).unwrap().clone();
        let statement = HandoffStatement {
            chain_id: hash(0x11),
            from_epoch: 9,
            to_epoch: 10,
            old_committee_id: old.id(),
            new_committee_id: new.id(),
            checkpoint_height: 1000,
            checkpoint_hash: hash(0x55),
            previous_handoff: hash(0x54),
        };
        let mut voter = HonestHandoffVoter::open(&database, secret.clone(), hash(0x11)).unwrap();
        voter
            .vote(&old, seat.index, HandoffRole::Old, &statement)
            .unwrap();
        drop(voter);

        let conflicting = HandoffStatement {
            checkpoint_hash: hash(0x56),
            ..statement
        };
        let mut reopened = HonestHandoffVoter::open(&database, secret, hash(0x11)).unwrap();
        assert_eq!(
            reopened.vote(&old, seat.index, HandoffRole::Old, &conflicting),
            Err(FairFinalityError::HandoffEquivocation)
        );
    }
}
