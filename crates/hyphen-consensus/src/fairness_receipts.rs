//! Quorum inclusion receipts for visible-domain ordering.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{Hash256, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use thiserror::Error;

use crate::fast_ordering::Committee;
use crate::private_fair_ordering::{VisibleFairOrder, VisibleMetadata};

const RECEIPT_VERSION: u8 = 0;
const D_RECEIPT: &[u8] = b"HYPHEN_FAIR_INCLUSION_RECEIPT_V0";
pub const MAX_RECEIPT_VOTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionReceiptStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub slot: u64,
    pub cutoff: u64,
    pub transaction_id: Hash256,
    pub metadata_hash: Hash256,
}

impl InclusionReceiptStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(153);
        bytes.push(RECEIPT_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(&self.cutoff.to_be_bytes());
        bytes.extend_from_slice(self.transaction_id.as_bytes());
        bytes.extend_from_slice(self.metadata_hash.as_bytes());
        bytes
    }

    pub fn digest(&self) -> Hash256 {
        hash_parts(D_RECEIPT, &[&self.canonical_bytes()])
    }

    fn vote_digest(&self, seat: u16, observed_at: u64) -> Hash256 {
        hash_parts(
            b"HYPHEN_FAIR_INCLUSION_VOTE_V0",
            &[
                self.digest().as_bytes(),
                &seat.to_be_bytes(),
                &observed_at.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionReceiptVote {
    pub seat: u16,
    pub observed_at: u64,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumInclusionReceipt {
    pub statement: InclusionReceiptStatement,
    pub votes: Vec<InclusionReceiptVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionReceiptVoteGossip {
    pub statement: InclusionReceiptStatement,
    pub metadata: VisibleMetadata,
    pub vote: InclusionReceiptVote,
}

impl InclusionReceiptVoteGossip {
    pub fn validate_shape(&self) -> Result<(), InclusionReceiptError> {
        validate_metadata_statement(&self.statement, &self.metadata)?;
        if self.vote.observed_at > self.statement.cutoff {
            return Err(InclusionReceiptError::AfterCutoff);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        committee: &Committee,
        expected_chain_id: Hash256,
    ) -> Result<(), InclusionReceiptError> {
        self.validate_shape()?;
        validate_context(committee, &self.statement)?;
        if self.statement.chain_id != expected_chain_id {
            return Err(InclusionReceiptError::WrongContext);
        }
        let seat = committee
            .seat(self.vote.seat)
            .ok_or(InclusionReceiptError::UnknownSeat)?;
        seat.public_key
            .verify(
                self.statement
                    .vote_digest(self.vote.seat, self.vote.observed_at)
                    .as_bytes(),
                &self.vote.signature,
            )
            .map_err(|_| InclusionReceiptError::InvalidSignature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumInclusionReceiptGossip {
    pub metadata: VisibleMetadata,
    pub receipt: QuorumInclusionReceipt,
}

impl QuorumInclusionReceiptGossip {
    pub fn validate_shape(&self) -> Result<(), InclusionReceiptError> {
        validate_metadata_statement(&self.receipt.statement, &self.metadata)?;
        if self.receipt.votes.is_empty() || self.receipt.votes.len() > MAX_RECEIPT_VOTES {
            return Err(InclusionReceiptError::NoQuorum);
        }
        let mut seats = BTreeSet::new();
        for vote in &self.receipt.votes {
            if vote.observed_at > self.receipt.statement.cutoff {
                return Err(InclusionReceiptError::AfterCutoff);
            }
            if !seats.insert(vote.seat) {
                return Err(InclusionReceiptError::DuplicateSeat);
            }
        }
        Ok(())
    }

    pub fn verify(
        &self,
        committee: &Committee,
        expected_chain_id: Hash256,
    ) -> Result<(), InclusionReceiptError> {
        self.validate_shape()?;
        self.receipt.verify(
            committee,
            expected_chain_id,
            self.receipt.statement.slot,
            &self.metadata,
        )
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InclusionReceiptError {
    #[error("receipt belongs to another chain, committee, epoch or slot")]
    WrongContext,
    #[error("receipt observation is after the declared cutoff")]
    AfterCutoff,
    #[error("receipt metadata does not match the transaction projection")]
    MetadataMismatch,
    #[error("receipt does not contain 2f+1 distinct seats")]
    NoQuorum,
    #[error("receipt repeats a committee seat")]
    DuplicateSeat,
    #[error("receipt references an unknown seat")]
    UnknownSeat,
    #[error("receipt signature is invalid")]
    InvalidSignature,
    #[error("secret key does not own the receipt seat")]
    WrongSigner,
    #[error("a required quorum-receipted transaction is missing from the order")]
    MissingRequiredTransaction,
    #[error("two quorum receipts conflict for one transaction and slot")]
    ConflictingReceipt,
    #[error("durable receipt obligation changed concurrently")]
    StorageConflict,
    #[error("receipt-vote capacity for this slot is exhausted")]
    SlotCapacity,
    #[error("receipt-vote capacity must be greater than zero")]
    InvalidCapacity,
    #[error("durable receipt obligation failed: {0}")]
    Storage(String),
}

#[cfg(test)]
fn sign_inclusion_receipt(
    secret: &SecretKey,
    committee: &Committee,
    seat: u16,
    statement: InclusionReceiptStatement,
    observed_at: u64,
) -> Result<InclusionReceiptVote, InclusionReceiptError> {
    validate_context(committee, &statement)?;
    if observed_at > statement.cutoff {
        return Err(InclusionReceiptError::AfterCutoff);
    }
    let committee_seat = committee
        .seat(seat)
        .ok_or(InclusionReceiptError::UnknownSeat)?;
    if committee_seat.public_key != secret.public_key() {
        return Err(InclusionReceiptError::WrongSigner);
    }
    Ok(InclusionReceiptVote {
        seat,
        observed_at,
        signature: secret.sign(statement.vote_digest(seat, observed_at).as_bytes()),
    })
}

impl QuorumInclusionReceipt {
    pub fn verify(
        &self,
        committee: &Committee,
        expected_chain_id: Hash256,
        expected_slot: u64,
        metadata: &VisibleMetadata,
    ) -> Result<(), InclusionReceiptError> {
        validate_context(committee, &self.statement)?;
        if self.statement.chain_id != expected_chain_id || self.statement.slot != expected_slot {
            return Err(InclusionReceiptError::WrongContext);
        }
        validate_metadata_statement(&self.statement, metadata)?;
        if self.votes.len() < committee.quorum() || self.votes.len() > committee.seats.len() {
            return Err(InclusionReceiptError::NoQuorum);
        }
        let mut seen = BTreeSet::new();
        for vote in &self.votes {
            if vote.observed_at > self.statement.cutoff {
                return Err(InclusionReceiptError::AfterCutoff);
            }
            if !seen.insert(vote.seat) {
                return Err(InclusionReceiptError::DuplicateSeat);
            }
            let seat = committee
                .seat(vote.seat)
                .ok_or(InclusionReceiptError::UnknownSeat)?;
            seat.public_key
                .verify(
                    self.statement
                        .vote_digest(vote.seat, vote.observed_at)
                        .as_bytes(),
                    &vote.signature,
                )
                .map_err(|_| InclusionReceiptError::InvalidSignature)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ReceiptObligationSet {
    required: BTreeMap<(u64, Hash256), Hash256>,
    storage: Option<sled::Tree>,
    chain_id: Option<Hash256>,
}

impl ReceiptObligationSet {
    pub fn open(database: &sled::Db, chain_id: Hash256) -> Result<Self, InclusionReceiptError> {
        let storage = database
            .open_tree("fair_receipt_obligations_v0")
            .map_err(receipt_storage_error)?;
        let prefix = obligation_prefix(chain_id);
        let mut required = BTreeMap::new();
        for entry in storage.scan_prefix(&prefix) {
            let (key, value) = entry.map_err(receipt_storage_error)?;
            if key.len() != prefix.len() + 40 || value.len() != 32 {
                return Err(InclusionReceiptError::Storage(
                    "malformed persisted obligation".into(),
                ));
            }
            let slot = u64::from_be_bytes(
                key[prefix.len()..prefix.len() + 8]
                    .try_into()
                    .map_err(receipt_storage_error)?,
            );
            let transaction = Hash256::from_bytes(
                key[prefix.len() + 8..]
                    .try_into()
                    .map_err(receipt_storage_error)?,
            );
            let digest =
                Hash256::from_bytes(value.as_ref().try_into().map_err(receipt_storage_error)?);
            required.insert((slot, transaction), digest);
        }
        Ok(Self {
            required,
            storage: Some(storage),
            chain_id: Some(chain_id),
        })
    }

    pub fn register(
        &mut self,
        committee: &Committee,
        expected_chain_id: Hash256,
        metadata: &VisibleMetadata,
        receipt: &QuorumInclusionReceipt,
    ) -> Result<(), InclusionReceiptError> {
        receipt.verify(
            committee,
            expected_chain_id,
            receipt.statement.slot,
            metadata,
        )?;
        self.register_statement(committee, expected_chain_id, metadata, &receipt.statement)
    }

    fn register_statement(
        &mut self,
        committee: &Committee,
        expected_chain_id: Hash256,
        metadata: &VisibleMetadata,
        statement: &InclusionReceiptStatement,
    ) -> Result<(), InclusionReceiptError> {
        validate_context(committee, statement)?;
        if statement.chain_id != expected_chain_id {
            return Err(InclusionReceiptError::WrongContext);
        }
        if statement.transaction_id != metadata.transaction_id
            || statement.metadata_hash != metadata.hash()
        {
            return Err(InclusionReceiptError::MetadataMismatch);
        }
        if self
            .chain_id
            .is_some_and(|chain_id| chain_id != expected_chain_id)
        {
            return Err(InclusionReceiptError::WrongContext);
        }
        let key = (statement.slot, statement.transaction_id);
        let digest = statement.digest();
        if let Some(previous) = self.required.get(&key) {
            if *previous != digest {
                return Err(InclusionReceiptError::ConflictingReceipt);
            }
        }
        if let Some(storage) = &self.storage {
            let storage_key = obligation_key(expected_chain_id, key.0, key.1);
            match storage.get(&storage_key).map_err(receipt_storage_error)? {
                Some(previous) if previous.as_ref() != digest.as_bytes() => {
                    return Err(InclusionReceiptError::ConflictingReceipt);
                }
                Some(_) => {}
                None => {
                    storage
                        .compare_and_swap(
                            storage_key,
                            None as Option<&[u8]>,
                            Some(digest.as_bytes()),
                        )
                        .map_err(receipt_storage_error)?
                        .map_err(|_| InclusionReceiptError::StorageConflict)?;
                    storage.flush().map_err(receipt_storage_error)?;
                }
            }
        }
        self.required.insert(key, digest);
        Ok(())
    }

    pub fn validate_order(
        &self,
        slot: u64,
        order: &VisibleFairOrder,
    ) -> Result<(), InclusionReceiptError> {
        let included = order
            .batches
            .iter()
            .flat_map(|batch| batch.transactions.iter().copied())
            .collect::<BTreeSet<_>>();
        if self.required.keys().any(|(required_slot, transaction)| {
            *required_slot == slot && !included.contains(transaction)
        }) {
            return Err(InclusionReceiptError::MissingRequiredTransaction);
        }
        Ok(())
    }

    pub fn finalize_slot(&mut self, slot: u64) -> Result<(), InclusionReceiptError> {
        if let (Some(storage), Some(chain_id)) = (&self.storage, self.chain_id) {
            let mut batch = sled::Batch::default();
            for (_, transaction) in self
                .required
                .keys()
                .filter(|(required_slot, _)| *required_slot == slot)
            {
                batch.remove(obligation_key(chain_id, slot, *transaction));
            }
            storage.apply_batch(batch).map_err(receipt_storage_error)?;
            storage.flush().map_err(receipt_storage_error)?;
        }
        self.required
            .retain(|(required_slot, _), _| *required_slot != slot);
        Ok(())
    }

    pub fn required_count(&self, slot: u64) -> usize {
        self.required
            .keys()
            .filter(|(required_slot, _)| *required_slot == slot)
            .count()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedReceiptVote {
    statement_digest: Hash256,
    observed_at: u64,
}

#[derive(Clone, Debug)]
enum VoteStorageAbort {
    Conflict,
    Capacity,
    Malformed(String),
}

/// Crash-durable receipt signer. A returned signature implies that the same
/// node has already persisted an obligation to reject omission of the
/// transaction from the corresponding slot order.
pub struct HonestReceiptVoter {
    secret: SecretKey,
    chain_id: Hash256,
    max_obligations_per_slot: u32,
    votes: sled::Tree,
    obligations: ReceiptObligationSet,
}

impl HonestReceiptVoter {
    pub fn open(
        database: &sled::Db,
        secret: SecretKey,
        chain_id: Hash256,
        max_obligations_per_slot: u32,
    ) -> Result<Self, InclusionReceiptError> {
        if max_obligations_per_slot == 0 {
            return Err(InclusionReceiptError::InvalidCapacity);
        }
        let votes = database
            .open_tree("fair_receipt_votes_v0")
            .map_err(receipt_storage_error)?;
        let obligations = ReceiptObligationSet::open(database, chain_id)?;
        Ok(Self {
            secret,
            chain_id,
            max_obligations_per_slot,
            votes,
            obligations,
        })
    }

    pub fn vote(
        &mut self,
        committee: &Committee,
        seat: u16,
        statement: InclusionReceiptStatement,
        metadata: &VisibleMetadata,
        observed_at: u64,
    ) -> Result<InclusionReceiptVote, InclusionReceiptError> {
        validate_context(committee, &statement)?;
        if statement.chain_id != self.chain_id {
            return Err(InclusionReceiptError::WrongContext);
        }
        if statement.transaction_id != metadata.transaction_id
            || statement.metadata_hash != metadata.hash()
        {
            return Err(InclusionReceiptError::MetadataMismatch);
        }
        if observed_at > statement.cutoff {
            return Err(InclusionReceiptError::AfterCutoff);
        }
        let committee_seat = committee
            .seat(seat)
            .ok_or(InclusionReceiptError::UnknownSeat)?;
        if committee_seat.public_key != self.secret.public_key() {
            return Err(InclusionReceiptError::WrongSigner);
        }

        let record = self.persist_vote_record(&statement, observed_at)?;
        self.obligations
            .register_statement(committee, self.chain_id, metadata, &statement)?;

        Ok(InclusionReceiptVote {
            seat,
            observed_at: record.observed_at,
            signature: self
                .secret
                .sign(statement.vote_digest(seat, record.observed_at).as_bytes()),
        })
    }

    pub fn validate_order(
        &self,
        slot: u64,
        order: &VisibleFairOrder,
    ) -> Result<(), InclusionReceiptError> {
        self.obligations.validate_order(slot, order)
    }

    pub fn finalize_slot(&mut self, slot: u64) -> Result<(), InclusionReceiptError> {
        let prefix = voter_slot_prefix(self.chain_id, self.secret.public_key().as_bytes(), slot);
        let mut batch = sled::Batch::default();
        for entry in self.votes.scan_prefix(prefix) {
            let (key, _) = entry.map_err(receipt_storage_error)?;
            batch.remove(key);
        }
        batch.remove(voter_count_key(
            self.chain_id,
            self.secret.public_key().as_bytes(),
            slot,
        ));
        self.votes
            .apply_batch(batch)
            .map_err(receipt_storage_error)?;
        self.votes.flush().map_err(receipt_storage_error)?;
        self.obligations.finalize_slot(slot)
    }

    fn persist_vote_record(
        &self,
        statement: &InclusionReceiptStatement,
        observed_at: u64,
    ) -> Result<PersistedReceiptVote, InclusionReceiptError> {
        let public_key = self.secret.public_key();
        let key = voter_record_key(
            self.chain_id,
            public_key.as_bytes(),
            statement.slot,
            statement.transaction_id,
        );
        let count_key = voter_count_key(self.chain_id, public_key.as_bytes(), statement.slot);
        let proposed = PersistedReceiptVote {
            statement_digest: statement.digest(),
            observed_at,
        };
        let proposed_bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&proposed)
            .map_err(receipt_storage_error)?;
        let limit = self.max_obligations_per_slot;

        let result: Result<PersistedReceiptVote, TransactionError<VoteStorageAbort>> =
            self.votes.transaction(|tree| {
                if let Some(bytes) = tree.get(key.as_slice())? {
                    let existing: PersistedReceiptVote =
                        crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                            .deserialize(&bytes)
                            .map_err(|error| {
                                ConflictableTransactionError::Abort(VoteStorageAbort::Malformed(
                                    error.to_string(),
                                ))
                            })?;
                    if existing.statement_digest != proposed.statement_digest {
                        return Err(ConflictableTransactionError::Abort(
                            VoteStorageAbort::Conflict,
                        ));
                    }
                    return Ok(existing);
                }

                let count = match tree.get(count_key.as_slice())? {
                    Some(bytes) if bytes.len() == 4 => {
                        u32::from_be_bytes(bytes.as_ref().try_into().map_err(|_| {
                            ConflictableTransactionError::Abort(VoteStorageAbort::Malformed(
                                "invalid receipt-vote count".into(),
                            ))
                        })?)
                    }
                    Some(_) => {
                        return Err(ConflictableTransactionError::Abort(
                            VoteStorageAbort::Malformed("invalid receipt-vote count".into()),
                        ));
                    }
                    None => 0,
                };
                if count >= limit {
                    return Err(ConflictableTransactionError::Abort(
                        VoteStorageAbort::Capacity,
                    ));
                }
                let next_count = count.checked_add(1).ok_or_else(|| {
                    ConflictableTransactionError::Abort(VoteStorageAbort::Capacity)
                })?;
                tree.insert(key.as_slice(), proposed_bytes.as_slice())?;
                tree.insert(count_key.as_slice(), &next_count.to_be_bytes())?;
                Ok(proposed.clone())
            });

        let record = match result {
            Ok(record) => record,
            Err(TransactionError::Abort(VoteStorageAbort::Conflict)) => {
                return Err(InclusionReceiptError::ConflictingReceipt);
            }
            Err(TransactionError::Abort(VoteStorageAbort::Capacity)) => {
                return Err(InclusionReceiptError::SlotCapacity);
            }
            Err(TransactionError::Abort(VoteStorageAbort::Malformed(error))) => {
                return Err(InclusionReceiptError::Storage(error));
            }
            Err(TransactionError::Storage(error)) => {
                return Err(receipt_storage_error(error));
            }
        };
        self.votes.flush().map_err(receipt_storage_error)?;
        Ok(record)
    }
}

fn validate_context(
    committee: &Committee,
    statement: &InclusionReceiptStatement,
) -> Result<(), InclusionReceiptError> {
    let target_epoch = committee
        .source_epoch
        .checked_add(1)
        .ok_or(InclusionReceiptError::WrongContext)?;
    if statement.epoch != target_epoch || statement.committee_id != committee.id() {
        return Err(InclusionReceiptError::WrongContext);
    }
    Ok(())
}

fn validate_metadata_statement(
    statement: &InclusionReceiptStatement,
    metadata: &VisibleMetadata,
) -> Result<(), InclusionReceiptError> {
    if statement.transaction_id != metadata.transaction_id
        || statement.metadata_hash != metadata.hash()
    {
        return Err(InclusionReceiptError::MetadataMismatch);
    }
    Ok(())
}

fn obligation_prefix(chain_id: Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(50);
    key.extend_from_slice(b"FAIR_OBLIGATION_V0");
    key.extend_from_slice(chain_id.as_bytes());
    key
}

fn obligation_key(chain_id: Hash256, slot: u64, transaction: Hash256) -> Vec<u8> {
    let mut key = obligation_prefix(chain_id);
    key.extend_from_slice(&slot.to_be_bytes());
    key.extend_from_slice(transaction.as_bytes());
    key
}

fn voter_slot_prefix(chain_id: Hash256, public_key: &[u8; 32], slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(92);
    key.extend_from_slice(b"FAIR_RECEIPT_VOTE_V0");
    key.extend_from_slice(chain_id.as_bytes());
    key.extend_from_slice(public_key);
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

fn voter_record_key(
    chain_id: Hash256,
    public_key: &[u8; 32],
    slot: u64,
    transaction: Hash256,
) -> Vec<u8> {
    let mut key = voter_slot_prefix(chain_id, public_key, slot);
    key.extend_from_slice(transaction.as_bytes());
    key
}

fn voter_count_key(chain_id: Hash256, public_key: &[u8; 32], slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(93);
    key.extend_from_slice(b"FAIR_RECEIPT_COUNT_V0");
    key.extend_from_slice(chain_id.as_bytes());
    key.extend_from_slice(public_key);
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

fn receipt_storage_error(error: impl std::fmt::Display) -> InclusionReceiptError {
    InclusionReceiptError::Storage(error.to_string())
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

    fn fixture() -> (Committee, BTreeMap<[u8; 32], SecretKey>) {
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
        let committee = (1..=u8::MAX)
            .map(|seed| Committee::from_finalized_work(8, hash(seed), 1, &work).unwrap())
            .find(|candidate| {
                candidate
                    .seats
                    .iter()
                    .map(|seat| seat.public_key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == candidate.seats.len()
            })
            .unwrap();
        let secrets = secrets
            .into_iter()
            .map(|secret| (*secret.public_key().as_bytes(), secret))
            .collect();
        (committee, secrets)
    }

    fn metadata() -> VisibleMetadata {
        VisibleMetadata {
            transaction_id: hash(0x44),
            fee_class: 1,
            encoded_len: 512,
            conflict_tag: Hash256::ZERO,
        }
    }

    fn statement(committee: &Committee, metadata: &VisibleMetadata) -> InclusionReceiptStatement {
        InclusionReceiptStatement {
            chain_id: hash(0x11),
            epoch: committee.source_epoch + 1,
            committee_id: committee.id(),
            slot: 7,
            cutoff: 100,
            transaction_id: metadata.transaction_id,
            metadata_hash: metadata.hash(),
        }
    }

    #[test]
    fn quorum_receipt_creates_an_enforced_local_obligation() {
        let (committee, secrets) = fixture();
        let metadata = metadata();
        let statement = InclusionReceiptStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            slot: 7,
            cutoff: 100,
            transaction_id: metadata.transaction_id,
            metadata_hash: metadata.hash(),
        };
        let votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                sign_inclusion_receipt(
                    secrets.get(seat.public_key.as_bytes()).unwrap(),
                    &committee,
                    seat.index,
                    statement.clone(),
                    90 + u64::from(seat.index),
                )
                .unwrap()
            })
            .collect();
        let receipt = QuorumInclusionReceipt { statement, votes };
        let mut obligations = ReceiptObligationSet::default();
        obligations
            .register(&committee, hash(0x11), &metadata, &receipt)
            .unwrap();
        assert_eq!(obligations.required_count(7), 1);

        let omitted = VisibleFairOrder {
            metadata_root: hash(1),
            evidence_root: hash(2),
            batches: vec![FairBatch {
                transactions: vec![hash(0x45)],
            }],
            order_root: hash(3),
        };
        assert_eq!(
            obligations.validate_order(7, &omitted),
            Err(InclusionReceiptError::MissingRequiredTransaction)
        );
        let included = VisibleFairOrder {
            batches: vec![FairBatch {
                transactions: vec![metadata.transaction_id],
            }],
            ..omitted
        };
        obligations.validate_order(7, &included).unwrap();
        obligations.finalize_slot(7).unwrap();
        assert_eq!(obligations.required_count(7), 0);
    }

    #[test]
    fn post_cutoff_and_duplicate_receipts_fail() {
        let (committee, secrets) = fixture();
        let metadata = metadata();
        let statement = InclusionReceiptStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            slot: 7,
            cutoff: 100,
            transaction_id: metadata.transaction_id,
            metadata_hash: metadata.hash(),
        };
        let seat = committee.seats[0];
        assert_eq!(
            sign_inclusion_receipt(
                secrets.get(seat.public_key.as_bytes()).unwrap(),
                &committee,
                seat.index,
                statement.clone(),
                101,
            ),
            Err(InclusionReceiptError::AfterCutoff)
        );
        let vote = sign_inclusion_receipt(
            secrets.get(seat.public_key.as_bytes()).unwrap(),
            &committee,
            seat.index,
            statement.clone(),
            99,
        )
        .unwrap();
        let receipt = QuorumInclusionReceipt {
            statement,
            votes: vec![vote; committee.quorum()],
        };
        assert_eq!(
            receipt.verify(&committee, hash(0x11), 7, &metadata),
            Err(InclusionReceiptError::DuplicateSeat)
        );
    }

    #[test]
    fn receipt_obligation_survives_restart() {
        let database = sled::Config::new().temporary(true).open().unwrap();
        let (committee, secrets) = fixture();
        let metadata = metadata();
        let statement = InclusionReceiptStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            slot: 7,
            cutoff: 100,
            transaction_id: metadata.transaction_id,
            metadata_hash: metadata.hash(),
        };
        let votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                sign_inclusion_receipt(
                    secrets.get(seat.public_key.as_bytes()).unwrap(),
                    &committee,
                    seat.index,
                    statement.clone(),
                    90 + u64::from(seat.index),
                )
                .unwrap()
            })
            .collect();
        let receipt = QuorumInclusionReceipt { statement, votes };
        let mut obligations = ReceiptObligationSet::open(&database, hash(0x11)).unwrap();
        obligations
            .register(&committee, hash(0x11), &metadata, &receipt)
            .unwrap();
        drop(obligations);

        let reopened = ReceiptObligationSet::open(&database, hash(0x11)).unwrap();
        assert_eq!(reopened.required_count(7), 1);
        let omitted = VisibleFairOrder {
            metadata_root: hash(1),
            evidence_root: hash(2),
            batches: vec![],
            order_root: hash(3),
        };
        assert_eq!(
            reopened.validate_order(7, &omitted),
            Err(InclusionReceiptError::MissingRequiredTransaction)
        );
    }

    #[test]
    fn honest_voter_persists_obligation_before_releasing_signature() {
        let database = sled::Config::new().temporary(true).open().unwrap();
        let (committee, secrets) = fixture();
        let metadata = metadata();
        let statement = statement(&committee, &metadata);
        let seat = committee.seats[0];
        let secret = secrets.get(seat.public_key.as_bytes()).unwrap().clone();

        let first_vote = {
            let mut voter =
                HonestReceiptVoter::open(&database, secret.clone(), statement.chain_id, 16)
                    .unwrap();
            voter
                .vote(&committee, seat.index, statement.clone(), &metadata, 90)
                .unwrap()
        };

        let obligations = ReceiptObligationSet::open(&database, statement.chain_id).unwrap();
        assert_eq!(obligations.required_count(statement.slot), 1);
        let omitted = VisibleFairOrder {
            metadata_root: hash(1),
            evidence_root: hash(2),
            batches: vec![],
            order_root: hash(3),
        };
        assert_eq!(
            obligations.validate_order(statement.slot, &omitted),
            Err(InclusionReceiptError::MissingRequiredTransaction)
        );

        let mut reopened =
            HonestReceiptVoter::open(&database, secret, statement.chain_id, 16).unwrap();
        let retransmission = reopened
            .vote(&committee, seat.index, statement, &metadata, 95)
            .unwrap();
        assert_eq!(retransmission, first_vote);
    }

    #[test]
    fn honest_voter_rejects_conflicts_and_enforces_slot_capacity() {
        let database = sled::Config::new().temporary(true).open().unwrap();
        let (committee, secrets) = fixture();
        let first_metadata = metadata();
        let first_statement = statement(&committee, &first_metadata);
        let seat = committee.seats[0];
        let secret = secrets.get(seat.public_key.as_bytes()).unwrap().clone();
        let mut voter =
            HonestReceiptVoter::open(&database, secret, first_statement.chain_id, 1).unwrap();
        voter
            .vote(
                &committee,
                seat.index,
                first_statement.clone(),
                &first_metadata,
                90,
            )
            .unwrap();

        let mut conflicting = first_statement.clone();
        conflicting.cutoff += 1;
        assert_eq!(
            voter.vote(&committee, seat.index, conflicting, &first_metadata, 90,),
            Err(InclusionReceiptError::ConflictingReceipt)
        );

        let second_metadata = VisibleMetadata {
            transaction_id: hash(0x45),
            ..first_metadata
        };
        let second_statement = statement(&committee, &second_metadata);
        assert_eq!(
            voter.vote(
                &committee,
                seat.index,
                second_statement.clone(),
                &second_metadata,
                90,
            ),
            Err(InclusionReceiptError::SlotCapacity)
        );

        voter.finalize_slot(first_statement.slot).unwrap();
        voter
            .vote(
                &committee,
                seat.index,
                second_statement,
                &second_metadata,
                90,
            )
            .unwrap();
    }
}
