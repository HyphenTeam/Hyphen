//! Quorum attestations that a committee fetched and authenticated a complete blob.
//!
//! A certificate proves a threshold of sampled seats signed after checking the
//! content hash and chunk root. It does not make the blob permanently
//! available: retention and periodic re-certification remain protocol duties.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{Hash256, SecretKey, Signature};
use hyphen_state::{describe_blob, BlobMetadata};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fast_ordering::Committee;

const AVAILABILITY_VERSION: u8 = 0;
const D_AVAILABILITY: &[u8] = b"HYPHEN_DA_ATTESTATION_V0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvailabilityStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub published_height: u64,
    pub retain_until_height: u64,
    pub blob: BlobMetadata,
}

impl AvailabilityStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(169);
        bytes.push(AVAILABILITY_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.published_height.to_be_bytes());
        bytes.extend_from_slice(&self.retain_until_height.to_be_bytes());
        bytes.extend_from_slice(&self.blob.canonical_bytes());
        bytes
    }

    pub fn digest(&self) -> Hash256 {
        hash_parts(D_AVAILABILITY, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvailabilityVote {
    pub seat: u16,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvailabilityCertificate {
    pub statement: AvailabilityStatement,
    pub votes: Vec<AvailabilityVote>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AvailabilityError {
    #[error("availability statement belongs to another chain")]
    WrongChain,
    #[error("availability statement belongs to another committee or epoch")]
    WrongCommittee,
    #[error("availability retention interval is invalid or has expired")]
    InvalidRetention,
    #[error("availability certificate does not contain a committee quorum")]
    NoQuorum,
    #[error("availability certificate repeats a seat")]
    DuplicateSeat,
    #[error("availability certificate references an unknown seat")]
    UnknownSeat,
    #[error("availability signature is invalid")]
    InvalidSignature,
    #[error("secret key does not own the availability seat")]
    WrongSigner,
    #[error("provided blob does not match the availability statement")]
    BlobMismatch,
    #[error("operator refuses to attest conflicting metadata for one object")]
    ConflictingAttestation,
}

pub struct HonestAvailabilityVoter {
    secret: SecretKey,
    chain_id: Hash256,
    decisions: BTreeMap<(u64, Hash256), Hash256>,
}

impl HonestAvailabilityVoter {
    pub fn new(secret: SecretKey, chain_id: Hash256) -> Self {
        Self {
            secret,
            chain_id,
            decisions: BTreeMap::new(),
        }
    }

    pub fn attest(
        &mut self,
        committee: &Committee,
        seat: u16,
        statement: &AvailabilityStatement,
        blob: &[u8],
    ) -> Result<AvailabilityVote, AvailabilityError> {
        if statement.chain_id != self.chain_id {
            return Err(AvailabilityError::WrongChain);
        }
        validate_statement(committee, statement)?;
        let committee_seat = committee.seat(seat).ok_or(AvailabilityError::UnknownSeat)?;
        if committee_seat.public_key != self.secret.public_key() {
            return Err(AvailabilityError::WrongSigner);
        }
        let actual = describe_blob(blob, statement.blob.chunk_size)
            .map_err(|_| AvailabilityError::BlobMismatch)?;
        if actual != statement.blob {
            return Err(AvailabilityError::BlobMismatch);
        }
        let digest = statement.digest();
        let decision_key = (statement.epoch, statement.blob.object_hash);
        if let Some(previous) = self.decisions.get(&decision_key) {
            if *previous != digest {
                return Err(AvailabilityError::ConflictingAttestation);
            }
        } else {
            self.decisions.insert(decision_key, digest);
        }
        Ok(AvailabilityVote {
            seat,
            signature: self.secret.sign(digest.as_bytes()),
        })
    }
}

impl AvailabilityCertificate {
    pub fn verify(
        &self,
        committee: &Committee,
        expected_chain_id: Hash256,
        at_height: u64,
    ) -> Result<(), AvailabilityError> {
        if self.statement.chain_id != expected_chain_id {
            return Err(AvailabilityError::WrongChain);
        }
        validate_statement(committee, &self.statement)?;
        if at_height < self.statement.published_height
            || at_height > self.statement.retain_until_height
        {
            return Err(AvailabilityError::InvalidRetention);
        }
        if self.votes.len() < committee.quorum() || self.votes.len() > committee.seats.len() {
            return Err(AvailabilityError::NoQuorum);
        }
        let digest = self.statement.digest();
        let mut seats = BTreeSet::new();
        for vote in &self.votes {
            if !seats.insert(vote.seat) {
                return Err(AvailabilityError::DuplicateSeat);
            }
            let seat = committee
                .seat(vote.seat)
                .ok_or(AvailabilityError::UnknownSeat)?;
            seat.public_key
                .verify(digest.as_bytes(), &vote.signature)
                .map_err(|_| AvailabilityError::InvalidSignature)?;
        }
        Ok(())
    }
}

fn validate_statement(
    committee: &Committee,
    statement: &AvailabilityStatement,
) -> Result<(), AvailabilityError> {
    let target_epoch = committee
        .source_epoch
        .checked_add(1)
        .ok_or(AvailabilityError::WrongCommittee)?;
    if statement.epoch != target_epoch || statement.committee_id != committee.id() {
        return Err(AvailabilityError::WrongCommittee);
    }
    if statement.retain_until_height <= statement.published_height {
        return Err(AvailabilityError::InvalidRetention);
    }
    Ok(())
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
    use hyphen_state::MIN_BLOB_CHUNK_SIZE;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn fixture() -> (
        Committee,
        BTreeMap<[u8; 32], HonestAvailabilityVoter>,
        Vec<u8>,
    ) {
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
        let voters = secrets
            .into_iter()
            .map(|secret| {
                (
                    *secret.public_key().as_bytes(),
                    HonestAvailabilityVoter::new(secret, hash(0x11)),
                )
            })
            .collect();
        (committee, voters, vec![0x5a; 9000])
    }

    #[test]
    fn quorum_only_forms_after_every_signer_checks_the_blob() {
        let (committee, mut voters, blob) = fixture();
        let statement = AvailabilityStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            published_height: 100,
            retain_until_height: 200,
            blob: describe_blob(&blob, MIN_BLOB_CHUNK_SIZE).unwrap(),
        };
        let votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .attest(&committee, seat.index, &statement, &blob)
                    .unwrap()
            })
            .collect();
        AvailabilityCertificate { statement, votes }
            .verify(&committee, hash(0x11), 150)
            .unwrap();
    }

    #[test]
    fn wrong_blob_expiry_and_duplicate_seat_fail() {
        let (committee, mut voters, blob) = fixture();
        let statement = AvailabilityStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            published_height: 100,
            retain_until_height: 200,
            blob: describe_blob(&blob, MIN_BLOB_CHUNK_SIZE).unwrap(),
        };
        let first_seat = committee.seats[0];
        assert_eq!(
            voters
                .get_mut(first_seat.public_key.as_bytes())
                .unwrap()
                .attest(&committee, first_seat.index, &statement, &[1, 2, 3]),
            Err(AvailabilityError::BlobMismatch)
        );
        let vote = voters
            .get_mut(first_seat.public_key.as_bytes())
            .unwrap()
            .attest(&committee, first_seat.index, &statement, &blob)
            .unwrap();
        let certificate = AvailabilityCertificate {
            statement,
            votes: vec![vote; committee.quorum()],
        };
        assert_eq!(
            certificate.verify(&committee, hash(0x11), 201),
            Err(AvailabilityError::InvalidRetention)
        );
        assert_eq!(
            certificate.verify(&committee, hash(0x11), 150),
            Err(AvailabilityError::DuplicateSeat)
        );
    }
}
