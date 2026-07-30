//! Reference safety kernel for Hyphen Fast Ordering Certificates (H-FOC).
//!
//! A certificate is an optimistic preorder, not unconditional finality. The
//! 100 ms figure is a benchmark target and is not enforced or implied by this
//! state machine. Committee work must come from a previously finalized PoW
//! epoch; this module does not decide which epoch is final.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{Hash256, PublicKey, SecretKey, Signature};
use thiserror::Error;

const STATEMENT_VERSION: u8 = 0;
const D_COMMITTEE_SAMPLE: &[u8] = b"HYPHEN_FOC_COMMITTEE_SAMPLE_V0";
const D_COMMITTEE_ID: &[u8] = b"HYPHEN_FOC_COMMITTEE_ID_V0";
const D_STATEMENT: &[u8] = b"HYPHEN_FOC_ORDER_STATEMENT_V0";
const MAX_COMMITTEE_SEATS: u16 = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkContribution {
    pub public_key: PublicKey,
    /// Independently verified cumulative PoW for this identity in the source
    /// epoch. Repeated public keys are aggregated before sampling.
    pub work: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeSeat {
    pub index: u16,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committee {
    pub source_epoch: u64,
    pub seed: Hash256,
    pub f: u16,
    pub seats: Vec<CommitteeSeat>,
    id: Hash256,
}

impl Committee {
    /// Samples `n = 3f+1` seats with replacement, proportional to verified
    /// prior-epoch work. Repeated keys represent repeated work-weighted seats,
    /// not independent operators.
    pub fn from_finalized_work(
        source_epoch: u64,
        seed: Hash256,
        f: u16,
        contributions: &[WorkContribution],
    ) -> Result<Self, FastOrderingError> {
        source_epoch
            .checked_add(1)
            .ok_or(FastOrderingError::EpochOverflow)?;
        let seat_count = f
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
            .ok_or(FastOrderingError::InvalidCommitteeSize)?;
        if seat_count == 0 || seat_count > MAX_COMMITTEE_SEATS {
            return Err(FastOrderingError::InvalidCommitteeSize);
        }

        let mut work_by_key = BTreeMap::<[u8; 32], u128>::new();
        for contribution in contributions {
            if contribution.work == 0 {
                return Err(FastOrderingError::ZeroWork);
            }
            let total = work_by_key
                .entry(*contribution.public_key.as_bytes())
                .or_default();
            *total = total
                .checked_add(contribution.work)
                .ok_or(FastOrderingError::WorkOverflow)?;
        }
        if work_by_key.is_empty() {
            return Err(FastOrderingError::EmptyWorkSet);
        }
        let total_work = work_by_key.values().try_fold(0u128, |sum, work| {
            sum.checked_add(*work)
                .ok_or(FastOrderingError::WorkOverflow)
        })?;

        let weighted = work_by_key.into_iter().collect::<Vec<_>>();
        let mut seats = Vec::with_capacity(seat_count as usize);
        for index in 0..seat_count {
            let target = sample_below(seed, source_epoch, index, total_work);
            let mut cumulative = 0u128;
            let mut selected = None;
            for (key, work) in &weighted {
                cumulative = cumulative
                    .checked_add(*work)
                    .ok_or(FastOrderingError::WorkOverflow)?;
                if target < cumulative {
                    selected = Some(PublicKey(*key));
                    break;
                }
            }
            seats.push(CommitteeSeat {
                index,
                public_key: selected.expect("sample is below total work"),
            });
        }
        let id = committee_id(source_epoch, seed, f, &seats);
        Ok(Self {
            source_epoch,
            seed,
            f,
            seats,
            id,
        })
    }

    pub fn id(&self) -> Hash256 {
        self.id
    }

    pub fn quorum(&self) -> usize {
        (2 * self.f + 1) as usize
    }

    pub fn seat(&self, index: u16) -> Option<&CommitteeSeat> {
        self.seats
            .get(index as usize)
            .filter(|seat| seat.index == index)
    }

    pub fn verify_certificate(
        &self,
        expected_chain_id: Hash256,
        certificate: &OrderingCertificate,
    ) -> Result<(), FastOrderingError> {
        let statement = &certificate.statement;
        if statement.chain_id != expected_chain_id {
            return Err(FastOrderingError::WrongChain);
        }
        let target_epoch = self
            .source_epoch
            .checked_add(1)
            .ok_or(FastOrderingError::EpochOverflow)?;
        if statement.committee_id != self.id || statement.epoch != target_epoch {
            return Err(FastOrderingError::WrongCommittee);
        }
        if certificate.votes.len() < self.quorum() || certificate.votes.len() > self.seats.len() {
            return Err(FastOrderingError::NoQuorum);
        }
        let digest = statement.digest();
        let mut seen = BTreeSet::new();
        for vote in &certificate.votes {
            if !seen.insert(vote.seat) {
                return Err(FastOrderingError::DuplicateSeat);
            }
            let seat = self.seat(vote.seat).ok_or(FastOrderingError::UnknownSeat)?;
            seat.public_key
                .verify(digest.as_bytes(), &vote.signature)
                .map_err(|_| FastOrderingError::InvalidSignature)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderingStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub view: u64,
    pub slot: u64,
    pub parent_frontier: Hash256,
    pub order_root: Hash256,
}

impl OrderingStatement {
    /// Fixed-width encoding: version byte followed by unsigned big-endian
    /// integers and 32-byte hashes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(153);
        bytes.push(STATEMENT_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(self.parent_frontier.as_bytes());
        bytes.extend_from_slice(self.order_root.as_bytes());
        bytes
    }

    pub fn digest(&self) -> Hash256 {
        hash_parts(D_STATEMENT, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderingVote {
    pub seat: u16,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderingCertificate {
    pub statement: OrderingStatement,
    pub votes: Vec<OrderingVote>,
}

/// Per-operator guard. If one key owns several sampled seats, one decision is
/// reused for all of them and the operator cannot equivocate seat-by-seat.
pub struct HonestVoter {
    secret: SecretKey,
    chain_id: Hash256,
    decisions: BTreeMap<(u64, u64, u64), Hash256>,
}

impl HonestVoter {
    pub fn new(secret: SecretKey, chain_id: Hash256) -> Self {
        Self {
            secret,
            chain_id,
            decisions: BTreeMap::new(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret.public_key()
    }

    pub fn vote(
        &mut self,
        committee: &Committee,
        seat_index: u16,
        statement: &OrderingStatement,
    ) -> Result<OrderingVote, FastOrderingError> {
        if statement.chain_id != self.chain_id {
            return Err(FastOrderingError::WrongChain);
        }
        let seat = committee
            .seat(seat_index)
            .ok_or(FastOrderingError::UnknownSeat)?;
        if seat.public_key != self.public_key() || statement.committee_id != committee.id() {
            return Err(FastOrderingError::WrongVoter);
        }
        let digest = statement.digest();
        let context = (statement.epoch, statement.view, statement.slot);
        if let Some(previous) = self.decisions.get(&context) {
            if *previous != digest {
                return Err(FastOrderingError::Equivocation);
            }
        } else {
            self.decisions.insert(context, digest);
        }
        Ok(OrderingVote {
            seat: seat_index,
            signature: self.secret.sign(digest.as_bytes()),
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FastOrderingError {
    #[error("committee must have n=3f+1 seats within the protocol bound")]
    InvalidCommitteeSize,
    #[error("work set is empty")]
    EmptyWorkSet,
    #[error("work contribution must be nonzero")]
    ZeroWork,
    #[error("work total overflow")]
    WorkOverflow,
    #[error("source epoch has no representable successor")]
    EpochOverflow,
    #[error("ordering statement belongs to another chain")]
    WrongChain,
    #[error("statement names the wrong committee or epoch")]
    WrongCommittee,
    #[error("certificate does not contain 2f+1 distinct seats")]
    NoQuorum,
    #[error("certificate repeats a seat")]
    DuplicateSeat,
    #[error("certificate references an unknown seat")]
    UnknownSeat,
    #[error("certificate signature is invalid")]
    InvalidSignature,
    #[error("secret key does not own the requested seat")]
    WrongVoter,
    #[error("honest voter refuses a conflicting order in the same epoch/view/slot")]
    Equivocation,
}

/// Probability that more than `f` of `n` independently sampled seats are
/// adversarial, given adversarial finalized-work fraction `alpha`.
///
/// This is research instrumentation, not consensus arithmetic. Independence
/// and a static work fraction are explicit modeling assumptions.
pub fn committee_capture_probability(n: u16, f: u16, alpha: f64) -> Option<f64> {
    if n != f.checked_mul(3)?.checked_add(1)? || !(0.0..=1.0).contains(&alpha) {
        return None;
    }
    if alpha == 0.0 {
        return Some(0.0);
    }
    if alpha == 1.0 {
        return Some(1.0);
    }
    let n = n as usize;
    let mut log_factorial = vec![0.0; n + 1];
    for value in 2..=n {
        log_factorial[value] = log_factorial[value - 1] + (value as f64).ln();
    }
    let log_alpha = alpha.ln();
    let log_honest = (1.0 - alpha).ln();
    let log_terms = ((f as usize + 1)..=n)
        .map(|k| {
            log_factorial[n] - log_factorial[k] - log_factorial[n - k]
                + k as f64 * log_alpha
                + (n - k) as f64 * log_honest
        })
        .collect::<Vec<_>>();
    let max_log = log_terms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let scaled_sum = log_terms
        .iter()
        .map(|log_term| (log_term - max_log).exp())
        .sum::<f64>();
    Some((max_log.exp() * scaled_sum).clamp(0.0, 1.0))
}

fn sample_below(seed: Hash256, source_epoch: u64, seat: u16, upper: u128) -> u128 {
    let threshold = upper.wrapping_neg() % upper;
    let mut counter = 0u32;
    loop {
        let digest = hash_parts(
            D_COMMITTEE_SAMPLE,
            &[
                seed.as_bytes(),
                &source_epoch.to_be_bytes(),
                &seat.to_be_bytes(),
                &counter.to_be_bytes(),
            ],
        );
        let sample = u128::from_be_bytes(digest.as_bytes()[..16].try_into().expect("16 bytes"));
        if sample >= threshold {
            return sample % upper;
        }
        counter = counter.wrapping_add(1);
    }
}

fn committee_id(source_epoch: u64, seed: Hash256, f: u16, seats: &[CommitteeSeat]) -> Hash256 {
    let mut bytes = Vec::with_capacity(44 + seats.len() * 34);
    bytes.extend_from_slice(&source_epoch.to_be_bytes());
    bytes.extend_from_slice(seed.as_bytes());
    bytes.extend_from_slice(&f.to_be_bytes());
    bytes.extend_from_slice(&(seats.len() as u16).to_be_bytes());
    for seat in seats {
        bytes.extend_from_slice(&seat.index.to_be_bytes());
        bytes.extend_from_slice(seat.public_key.as_bytes());
    }
    hash_parts(D_COMMITTEE_ID, &[&bytes])
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let total_len = domain.len() + 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(total_len);
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

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn committee_and_voters() -> (Committee, BTreeMap<[u8; 32], HonestVoter>) {
        let secrets = [SecretKey([1; 32]), SecretKey([2; 32]), SecretKey([3; 32])];
        let work = secrets
            .iter()
            .map(|secret| WorkContribution {
                public_key: secret.public_key(),
                work: 100,
            })
            .collect::<Vec<_>>();
        let voters = secrets
            .into_iter()
            .map(|secret| {
                (
                    *secret.public_key().as_bytes(),
                    HonestVoter::new(secret, hash(0x11)),
                )
            })
            .collect();
        (
            Committee::from_finalized_work(8, hash(0x55), 1, &work).unwrap(),
            voters,
        )
    }

    fn statement(committee: &Committee, order: u8) -> OrderingStatement {
        OrderingStatement {
            chain_id: hash(0x11),
            epoch: 9,
            committee_id: committee.id(),
            view: 2,
            slot: 7,
            parent_frontier: hash(0x22),
            order_root: hash(order),
        }
    }

    fn certificate(
        committee: &Committee,
        voters: &mut BTreeMap<[u8; 32], HonestVoter>,
        statement: OrderingStatement,
    ) -> OrderingCertificate {
        let votes = committee
            .seats
            .iter()
            .take(committee.quorum())
            .map(|seat| {
                voters
                    .get_mut(seat.public_key.as_bytes())
                    .unwrap()
                    .vote(committee, seat.index, &statement)
                    .unwrap()
            })
            .collect();
        OrderingCertificate { statement, votes }
    }

    #[test]
    fn deterministic_work_sampling_aggregates_repeated_keys() {
        let key = SecretKey([9; 32]).public_key();
        let split = vec![
            WorkContribution {
                public_key: key,
                work: 40,
            },
            WorkContribution {
                public_key: key,
                work: 60,
            },
        ];
        let combined = vec![WorkContribution {
            public_key: key,
            work: 100,
        }];
        assert_eq!(
            Committee::from_finalized_work(1, hash(2), 2, &split).unwrap(),
            Committee::from_finalized_work(1, hash(2), 2, &combined).unwrap()
        );
    }

    #[test]
    fn valid_quorum_certificate_verifies_real_signatures() {
        let (committee, mut voters) = committee_and_voters();
        let certificate = certificate(&committee, &mut voters, statement(&committee, 0x33));
        assert_eq!(certificate.statement.canonical_bytes().len(), 153);
        committee
            .verify_certificate(hash(0x11), &certificate)
            .unwrap();
    }

    #[test]
    fn too_few_duplicate_and_tampered_votes_fail() {
        let (committee, mut voters) = committee_and_voters();
        let certificate = certificate(&committee, &mut voters, statement(&committee, 0x33));

        let mut too_few = certificate.clone();
        too_few.votes.truncate(committee.quorum() - 1);
        assert_eq!(
            committee.verify_certificate(hash(0x11), &too_few),
            Err(FastOrderingError::NoQuorum)
        );

        let mut duplicate = certificate.clone();
        duplicate.votes[1] = duplicate.votes[0];
        assert_eq!(
            committee.verify_certificate(hash(0x11), &duplicate),
            Err(FastOrderingError::DuplicateSeat)
        );

        let mut tampered = certificate;
        tampered.statement.order_root = hash(0x44);
        assert_eq!(
            committee.verify_certificate(hash(0x11), &tampered),
            Err(FastOrderingError::InvalidSignature)
        );
    }

    #[test]
    fn honest_operator_refuses_same_view_equivocation_across_its_seats() {
        let (committee, mut voters) = committee_and_voters();
        let first = statement(&committee, 0x33);
        let second = statement(&committee, 0x44);
        let seat = committee.seats[0];
        let voter = voters.get_mut(seat.public_key.as_bytes()).unwrap();
        voter.vote(&committee, seat.index, &first).unwrap();
        assert_eq!(
            voter.vote(&committee, seat.index, &second),
            Err(FastOrderingError::Equivocation)
        );
    }

    #[test]
    fn certificates_and_honest_voters_reject_cross_chain_replay() {
        let (committee, mut voters) = committee_and_voters();
        let certificate = certificate(&committee, &mut voters, statement(&committee, 0x33));
        assert_eq!(
            committee.verify_certificate(hash(0x12), &certificate),
            Err(FastOrderingError::WrongChain)
        );

        let mut wrong_chain_statement = statement(&committee, 0x33);
        wrong_chain_statement.chain_id = hash(0x12);
        let seat = committee.seats[0];
        assert_eq!(
            voters.get_mut(seat.public_key.as_bytes()).unwrap().vote(
                &committee,
                seat.index,
                &wrong_chain_statement
            ),
            Err(FastOrderingError::WrongChain)
        );
    }

    #[test]
    fn source_epoch_must_have_a_representable_target_epoch() {
        let contribution = WorkContribution {
            public_key: SecretKey([9; 32]).public_key(),
            work: 1,
        };
        assert_eq!(
            Committee::from_finalized_work(u64::MAX, hash(2), 0, &[contribution]),
            Err(FastOrderingError::EpochOverflow)
        );
    }

    #[test]
    fn quorum_intersection_bound_holds_exhaustively_for_small_committees() {
        for f in 1usize..=3 {
            let n = 3 * f + 1;
            let q = 2 * f + 1;
            let subsets = (0usize..(1usize << n))
                .filter(|mask| mask.count_ones() as usize == q)
                .collect::<Vec<_>>();
            for left in &subsets {
                for right in &subsets {
                    assert!((left & right).count_ones() as usize > f);
                }
            }
        }
    }

    #[test]
    fn capture_probability_exposes_the_work_fraction_assumption() {
        assert_eq!(committee_capture_probability(100, 33, 0.0), Some(0.0));
        assert_eq!(committee_capture_probability(100, 33, 1.0), Some(1.0));
        let probability = committee_capture_probability(100, 33, 0.25).unwrap();
        assert!(probability > 0.0 && probability < 1.0);
        assert!(committee_capture_probability(4096, 1365, 0.99).unwrap() > 0.999_999);
        assert_eq!(committee_capture_probability(11, 3, 0.25), None);
    }

    #[test]
    fn reference_statement_vector_is_stable() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/h-foc-v0.json")).unwrap();
        assert_eq!(vector["schema"], "hyphen-h-foc-vector-v0");
        let (committee, _) = committee_and_voters();
        let statement = statement(&committee, 0x33);
        assert_eq!(
            committee.id().to_string(),
            vector["committee"]["committee_id"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(statement.canonical_bytes()),
            vector["statement"]["canonical_encoding"].as_str().unwrap()
        );
        assert_eq!(
            statement.digest().to_string(),
            vector["statement"]["digest"].as_str().unwrap()
        );
        assert_eq!(committee.quorum() as u64, vector["committee"]["quorum"]);
    }
}
