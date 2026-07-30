//! Visible-domain order-fairness reference model for private transactions.
//!
//! The ordering function receives only an explicit public projection and
//! signed reception sequences. It cannot claim fairness for hidden amounts,
//! parties or semantics. This module is not active consensus.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{Hash256, SecretKey, Signature};
use thiserror::Error;

use crate::fast_ordering::Committee;

const OBSERVATION_VERSION: u8 = 0;
const MAX_VISIBLE_TRANSACTIONS: usize = 1024;
const MAX_PAIRWISE_COMPARISONS: usize = 8_000_000;
const D_METADATA: &[u8] = b"HYPHEN_PRIVATE_FAIR_METADATA_V0";
const D_METADATA_ROOT: &[u8] = b"HYPHEN_PRIVATE_FAIR_METADATA_ROOT_V0";
const D_OBSERVATION: &[u8] = b"HYPHEN_PRIVATE_FAIR_OBSERVATION_V0";
const D_EVIDENCE_ROOT: &[u8] = b"HYPHEN_PRIVATE_FAIR_EVIDENCE_ROOT_V0";
const D_TIE_BREAK: &[u8] = b"HYPHEN_PRIVATE_FAIR_TIE_BREAK_V0";
const D_ORDER_ROOT: &[u8] = b"HYPHEN_PRIVATE_FAIR_ORDER_ROOT_V0";

/// Complete public projection admitted by this fairness profile.
///
/// `conflict_tag` may contain a public nullifier/conflict class. It must never
/// contain a sender, receiver, amount or plaintext application payload unless
/// a future profile explicitly declares that leakage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VisibleMetadata {
    pub transaction_id: Hash256,
    pub fee_class: u32,
    pub encoded_len: u32,
    pub conflict_tag: Hash256,
}

impl VisibleMetadata {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(72);
        bytes.extend_from_slice(self.transaction_id.as_bytes());
        bytes.extend_from_slice(&self.fee_class.to_be_bytes());
        bytes.extend_from_slice(&self.encoded_len.to_be_bytes());
        bytes.extend_from_slice(self.conflict_tag.as_bytes());
        bytes
    }

    pub fn hash(&self) -> Hash256 {
        hash_parts(D_METADATA, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceptionStatement {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub committee_id: Hash256,
    pub view: u64,
    pub slot: u64,
    pub cutoff: u64,
    pub seat: u16,
    pub metadata_root: Hash256,
    /// Transaction IDs in the observer's authenticated local receive order.
    pub sequence: Vec<Hash256>,
}

impl ReceptionStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FairOrderingError> {
        if self.sequence.len() > MAX_VISIBLE_TRANSACTIONS {
            return Err(FairOrderingError::TooManyTransactions);
        }
        let count = u16::try_from(self.sequence.len())
            .map_err(|_| FairOrderingError::TooManyTransactions)?;
        let mut bytes = Vec::with_capacity(131 + self.sequence.len() * 32);
        bytes.push(OBSERVATION_VERSION);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.committee_id.as_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.extend_from_slice(&self.cutoff.to_be_bytes());
        bytes.extend_from_slice(&self.seat.to_be_bytes());
        bytes.extend_from_slice(self.metadata_root.as_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for transaction_id in &self.sequence {
            bytes.extend_from_slice(transaction_id.as_bytes());
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<Hash256, FairOrderingError> {
        Ok(hash_parts(D_OBSERVATION, &[&self.canonical_bytes()?]))
    }
}

#[derive(Clone, Debug)]
pub struct ReceptionObservation {
    pub statement: ReceptionStatement,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FairBatch {
    pub transactions: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleFairOrder {
    pub metadata_root: Hash256,
    pub evidence_root: Hash256,
    pub batches: Vec<FairBatch>,
    pub order_root: Hash256,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FairOrderingError {
    #[error("visible metadata set is empty")]
    EmptyMetadata,
    #[error("visible transaction bound exceeded")]
    TooManyTransactions,
    #[error("visible metadata contains a duplicate transaction ID")]
    DuplicateTransaction,
    #[error("fairness evidence does not contain a committee quorum")]
    NoObservationQuorum,
    #[error("fairness evidence repeats a committee seat")]
    DuplicateSeat,
    #[error("one work identity reported conflicting receive orders across its seats")]
    ConflictingOperatorObservation,
    #[error("fairness evidence references an unknown committee seat")]
    UnknownSeat,
    #[error("fairness evidence is bound to another chain, epoch, view or slot")]
    WrongContext,
    #[error("fairness evidence names a different visible metadata root")]
    WrongMetadataRoot,
    #[error("fairness evidence contains an unknown or duplicate transaction")]
    InvalidSequence,
    #[error("fairness evidence signature is invalid")]
    InvalidSignature,
    #[error("pairwise fairness work exceeds the deterministic protocol budget")]
    WorkBudgetExceeded,
    #[error("tie-break seed is unavailable")]
    MissingTieBreakSeed,
    #[error("secret key does not own the observation seat")]
    WrongObserver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FairOrderingContext {
    pub chain_id: Hash256,
    pub epoch: u64,
    pub view: u64,
    pub slot: u64,
    pub cutoff: u64,
    /// Unbiasable seed fixed only after the reception cutoff.
    pub tie_break_seed: Hash256,
}

pub fn visible_metadata_root(metadata: &[VisibleMetadata]) -> Result<Hash256, FairOrderingError> {
    let sorted = canonical_metadata(metadata)?;
    let mut bytes = Vec::with_capacity(4 + sorted.len() * 64);
    bytes.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for item in sorted {
        bytes.extend_from_slice(item.transaction_id.as_bytes());
        bytes.extend_from_slice(item.hash().as_bytes());
    }
    Ok(hash_parts(D_METADATA_ROOT, &[&bytes]))
}

pub fn sign_reception(
    secret: &SecretKey,
    committee: &Committee,
    statement: ReceptionStatement,
) -> Result<ReceptionObservation, FairOrderingError> {
    let seat = committee
        .seat(statement.seat)
        .ok_or(FairOrderingError::UnknownSeat)?;
    if seat.public_key != secret.public_key() {
        return Err(FairOrderingError::WrongObserver);
    }
    let digest = statement.digest()?;
    Ok(ReceptionObservation {
        statement,
        signature: secret.sign(digest.as_bytes()),
    })
}

/// Builds strong receive-order evidence over the declared visible domain.
///
/// A transaction is eligible only when at least `2f+1` distinct sampled seats
/// report it. An edge `x -> y` exists only when at least `2f+1` seats report x
/// before y. Cycles become one batch; no arbitrary linear order is presented as
/// a fairness guarantee. The deterministic order inside a batch uses a seed
/// fixed after cutoff and is outside the pairwise fairness claim.
pub fn build_visible_fair_order(
    committee: &Committee,
    context: FairOrderingContext,
    metadata: &[VisibleMetadata],
    observations: &[ReceptionObservation],
) -> Result<VisibleFairOrder, FairOrderingError> {
    if context.tie_break_seed == Hash256::from_bytes([0; 32]) {
        return Err(FairOrderingError::MissingTieBreakSeed);
    }
    let sorted_metadata = canonical_metadata(metadata)?;
    let metadata_root = visible_metadata_root(&sorted_metadata)?;
    let verified = verify_observations(
        committee,
        context,
        metadata_root,
        &sorted_metadata,
        observations,
    )?;
    let quorum = committee.quorum();
    let mut appearances = BTreeMap::<Hash256, usize>::new();
    for observation in &verified {
        for transaction_id in &observation.statement.sequence {
            *appearances.entry(*transaction_id).or_default() += 1;
        }
    }
    let eligible = sorted_metadata
        .iter()
        .filter(|item| appearances.get(&item.transaction_id).copied().unwrap_or(0) >= quorum)
        .map(|item| item.transaction_id)
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Err(FairOrderingError::NoObservationQuorum);
    }
    let pair_work = verified
        .len()
        .checked_mul(eligible.len())
        .and_then(|value| value.checked_mul(eligible.len().saturating_sub(1)))
        .ok_or(FairOrderingError::WorkBudgetExceeded)?;
    if pair_work > MAX_PAIRWISE_COMPARISONS {
        return Err(FairOrderingError::WorkBudgetExceeded);
    }

    let positions = verified
        .iter()
        .map(|observation| {
            observation
                .statement
                .sequence
                .iter()
                .enumerate()
                .map(|(position, transaction_id)| (*transaction_id, position))
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    let mut adjacency = vec![BTreeSet::<usize>::new(); eligible.len()];
    for left in 0..eligible.len() {
        for right in 0..eligible.len() {
            if left == right {
                continue;
            }
            let before = positions
                .iter()
                .filter(|position| {
                    let Some(left_position) = position.get(&eligible[left]) else {
                        return false;
                    };
                    let Some(right_position) = position.get(&eligible[right]) else {
                        return false;
                    };
                    left_position < right_position
                })
                .count();
            if before >= quorum {
                adjacency[left].insert(right);
            }
        }
    }

    let components = strongly_connected_components(&adjacency);
    let batches =
        canonical_component_order(&eligible, &adjacency, &components, context.tie_break_seed);
    let evidence_root = evidence_root(&verified)?;
    let order_root = order_root(metadata_root, evidence_root, &batches);
    Ok(VisibleFairOrder {
        metadata_root,
        evidence_root,
        batches,
        order_root,
    })
}

fn canonical_metadata(
    metadata: &[VisibleMetadata],
) -> Result<Vec<VisibleMetadata>, FairOrderingError> {
    if metadata.is_empty() {
        return Err(FairOrderingError::EmptyMetadata);
    }
    if metadata.len() > MAX_VISIBLE_TRANSACTIONS {
        return Err(FairOrderingError::TooManyTransactions);
    }
    let mut sorted = metadata.to_vec();
    sorted.sort_by_key(|item| item.transaction_id);
    if sorted
        .windows(2)
        .any(|pair| pair[0].transaction_id == pair[1].transaction_id)
    {
        return Err(FairOrderingError::DuplicateTransaction);
    }
    Ok(sorted)
}

fn verify_observations(
    committee: &Committee,
    context: FairOrderingContext,
    metadata_root: Hash256,
    metadata: &[VisibleMetadata],
    observations: &[ReceptionObservation],
) -> Result<Vec<ReceptionObservation>, FairOrderingError> {
    if observations.len() < committee.quorum() || observations.len() > committee.seats.len() {
        return Err(FairOrderingError::NoObservationQuorum);
    }
    let known = metadata
        .iter()
        .map(|item| item.transaction_id)
        .collect::<BTreeSet<_>>();
    let target_epoch = committee
        .source_epoch
        .checked_add(1)
        .ok_or(FairOrderingError::WrongContext)?;
    let mut seen_seats = BTreeSet::new();
    let mut sequence_by_key = BTreeMap::<[u8; 32], Vec<Hash256>>::new();
    let mut verified = observations.to_vec();
    verified.sort_by_key(|observation| observation.statement.seat);
    for observation in &verified {
        let statement = &observation.statement;
        if statement.chain_id != context.chain_id
            || statement.epoch != context.epoch
            || statement.epoch != target_epoch
            || statement.committee_id != committee.id()
            || statement.view != context.view
            || statement.slot != context.slot
            || statement.cutoff != context.cutoff
        {
            return Err(FairOrderingError::WrongContext);
        }
        if statement.metadata_root != metadata_root {
            return Err(FairOrderingError::WrongMetadataRoot);
        }
        if !seen_seats.insert(statement.seat) {
            return Err(FairOrderingError::DuplicateSeat);
        }
        let seat = committee
            .seat(statement.seat)
            .ok_or(FairOrderingError::UnknownSeat)?;
        if let Some(previous) = sequence_by_key.get(seat.public_key.as_bytes()) {
            if previous != &statement.sequence {
                return Err(FairOrderingError::ConflictingOperatorObservation);
            }
        } else {
            sequence_by_key.insert(*seat.public_key.as_bytes(), statement.sequence.clone());
        }
        let mut seen_transactions = BTreeSet::new();
        if statement.sequence.is_empty()
            || statement.sequence.len() > MAX_VISIBLE_TRANSACTIONS
            || statement.sequence.iter().any(|transaction_id| {
                !known.contains(transaction_id) || !seen_transactions.insert(*transaction_id)
            })
        {
            return Err(FairOrderingError::InvalidSequence);
        }
        seat.public_key
            .verify(statement.digest()?.as_bytes(), &observation.signature)
            .map_err(|_| FairOrderingError::InvalidSignature)?;
    }
    Ok(verified)
}

fn strongly_connected_components(adjacency: &[BTreeSet<usize>]) -> Vec<Vec<usize>> {
    fn visit(
        node: usize,
        adjacency: &[BTreeSet<usize>],
        visited: &mut [bool],
        order: &mut Vec<usize>,
    ) {
        if visited[node] {
            return;
        }
        visited[node] = true;
        for next in &adjacency[node] {
            visit(*next, adjacency, visited, order);
        }
        order.push(node);
    }

    fn collect(
        node: usize,
        reverse: &[BTreeSet<usize>],
        assigned: &mut [bool],
        component: &mut Vec<usize>,
    ) {
        if assigned[node] {
            return;
        }
        assigned[node] = true;
        component.push(node);
        for next in &reverse[node] {
            collect(*next, reverse, assigned, component);
        }
    }

    let mut visited = vec![false; adjacency.len()];
    let mut order = Vec::with_capacity(adjacency.len());
    for node in 0..adjacency.len() {
        visit(node, adjacency, &mut visited, &mut order);
    }
    let mut reverse = vec![BTreeSet::new(); adjacency.len()];
    for (source, targets) in adjacency.iter().enumerate() {
        for target in targets {
            reverse[*target].insert(source);
        }
    }
    let mut assigned = vec![false; adjacency.len()];
    let mut components = Vec::new();
    while let Some(node) = order.pop() {
        if assigned[node] {
            continue;
        }
        let mut component = Vec::new();
        collect(node, &reverse, &mut assigned, &mut component);
        component.sort_unstable();
        components.push(component);
    }
    components
}

fn canonical_component_order(
    transactions: &[Hash256],
    adjacency: &[BTreeSet<usize>],
    components: &[Vec<usize>],
    tie_break_seed: Hash256,
) -> Vec<FairBatch> {
    let mut component_of = vec![0usize; transactions.len()];
    for (component_index, component) in components.iter().enumerate() {
        for node in component {
            component_of[*node] = component_index;
        }
    }
    let mut edges = vec![BTreeSet::<usize>::new(); components.len()];
    let mut indegree = vec![0usize; components.len()];
    for (source, targets) in adjacency.iter().enumerate() {
        for target in targets {
            let left = component_of[source];
            let right = component_of[*target];
            if left != right && edges[left].insert(right) {
                indegree[right] += 1;
            }
        }
    }
    let rank = |transaction_id: Hash256| {
        hash_parts(
            D_TIE_BREAK,
            &[tie_break_seed.as_bytes(), transaction_id.as_bytes()],
        )
    };
    let mut available = BTreeSet::<(Hash256, usize)>::new();
    for (index, component) in components.iter().enumerate() {
        if indegree[index] == 0 {
            let component_rank = component
                .iter()
                .map(|node| rank(transactions[*node]))
                .min()
                .expect("component is nonempty");
            available.insert((component_rank, index));
        }
    }
    let mut batches = Vec::with_capacity(components.len());
    while let Some((_, component_index)) = available.pop_first() {
        let mut batch = components[component_index]
            .iter()
            .map(|node| transactions[*node])
            .collect::<Vec<_>>();
        batch.sort_by_key(|transaction_id| (rank(*transaction_id), *transaction_id));
        batches.push(FairBatch {
            transactions: batch,
        });
        for target in &edges[component_index] {
            indegree[*target] -= 1;
            if indegree[*target] == 0 {
                let target_rank = components[*target]
                    .iter()
                    .map(|node| rank(transactions[*node]))
                    .min()
                    .expect("component is nonempty");
                available.insert((target_rank, *target));
            }
        }
    }
    debug_assert_eq!(batches.len(), components.len());
    batches
}

fn evidence_root(observations: &[ReceptionObservation]) -> Result<Hash256, FairOrderingError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(observations.len() as u16).to_be_bytes());
    for observation in observations {
        bytes.extend_from_slice(observation.statement.digest()?.as_bytes());
        bytes.extend_from_slice(observation.signature.as_bytes());
    }
    Ok(hash_parts(D_EVIDENCE_ROOT, &[&bytes]))
}

fn order_root(metadata_root: Hash256, evidence_root: Hash256, batches: &[FairBatch]) -> Hash256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(metadata_root.as_bytes());
    bytes.extend_from_slice(evidence_root.as_bytes());
    bytes.extend_from_slice(&(batches.len() as u16).to_be_bytes());
    for batch in batches {
        bytes.extend_from_slice(&(batch.transactions.len() as u16).to_be_bytes());
        for transaction_id in &batch.transactions {
            bytes.extend_from_slice(transaction_id.as_bytes());
        }
    }
    hash_parts(D_ORDER_ROOT, &[&bytes])
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
    use crate::fast_ordering::WorkContribution;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn committee_fixture() -> (Committee, BTreeMap<[u8; 32], SecretKey>) {
        let secrets = (1..=4u8)
            .map(|byte| SecretKey([byte; 32]))
            .collect::<Vec<_>>();
        let contributions = secrets
            .iter()
            .map(|secret| WorkContribution {
                public_key: secret.public_key(),
                work: 1,
            })
            .collect::<Vec<_>>();
        let committee = (1..=u8::MAX)
            .map(|seed| Committee::from_finalized_work(8, hash(seed), 1, &contributions).unwrap())
            .find(|candidate| {
                candidate
                    .seats
                    .iter()
                    .map(|seat| *seat.public_key.as_bytes())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == candidate.seats.len()
            })
            .expect("a deterministic seed with four distinct identities must exist");
        let by_key = secrets
            .into_iter()
            .map(|secret| (*secret.public_key().as_bytes(), secret))
            .collect();
        (committee, by_key)
    }

    fn metadata(ids: &[u8]) -> Vec<VisibleMetadata> {
        ids.iter()
            .map(|byte| VisibleMetadata {
                transaction_id: hash(*byte),
                fee_class: 1,
                encoded_len: 512,
                conflict_tag: hash(0),
            })
            .collect()
    }

    fn context() -> FairOrderingContext {
        FairOrderingContext {
            chain_id: hash(1),
            epoch: 9,
            view: 2,
            slot: 3,
            cutoff: 100,
            tie_break_seed: hash(10),
        }
    }

    fn observations(
        committee: &Committee,
        secrets: &BTreeMap<[u8; 32], SecretKey>,
        metadata: &[VisibleMetadata],
        sequences: &[Vec<Hash256>],
    ) -> Vec<ReceptionObservation> {
        let root = visible_metadata_root(metadata).unwrap();
        committee
            .seats
            .iter()
            .zip(sequences.iter())
            .map(|(seat, sequence)| {
                let statement = ReceptionStatement {
                    chain_id: context().chain_id,
                    epoch: context().epoch,
                    committee_id: committee.id(),
                    view: context().view,
                    slot: context().slot,
                    cutoff: context().cutoff,
                    seat: seat.index,
                    metadata_root: root,
                    sequence: sequence.clone(),
                };
                sign_reception(
                    secrets.get(seat.public_key.as_bytes()).unwrap(),
                    committee,
                    statement,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn quorum_receive_order_creates_a_strict_batch_precedence() {
        let (committee, secrets) = committee_fixture();
        let metadata = metadata(&[11, 12]);
        let x = hash(11);
        let y = hash(12);
        let evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![x, y], vec![x, y], vec![y, x]],
        );
        let result = build_visible_fair_order(&committee, context(), &metadata, &evidence).unwrap();
        assert_eq!(result.batches.len(), 2);
        assert_eq!(result.batches[0].transactions, vec![x]);
        assert_eq!(result.batches[1].transactions, vec![y]);
    }

    #[test]
    fn cyclic_strong_evidence_is_reported_as_one_fair_batch() {
        let (committee, secrets) = committee_fixture();
        let metadata = metadata(&[11, 12, 13, 14]);
        let a = hash(11);
        let b = hash(12);
        let c = hash(13);
        let d = hash(14);
        let evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[
                vec![b, c, d, a],
                vec![c, d, a, b],
                vec![d, a, b, c],
                vec![a, b, c, d],
            ],
        );
        let result = build_visible_fair_order(&committee, context(), &metadata, &evidence).unwrap();
        assert_eq!(result.batches.len(), 1);
        assert_eq!(result.batches[0].transactions.len(), 4);
    }

    #[test]
    fn input_permutations_do_not_change_the_committed_order() {
        let (committee, secrets) = committee_fixture();
        let metadata = metadata(&[11, 12]);
        let x = hash(11);
        let y = hash(12);
        let mut evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![x, y], vec![x, y], vec![y, x]],
        );
        let expected =
            build_visible_fair_order(&committee, context(), &metadata, &evidence).unwrap();
        evidence.reverse();
        let mut reversed_metadata = metadata.clone();
        reversed_metadata.reverse();
        let actual =
            build_visible_fair_order(&committee, context(), &reversed_metadata, &evidence).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn forged_or_duplicate_observations_are_rejected() {
        let (committee, secrets) = committee_fixture();
        let metadata = metadata(&[11, 12]);
        let x = hash(11);
        let y = hash(12);
        let mut evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![x, y], vec![x, y], vec![y, x]],
        );
        evidence[0].signature.0[0] ^= 1;
        assert_eq!(
            build_visible_fair_order(&committee, context(), &metadata, &evidence),
            Err(FairOrderingError::InvalidSignature)
        );

        let mut evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![x, y], vec![x, y], vec![y, x]],
        );
        evidence[1] = evidence[0].clone();
        assert_eq!(
            build_visible_fair_order(&committee, context(), &metadata, &evidence),
            Err(FairOrderingError::DuplicateSeat)
        );
    }

    #[test]
    fn one_work_identity_cannot_report_different_orders_per_seat() {
        let secret = SecretKey([42; 32]);
        let committee = Committee::from_finalized_work(
            8,
            hash(9),
            1,
            &[WorkContribution {
                public_key: secret.public_key(),
                work: 1,
            }],
        )
        .unwrap();
        let secrets = BTreeMap::from([(*secret.public_key().as_bytes(), secret)]);
        let metadata = metadata(&[11, 12]);
        let x = hash(11);
        let y = hash(12);
        let evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![y, x], vec![x, y], vec![x, y]],
        );
        assert_eq!(
            build_visible_fair_order(&committee, context(), &metadata, &evidence),
            Err(FairOrderingError::ConflictingOperatorObservation)
        );
    }

    #[test]
    fn reference_vector_is_stable() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/h-private-fair-ordering-v0.json"
        ))
        .unwrap();
        assert_eq!(vector["schema"], "hyphen-private-fair-ordering-vector-v0");

        let secrets = (1..=4u8)
            .map(|byte| SecretKey([byte; 32]))
            .collect::<Vec<_>>();
        let contributions = secrets
            .iter()
            .map(|secret| WorkContribution {
                public_key: secret.public_key(),
                work: 1,
            })
            .collect::<Vec<_>>();
        let committee = Committee::from_finalized_work(8, hash(6), 1, &contributions).unwrap();
        let secrets = secrets
            .into_iter()
            .map(|secret| (*secret.public_key().as_bytes(), secret))
            .collect::<BTreeMap<_, _>>();
        let metadata = metadata(&[11, 12]);
        let x = hash(11);
        let y = hash(12);
        let evidence = observations(
            &committee,
            &secrets,
            &metadata,
            &[vec![x, y], vec![x, y], vec![x, y], vec![y, x]],
        );
        let result = build_visible_fair_order(&committee, context(), &metadata, &evidence).unwrap();

        assert_eq!(
            committee.id().to_string(),
            vector["committee"]["committee_id"]
        );
        for (seat, expected) in committee
            .seats
            .iter()
            .zip(vector["committee"]["seat_public_keys"].as_array().unwrap())
        {
            assert_eq!(
                hex::encode(seat.public_key.as_bytes()),
                expected.as_str().unwrap()
            );
        }
        assert_eq!(result.metadata_root.to_string(), vector["metadata_root"]);
        for (observation, expected) in evidence
            .iter()
            .zip(vector["observations"].as_array().unwrap())
        {
            assert_eq!(
                hex::encode(observation.statement.canonical_bytes().unwrap()),
                expected["canonical_encoding"].as_str().unwrap()
            );
            assert_eq!(
                observation.statement.digest().unwrap().to_string(),
                expected["digest"]
            );
            assert_eq!(
                hex::encode(observation.signature.as_bytes()),
                expected["signature"].as_str().unwrap()
            );
        }
        assert_eq!(result.evidence_root.to_string(), vector["evidence_root"]);
        assert_eq!(result.order_root.to_string(), vector["order_root"]);
        let batches = result
            .batches
            .iter()
            .map(|batch| {
                batch
                    .transactions
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            batches,
            serde_json::from_value::<Vec<Vec<String>>>(vector["batches"].clone()).unwrap()
        );
    }
}
