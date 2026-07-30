//! Executable reference model for Hyphen Braided Fusion Mesh (H-BFM).
//!
//! This module is not active in `hyphen-devnet-v2`. Block identifiers are
//! opaque, prevalidated hashes: callers must verify canonical block encoding,
//! signatures/PoW and data availability before adding an ID to
//! `certified_blocks`. This model specifies frontier closure, lane invariants,
//! deterministic ordering and atomic conflict receipts.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::Hash256;
use thiserror::Error;

const D_FRONTIER: &[u8] = b"HYPHEN_BFM_FRONTIER_V0";
const D_ORDER: &[u8] = b"HYPHEN_BFM_ORDER_V0";
const D_RECEIPT: &[u8] = b"HYPHEN_BFM_RECEIPT_V0";
const D_RECEIPT_ROOT: &[u8] = b"HYPHEN_BFM_RECEIPT_ROOT_V0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierTip {
    Anchor(Hash256),
    Block(Hash256),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictKey {
    Nullifier(Hash256),
    StateKey(Hash256),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionTransaction {
    pub id: Hash256,
    /// Resources consumed by this transaction. Application is atomic: a
    /// transaction that conflicts on one claim consumes none of its claims.
    pub claims: Vec<ConflictKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionBlock {
    pub id: Hash256,
    pub epoch: u64,
    pub lane: u16,
    pub logical_round: u64,
    pub lane_parent: FrontierTip,
    pub braid_parents: Vec<Hash256>,
    pub transactions: Vec<FusionTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionInput {
    pub epoch: u64,
    pub lane_count: u16,
    pub previous_frontier: Vec<Hash256>,
    pub selected_frontier: Vec<FrontierTip>,
    pub blocks: Vec<FusionBlock>,
    /// IDs with a certificate accepted by the selected DA verifier.
    pub certified_blocks: BTreeSet<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub block_id: Hash256,
    pub tx_id: Hash256,
    pub success: bool,
    pub conflicts: Vec<ConflictKey>,
}

impl TransactionReceipt {
    fn hash(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(67 + self.conflicts.len() * 33);
        bytes.extend_from_slice(self.block_id.as_bytes());
        bytes.extend_from_slice(self.tx_id.as_bytes());
        bytes.push(u8::from(self.success));
        bytes.extend_from_slice(&(self.conflicts.len() as u16).to_be_bytes());
        for conflict in &self.conflicts {
            match conflict {
                ConflictKey::Nullifier(value) => {
                    bytes.push(1);
                    bytes.extend_from_slice(value.as_bytes());
                }
                ConflictKey::StateKey(value) => {
                    bytes.push(2);
                    bytes.extend_from_slice(value.as_bytes());
                }
            }
        }
        hash_parts(D_RECEIPT, &[&bytes])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionResult {
    pub frontier_commitment: Hash256,
    pub order_root: Hash256,
    pub receipt_root: Hash256,
    pub block_order: Vec<Hash256>,
    pub included_blocks: BTreeSet<Hash256>,
    pub excluded_blocks: BTreeSet<Hash256>,
    pub receipts: Vec<TransactionReceipt>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FusionError {
    #[error("lane count must be nonzero")]
    ZeroLanes,
    #[error("frontier length does not match lane count")]
    FrontierLength,
    #[error("duplicate block identifier")]
    DuplicateBlock,
    #[error("frontier selects a missing block")]
    MissingFrontierBlock,
    #[error("frontier selects a block from the wrong epoch or lane")]
    WrongFrontierBlock,
    #[error("frontier anchor differs from the previous frontier")]
    WrongAnchor,
    #[error("reachable block belongs to the wrong epoch or lane")]
    WrongBlockDomain,
    #[error("reachable block references a missing parent")]
    MissingParent,
    #[error("lane parent is not an earlier block in the same lane")]
    InvalidLaneParent,
    #[error("braid parent must be in another lane and not in a later round")]
    InvalidBraidParent,
    #[error("duplicate braid parent")]
    DuplicateBraidParent,
    #[error("frontier does not select one coherent chain per lane")]
    InconsistentFrontier,
    #[error("reachable block lacks a data-availability certificate")]
    UnavailableBlock,
    #[error("reachable graph contains a cycle")]
    Cycle,
    #[error("transaction repeats a claim")]
    DuplicateClaim,
    #[error("transaction identifier occurs more than once")]
    DuplicateTransaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    logical_round: u64,
    lane: u16,
    id: Hash256,
}

pub fn fuse_certified_frontier(input: &FusionInput) -> Result<FusionResult, FusionError> {
    validate_frontier_shape(input)?;
    let blocks = index_blocks(&input.blocks)?;
    validate_frontier_tips(input, &blocks)?;
    let included = reachable_closure(input, &blocks)?;
    validate_reachable(input, &blocks, &included)?;
    validate_lane_frontiers(input, &blocks, &included)?;
    let block_order = canonical_topological_order(&blocks, &included)?;
    let receipts = execute_conflicts(&blocks, &block_order)?;
    let excluded_blocks = blocks
        .keys()
        .filter(|id| !included.contains(id))
        .copied()
        .collect();

    Ok(FusionResult {
        frontier_commitment: frontier_commitment(input),
        order_root: list_commitment(D_ORDER, &block_order),
        receipt_root: receipt_commitment(&receipts),
        block_order,
        included_blocks: included,
        excluded_blocks,
        receipts,
    })
}

fn validate_frontier_shape(input: &FusionInput) -> Result<(), FusionError> {
    if input.lane_count == 0 {
        return Err(FusionError::ZeroLanes);
    }
    let lanes = input.lane_count as usize;
    if input.previous_frontier.len() != lanes || input.selected_frontier.len() != lanes {
        return Err(FusionError::FrontierLength);
    }
    Ok(())
}

fn index_blocks(blocks: &[FusionBlock]) -> Result<BTreeMap<Hash256, &FusionBlock>, FusionError> {
    let mut indexed = BTreeMap::new();
    for block in blocks {
        if indexed.insert(block.id, block).is_some() {
            return Err(FusionError::DuplicateBlock);
        }
    }
    Ok(indexed)
}

fn validate_frontier_tips(
    input: &FusionInput,
    blocks: &BTreeMap<Hash256, &FusionBlock>,
) -> Result<(), FusionError> {
    for (lane, tip) in input.selected_frontier.iter().enumerate() {
        match tip {
            FrontierTip::Anchor(anchor) => {
                if *anchor != input.previous_frontier[lane] {
                    return Err(FusionError::WrongAnchor);
                }
            }
            FrontierTip::Block(id) => {
                let block = blocks.get(id).ok_or(FusionError::MissingFrontierBlock)?;
                if block.epoch != input.epoch || block.lane as usize != lane {
                    return Err(FusionError::WrongFrontierBlock);
                }
            }
        }
    }
    Ok(())
}

fn reachable_closure(
    input: &FusionInput,
    blocks: &BTreeMap<Hash256, &FusionBlock>,
) -> Result<BTreeSet<Hash256>, FusionError> {
    let mut stack = input
        .selected_frontier
        .iter()
        .filter_map(|tip| match tip {
            FrontierTip::Anchor(_) => None,
            FrontierTip::Block(id) => Some(*id),
        })
        .collect::<Vec<_>>();
    let mut reachable = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let block = blocks.get(&id).ok_or(FusionError::MissingParent)?;
        if let FrontierTip::Block(parent) = block.lane_parent {
            if !blocks.contains_key(&parent) {
                return Err(FusionError::MissingParent);
            }
            stack.push(parent);
        }
        for parent in &block.braid_parents {
            if !blocks.contains_key(parent) {
                return Err(FusionError::MissingParent);
            }
            stack.push(*parent);
        }
    }
    Ok(reachable)
}

fn validate_reachable(
    input: &FusionInput,
    blocks: &BTreeMap<Hash256, &FusionBlock>,
    included: &BTreeSet<Hash256>,
) -> Result<(), FusionError> {
    for id in included {
        let block = blocks[id];
        if block.epoch != input.epoch || block.lane >= input.lane_count {
            return Err(FusionError::WrongBlockDomain);
        }
        if !input.certified_blocks.contains(id) {
            return Err(FusionError::UnavailableBlock);
        }
        match block.lane_parent {
            FrontierTip::Anchor(anchor) => {
                if anchor != input.previous_frontier[block.lane as usize] {
                    return Err(FusionError::WrongAnchor);
                }
            }
            FrontierTip::Block(parent_id) => {
                let parent = blocks.get(&parent_id).ok_or(FusionError::MissingParent)?;
                if parent.epoch != input.epoch
                    || parent.lane != block.lane
                    || parent.logical_round >= block.logical_round
                {
                    return Err(FusionError::InvalidLaneParent);
                }
            }
        }
        let mut braid_seen = BTreeSet::new();
        for parent_id in &block.braid_parents {
            if !braid_seen.insert(*parent_id) {
                return Err(FusionError::DuplicateBraidParent);
            }
            let parent = blocks.get(parent_id).ok_or(FusionError::MissingParent)?;
            if parent.epoch != input.epoch
                || parent.lane == block.lane
                || parent.logical_round > block.logical_round
            {
                return Err(FusionError::InvalidBraidParent);
            }
        }
    }
    Ok(())
}

fn validate_lane_frontiers(
    input: &FusionInput,
    blocks: &BTreeMap<Hash256, &FusionBlock>,
    included: &BTreeSet<Hash256>,
) -> Result<(), FusionError> {
    for lane in 0..input.lane_count {
        let mut lane_chain = BTreeSet::new();
        let mut cursor = match input.selected_frontier[lane as usize] {
            FrontierTip::Anchor(_) => None,
            FrontierTip::Block(id) => Some(id),
        };
        while let Some(id) = cursor {
            if !lane_chain.insert(id) {
                return Err(FusionError::Cycle);
            }
            cursor = match blocks[&id].lane_parent {
                FrontierTip::Anchor(_) => None,
                FrontierTip::Block(parent) => Some(parent),
            };
        }
        if included
            .iter()
            .any(|id| blocks[id].lane == lane && !lane_chain.contains(id))
        {
            return Err(FusionError::InconsistentFrontier);
        }
    }
    Ok(())
}

fn canonical_topological_order(
    blocks: &BTreeMap<Hash256, &FusionBlock>,
    included: &BTreeSet<Hash256>,
) -> Result<Vec<Hash256>, FusionError> {
    let mut indegree = included
        .iter()
        .map(|id| (*id, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<Hash256, BTreeSet<Hash256>>::new();
    for id in included {
        let block = blocks[id];
        let mut parents = block.braid_parents.clone();
        if let FrontierTip::Block(parent) = block.lane_parent {
            parents.push(parent);
        }
        for parent in parents {
            if included.contains(&parent) && children.entry(parent).or_default().insert(*id) {
                *indegree.get_mut(id).expect("included block has indegree") += 1;
            }
        }
    }

    let mut ready = BTreeSet::new();
    for (id, degree) in &indegree {
        if *degree == 0 {
            ready.insert(rank(blocks[id]));
        }
    }
    let mut order = Vec::with_capacity(included.len());
    while let Some(next) = ready.pop_first() {
        order.push(next.id);
        if let Some(next_children) = children.get(&next.id) {
            for child in next_children {
                let degree = indegree.get_mut(child).expect("child is included");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(rank(blocks[child]));
                }
            }
        }
    }
    if order.len() != included.len() {
        return Err(FusionError::Cycle);
    }
    Ok(order)
}

fn execute_conflicts(
    blocks: &BTreeMap<Hash256, &FusionBlock>,
    order: &[Hash256],
) -> Result<Vec<TransactionReceipt>, FusionError> {
    let mut claimed = BTreeSet::new();
    let mut transaction_ids = BTreeSet::new();
    let mut receipts = Vec::new();
    for block_id in order {
        for transaction in &blocks[block_id].transactions {
            if !transaction_ids.insert(transaction.id) {
                return Err(FusionError::DuplicateTransaction);
            }
            let unique_claims = transaction.claims.iter().cloned().collect::<BTreeSet<_>>();
            if unique_claims.len() != transaction.claims.len() {
                return Err(FusionError::DuplicateClaim);
            }
            let conflicts = unique_claims
                .iter()
                .filter(|claim| claimed.contains(*claim))
                .cloned()
                .collect::<Vec<_>>();
            let success = conflicts.is_empty();
            if success {
                claimed.extend(unique_claims);
            }
            receipts.push(TransactionReceipt {
                block_id: *block_id,
                tx_id: transaction.id,
                success,
                conflicts,
            });
        }
    }
    Ok(receipts)
}

fn rank(block: &FusionBlock) -> Rank {
    Rank {
        logical_round: block.logical_round,
        lane: block.lane,
        id: block.id,
    }
}

fn frontier_commitment(input: &FusionInput) -> Hash256 {
    let mut bytes = Vec::with_capacity(10 + input.selected_frontier.len() * 65);
    bytes.extend_from_slice(&input.epoch.to_be_bytes());
    bytes.extend_from_slice(&input.lane_count.to_be_bytes());
    for (previous, tip) in input.previous_frontier.iter().zip(&input.selected_frontier) {
        bytes.extend_from_slice(previous.as_bytes());
        match tip {
            FrontierTip::Anchor(id) => {
                bytes.push(0);
                bytes.extend_from_slice(id.as_bytes());
            }
            FrontierTip::Block(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
        }
    }
    hash_parts(D_FRONTIER, &[&bytes])
}

fn list_commitment(domain: &[u8], ids: &[Hash256]) -> Hash256 {
    let mut bytes = Vec::with_capacity(8 + ids.len() * 32);
    bytes.extend_from_slice(&(ids.len() as u64).to_be_bytes());
    for id in ids {
        bytes.extend_from_slice(id.as_bytes());
    }
    hash_parts(domain, &[&bytes])
}

fn receipt_commitment(receipts: &[TransactionReceipt]) -> Hash256 {
    let hashes = receipts
        .iter()
        .map(TransactionReceipt::hash)
        .collect::<Vec<_>>();
    list_commitment(D_RECEIPT_ROOT, &hashes)
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

    fn tx(id: u8, claim: ConflictKey) -> FusionTransaction {
        FusionTransaction {
            id: hash(id),
            claims: vec![claim],
        }
    }

    fn block(
        id: u8,
        lane: u16,
        round: u64,
        lane_parent: FrontierTip,
        braid_parents: Vec<Hash256>,
        transactions: Vec<FusionTransaction>,
    ) -> FusionBlock {
        FusionBlock {
            id: hash(id),
            epoch: 7,
            lane,
            logical_round: round,
            lane_parent,
            braid_parents,
            transactions,
        }
    }

    fn valid_input() -> FusionInput {
        let anchors = vec![hash(1), hash(2), hash(3)];
        let conflict = ConflictKey::Nullifier(hash(0xf0));
        let b0 = block(
            10,
            0,
            1,
            FrontierTip::Anchor(anchors[0]),
            vec![],
            vec![tx(20, conflict.clone())],
        );
        let b1 = block(
            11,
            1,
            1,
            FrontierTip::Anchor(anchors[1]),
            vec![],
            vec![tx(21, conflict)],
        );
        let b2 = block(
            12,
            2,
            2,
            FrontierTip::Anchor(anchors[2]),
            vec![b0.id, b1.id],
            vec![tx(22, ConflictKey::StateKey(hash(0xf1)))],
        );
        let excluded = block(13, 0, 2, FrontierTip::Block(b0.id), vec![], vec![]);
        FusionInput {
            epoch: 7,
            lane_count: 3,
            previous_frontier: anchors,
            selected_frontier: vec![
                FrontierTip::Block(b0.id),
                FrontierTip::Block(b1.id),
                FrontierTip::Block(b2.id),
            ],
            blocks: vec![excluded, b2, b0, b1],
            certified_blocks: [hash(10), hash(11), hash(12)].into_iter().collect(),
        }
    }

    #[test]
    fn fusion_is_independent_of_input_arrival_order() {
        let input = valid_input();
        let expected = fuse_certified_frontier(&input).unwrap();
        let mut reversed = input;
        reversed.blocks.reverse();
        let actual = fuse_certified_frontier(&reversed).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.block_order, vec![hash(10), hash(11), hash(12)]);
        assert_eq!(actual.excluded_blocks, [hash(13)].into_iter().collect());
    }

    #[test]
    fn first_canonical_transaction_wins_conflict_atomically() {
        let result = fuse_certified_frontier(&valid_input()).unwrap();
        assert!(result.receipts[0].success);
        assert!(!result.receipts[1].success);
        assert_eq!(
            result.receipts[1].conflicts,
            vec![ConflictKey::Nullifier(hash(0xf0))]
        );
        assert!(result.receipts[2].success);
    }

    #[test]
    fn unavailable_reachable_block_is_rejected() {
        let mut input = valid_input();
        input.certified_blocks.remove(&hash(11));
        assert_eq!(
            fuse_certified_frontier(&input),
            Err(FusionError::UnavailableBlock)
        );
    }

    #[test]
    fn braid_cannot_smuggle_a_competing_lane_branch() {
        let mut input = valid_input();
        let fork = block(14, 0, 2, FrontierTip::Block(hash(10)), vec![], vec![]);
        input.blocks.push(fork);
        input.certified_blocks.insert(hash(14));
        let b2 = input
            .blocks
            .iter_mut()
            .find(|block| block.id == hash(12))
            .unwrap();
        b2.braid_parents.push(hash(14));
        assert_eq!(
            fuse_certified_frontier(&input),
            Err(FusionError::InconsistentFrontier)
        );
    }

    #[test]
    fn missing_parent_and_cross_lane_parent_are_rejected() {
        let mut missing = valid_input();
        let b2 = missing
            .blocks
            .iter_mut()
            .find(|block| block.id == hash(12))
            .unwrap();
        b2.braid_parents.push(hash(99));
        assert_eq!(
            fuse_certified_frontier(&missing),
            Err(FusionError::MissingParent)
        );

        let mut cross_lane = valid_input();
        let b1 = cross_lane
            .blocks
            .iter_mut()
            .find(|block| block.id == hash(11))
            .unwrap();
        b1.lane_parent = FrontierTip::Block(hash(10));
        assert_eq!(
            fuse_certified_frontier(&cross_lane),
            Err(FusionError::InvalidLaneParent)
        );
    }

    #[test]
    fn same_round_braid_cycle_is_rejected() {
        let anchors = vec![hash(1), hash(2)];
        let b0 = block(
            10,
            0,
            1,
            FrontierTip::Anchor(anchors[0]),
            vec![hash(11)],
            vec![],
        );
        let b1 = block(
            11,
            1,
            1,
            FrontierTip::Anchor(anchors[1]),
            vec![hash(10)],
            vec![],
        );
        let input = FusionInput {
            epoch: 7,
            lane_count: 2,
            previous_frontier: anchors,
            selected_frontier: vec![FrontierTip::Block(hash(10)), FrontierTip::Block(hash(11))],
            blocks: vec![b0, b1],
            certified_blocks: [hash(10), hash(11)].into_iter().collect(),
        };
        assert_eq!(fuse_certified_frontier(&input), Err(FusionError::Cycle));
    }

    #[test]
    fn duplicate_transaction_and_claim_are_rejected() {
        let mut duplicate_tx = valid_input();
        let b1 = duplicate_tx
            .blocks
            .iter_mut()
            .find(|block| block.id == hash(11))
            .unwrap();
        b1.transactions[0].id = hash(20);
        assert_eq!(
            fuse_certified_frontier(&duplicate_tx),
            Err(FusionError::DuplicateTransaction)
        );

        let mut duplicate_claim = valid_input();
        let b0 = duplicate_claim
            .blocks
            .iter_mut()
            .find(|block| block.id == hash(10))
            .unwrap();
        b0.transactions[0]
            .claims
            .push(ConflictKey::Nullifier(hash(0xf0)));
        assert_eq!(
            fuse_certified_frontier(&duplicate_claim),
            Err(FusionError::DuplicateClaim)
        );
    }

    #[test]
    fn reference_commitments_are_stable() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/h-bfm-v0.json")).unwrap();
        assert_eq!(vector["schema"], "hyphen-h-bfm-vector-v0");
        let input = valid_input();
        assert_eq!(vector["epoch"].as_u64().unwrap(), input.epoch);
        assert_eq!(
            vector["lane_count"].as_u64().unwrap(),
            u64::from(input.lane_count)
        );
        let previous_frontier = input
            .previous_frontier
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            previous_frontier,
            serde_json::from_value::<Vec<String>>(vector["previous_frontier"].clone()).unwrap()
        );
        let selected_frontier = input
            .selected_frontier
            .iter()
            .map(|tip| match tip {
                FrontierTip::Anchor(hash) | FrontierTip::Block(hash) => hash.to_string(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected_frontier,
            serde_json::from_value::<Vec<String>>(vector["selected_frontier"].clone()).unwrap()
        );
        let result = fuse_certified_frontier(&input).unwrap();
        assert_eq!(
            result.frontier_commitment.to_string(),
            vector["frontier_commitment"].as_str().unwrap()
        );
        assert_eq!(
            result.order_root.to_string(),
            vector["order_root"].as_str().unwrap()
        );
        assert_eq!(
            result.receipt_root.to_string(),
            vector["receipt_root"].as_str().unwrap()
        );
        let order = result
            .block_order
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            serde_json::from_value::<Vec<String>>(vector["canonical_block_order"].clone()).unwrap()
        );
        let excluded = result
            .excluded_blocks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            excluded,
            serde_json::from_value::<Vec<String>>(vector["excluded_blocks"].clone()).unwrap()
        );
    }
}
