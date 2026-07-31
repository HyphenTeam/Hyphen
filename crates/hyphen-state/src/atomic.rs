//! Atomic cross-tree persistence for one canonical block transition.

use std::collections::BTreeSet;

use hyphen_core::block::Block;
use hyphen_crypto::{blake3_hash, Hash256};
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use thiserror::Error;

use crate::chain_state::{ChainState, ChainTip, EPOCH_SEED_PREFIX, TIP_KEY};
use crate::commitment_tree::{PersistentCommitmentTree, TREE_STATE_KEY};
use crate::compress::{compress, decompress};
use crate::nullifier_set::NullifierSet;
use crate::store::BlockStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedOutput {
    pub global_index: u64,
    pub one_time_pubkey: [u8; 32],
    pub commitment: [u8; 32],
    pub block_height: u64,
}

pub struct AtomicBlockUpdate<'a> {
    pub block: &'a Block,
    pub commitment_tree: hyphen_crypto::merkle::MerkleTree,
    pub outputs: Vec<IndexedOutput>,
    pub nullifiers: Vec<[u8; 32]>,
    pub coinbase: Option<Vec<u8>>,
    pub tip: ChainTip,
    pub next_epoch_seed: Option<(u64, Hash256)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockUndo {
    block_hash: Hash256,
    height: u64,
    previous_tip: Option<ChainTip>,
    previous_commitment_tree: hyphen_crypto::merkle::MerkleTree,
    transaction_hashes: Vec<Hash256>,
    output_indices: Vec<u64>,
    nullifiers: Vec<[u8; 32]>,
    had_coinbase: bool,
    epoch_seed: Option<(u64, Option<Hash256>)>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AtomicStateError {
    #[error("serialisation failed: {0}")]
    Serialize(String),
    #[error("compression failed: {0}")]
    Compress(String),
    #[error("block already exists")]
    DuplicateBlock,
    #[error("canonical height is already occupied by another block")]
    HeightConflict,
    #[error("transaction is already indexed")]
    DuplicateTransaction,
    #[error("output index is already occupied")]
    OutputConflict,
    #[error("nullifier already exists")]
    DuplicateNullifier,
    #[error("coinbase height is already occupied")]
    CoinbaseConflict,
    #[error("undo journal not found for block {0}")]
    MissingUndo(Hash256),
    #[error("only the current canonical tip can be reverted")]
    NotCanonicalTip,
    #[error("undo journal does not match canonical state: {0}")]
    UndoMismatch(String),
    #[error("canonical state changed while the block update was being prepared")]
    ConcurrentStateChange,
    #[error("invalid canonical block transition: {0}")]
    InvalidTransition(String),
    #[error("storage transaction failed: {0}")]
    Storage(String),
}

#[derive(Clone, Debug)]
enum AbortReason {
    DuplicateBlock,
    HeightConflict,
    DuplicateTransaction,
    OutputConflict,
    DuplicateNullifier,
    CoinbaseConflict,
    NotCanonicalTip,
    UndoMismatch,
    ConcurrentStateChange,
}

/// Commits every persistent effect of a canonical block as one sled
/// transaction. The in-memory commitment tree changes only after persistence
/// succeeds.
pub fn commit_block_update(
    blocks: &BlockStore,
    chain_state: &ChainState,
    nullifiers: &NullifierSet,
    commitment_tree: &mut PersistentCommitmentTree,
    update: AtomicBlockUpdate<'_>,
) -> Result<(), AtomicStateError> {
    let block_hash = update.block.hash();
    let expected_tip_state = chain_state
        .tree
        .get_raw(TIP_KEY)
        .map_err(|error| AtomicStateError::Storage(error.to_string()))?
        .map(|value| value.to_vec());
    let previous_tip = expected_tip_state
        .as_ref()
        .map(|compressed| {
            let bytes = decompress(compressed)
                .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
            hyphen_codec::deserialize(&bytes)
                .map_err(|error| AtomicStateError::Serialize(error.to_string()))
        })
        .transpose()?;
    let previous_commitment_tree = commitment_tree.snapshot();
    validate_update(
        &update,
        block_hash,
        previous_tip.as_ref(),
        &previous_commitment_tree,
    )?;
    let previous_tree_bytes = hyphen_codec::serialize(&previous_commitment_tree)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_previous_tree = compress(&previous_tree_bytes)
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let expected_tree_state = commitment_tree
        .tree_data
        .get_raw(TREE_STATE_KEY)
        .map_err(|error| AtomicStateError::Storage(error.to_string()))?
        .map(|value| value.to_vec());
    if expected_tree_state
        .as_deref()
        .is_some_and(|persisted| persisted != compressed_previous_tree.as_slice())
    {
        return Err(AtomicStateError::ConcurrentStateChange);
    }
    let epoch_seed_key = update.next_epoch_seed.map(|(epoch, _)| {
        let mut key = EPOCH_SEED_PREFIX.to_vec();
        key.extend_from_slice(&epoch.to_be_bytes());
        key
    });
    let expected_epoch_seed_state = epoch_seed_key
        .as_ref()
        .map(|key| {
            chain_state
                .tree
                .get_raw(key)
                .map(|value| value.map(|bytes| bytes.to_vec()))
                .map_err(|error| AtomicStateError::Storage(error.to_string()))
        })
        .transpose()?;
    let previous_epoch_seed = update
        .next_epoch_seed
        .map(|(epoch, _)| {
            let seed = expected_epoch_seed_state
                .as_ref()
                .and_then(|value| value.as_ref())
                .map(|compressed| {
                    let bytes = decompress(compressed)
                        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
                    let seed_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                        AtomicStateError::Storage("invalid persisted epoch seed length".into())
                    })?;
                    Ok(Hash256::from_bytes(seed_bytes))
                })
                .transpose()?;
            Ok((epoch, seed))
        })
        .transpose()?;
    let block_bytes = hyphen_codec::serialize(update.block)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_block =
        compress(&block_bytes).map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let tip_bytes = hyphen_codec::serialize(&update.tip)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_tip =
        compress(&tip_bytes).map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let tree_bytes = hyphen_codec::serialize(&update.commitment_tree)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_tree =
        compress(&tree_bytes).map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let compressed_epoch_seed = update
        .next_epoch_seed
        .map(|(_, seed)| compress(seed.as_bytes()))
        .transpose()
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let transaction_locations = update
        .block
        .transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| {
            let mut location = [0u8; 36];
            location[..32].copy_from_slice(block_hash.as_bytes());
            location[32..].copy_from_slice(&(index as u32).to_le_bytes());
            (blake3_hash(transaction), location)
        })
        .collect::<Vec<_>>();
    let undo = BlockUndo {
        block_hash,
        height: update.block.header.height,
        previous_tip,
        previous_commitment_tree,
        transaction_hashes: transaction_locations
            .iter()
            .map(|(hash, _)| *hash)
            .collect(),
        output_indices: update
            .outputs
            .iter()
            .map(|output| output.global_index)
            .collect(),
        nullifiers: update.nullifiers.clone(),
        had_coinbase: update.coinbase.is_some(),
        epoch_seed: previous_epoch_seed,
    };
    let undo_bytes = hyphen_codec::serialize(&undo)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_undo =
        compress(&undo_bytes).map_err(|error| AtomicStateError::Compress(error.to_string()))?;

    let trees = (
        blocks.blocks.inner(),
        &blocks.height_index,
        &blocks.tx_index,
        &blocks.output_index,
        &blocks.coinbase_index,
        chain_state.tree.inner(),
        commitment_tree.tree_data.inner(),
        &nullifiers.tree,
        blocks.undo_index.inner(),
    );
    let transaction_result: Result<(), TransactionError<AbortReason>> = trees.transaction(
        |(
            block_tree,
            height_tree,
            tx_tree,
            output_tree,
            coinbase_tree,
            state_tree,
            commitment_tree_data,
            nullifier_tree,
            undo_tree,
        )| {
            if state_tree.get(TIP_KEY)?.as_deref() != expected_tip_state.as_deref()
                || commitment_tree_data.get(TREE_STATE_KEY)?.as_deref()
                    != expected_tree_state.as_deref()
            {
                return Err(ConflictableTransactionError::Abort(
                    AbortReason::ConcurrentStateChange,
                ));
            }
            if let (Some(key), Some(expected)) =
                (epoch_seed_key.as_ref(), expected_epoch_seed_state.as_ref())
            {
                if state_tree.get(key)?.as_deref() != expected.as_deref() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::ConcurrentStateChange,
                    ));
                }
            }
            if let Some(existing) = height_tree.get(update.block.header.height.to_be_bytes())? {
                if existing.as_ref() != block_hash.as_bytes() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::HeightConflict,
                    ));
                }
                return Err(ConflictableTransactionError::Abort(
                    AbortReason::DuplicateBlock,
                ));
            }
            if let Some(existing) = block_tree.get(block_hash.as_bytes().as_slice())? {
                if existing.as_ref() != compressed_block.as_slice() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::DuplicateBlock,
                    ));
                }
            } else {
                block_tree.insert(
                    block_hash.as_bytes().as_slice(),
                    compressed_block.as_slice(),
                )?;
            }
            height_tree.insert(
                update.block.header.height.to_be_bytes().as_slice(),
                block_hash.as_bytes().as_slice(),
            )?;

            for (tx_hash, location) in &transaction_locations {
                if tx_tree.get(tx_hash.as_bytes().as_slice())?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::DuplicateTransaction,
                    ));
                }
                tx_tree.insert(tx_hash.as_bytes().as_slice(), location.as_slice())?;
            }
            for output in &update.outputs {
                let key = output.global_index.to_be_bytes();
                if output_tree.get(key.as_slice())?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::OutputConflict,
                    ));
                }
                let mut value = [0u8; 72];
                value[..32].copy_from_slice(&output.one_time_pubkey);
                value[32..64].copy_from_slice(&output.commitment);
                value[64..].copy_from_slice(&output.block_height.to_le_bytes());
                output_tree.insert(key.as_slice(), value.as_slice())?;
            }
            for nullifier in &update.nullifiers {
                if nullifier_tree.get(nullifier.as_slice())?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::DuplicateNullifier,
                    ));
                }
                nullifier_tree.insert(
                    nullifier.as_slice(),
                    update.block.header.height.to_le_bytes().as_slice(),
                )?;
            }
            if let Some(coinbase) = &update.coinbase {
                let key = update.block.header.height.to_be_bytes();
                if coinbase_tree.get(key.as_slice())?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::CoinbaseConflict,
                    ));
                }
                coinbase_tree.insert(key.as_slice(), coinbase.as_slice())?;
            } else if coinbase_tree
                .get(update.block.header.height.to_be_bytes())?
                .is_some()
            {
                return Err(ConflictableTransactionError::Abort(
                    AbortReason::CoinbaseConflict,
                ));
            }

            state_tree.insert(TIP_KEY, compressed_tip.as_slice())?;
            if let (Some((epoch, _)), Some(seed)) =
                (update.next_epoch_seed, compressed_epoch_seed.as_ref())
            {
                let mut key = EPOCH_SEED_PREFIX.to_vec();
                key.extend_from_slice(&epoch.to_be_bytes());
                state_tree.insert(key, seed.as_slice())?;
            }
            commitment_tree_data.insert(TREE_STATE_KEY, compressed_tree.as_slice())?;
            if let Some(existing) = undo_tree.get(block_hash.as_bytes().as_slice())? {
                if existing.as_ref() != compressed_undo.as_slice() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::UndoMismatch,
                    ));
                }
            } else {
                undo_tree.insert(block_hash.as_bytes().as_slice(), compressed_undo.as_slice())?;
            }
            Ok(())
        },
    );

    match transaction_result {
        Ok(()) => {
            commitment_tree.replace_committed(update.commitment_tree);
            Ok(())
        }
        Err(TransactionError::Abort(reason)) => Err(match reason {
            AbortReason::DuplicateBlock => AtomicStateError::DuplicateBlock,
            AbortReason::HeightConflict => AtomicStateError::HeightConflict,
            AbortReason::DuplicateTransaction => AtomicStateError::DuplicateTransaction,
            AbortReason::OutputConflict => AtomicStateError::OutputConflict,
            AbortReason::DuplicateNullifier => AtomicStateError::DuplicateNullifier,
            AbortReason::CoinbaseConflict => AtomicStateError::CoinbaseConflict,
            AbortReason::NotCanonicalTip => AtomicStateError::NotCanonicalTip,
            AbortReason::UndoMismatch => {
                AtomicStateError::UndoMismatch("state changed during transaction".into())
            }
            AbortReason::ConcurrentStateChange => AtomicStateError::ConcurrentStateChange,
        }),
        Err(TransactionError::Storage(error)) => Err(AtomicStateError::Storage(error.to_string())),
    }
}

fn validate_update(
    update: &AtomicBlockUpdate<'_>,
    block_hash: Hash256,
    previous_tip: Option<&ChainTip>,
    previous_tree: &hyphen_crypto::merkle::MerkleTree,
) -> Result<(), AtomicStateError> {
    if update.tip.hash != block_hash || update.tip.height != update.block.header.height {
        return Err(AtomicStateError::InvalidTransition(
            "tip identity does not match the block".into(),
        ));
    }
    let expected_cumulative_difficulty = match previous_tip {
        Some(tip) => {
            let expected_height = tip.height.checked_add(1).ok_or_else(|| {
                AtomicStateError::InvalidTransition("parent height is exhausted".into())
            })?;
            if update.block.header.height != expected_height
                || update.block.header.prev_hash != tip.hash
            {
                return Err(AtomicStateError::InvalidTransition(
                    "block does not directly extend the previous tip".into(),
                ));
            }
            tip.cumulative_difficulty
                .checked_add(update.block.header.difficulty as u128)
                .ok_or_else(|| {
                    AtomicStateError::InvalidTransition("cumulative difficulty is exhausted".into())
                })?
        }
        None => {
            if update.block.header.height != 0 || update.block.header.prev_hash != Hash256::ZERO {
                return Err(AtomicStateError::InvalidTransition(
                    "first committed block must be genesis".into(),
                ));
            }
            update.block.header.difficulty as u128
        }
    };
    if update.tip.cumulative_difficulty != expected_cumulative_difficulty {
        return Err(AtomicStateError::InvalidTransition(
            "tip cumulative difficulty is incorrect".into(),
        ));
    }

    let previous_count = previous_tree.count();
    let expected_count = previous_count
        .checked_add(update.outputs.len() as u64)
        .ok_or_else(|| AtomicStateError::InvalidTransition("output count is exhausted".into()))?;
    if update.commitment_tree.count() != expected_count
        || update.tip.total_outputs != expected_count
    {
        return Err(AtomicStateError::InvalidTransition(
            "commitment tree and tip output counts are inconsistent".into(),
        ));
    }
    for (offset, output) in update.outputs.iter().enumerate() {
        if output.global_index != previous_count + offset as u64
            || output.block_height != update.block.header.height
        {
            return Err(AtomicStateError::InvalidTransition(
                "output indexes are not canonical and contiguous".into(),
            ));
        }
    }
    if update.nullifiers.iter().collect::<BTreeSet<_>>().len() != update.nullifiers.len() {
        return Err(AtomicStateError::InvalidTransition(
            "block update repeats a nullifier".into(),
        ));
    }
    let transaction_hashes = update
        .block
        .transactions
        .iter()
        .map(|transaction| blake3_hash(transaction))
        .collect::<BTreeSet<_>>();
    if transaction_hashes.len() != update.block.transactions.len() {
        return Err(AtomicStateError::InvalidTransition(
            "block update repeats a transaction".into(),
        ));
    }
    Ok(())
}

/// Reverts the current canonical tip in one sled transaction. The block body
/// and undo journal remain archived so the branch can be applied again.
pub fn revert_block_update(
    blocks: &BlockStore,
    chain_state: &ChainState,
    nullifiers: &NullifierSet,
    commitment_tree: &mut PersistentCommitmentTree,
    block_hash: &Hash256,
) -> Result<(), AtomicStateError> {
    let undo_bytes = blocks
        .undo_index
        .get(block_hash.as_bytes())
        .map_err(|error| AtomicStateError::Storage(error.to_string()))?
        .ok_or(AtomicStateError::MissingUndo(*block_hash))?;
    let undo: BlockUndo = hyphen_codec::deserialize(&undo_bytes)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    if undo.block_hash != *block_hash {
        return Err(AtomicStateError::UndoMismatch(
            "journal key and block hash differ".into(),
        ));
    }

    let current_tip = chain_state
        .get_tip()
        .map_err(|error| AtomicStateError::Storage(error.to_string()))?
        .ok_or(AtomicStateError::NotCanonicalTip)?;
    if current_tip.hash != *block_hash || current_tip.height != undo.height {
        return Err(AtomicStateError::NotCanonicalTip);
    }
    let current_tip_bytes = hyphen_codec::serialize(&current_tip)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_current_tip = compress(&current_tip_bytes)
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let compressed_previous_tip = undo
        .previous_tip
        .as_ref()
        .map(hyphen_codec::serialize)
        .transpose()
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?
        .map(|bytes| compress(&bytes))
        .transpose()
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let previous_tree_bytes = hyphen_codec::serialize(&undo.previous_commitment_tree)
        .map_err(|error| AtomicStateError::Serialize(error.to_string()))?;
    let compressed_previous_tree = compress(&previous_tree_bytes)
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;
    let compressed_previous_epoch_seed = undo
        .epoch_seed
        .as_ref()
        .and_then(|(_, seed)| seed.as_ref())
        .map(|seed| compress(seed.as_bytes()))
        .transpose()
        .map_err(|error| AtomicStateError::Compress(error.to_string()))?;

    let trees = (
        &blocks.height_index,
        &blocks.tx_index,
        &blocks.output_index,
        &blocks.coinbase_index,
        chain_state.tree.inner(),
        commitment_tree.tree_data.inner(),
        &nullifiers.tree,
    );
    let transaction_result: Result<(), TransactionError<AbortReason>> = trees.transaction(
        |(
            height_tree,
            tx_tree,
            output_tree,
            coinbase_tree,
            state_tree,
            commitment_tree_data,
            nullifier_tree,
        )| {
            let height_key = undo.height.to_be_bytes();
            match height_tree.get(height_key.as_slice())? {
                Some(hash) if hash.as_ref() == block_hash.as_bytes() => {}
                _ => {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::NotCanonicalTip,
                    ));
                }
            }
            match state_tree.get(TIP_KEY)? {
                Some(tip) if tip.as_ref() == compressed_current_tip.as_slice() => {}
                _ => {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::NotCanonicalTip,
                    ));
                }
            }

            for tx_hash in &undo.transaction_hashes {
                match tx_tree.get(tx_hash.as_bytes().as_slice())? {
                    Some(location)
                        if location.len() >= 32
                            && &location[..32] == block_hash.as_bytes().as_slice() =>
                    {
                        tx_tree.remove(tx_hash.as_bytes().as_slice())?;
                    }
                    _ => {
                        return Err(ConflictableTransactionError::Abort(
                            AbortReason::UndoMismatch,
                        ));
                    }
                }
            }
            for output_index in &undo.output_indices {
                let key = output_index.to_be_bytes();
                match output_tree.get(key.as_slice())? {
                    Some(output)
                        if output.len() >= 72 && output[64..72] == undo.height.to_le_bytes() =>
                    {
                        output_tree.remove(key.as_slice())?;
                    }
                    _ => {
                        return Err(ConflictableTransactionError::Abort(
                            AbortReason::UndoMismatch,
                        ));
                    }
                }
            }
            for nullifier in &undo.nullifiers {
                match nullifier_tree.get(nullifier.as_slice())? {
                    Some(height) if height.as_ref() == undo.height.to_le_bytes() => {
                        nullifier_tree.remove(nullifier.as_slice())?;
                    }
                    _ => {
                        return Err(ConflictableTransactionError::Abort(
                            AbortReason::UndoMismatch,
                        ));
                    }
                }
            }
            if undo.had_coinbase {
                if coinbase_tree.get(height_key.as_slice())?.is_none() {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::UndoMismatch,
                    ));
                }
                coinbase_tree.remove(height_key.as_slice())?;
            }

            height_tree.remove(height_key.as_slice())?;
            if let Some(previous_tip) = compressed_previous_tip.as_ref() {
                state_tree.insert(TIP_KEY, previous_tip.as_slice())?;
            } else {
                state_tree.remove(TIP_KEY)?;
            }
            if let Some((epoch, previous_seed)) = &undo.epoch_seed {
                let mut key = EPOCH_SEED_PREFIX.to_vec();
                key.extend_from_slice(&epoch.to_be_bytes());
                if previous_seed.is_some() {
                    state_tree.insert(
                        key,
                        compressed_previous_epoch_seed
                            .as_ref()
                            .expect("compressed seed exists")
                            .as_slice(),
                    )?;
                } else {
                    state_tree.remove(key)?;
                }
            }
            commitment_tree_data.insert(TREE_STATE_KEY, compressed_previous_tree.as_slice())?;
            Ok(())
        },
    );

    match transaction_result {
        Ok(()) => {
            commitment_tree.replace_committed(undo.previous_commitment_tree);
            Ok(())
        }
        Err(TransactionError::Abort(AbortReason::NotCanonicalTip)) => {
            Err(AtomicStateError::NotCanonicalTip)
        }
        Err(TransactionError::Abort(AbortReason::UndoMismatch)) => Err(
            AtomicStateError::UndoMismatch("indexed state does not match undo journal".into()),
        ),
        Err(TransactionError::Abort(AbortReason::ConcurrentStateChange)) => {
            Err(AtomicStateError::ConcurrentStateChange)
        }
        Err(TransactionError::Abort(reason)) => Err(AtomicStateError::UndoMismatch(format!(
            "unexpected rollback abort: {reason:?}"
        ))),
        Err(TransactionError::Storage(error)) => Err(AtomicStateError::Storage(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::block::{Block, BlockHeader};

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn block(height: u64, previous: Hash256, marker: u8) -> Block {
        Block {
            header: BlockHeader {
                version: 2,
                height,
                timestamp: 1_700_000_000_000 + height,
                prev_hash: previous,
                tx_root: Hash256::ZERO,
                commitment_root: Hash256::ZERO,
                nullifier_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
                receipt_root: Hash256::ZERO,
                uncle_root: Hash256::ZERO,
                pow_commitment: hash(marker),
                epoch_seed: hash(3),
                difficulty: 1,
                nonce: marker as u64,
                extra_nonce: [marker; 32],
                miner_pubkey: [marker; 32],
                total_fee: 0,
                reward: 0,
                view_tag: 0,
                block_size: 0,
            },
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: Vec::new(),
        }
    }

    #[test]
    fn aborted_cross_tree_update_leaves_no_partial_state() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let blocks = BlockStore::open(&db).unwrap();
        let chain_state = ChainState::open(&db).unwrap();
        let nullifiers = NullifierSet::open(&db).unwrap();
        let mut commitments = PersistentCommitmentTree::open(&db).unwrap();
        let first = block(0, Hash256::ZERO, 10);
        let mut first_tree = commitments.snapshot();
        first_tree.append(hash(20));
        let repeated_nullifier = [30; 32];
        commit_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            AtomicBlockUpdate {
                block: &first,
                commitment_tree: first_tree,
                outputs: vec![IndexedOutput {
                    global_index: 0,
                    one_time_pubkey: [40; 32],
                    commitment: [41; 32],
                    block_height: 0,
                }],
                nullifiers: vec![repeated_nullifier],
                coinbase: None,
                tip: ChainTip {
                    height: 0,
                    hash: first.hash(),
                    cumulative_difficulty: 1,
                    total_outputs: 1,
                },
                next_epoch_seed: None,
            },
        )
        .unwrap();

        let committed_root = commitments.root();
        let second = block(1, first.hash(), 11);
        let mut second_tree = commitments.snapshot();
        second_tree.append(hash(21));
        let result = commit_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            AtomicBlockUpdate {
                block: &second,
                commitment_tree: second_tree,
                outputs: vec![IndexedOutput {
                    global_index: 1,
                    one_time_pubkey: [42; 32],
                    commitment: [43; 32],
                    block_height: 1,
                }],
                nullifiers: vec![repeated_nullifier],
                coinbase: Some(vec![44]),
                tip: ChainTip {
                    height: 1,
                    hash: second.hash(),
                    cumulative_difficulty: 2,
                    total_outputs: 2,
                },
                next_epoch_seed: Some((1, hash(45))),
            },
        );

        assert_eq!(result, Err(AtomicStateError::DuplicateNullifier));
        assert!(!blocks.has_block(&second.hash()).unwrap());
        assert!(blocks.get_block_by_height(1).is_err());
        assert!(blocks.get_output(1).is_err());
        assert!(blocks.get_coinbase(1).is_err());
        assert!(chain_state.get_epoch_seed(1).unwrap().is_none());
        let tip = chain_state.get_tip().unwrap().unwrap();
        assert_eq!(tip.hash, first.hash());
        assert_eq!(tip.total_outputs, 1);
        assert_eq!(commitments.count(), 1);
        assert_eq!(commitments.root(), committed_root);

        drop(commitments);
        let reopened = PersistentCommitmentTree::open(&db).unwrap();
        assert_eq!(reopened.count(), 1);
        assert_eq!(reopened.root(), committed_root);
    }

    #[test]
    fn canonical_tip_can_be_reverted_and_reapplied_atomically() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let blocks = BlockStore::open(&db).unwrap();
        let chain_state = ChainState::open(&db).unwrap();
        let nullifiers = NullifierSet::open(&db).unwrap();
        let mut commitments = PersistentCommitmentTree::open(&db).unwrap();

        let first = block(0, Hash256::ZERO, 50);
        let mut first_tree = commitments.snapshot();
        first_tree.append(hash(51));
        let first_tip = ChainTip {
            height: 0,
            hash: first.hash(),
            cumulative_difficulty: 1,
            total_outputs: 1,
        };
        commit_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            AtomicBlockUpdate {
                block: &first,
                commitment_tree: first_tree,
                outputs: vec![IndexedOutput {
                    global_index: 0,
                    one_time_pubkey: [52; 32],
                    commitment: [53; 32],
                    block_height: 0,
                }],
                nullifiers: vec![],
                coinbase: None,
                tip: first_tip.clone(),
                next_epoch_seed: Some((7, hash(54))),
            },
        )
        .unwrap();
        let first_root = commitments.root();

        let mut second = block(1, first.hash(), 55);
        second.transactions.push(vec![56, 57, 58]);
        let transaction_hash = blake3_hash(&second.transactions[0]);
        let second_hash = second.hash();
        let second_tip = ChainTip {
            height: 1,
            hash: second_hash,
            cumulative_difficulty: 2,
            total_outputs: 2,
        };
        let second_nullifier = [59; 32];
        let second_output = IndexedOutput {
            global_index: 1,
            one_time_pubkey: [60; 32],
            commitment: [61; 32],
            block_height: 1,
        };
        let mut second_tree = commitments.snapshot();
        second_tree.append(hash(62));
        let second_root = second_tree.root();
        commit_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            AtomicBlockUpdate {
                block: &second,
                commitment_tree: second_tree,
                outputs: vec![second_output.clone()],
                nullifiers: vec![second_nullifier],
                coinbase: Some(vec![63, 64]),
                tip: second_tip.clone(),
                next_epoch_seed: Some((7, hash(65))),
            },
        )
        .unwrap();

        assert_eq!(chain_state.get_tip().unwrap(), Some(second_tip.clone()));
        assert_eq!(chain_state.get_epoch_seed(7).unwrap(), Some(hash(65)));
        assert_eq!(
            blocks.get_tx_location(&transaction_hash).unwrap().0,
            second_hash
        );
        assert_eq!(commitments.root(), second_root);

        revert_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            &second_hash,
        )
        .unwrap();

        assert!(blocks.has_block(&second_hash).unwrap());
        assert_eq!(
            blocks.get_block_by_hash(&second_hash).unwrap().hash(),
            second_hash
        );
        assert!(blocks.get_block_by_height(1).is_err());
        assert!(blocks.get_tx_location(&transaction_hash).is_err());
        assert!(blocks.get_output(1).is_err());
        assert!(blocks.get_coinbase(1).is_err());
        assert!(!nullifiers.contains(&second_nullifier).unwrap());
        assert_eq!(chain_state.get_tip().unwrap(), Some(first_tip.clone()));
        assert_eq!(chain_state.get_epoch_seed(7).unwrap(), Some(hash(54)));
        assert_eq!(commitments.count(), 1);
        assert_eq!(commitments.root(), first_root);
        assert!(blocks
            .undo_index
            .contains_key(second_hash.as_bytes())
            .unwrap());

        let reopened = PersistentCommitmentTree::open(&db).unwrap();
        assert_eq!(reopened.count(), 1);
        assert_eq!(reopened.root(), first_root);
        drop(reopened);

        let mut reapplied_tree = commitments.snapshot();
        reapplied_tree.append(hash(62));
        commit_block_update(
            &blocks,
            &chain_state,
            &nullifiers,
            &mut commitments,
            AtomicBlockUpdate {
                block: &second,
                commitment_tree: reapplied_tree,
                outputs: vec![second_output],
                nullifiers: vec![second_nullifier],
                coinbase: Some(vec![63, 64]),
                tip: second_tip.clone(),
                next_epoch_seed: Some((7, hash(65))),
            },
        )
        .unwrap();

        assert_eq!(chain_state.get_tip().unwrap(), Some(second_tip));
        assert_eq!(chain_state.get_epoch_seed(7).unwrap(), Some(hash(65)));
        assert_eq!(blocks.get_block_by_height(1).unwrap().hash(), second_hash);
        assert_eq!(
            blocks.get_tx_location(&transaction_hash).unwrap().0,
            second_hash
        );
        assert_eq!(blocks.get_output(1).unwrap(), ([60; 32], [61; 32]));
        assert_eq!(blocks.get_coinbase(1).unwrap(), vec![63, 64]);
        assert!(nullifiers.contains(&second_nullifier).unwrap());
        assert_eq!(commitments.count(), 2);
        assert_eq!(commitments.root(), second_root);
    }
}
