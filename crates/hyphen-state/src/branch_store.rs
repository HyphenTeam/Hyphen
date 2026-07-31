//! Persistent metadata for validated competing branches.
//!
//! This module does not execute a reorganisation. It records enough immutable
//! ancestry and work data to build a reorg plan after branch-specific state
//! validation has completed.

use std::collections::HashSet;

use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError, Transactional};
use thiserror::Error;

use crate::compress::{compress, CompressedTree};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchValidation {
    HeaderValidated,
    StateValidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchMetadata {
    pub hash: Hash256,
    pub parent: Option<Hash256>,
    pub height: u64,
    /// Work derived from the already-validated PoW target for this block.
    pub block_work: u128,
    pub cumulative_work: u128,
    pub validation: BranchValidation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    pub common_ancestor: Hash256,
    /// Canonical blocks to disconnect, ordered from the current tip backwards.
    pub detach: Vec<Hash256>,
    /// Candidate blocks to connect, ordered from the ancestor forwards.
    pub attach: Vec<Hash256>,
    pub old_work: u128,
    pub new_work: u128,
}

#[derive(Debug, Error)]
pub enum BranchStoreError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("compression error: {0}")]
    Compress(#[from] crate::compress::CompressError),
    #[error("serialisation error: {0}")]
    Serde(String),
    #[error("branch block already exists: {0}")]
    Duplicate(Hash256),
    #[error("branch store is already bound to a different genesis block")]
    GenesisConflict,
    #[error("branch block not found: {0}")]
    NotFound(Hash256),
    #[error("parent block not found: {0}")]
    ParentNotFound(Hash256),
    #[error("child height {child} does not follow parent height {parent}")]
    HeightMismatch { parent: u64, child: u64 },
    #[error("branch block work must be nonzero")]
    ZeroWork,
    #[error("parent height has no representable child height")]
    HeightOverflow,
    #[error("cumulative work overflow")]
    WorkOverflow,
    #[error("block has not completed branch-specific state validation: {0}")]
    StateNotValidated(Hash256),
    #[error("candidate branch does not have strictly more cumulative work")]
    CandidateNotHeavier,
    #[error("branches have no common recorded ancestor")]
    NoCommonAncestor,
    #[error("branch metadata changed concurrently")]
    ConcurrentChange,
}

#[derive(Clone, Debug)]
enum AbortReason {
    Duplicate,
    GenesisConflict,
    ParentChanged,
    MetadataChanged,
}

pub struct BranchStore {
    metadata: CompressedTree,
    children: sled::Tree,
    tips: sled::Tree,
    root: sled::Tree,
}

impl BranchStore {
    pub fn open(db: &sled::Db) -> Result<Self, BranchStoreError> {
        Ok(Self {
            metadata: CompressedTree::new(db.open_tree("branch_metadata")?),
            children: db.open_tree("branch_children")?,
            tips: db.open_tree("branch_tips")?,
            root: db.open_tree("branch_root")?,
        })
    }

    pub fn insert_genesis(
        &self,
        hash: Hash256,
        block_work: u128,
    ) -> Result<BranchMetadata, BranchStoreError> {
        if block_work == 0 {
            return Err(BranchStoreError::ZeroWork);
        }
        let metadata = BranchMetadata {
            hash,
            parent: None,
            height: 0,
            block_work,
            cumulative_work: block_work,
            validation: BranchValidation::StateValidated,
        };
        self.insert(metadata, None)?;
        self.get(&hash)
    }

    pub fn insert_child(
        &self,
        hash: Hash256,
        parent_hash: Hash256,
        height: u64,
        block_work: u128,
        validation: BranchValidation,
    ) -> Result<BranchMetadata, BranchStoreError> {
        if block_work == 0 {
            return Err(BranchStoreError::ZeroWork);
        }
        let parent_raw = self
            .metadata
            .get_raw(parent_hash.as_bytes())?
            .ok_or(BranchStoreError::ParentNotFound(parent_hash))?;
        let parent = self.get(&parent_hash)?;
        let expected_height = parent
            .height
            .checked_add(1)
            .ok_or(BranchStoreError::HeightOverflow)?;
        if height != expected_height {
            return Err(BranchStoreError::HeightMismatch {
                parent: parent.height,
                child: height,
            });
        }
        if validation == BranchValidation::StateValidated
            && parent.validation != BranchValidation::StateValidated
        {
            return Err(BranchStoreError::StateNotValidated(parent_hash));
        }
        let cumulative_work = parent
            .cumulative_work
            .checked_add(block_work)
            .ok_or(BranchStoreError::WorkOverflow)?;
        let metadata = BranchMetadata {
            hash,
            parent: Some(parent_hash),
            height,
            block_work,
            cumulative_work,
            validation,
        };
        self.insert(metadata, Some((parent_hash, parent_raw.to_vec())))?;
        self.get(&hash)
    }

    pub fn mark_state_validated(&self, hash: &Hash256) -> Result<BranchMetadata, BranchStoreError> {
        let current_raw = self
            .metadata
            .get_raw(hash.as_bytes())?
            .ok_or(BranchStoreError::NotFound(*hash))?;
        let mut metadata = self.get(hash)?;
        if metadata.validation == BranchValidation::StateValidated {
            return Ok(metadata);
        }
        if let Some(parent_hash) = metadata.parent {
            let parent = self.get(&parent_hash)?;
            if parent.validation != BranchValidation::StateValidated {
                return Err(BranchStoreError::StateNotValidated(parent_hash));
            }
        }
        metadata.validation = BranchValidation::StateValidated;
        let encoded = hyphen_codec::serialize(&metadata)
            .map_err(|error| BranchStoreError::Serde(error.to_string()))?;
        let compressed = compress(&encoded)?;
        let result: Result<(), TransactionError<AbortReason>> =
            self.metadata.inner().transaction(|tree| {
                if tree.get(hash.as_bytes().as_slice())?.as_deref() != Some(current_raw.as_ref()) {
                    return Err(ConflictableTransactionError::Abort(
                        AbortReason::MetadataChanged,
                    ));
                }
                tree.insert(hash.as_bytes().as_slice(), compressed.as_slice())?;
                Ok(())
            });
        match result {
            Ok(()) => Ok(metadata),
            Err(TransactionError::Abort(_)) => Err(BranchStoreError::ConcurrentChange),
            Err(TransactionError::Storage(error)) => Err(BranchStoreError::Sled(error)),
        }
    }

    pub fn get(&self, hash: &Hash256) -> Result<BranchMetadata, BranchStoreError> {
        let encoded = self
            .metadata
            .get(hash.as_bytes())?
            .ok_or(BranchStoreError::NotFound(*hash))?;
        hyphen_codec::deserialize(&encoded)
            .map_err(|error| BranchStoreError::Serde(error.to_string()))
    }

    pub fn contains(&self, hash: &Hash256) -> Result<bool, BranchStoreError> {
        Ok(self.metadata.contains_key(hash.as_bytes())?)
    }

    pub fn children_of(&self, parent: &Hash256) -> Result<Vec<Hash256>, BranchStoreError> {
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(parent.as_bytes());
        self.children
            .scan_prefix(prefix)
            .map(|entry| {
                let (key, _) = entry?;
                let bytes: [u8; 32] = key[32..]
                    .try_into()
                    .map_err(|_| BranchStoreError::Serde("invalid child index key".into()))?;
                Ok(Hash256::from_bytes(bytes))
            })
            .collect()
    }

    pub fn tips(&self) -> Result<Vec<BranchMetadata>, BranchStoreError> {
        self.tips
            .iter()
            .map(|entry| {
                let (key, _) = entry?;
                let bytes: [u8; 32] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| BranchStoreError::Serde("invalid branch tip key".into()))?;
                self.get(&Hash256::from_bytes(bytes))
            })
            .collect()
    }

    pub fn reorg_plan(
        &self,
        current_tip: &Hash256,
        candidate_tip: &Hash256,
    ) -> Result<ReorgPlan, BranchStoreError> {
        let current = self.get(current_tip)?;
        let candidate = self.get(candidate_tip)?;
        if current.validation != BranchValidation::StateValidated {
            return Err(BranchStoreError::StateNotValidated(*current_tip));
        }
        if candidate.validation != BranchValidation::StateValidated {
            return Err(BranchStoreError::StateNotValidated(*candidate_tip));
        }
        if candidate.cumulative_work <= current.cumulative_work {
            return Err(BranchStoreError::CandidateNotHeavier);
        }

        let mut current_ancestors = HashSet::new();
        let mut cursor = Some(current.clone());
        while let Some(metadata) = cursor {
            current_ancestors.insert(metadata.hash);
            cursor = metadata
                .parent
                .map(|parent| self.get(&parent))
                .transpose()?;
        }

        let mut attach_reverse = Vec::new();
        let mut candidate_cursor = candidate.clone();
        while !current_ancestors.contains(&candidate_cursor.hash) {
            attach_reverse.push(candidate_cursor.hash);
            let parent = candidate_cursor
                .parent
                .ok_or(BranchStoreError::NoCommonAncestor)?;
            candidate_cursor = self.get(&parent)?;
        }
        let common_ancestor = candidate_cursor.hash;

        let mut detach = Vec::new();
        let mut current_cursor = current.clone();
        while current_cursor.hash != common_ancestor {
            detach.push(current_cursor.hash);
            let parent = current_cursor
                .parent
                .ok_or(BranchStoreError::NoCommonAncestor)?;
            current_cursor = self.get(&parent)?;
        }
        attach_reverse.reverse();

        Ok(ReorgPlan {
            common_ancestor,
            detach,
            attach: attach_reverse,
            old_work: current.cumulative_work,
            new_work: candidate.cumulative_work,
        })
    }

    pub fn flush(&self) -> Result<(), BranchStoreError> {
        self.metadata.flush()?;
        self.children.flush()?;
        self.tips.flush()?;
        self.root.flush()?;
        Ok(())
    }

    fn insert(
        &self,
        metadata: BranchMetadata,
        expected_parent: Option<(Hash256, Vec<u8>)>,
    ) -> Result<(), BranchStoreError> {
        let encoded = hyphen_codec::serialize(&metadata)
            .map_err(|error| BranchStoreError::Serde(error.to_string()))?;
        let compressed = compress(&encoded)?;
        let child_key = metadata.parent.map(|parent| {
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(parent.as_bytes());
            key[32..].copy_from_slice(metadata.hash.as_bytes());
            key
        });
        let trees = (
            self.metadata.inner(),
            &self.children,
            &self.tips,
            &self.root,
        );
        let result: Result<(), TransactionError<AbortReason>> =
            trees.transaction(|(metadata_tree, children_tree, tips_tree, root_tree)| {
                if metadata_tree
                    .get(metadata.hash.as_bytes().as_slice())?
                    .is_some()
                {
                    return Err(ConflictableTransactionError::Abort(AbortReason::Duplicate));
                }
                if let Some((parent_hash, expected_raw)) = expected_parent.as_ref() {
                    if metadata_tree
                        .get(parent_hash.as_bytes().as_slice())?
                        .as_deref()
                        != Some(expected_raw.as_slice())
                    {
                        return Err(ConflictableTransactionError::Abort(
                            AbortReason::ParentChanged,
                        ));
                    }
                } else if let Some(existing_root) = root_tree.get(b"genesis")? {
                    if existing_root.as_ref() != metadata.hash.as_bytes() {
                        return Err(ConflictableTransactionError::Abort(
                            AbortReason::GenesisConflict,
                        ));
                    }
                } else {
                    root_tree.insert(b"genesis", metadata.hash.as_bytes().as_slice())?;
                }
                metadata_tree.insert(metadata.hash.as_bytes().as_slice(), compressed.as_slice())?;
                if let Some(key) = child_key.as_ref() {
                    children_tree.insert(key.as_slice(), &[])?;
                }
                tips_tree.insert(metadata.hash.as_bytes().as_slice(), &[])?;
                if let Some(parent) = metadata.parent {
                    tips_tree.remove(parent.as_bytes().as_slice())?;
                }
                Ok(())
            });
        match result {
            Ok(()) => Ok(()),
            Err(TransactionError::Abort(AbortReason::Duplicate)) => {
                Err(BranchStoreError::Duplicate(metadata.hash))
            }
            Err(TransactionError::Abort(AbortReason::GenesisConflict)) => {
                Err(BranchStoreError::GenesisConflict)
            }
            Err(TransactionError::Abort(_)) => Err(BranchStoreError::ConcurrentChange),
            Err(TransactionError::Storage(error)) => Err(BranchStoreError::Sled(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    #[test]
    fn persists_competing_tips_and_builds_heavier_reorg_plan() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let branches = BranchStore::open(&db).unwrap();
        branches.insert_genesis(hash(1), 1).unwrap();
        branches
            .insert_child(hash(2), hash(1), 1, 10, BranchValidation::StateValidated)
            .unwrap();
        branches
            .insert_child(hash(3), hash(2), 2, 10, BranchValidation::StateValidated)
            .unwrap();
        branches
            .insert_child(hash(4), hash(1), 1, 25, BranchValidation::StateValidated)
            .unwrap();

        let plan = branches.reorg_plan(&hash(3), &hash(4)).unwrap();
        assert_eq!(plan.common_ancestor, hash(1));
        assert_eq!(plan.detach, vec![hash(3), hash(2)]);
        assert_eq!(plan.attach, vec![hash(4)]);
        assert_eq!(plan.old_work, 21);
        assert_eq!(plan.new_work, 26);

        drop(branches);
        let reopened = BranchStore::open(&db).unwrap();
        let mut tips = reopened
            .tips()
            .unwrap()
            .into_iter()
            .map(|tip| tip.hash)
            .collect::<Vec<_>>();
        tips.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        assert_eq!(tips, vec![hash(3), hash(4)]);
        assert_eq!(reopened.children_of(&hash(1)).unwrap().len(), 2);
    }

    #[test]
    fn header_only_branch_is_ineligible_until_promoted() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let branches = BranchStore::open(&db).unwrap();
        branches.insert_genesis(hash(10), 1).unwrap();
        branches
            .insert_child(hash(11), hash(10), 1, 2, BranchValidation::StateValidated)
            .unwrap();
        branches
            .insert_child(hash(12), hash(10), 1, 3, BranchValidation::HeaderValidated)
            .unwrap();

        assert!(matches!(
            branches.reorg_plan(&hash(11), &hash(12)),
            Err(BranchStoreError::StateNotValidated(found)) if found == hash(12)
        ));
        branches.mark_state_validated(&hash(12)).unwrap();
        assert_eq!(
            branches.reorg_plan(&hash(11), &hash(12)).unwrap().attach,
            vec![hash(12)]
        );
    }

    #[test]
    fn equal_work_never_triggers_a_tie_break_reorg() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let branches = BranchStore::open(&db).unwrap();
        branches.insert_genesis(hash(20), 1).unwrap();
        for child in [hash(21), hash(22)] {
            branches
                .insert_child(child, hash(20), 1, 5, BranchValidation::StateValidated)
                .unwrap();
        }
        assert!(matches!(
            branches.reorg_plan(&hash(21), &hash(22)),
            Err(BranchStoreError::CandidateNotHeavier)
        ));
    }

    #[test]
    fn store_rejects_a_second_genesis_root() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let branches = BranchStore::open(&db).unwrap();
        branches.insert_genesis(hash(30), 1).unwrap();
        assert!(matches!(
            branches.insert_genesis(hash(31), 1),
            Err(BranchStoreError::GenesisConflict)
        ));
    }
}
