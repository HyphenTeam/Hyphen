//! Persistent, namespaced 256-bit sparse Merkle tree.
//!
//! The tree stores only non-default nodes in one `sled::Tree`. A batch of leaf
//! mutations, every affected internal node and the committed root are written
//! in one optimistic transaction. Proofs are read in a transaction, so a
//! concurrent writer cannot produce a witness assembled from different roots.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use thiserror::Error;

const FORMAT_VERSION: u8 = 1;
const META_VERSION: &[u8] = b"\x00version";
const META_NAMESPACE: &[u8] = b"\x00namespace";
const META_ROOT: &[u8] = b"\x00root";
const LEAF_PREFIX: u8 = 0x10;
const NODE_PREFIX: u8 = 0x11;
const TREE_DEPTH: usize = 256;
const D_EMPTY_LEAF: &[u8] = b"HYPHEN_SMT_EMPTY_LEAF_V1";
const D_LEAF: &[u8] = b"HYPHEN_SMT_LEAF_V1";
const D_NODE: &[u8] = b"HYPHEN_SMT_NODE_V1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtMutation {
    pub key: Hash256,
    /// `Some(value)` inserts or replaces a leaf; `None` deletes it.
    pub value: Option<Hash256>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SparseMerkleProof {
    pub namespace: Hash256,
    pub key: Hash256,
    pub value: Option<Hash256>,
    /// Siblings from leaf level to root level. The length is exactly 256.
    pub siblings: Vec<Hash256>,
}

#[derive(Debug, Error)]
pub enum PersistentSmtError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("tree name must not be empty")]
    EmptyTreeName,
    #[error("persisted sparse Merkle tree format is unsupported")]
    UnsupportedFormat,
    #[error("persisted sparse Merkle tree namespace does not match")]
    NamespaceMismatch,
    #[error("persisted sparse Merkle root has an invalid length")]
    InvalidRoot,
    #[error("a sparse Merkle batch contains the same key more than once")]
    DuplicateMutation,
    #[error("sparse Merkle state changed concurrently")]
    ConcurrentUpdate,
    #[error("sparse Merkle storage transaction failed: {0}")]
    Transaction(String),
}

#[derive(Clone, Copy, Debug)]
enum SmtAbort {
    ConcurrentUpdate,
    CorruptMetadata,
}

pub struct PersistentSparseMerkleTree {
    tree: sled::Tree,
    namespace: Hash256,
    defaults: Vec<Hash256>,
}

impl PersistentSparseMerkleTree {
    pub fn open(
        db: &sled::Db,
        tree_name: &str,
        namespace: Hash256,
    ) -> Result<Self, PersistentSmtError> {
        if tree_name.is_empty() {
            return Err(PersistentSmtError::EmptyTreeName);
        }
        let tree = db.open_tree(tree_name)?;
        let defaults = default_hashes(namespace);
        let expected_root = defaults[0];
        let result: Result<(), TransactionError<SmtAbort>> = tree.transaction(|tx| {
            match tx.get(META_VERSION)? {
                Some(version) if version.as_ref() != [FORMAT_VERSION] => {
                    return Err(ConflictableTransactionError::Abort(
                        SmtAbort::CorruptMetadata,
                    ));
                }
                Some(_) => {}
                None => {
                    tx.insert(META_VERSION, &[FORMAT_VERSION])?;
                }
            }
            match tx.get(META_NAMESPACE)? {
                Some(stored) if stored.as_ref() != namespace.as_bytes() => {
                    return Err(ConflictableTransactionError::Abort(
                        SmtAbort::CorruptMetadata,
                    ));
                }
                Some(_) => {}
                None => {
                    tx.insert(META_NAMESPACE, namespace.as_bytes().as_slice())?;
                }
            }
            if tx.get(META_ROOT)?.is_none() {
                tx.insert(META_ROOT, expected_root.as_bytes().as_slice())?;
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                tree.flush()?;
            }
            Err(TransactionError::Abort(SmtAbort::CorruptMetadata)) => {
                let version = tree.get(META_VERSION)?;
                if version.as_deref() != Some(&[FORMAT_VERSION]) {
                    return Err(PersistentSmtError::UnsupportedFormat);
                }
                return Err(PersistentSmtError::NamespaceMismatch);
            }
            Err(TransactionError::Abort(SmtAbort::ConcurrentUpdate)) => {
                return Err(PersistentSmtError::ConcurrentUpdate);
            }
            Err(TransactionError::Storage(error)) => return Err(error.into()),
        }
        if tree.get(META_ROOT)?.is_none_or(|root| root.len() != 32) {
            return Err(PersistentSmtError::InvalidRoot);
        }
        Ok(Self {
            tree,
            namespace,
            defaults,
        })
    }

    pub fn namespace(&self) -> Hash256 {
        self.namespace
    }

    pub fn root(&self) -> Result<Hash256, PersistentSmtError> {
        let root = self
            .tree
            .get(META_ROOT)?
            .ok_or(PersistentSmtError::InvalidRoot)?;
        hash_from_slice(&root).ok_or(PersistentSmtError::InvalidRoot)
    }

    pub fn get(&self, key: Hash256) -> Result<Option<Hash256>, PersistentSmtError> {
        self.tree
            .get(leaf_storage_key(key))?
            .map(|value| hash_from_slice(&value).ok_or(PersistentSmtError::InvalidRoot))
            .transpose()
    }

    pub fn prove(&self, key: Hash256) -> Result<SparseMerkleProof, PersistentSmtError> {
        self.prove_at_root(key, self.root()?)
    }

    pub fn prove_at_root(
        &self,
        key: Hash256,
        expected_root: Hash256,
    ) -> Result<SparseMerkleProof, PersistentSmtError> {
        let namespace = self.namespace;
        let defaults = &self.defaults;
        let result: Result<SparseMerkleProof, TransactionError<SmtAbort>> =
            self.tree.transaction(|tx| {
                let root = tx
                    .get(META_ROOT)?
                    .ok_or(ConflictableTransactionError::Abort(
                        SmtAbort::CorruptMetadata,
                    ))?;
                if root.as_ref() != expected_root.as_bytes() {
                    return Err(ConflictableTransactionError::Abort(
                        SmtAbort::ConcurrentUpdate,
                    ));
                }
                let value = tx
                    .get(leaf_storage_key(key))?
                    .map(|bytes| {
                        hash_from_slice(&bytes).ok_or(ConflictableTransactionError::Abort(
                            SmtAbort::CorruptMetadata,
                        ))
                    })
                    .transpose()?;
                let mut siblings = Vec::with_capacity(TREE_DEPTH);
                for child_depth in (1..=TREE_DEPTH).rev() {
                    let sibling_prefix = sibling_prefix(key, child_depth);
                    let sibling = tx
                        .get(node_storage_key(child_depth, sibling_prefix))?
                        .map(|bytes| {
                            hash_from_slice(&bytes).ok_or(ConflictableTransactionError::Abort(
                                SmtAbort::CorruptMetadata,
                            ))
                        })
                        .transpose()?
                        .unwrap_or(defaults[child_depth]);
                    siblings.push(sibling);
                }
                Ok(SparseMerkleProof {
                    namespace,
                    key,
                    value,
                    siblings,
                })
            });
        match result {
            Ok(proof) => Ok(proof),
            Err(TransactionError::Abort(SmtAbort::CorruptMetadata)) => {
                Err(PersistentSmtError::InvalidRoot)
            }
            Err(TransactionError::Abort(SmtAbort::ConcurrentUpdate)) => {
                Err(PersistentSmtError::ConcurrentUpdate)
            }
            Err(TransactionError::Storage(error)) => Err(error.into()),
        }
    }

    pub fn apply_batch(&self, mutations: &[SmtMutation]) -> Result<Hash256, PersistentSmtError> {
        if mutations.is_empty() {
            return self.root();
        }
        let mut seen = BTreeSet::new();
        if mutations.iter().any(|mutation| !seen.insert(mutation.key)) {
            return Err(PersistentSmtError::DuplicateMutation);
        }

        let expected_root = self.root()?;
        let mut node_overlay = BTreeMap::<Vec<u8>, Option<Hash256>>::new();
        let mut leaf_overlay = BTreeMap::<Vec<u8>, Option<Hash256>>::new();
        let mut next_root = expected_root;

        for mutation in mutations {
            let leaf_key = leaf_storage_key(mutation.key);
            leaf_overlay.insert(leaf_key, mutation.value);
            let mut current = mutation
                .value
                .map(|value| leaf_hash(self.namespace, mutation.key, value))
                .unwrap_or(self.defaults[TREE_DEPTH]);
            let terminal_key = node_storage_key(TREE_DEPTH, *mutation.key.as_bytes());
            node_overlay.insert(
                terminal_key,
                (current != self.defaults[TREE_DEPTH]).then_some(current),
            );

            for child_depth in (1..=TREE_DEPTH).rev() {
                let sibling_key =
                    node_storage_key(child_depth, sibling_prefix(mutation.key, child_depth));
                let sibling = match node_overlay.get(&sibling_key) {
                    Some(Some(hash)) => *hash,
                    Some(None) => self.defaults[child_depth],
                    None => self
                        .tree
                        .get(&sibling_key)?
                        .map(|bytes| hash_from_slice(&bytes).ok_or(PersistentSmtError::InvalidRoot))
                        .transpose()?
                        .unwrap_or(self.defaults[child_depth]),
                };
                let parent_depth = child_depth - 1;
                current = if bit_at(mutation.key, parent_depth) == 0 {
                    node_hash(self.namespace, parent_depth, current, sibling)
                } else {
                    node_hash(self.namespace, parent_depth, sibling, current)
                };
                let parent_key =
                    node_storage_key(parent_depth, canonical_prefix(mutation.key, parent_depth));
                node_overlay.insert(
                    parent_key,
                    (current != self.defaults[parent_depth]).then_some(current),
                );
            }
            next_root = current;
        }

        let result: Result<(), TransactionError<SmtAbort>> = self.tree.transaction(|tx| {
            let current_root = tx
                .get(META_ROOT)?
                .ok_or(ConflictableTransactionError::Abort(
                    SmtAbort::CorruptMetadata,
                ))?;
            if current_root.as_ref() != expected_root.as_bytes() {
                return Err(ConflictableTransactionError::Abort(
                    SmtAbort::ConcurrentUpdate,
                ));
            }
            for (key, value) in &leaf_overlay {
                match value {
                    Some(value) => {
                        tx.insert(key.as_slice(), value.as_bytes().as_slice())?;
                    }
                    None => {
                        tx.remove(key.as_slice())?;
                    }
                }
            }
            for (key, value) in &node_overlay {
                match value {
                    Some(value) => {
                        tx.insert(key.as_slice(), value.as_bytes().as_slice())?;
                    }
                    None => {
                        tx.remove(key.as_slice())?;
                    }
                }
            }
            tx.insert(META_ROOT, next_root.as_bytes().as_slice())?;
            Ok(())
        });
        match result {
            Ok(()) => {
                self.tree.flush()?;
                Ok(next_root)
            }
            Err(TransactionError::Abort(SmtAbort::ConcurrentUpdate)) => {
                Err(PersistentSmtError::ConcurrentUpdate)
            }
            Err(TransactionError::Abort(SmtAbort::CorruptMetadata)) => {
                Err(PersistentSmtError::InvalidRoot)
            }
            Err(TransactionError::Storage(error)) => {
                Err(PersistentSmtError::Transaction(error.to_string()))
            }
        }
    }

    pub fn insert(&self, key: Hash256, value: Hash256) -> Result<Hash256, PersistentSmtError> {
        self.apply_batch(&[SmtMutation {
            key,
            value: Some(value),
        }])
    }

    pub fn remove(&self, key: Hash256) -> Result<Hash256, PersistentSmtError> {
        self.apply_batch(&[SmtMutation { key, value: None }])
    }

    pub fn flush(&self) -> Result<(), PersistentSmtError> {
        self.tree.flush()?;
        Ok(())
    }
}

pub fn verify_sparse_merkle_proof(expected_root: Hash256, proof: &SparseMerkleProof) -> bool {
    if proof.siblings.len() != TREE_DEPTH {
        return false;
    }
    let defaults = default_hashes(proof.namespace);
    let mut current = proof
        .value
        .map(|value| leaf_hash(proof.namespace, proof.key, value))
        .unwrap_or(defaults[TREE_DEPTH]);
    for (offset, sibling) in proof.siblings.iter().enumerate() {
        let parent_depth = TREE_DEPTH - 1 - offset;
        current = if bit_at(proof.key, parent_depth) == 0 {
            node_hash(proof.namespace, parent_depth, current, *sibling)
        } else {
            node_hash(proof.namespace, parent_depth, *sibling, current)
        };
    }
    current == expected_root
}

fn default_hashes(namespace: Hash256) -> Vec<Hash256> {
    let mut defaults = vec![Hash256::ZERO; TREE_DEPTH + 1];
    defaults[TREE_DEPTH] = hash_parts(D_EMPTY_LEAF, &[namespace.as_bytes()]);
    for depth in (0..TREE_DEPTH).rev() {
        defaults[depth] = node_hash(namespace, depth, defaults[depth + 1], defaults[depth + 1]);
    }
    defaults
}

fn leaf_hash(namespace: Hash256, key: Hash256, value: Hash256) -> Hash256 {
    hash_parts(
        D_LEAF,
        &[namespace.as_bytes(), key.as_bytes(), value.as_bytes()],
    )
}

fn node_hash(namespace: Hash256, depth: usize, left: Hash256, right: Hash256) -> Hash256 {
    hash_parts(
        D_NODE,
        &[
            namespace.as_bytes(),
            &(depth as u16).to_be_bytes(),
            left.as_bytes(),
            right.as_bytes(),
        ],
    )
}

fn leaf_storage_key(key: Hash256) -> Vec<u8> {
    let mut storage_key = Vec::with_capacity(33);
    storage_key.push(LEAF_PREFIX);
    storage_key.extend_from_slice(key.as_bytes());
    storage_key
}

fn node_storage_key(depth: usize, prefix: [u8; 32]) -> Vec<u8> {
    let mut storage_key = Vec::with_capacity(35);
    storage_key.push(NODE_PREFIX);
    storage_key.extend_from_slice(&(depth as u16).to_be_bytes());
    storage_key.extend_from_slice(&prefix);
    storage_key
}

fn sibling_prefix(key: Hash256, child_depth: usize) -> [u8; 32] {
    let mut prefix = canonical_prefix(key, child_depth);
    let bit = child_depth - 1;
    prefix[bit / 8] ^= 1 << (7 - bit % 8);
    prefix
}

fn canonical_prefix(key: Hash256, depth: usize) -> [u8; 32] {
    let mut prefix = *key.as_bytes();
    if depth == TREE_DEPTH {
        return prefix;
    }
    let full_bytes = depth / 8;
    let remaining_bits = depth % 8;
    if remaining_bits == 0 {
        prefix[full_bytes..].fill(0);
    } else {
        prefix[full_bytes] &= 0xff << (8 - remaining_bits);
        prefix[full_bytes + 1..].fill(0);
    }
    prefix
}

fn bit_at(key: Hash256, depth: usize) -> u8 {
    (key.as_bytes()[depth / 8] >> (7 - depth % 8)) & 1
}

fn hash_from_slice(bytes: &[u8]) -> Option<Hash256> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash256::from_bytes(array))
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    #[test]
    fn membership_and_non_membership_proofs_survive_reopen() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = PersistentSparseMerkleTree::open(&db, "wes_latest", hash(1)).unwrap();
        let empty_root = tree.root().unwrap();
        let empty_proof = tree.prove(hash(7)).unwrap();
        assert!(empty_proof.value.is_none());
        assert!(verify_sparse_merkle_proof(empty_root, &empty_proof));

        tree.apply_batch(&[
            SmtMutation {
                key: hash(7),
                value: Some(hash(70)),
            },
            SmtMutation {
                key: hash(8),
                value: Some(hash(80)),
            },
        ])
        .unwrap();
        tree.flush().unwrap();
        let committed_root = tree.root().unwrap();
        let proof = tree.prove(hash(7)).unwrap();
        assert_eq!(proof.value, Some(hash(70)));
        assert!(verify_sparse_merkle_proof(committed_root, &proof));
        drop(tree);

        let reopened = PersistentSparseMerkleTree::open(&db, "wes_latest", hash(1)).unwrap();
        assert_eq!(reopened.root().unwrap(), committed_root);
        assert_eq!(reopened.get(hash(8)).unwrap(), Some(hash(80)));
        assert!(verify_sparse_merkle_proof(
            committed_root,
            &reopened.prove(hash(8)).unwrap()
        ));
    }

    #[test]
    fn deletion_restores_the_empty_root() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = PersistentSparseMerkleTree::open(&db, "delete", hash(2)).unwrap();
        let empty_root = tree.root().unwrap();
        tree.insert(hash(9), hash(90)).unwrap();
        assert_ne!(tree.root().unwrap(), empty_root);
        assert_eq!(tree.remove(hash(9)).unwrap(), empty_root);
        let proof = tree.prove(hash(9)).unwrap();
        assert!(proof.value.is_none());
        assert!(verify_sparse_merkle_proof(empty_root, &proof));
    }

    #[test]
    fn failed_batch_does_not_change_the_root() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = PersistentSparseMerkleTree::open(&db, "atomic", hash(3)).unwrap();
        let before = tree.root().unwrap();
        let duplicate = [
            SmtMutation {
                key: hash(4),
                value: Some(hash(5)),
            },
            SmtMutation {
                key: hash(4),
                value: None,
            },
        ];
        assert!(matches!(
            tree.apply_batch(&duplicate),
            Err(PersistentSmtError::DuplicateMutation)
        ));
        assert_eq!(tree.root().unwrap(), before);
        assert_eq!(tree.get(hash(4)).unwrap(), None);
    }

    #[test]
    fn tampering_and_cross_namespace_replay_fail() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = PersistentSparseMerkleTree::open(&db, "proof", hash(4)).unwrap();
        let root = tree.insert(hash(5), hash(6)).unwrap();
        let proof = tree.prove(hash(5)).unwrap();
        assert!(verify_sparse_merkle_proof(root, &proof));

        let mut tampered = proof.clone();
        tampered.siblings[0] = hash(0xff);
        assert!(!verify_sparse_merkle_proof(root, &tampered));

        let mut replay = proof;
        replay.namespace = hash(5);
        assert!(!verify_sparse_merkle_proof(root, &replay));
        assert!(matches!(
            PersistentSparseMerkleTree::open(&db, "proof", hash(5)),
            Err(PersistentSmtError::NamespaceMismatch)
        ));
    }
}
