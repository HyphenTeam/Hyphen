//! Single-use proof-of-work witness set.
//!
//! PoUW v3 accepts a chain witness exactly once. That is the whole anti-replay
//! argument of the workload: a precomputed pool of prime chains is worthless
//! because each entry can be spent a single time, so total work is conserved
//! and precomputation degenerates into mining in advance.
//!
//! The set is a sparse Merkle tree keyed by the witness, so membership,
//! insertion, removal and the accumulated root are all `O(log n)`. The root is
//! what the block header commits to, which is why a lightweight verifier can
//! follow the dataset without holding it.
//!
//! Every mutation happens inside the exclusive block-transition lock held by
//! the chain: the set is one more store in the atomic transition, and a reorg
//! removes exactly the witnesses of the reverted blocks because the undo record
//! lists them.

use hyphen_crypto::Hash256;
use thiserror::Error;

use crate::persistent_smt::{PersistentSmtError, PersistentSparseMerkleTree};

const TREE_NAME: &str = "pow_witness_smt_v1";
const NAMESPACE_DOMAIN: &[u8] = b"HYPHEN_POW_WITNESS_NAMESPACE_V1";
const KEY_DOMAIN: &[u8] = b"Hyphen/PoW/witness/v1";
const VALUE_DOMAIN: &[u8] = b"Hyphen/PoW/witness-height/v1";

#[derive(Debug, Error)]
pub enum WitnessSetError {
    #[error("witness storage: {0}")]
    Storage(String),
    #[error("witness {0} was already claimed")]
    AlreadyClaimed(u64),
}

impl From<PersistentSmtError> for WitnessSetError {
    fn from(error: PersistentSmtError) -> Self {
        Self::Storage(error.to_string())
    }
}

pub struct WitnessSet {
    tree: PersistentSparseMerkleTree,
}

impl WitnessSet {
    pub fn open(db: &sled::Db, chain_id: Hash256) -> Result<Self, WitnessSetError> {
        let namespace = hyphen_crypto::blake3_hash_many(&[NAMESPACE_DOMAIN, chain_id.as_bytes()]);
        Ok(Self {
            tree: PersistentSparseMerkleTree::open(db, TREE_NAME, namespace)?,
        })
    }

    pub fn root(&self) -> Hash256 {
        self.tree.root().unwrap_or(Hash256::ZERO)
    }

    pub fn contains(&self, witness: u64) -> Result<bool, WitnessSetError> {
        Ok(self.tree.get(witness_key(witness))?.is_some())
    }

    /// Claims a witness. Claiming one twice is the single failure this store
    /// exists to prevent, so it is an error rather than an overwrite.
    pub fn insert(&self, witness: u64, height: u64) -> Result<Hash256, WitnessSetError> {
        if self.contains(witness)? {
            return Err(WitnessSetError::AlreadyClaimed(witness));
        }
        Ok(self.tree.insert(witness_key(witness), value(height))?)
    }

    pub fn remove(&self, witness: u64) -> Result<Hash256, WitnessSetError> {
        Ok(self.tree.remove(witness_key(witness))?)
    }
}

fn witness_key(witness: u64) -> Hash256 {
    hyphen_crypto::blake3_hash_many(&[KEY_DOMAIN, &witness.to_le_bytes()])
}

fn value(height: u64) -> Hash256 {
    hyphen_crypto::blake3_hash_many(&[VALUE_DOMAIN, &height.to_le_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_set() -> WitnessSet {
        let db = sled::Config::new().temporary(true).open().unwrap();
        WitnessSet::open(&db, Hash256::from_bytes([3u8; 32])).unwrap()
    }

    #[test]
    fn claims_are_single_use() {
        let set = open_set();
        assert!(!set.contains(89).unwrap());
        set.insert(89, 1).unwrap();
        assert!(set.contains(89).unwrap());
        assert!(matches!(
            set.insert(89, 2),
            Err(WitnessSetError::AlreadyClaimed(89))
        ));
    }

    #[test]
    fn removing_restores_the_previous_root_exactly() {
        let set = open_set();
        let empty = set.root();

        let after_first = set.insert(89, 1).unwrap();
        assert_ne!(after_first, empty);
        let after_second = set.insert(179, 1).unwrap();
        assert_ne!(after_second, after_first);

        assert_eq!(set.remove(179).unwrap(), after_first);
        assert_eq!(set.remove(89).unwrap(), empty);
        assert!(!set.contains(89).unwrap());
    }

    #[test]
    fn insertion_order_does_not_change_the_root() {
        let left = open_set();
        left.insert(89, 1).unwrap();
        let left_root = left.insert(179, 1).unwrap();

        let right = open_set();
        right.insert(179, 1).unwrap();
        let right_root = right.insert(89, 1).unwrap();

        assert_eq!(left_root, right_root, "the set is order independent");
    }

    #[test]
    fn the_claimed_height_is_committed() {
        let first = open_set();
        let second = open_set();
        assert_ne!(
            first.insert(89, 1).unwrap(),
            second.insert(89, 2).unwrap(),
            "the recording height is part of the leaf value"
        );
    }

    #[test]
    fn preview_is_gone_but_single_use_is_still_the_guarantee() {
        let set = open_set();
        set.insert(3, 7).unwrap();
        set.insert(5, 7).unwrap();
        set.insert(11, 7).unwrap();
        for witness in [3u64, 5, 11] {
            assert!(set.contains(witness).unwrap());
        }
        assert!(matches!(
            set.insert(11, 8),
            Err(WitnessSetError::AlreadyClaimed(11))
        ));
    }

    #[test]
    fn sets_are_namespaced_by_chain_identity() {
        // Two identities cannot share one tree: the sparse Merkle tree refuses a
        // namespace change on an existing tree, so each chain identity owns its
        // own database file.
        let mainnet_db = sled::Config::new().temporary(true).open().unwrap();
        let devnet_db = sled::Config::new().temporary(true).open().unwrap();
        let mainnet = WitnessSet::open(&mainnet_db, Hash256::from_bytes([1u8; 32])).unwrap();
        let devnet = WitnessSet::open(&devnet_db, Hash256::from_bytes([2u8; 32])).unwrap();

        mainnet.insert(89, 1).unwrap();
        assert!(!devnet.contains(89).unwrap());
        assert_ne!(mainnet.root(), devnet.root());

        // Reopening the same identity on the same database keeps the claims.
        let reopened = WitnessSet::open(&mainnet_db, Hash256::from_bytes([1u8; 32])).unwrap();
        assert!(reopened.contains(89).unwrap());
        assert_eq!(reopened.root(), mainnet.root());

        assert!(matches!(
            WitnessSet::open(&mainnet_db, Hash256::from_bytes([9u8; 32])),
            Err(WitnessSetError::Storage(_))
        ));
    }
}
