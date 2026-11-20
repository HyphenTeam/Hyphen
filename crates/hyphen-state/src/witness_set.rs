//! Single-use proof-of-work witnesses keyed by big-endian ID, with their claiming heights.

use hyphen_crypto::Hash256;
use sled::transaction::{ConflictableTransactionError, TransactionError};
use thiserror::Error;

/// Tree prefix. The chain identity is appended so two networks can never share
/// a claim set even if they are pointed at the same database file.
const INDEX_TREE_PREFIX: &str = "pow_witness_index_v2";

/// Witnesses claimed per transaction.
///
/// A block can carry thousands of witnesses. One transaction per witness costs
/// a flush per witness; one transaction for the whole block buffers the entire
/// batch in memory. A chunk bounds both.
const CLAIM_CHUNK: usize = 128;

/// Tree the previous 256-level representation used.
///
/// Claims are not migrated: the old tree stores hashed keys and node values,
/// not the witnesses themselves. Reusing a database that still holds them would
/// start the node with an empty claim index and let it accept witnesses this
/// chain has already spent, so the mismatch is refused instead.
const LEGACY_SMT_TREE: &str = "pow_witness_smt_v1";

#[derive(Debug, Error)]
pub enum WitnessSetError {
    #[error("witness storage: {0}")]
    Storage(String),
    #[error("witness {0} was already claimed")]
    AlreadyClaimed(u64),
}

impl From<sled::Error> for WitnessSetError {
    fn from(error: sled::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

pub struct WitnessSet {
    pub(crate) tree: sled::Tree,
}

impl WitnessSet {
    pub fn open(db: &sled::Db, chain_id: Hash256) -> Result<Self, WitnessSetError> {
        let mut tree_name = String::with_capacity(INDEX_TREE_PREFIX.len() + 17);
        tree_name.push_str(INDEX_TREE_PREFIX);
        tree_name.push('_');
        tree_name.push_str(&hyphen_crypto::hex_encode(&chain_id.as_bytes()[..8]));
        let tree = db.open_tree(tree_name)?;

        if tree.is_empty() {
            let legacy = db.open_tree(LEGACY_SMT_TREE)?;
            if !legacy.is_empty() {
                return Err(WitnessSetError::Storage(format!(
                    "this database holds {} entries of the legacy 256-level witness set and \
                     nothing in the claim index; those claims cannot be migrated because the \
                     old tree stores hashed keys, not witnesses. Resync {} from genesis into a \
                     fresh data directory",
                    legacy.len(),
                    chain_id,
                )));
            }
        }

        Ok(Self { tree })
    }

    /// Number of claimed witnesses. Diagnostics and operator output only.
    pub fn claimed_count(&self) -> u64 {
        self.tree.len() as u64
    }

    pub fn contains(&self, witness: u64) -> Result<bool, WitnessSetError> {
        Ok(self.tree.contains_key(key(witness))?)
    }

    /// Older nodes persisted claims before advancing the canonical tip. Rebuild
    /// their derived index once from committed blocks, including after an interrupted upgrade.
    pub fn reconcile_canonical(
        &self,
        blocks: &crate::BlockStore,
        tip: u64,
        meta: &sled::Tree,
    ) -> Result<(), WitnessSetError> {
        const FORMAT: &[u8] = b"atomic_witness_index_v1";
        if meta.contains_key(FORMAT)? {
            return Ok(());
        }
        self.tree.clear()?;
        for height in 1..=tip {
            let block = blocks
                .get_block_by_height(height)
                .map_err(|e| WitnessSetError::Storage(e.to_string()))?;
            let mut batch = sled::Batch::default();
            for witness in block.pow_witnesses {
                batch.insert(key(witness).as_slice(), &height.to_le_bytes());
            }
            self.tree.apply_batch(batch)?;
        }
        self.tree.flush()?;
        meta.insert(FORMAT, &[1])?;
        meta.flush()?;
        Ok(())
    }

    /// Claims a single witness.
    pub fn insert(&self, witness: u64, height: u64) -> Result<(), WitnessSetError> {
        self.insert_batch(&[(witness, height)])
    }

    /// Claims a block's witness list, chunked and atomic per chunk.
    pub fn insert_batch(&self, claims: &[(u64, u64)]) -> Result<(), WitnessSetError> {
        if claims.is_empty() {
            return Ok(());
        }

        let mut seen = std::collections::HashSet::with_capacity(claims.len());
        for (witness, _) in claims {
            if !seen.insert(*witness) {
                return Err(WitnessSetError::AlreadyClaimed(*witness));
            }
        }

        let mut claimed: Vec<u64> = Vec::with_capacity(claims.len());
        for chunk in claims.chunks(CLAIM_CHUNK) {
            match claim_chunk(&self.tree, chunk) {
                Ok(()) => claimed.extend(chunk.iter().map(|(witness, _)| *witness)),
                Err(error) => {
                    self.release(&claimed)?;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub fn remove(&self, witness: u64) -> Result<(), WitnessSetError> {
        self.remove_batch(&[witness])
    }

    /// Releases a block's witnesses, chunked and atomic per chunk.
    pub fn remove_batch(&self, witnesses: &[u64]) -> Result<(), WitnessSetError> {
        self.release(witnesses)
    }

    /// Best-effort release used by reorgs and by a failed claim.
    ///
    /// A failure here leaves the set stricter than the chain — the witness
    /// stays claimed although no block spends it — which costs liveness for one
    /// candidate and never admits a spent witness.
    fn release(&self, witnesses: &[u64]) -> Result<(), WitnessSetError> {
        for chunk in witnesses.chunks(CLAIM_CHUNK) {
            let result: Result<(), TransactionError<()>> = self.tree.transaction(|tx| {
                for witness in chunk {
                    tx.remove(key(*witness).as_slice())?;
                }
                Ok(())
            });
            if let Err(TransactionError::Storage(error)) = result {
                return Err(WitnessSetError::Storage(error.to_string()));
            }
        }
        Ok(())
    }
}

fn claim_chunk(tree: &sled::Tree, chunk: &[(u64, u64)]) -> Result<(), WitnessSetError> {
    let result: Result<(), TransactionError<u64>> = tree.transaction(|tx| {
        for (witness, _) in chunk {
            if tx.get(key(*witness).as_slice())?.is_some() {
                return Err(ConflictableTransactionError::Abort(*witness));
            }
        }
        for (witness, height) in chunk {
            tx.insert(key(*witness).as_slice(), &height.to_le_bytes())?;
        }
        Ok(())
    });

    match result {
        Ok(()) => Ok(()),
        Err(TransactionError::Abort(witness)) => Err(WitnessSetError::AlreadyClaimed(witness)),
        Err(TransactionError::Storage(error)) => Err(WitnessSetError::Storage(error.to_string())),
    }
}

/// Big-endian so the tree iterates in witness order, which keeps the on-disk
/// index sorted and lets an operator scan a claimed range without decoding.
fn key(witness: u64) -> [u8; 8] {
    witness.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_set() -> (sled::Db, WitnessSet) {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let set = WitnessSet::open(&db, Hash256::from_bytes([3u8; 32])).unwrap();
        (db, set)
    }

    #[test]
    fn claims_are_single_use() {
        let (_db, set) = open_set();
        assert!(!set.contains(89).unwrap());
        set.insert(89, 1).unwrap();
        assert!(set.contains(89).unwrap());
        assert!(matches!(
            set.insert(89, 2),
            Err(WitnessSetError::AlreadyClaimed(89))
        ));
    }

    #[test]
    fn releasing_restores_the_set_to_empty() {
        let (_db, set) = open_set();
        set.insert(89, 1).unwrap();
        set.insert(179, 1).unwrap();
        assert_eq!(set.claimed_count(), 2);

        set.remove_batch(&[89, 179]).unwrap();
        assert!(!set.contains(89).unwrap());
        assert!(!set.contains(179).unwrap());
        assert_eq!(set.claimed_count(), 0);

        set.insert(89, 3).unwrap();
        assert!(set.contains(89).unwrap());
    }

    #[test]
    fn a_duplicate_inside_one_batch_is_rejected_before_any_write() {
        let (_db, set) = open_set();
        assert!(matches!(
            set.insert_batch(&[(11, 1), (11, 1)]),
            Err(WitnessSetError::AlreadyClaimed(11))
        ));
        assert_eq!(set.claimed_count(), 0);
    }

    #[test]
    fn a_conflicting_batch_rolls_back_the_chunks_it_already_claimed() {
        let (_db, set) = open_set();
        set.insert(700, 1).unwrap();

        let mut claims: Vec<(u64, u64)> = (0..CLAIM_CHUNK as u64).map(|i| (i * 2 + 1, 1)).collect();
        claims.push((700, 2));

        assert!(matches!(
            set.insert_batch(&claims),
            Err(WitnessSetError::AlreadyClaimed(700))
        ));
        assert_eq!(
            set.claimed_count(),
            1,
            "only the pre-existing claim may remain after a rollback"
        );
        assert!(!set.contains(1).unwrap());
    }

    #[test]
    fn a_whole_block_batch_is_claimed_and_survives_reopen() {
        let (db, set) = open_set();
        let claims: Vec<(u64, u64)> = (0..4_096u64).map(|i| (i * 2 + 1, 7)).collect();
        set.insert_batch(&claims).unwrap();
        assert_eq!(set.claimed_count(), claims.len() as u64);

        let reopened = WitnessSet::open(&db, Hash256::from_bytes([3u8; 32])).unwrap();
        assert_eq!(reopened.claimed_count(), claims.len() as u64);
        assert!(reopened.contains(1).unwrap());
        assert!(matches!(
            reopened.insert(1, 8),
            Err(WitnessSetError::AlreadyClaimed(1))
        ));
    }

    #[test]
    fn a_database_holding_the_legacy_set_is_refused_instead_of_reset() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let legacy = db.open_tree(LEGACY_SMT_TREE).unwrap();
        legacy
            .insert(b"some-hashed-leaf", b"some-node-value")
            .unwrap();

        match WitnessSet::open(&db, Hash256::from_bytes([4u8; 32])) {
            Err(WitnessSetError::Storage(message)) => {
                assert!(
                    message.contains("legacy 256-level witness set"),
                    "the operator must be told why the node refuses to start: {message}"
                );
            }
            Err(other) => panic!("expected a storage refusal, got {other}"),
            Ok(_) => panic!("expected a refusal, got an opened set"),
        }
    }

    #[test]
    fn sets_are_namespaced_by_chain_identity() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let mainnet = WitnessSet::open(&db, Hash256::from_bytes([1u8; 32])).unwrap();
        let devnet = WitnessSet::open(&db, Hash256::from_bytes([2u8; 32])).unwrap();

        mainnet.insert(89, 1).unwrap();
        assert!(mainnet.contains(89).unwrap());
        assert!(
            !devnet.contains(89).unwrap(),
            "a claim on one chain must not be visible on another"
        );
        assert_eq!(devnet.claimed_count(), 0);
    }
}
