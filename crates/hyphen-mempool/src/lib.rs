use hyphen_crypto::Hash256;
use hyphen_tx::transaction::Transaction;
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("transaction already in mempool")]
    Duplicate,
    #[error("mempool full")]
    Full,
    #[error("double-spend: key image already in mempool")]
    DoubleSpend,
    #[error("fee too low")]
    FeeTooLow,
}

type Result<T> = std::result::Result<T, MempoolError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Priority {
    neg_fee_density: i64,
    seq: u64,
}

struct PoolEntry {
    tx: Transaction,
    #[allow(dead_code)]
    tx_hash: Hash256,
    serialised_size: usize,
    priority: Priority,
}

pub struct Mempool {
    entries: HashMap<Hash256, PoolEntry>,
    by_priority: BTreeMap<Priority, Hash256>,
    key_images: HashSet<[u8; 32]>,
    seq: u64,
    max_entries: usize,
}

impl Mempool {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_priority: BTreeMap::new(),
            key_images: HashSet::new(),
            seq: 0,
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<Hash256> {
        let tx_hash = tx.hash();

        if self.entries.contains_key(&tx_hash) {
            return Err(MempoolError::Duplicate);
        }

        // Check key image conflicts
        for inp in &tx.inputs {
            if self.key_images.contains(&inp.key_image) {
                return Err(MempoolError::DoubleSpend);
            }
        }

        let serialised_size = tx.serialise().len();
        let fee_density = if serialised_size > 0 {
            (tx.fee as i64) / (serialised_size as i64).max(1)
        } else {
            0
        };

        if self.entries.len() >= self.max_entries {
            if let Some((&worst_prio, &worst_hash)) = self.by_priority.iter().next_back() {
                if -fee_density >= worst_prio.neg_fee_density {
                    return Err(MempoolError::FeeTooLow);
                }
                self.remove_internal(&worst_hash);
            }
        }

        let prio = Priority {
            neg_fee_density: -fee_density,
            seq: self.seq,
        };
        self.seq += 1;

        for inp in &tx.inputs {
            self.key_images.insert(inp.key_image);
        }
        self.by_priority.insert(prio, tx_hash);
        self.entries.insert(
            tx_hash,
            PoolEntry {
                tx,
                tx_hash,
                serialised_size,
                priority: prio,
            },
        );

        Ok(tx_hash)
    }

    fn remove_internal(&mut self, hash: &Hash256) {
        if let Some(entry) = self.entries.remove(hash) {
            self.by_priority.remove(&entry.priority);
            for inp in &entry.tx.inputs {
                self.key_images.remove(&inp.key_image);
            }
        }
    }

    pub fn remove(&mut self, hash: &Hash256) {
        self.remove_internal(hash);
    }

    pub fn has_key_image(&self, ki: &[u8; 32]) -> bool {
        self.key_images.contains(ki)
    }

    pub fn get_block_candidates(&self, max_size: usize) -> Vec<&Transaction> {
        let mut result = Vec::new();
        let mut total_size = 0;
        for tx_hash in self.by_priority.values() {
            if let Some(entry) = self.entries.get(tx_hash) {
                if total_size + entry.serialised_size > max_size {
                    continue;
                }
                total_size += entry.serialised_size;
                result.push(&entry.tx);
            }
        }
        result
    }

    pub fn purge_confirmed(&mut self, key_images: &[[u8; 32]]) {
        let to_remove: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .tx
                    .inputs
                    .iter()
                    .any(|inp| key_images.contains(&inp.key_image))
            })
            .map(|(h, _)| *h)
            .collect();

        for h in to_remove {
            self.remove_internal(&h);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.values().map(|e| &e.tx)
    }
}
