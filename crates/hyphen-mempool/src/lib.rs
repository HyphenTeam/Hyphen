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

/// Proof that full consensus validation has been performed.
///
/// Callers MUST execute CLSAG + TERA + MD-VRE + balance + range-proof
/// validation before constructing this token. The mempool will refuse
/// transactions without it.
pub struct Validated {
    vre_quality: i64,
}

/// Proof that a non-payment protocol transaction was checked by the canonical
/// chain state machine at the next height.
pub struct ValidatedProtocol(());

impl ValidatedProtocol {
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for ValidatedProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Validated {
    /// Create a validation proof carrying the VRE quality score (0–10 000).
    pub fn new(vre_quality: i64) -> Self {
        Self { vre_quality }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Priority {
    neg_fee_density: i64,
    neg_vre_quality: i64,
    tx_hash: Hash256,
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
    protocol_entries: BTreeMap<Hash256, Vec<u8>>,
    max_entries: usize,
}

impl Mempool {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            by_priority: BTreeMap::new(),
            key_images: HashSet::new(),
            protocol_entries: BTreeMap::new(),
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.protocol_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.protocol_entries.is_empty()
    }

    pub fn insert(&mut self, tx: Transaction, proof: Validated) -> Result<Hash256> {
        let tx_hash = tx.hash();

        if self.entries.contains_key(&tx_hash) || self.protocol_entries.contains_key(&tx_hash) {
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

        if self.len() >= self.max_entries {
            if let Some((&worst_prio, &worst_hash)) = self.by_priority.iter().next_back() {
                if -fee_density >= worst_prio.neg_fee_density {
                    return Err(MempoolError::FeeTooLow);
                }
                self.remove_internal(&worst_hash);
            }
        }

        let prio = Priority {
            neg_fee_density: -fee_density,
            neg_vre_quality: -proof.vre_quality,
            tx_hash,
        };

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

    pub fn insert_protocol(
        &mut self,
        bytes: Vec<u8>,
        _proof: ValidatedProtocol,
    ) -> Result<Hash256> {
        let hash = hyphen_crypto::blake3_hash(&bytes);
        if self.entries.contains_key(&hash) || self.protocol_entries.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        if self.len() >= self.max_entries {
            return Err(MempoolError::Full);
        }
        self.protocol_entries.insert(hash, bytes);
        Ok(hash)
    }

    /// Returns owned canonical payloads so payment and protocol transactions
    /// share the same byte budget and block ordering path.
    pub fn get_block_candidate_blobs(&self, max_size: usize) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut total_size = 0usize;
        for tx_hash in self.by_priority.values() {
            let Some(entry) = self.entries.get(tx_hash) else {
                continue;
            };
            if total_size.saturating_add(entry.serialised_size) > max_size {
                continue;
            }
            total_size += entry.serialised_size;
            result.push(entry.tx.serialise());
        }
        for bytes in self.protocol_entries.values() {
            if total_size.saturating_add(bytes.len()) > max_size {
                continue;
            }
            total_size += bytes.len();
            result.push(bytes.clone());
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

    pub fn purge_confirmed_protocol(&mut self, transaction_hashes: &[Hash256]) {
        for hash in transaction_hashes {
            self.protocol_entries.remove(hash);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.values().map(|e| &e.tx)
    }

    pub fn hashes(&self) -> Vec<Hash256> {
        self.entries
            .keys()
            .chain(self.protocol_entries.keys())
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_crypto::{Hash256, SecretKey};
    use hyphen_state::{
        wes_owner_policy, SignedStateCreate, StateClass, StateRecord, StateStatus, WesTransaction,
    };

    #[test]
    fn h_wes_envelope_uses_protocol_capacity_ordering_and_purge() {
        let owner = SecretKey([41; 32]);
        let transaction = WesTransaction::Create(
            SignedStateCreate::sign(
                StateRecord {
                    chain_id: Hash256::from_bytes([42; 32]),
                    class: StateClass::ContractStorage,
                    key: Hash256::from_bytes([43; 32]),
                    version: 0,
                    value_hash: Hash256::from_bytes([44; 32]),
                    owner_policy: wes_owner_policy(owner.public_key()),
                    created_at: 1,
                    lease_end: 20,
                    status: StateStatus::Live,
                },
                &owner,
            )
            .unwrap(),
        );
        let payload = transaction.encode().unwrap();
        let hash = hyphen_crypto::blake3_hash(&payload);
        let mut pool = Mempool::new(1);

        assert_eq!(
            pool.insert_protocol(payload.clone(), ValidatedProtocol::new())
                .unwrap(),
            hash
        );
        assert!(matches!(
            pool.insert_protocol(payload.clone(), ValidatedProtocol::new()),
            Err(MempoolError::Duplicate)
        ));
        assert_eq!(pool.get_block_candidate_blobs(payload.len()), vec![payload]);

        pool.purge_confirmed_protocol(&[hash]);
        assert!(pool.is_empty());
    }
}
