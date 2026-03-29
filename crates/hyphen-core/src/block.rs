use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Hash256,
    pub tx_root: Hash256,
    pub commitment_root: Hash256,
    pub nullifier_root: Hash256,
    pub pow_commitment: Hash256,
    pub epoch_seed: Hash256,
    pub difficulty: u64,
    pub nonce: u64,
    pub extra_nonce: [u8; 32],
}

impl BlockHeader {
    pub fn serialise_for_hash(&self) -> Vec<u8> {
        bincode::serialize(self).expect("header serialisation infallible")
    }

    pub fn hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash(&self.serialise_for_hash())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Vec<u8>>,
}

impl Block {
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    pub fn compute_tx_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::ZERO;
        }
        let mut hashes: Vec<Hash256> = self
            .transactions
            .iter()
            .map(|tx| hyphen_crypto::blake3_hash(tx))
            .collect();
        while hashes.len() > 1 {
            let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
            for chunk in hashes.chunks(2) {
                if chunk.len() == 2 {
                    next.push(hyphen_crypto::blake3_hash_many(&[
                        chunk[0].as_bytes(),
                        chunk[1].as_bytes(),
                    ]));
                } else {
                    next.push(chunk[0]);
                }
            }
            hashes = next;
        }
        hashes[0]
    }
}
