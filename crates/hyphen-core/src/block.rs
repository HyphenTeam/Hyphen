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
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    pub uncle_root: Hash256,

    pub pow_commitment: Hash256,
    pub epoch_seed: Hash256,
    pub difficulty: u64,
    pub nonce: u64,
    pub extra_nonce: [u8; 32],

    pub miner_pubkey: [u8; 32],
    pub total_fee: u64,
    pub reward: u64,
    pub view_tag: u8,
    pub block_size: u32,
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
    pub uncle_headers: Vec<BlockHeader>,
    pub pq_signature: Vec<u8>,
}

impl Block {
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    pub fn compute_tx_root(&self) -> Hash256 {
        merkle_root(
            &self
                .transactions
                .iter()
                .map(|tx| hyphen_crypto::blake3_hash(tx))
                .collect::<Vec<_>>(),
        )
    }

    pub fn compute_uncle_root(&self) -> Hash256 {
        let uncle_hashes: Vec<Hash256> = self.uncle_headers.iter().map(|h| h.hash()).collect();
        merkle_root(&uncle_hashes)
    }
}

pub fn merkle_root(hashes: &[Hash256]) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }
    let mut current: Vec<Hash256> = hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                next.push(hyphen_crypto::blake3_hash_many(&[
                    chunk[0].as_bytes(),
                    chunk[1].as_bytes(),
                ]));
            } else {
                next.push(chunk[0]);
            }
        }
        current = next;
    }
    current[0]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: Hash256,
    pub success: bool,
    pub gas_used: u64,
    pub cumulative_gas: u64,
    pub logs: Vec<ReceiptLog>,
    pub state_root_after: Hash256,
}

impl TransactionReceipt {
    pub fn hash(&self) -> Hash256 {
        let data = bincode::serialize(self).expect("receipt serialisation infallible");
        hyphen_crypto::blake3_hash(&data)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptLog {
    pub contract: [u8; 32],
    pub topics: Vec<Hash256>,
    pub data: Vec<u8>,
}

pub fn compute_receipt_root(receipts: &[TransactionReceipt]) -> Hash256 {
    let hashes: Vec<Hash256> = receipts.iter().map(|r| r.hash()).collect();
    merkle_root(&hashes)
}
