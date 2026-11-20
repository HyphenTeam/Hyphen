use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};

use crate::authorization::BlockAuthorization;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, rustbinary::CompactBinary)]
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
        crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(self)
            .expect("header serialisation infallible")
    }

    pub fn hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash(&self.serialise_for_hash())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Block {
    pub header: BlockHeader,
    /// Cunningham origins committed in order with the parent's work commitment,
    /// or the solution components on the neural-work profile.
    pub pow_witnesses: Vec<u64>,
    pub transactions: Vec<Vec<u8>>,
    pub uncle_headers: Vec<BlockHeader>,
    /// Versioned miner authorization envelope required for post-genesis blocks.
    pub block_authorization: Vec<u8>,
}

impl Block {
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    pub fn compute_tx_root(&self) -> Hash256 {
        merkle_root_iter(
            self.transactions
                .iter()
                .map(|tx| hyphen_crypto::blake3_hash(tx)),
        )
    }

    pub fn compute_uncle_root(&self) -> Hash256 {
        merkle_root_iter(self.uncle_headers.iter().map(BlockHeader::hash))
    }

    pub fn decode_authorization(&self) -> Result<BlockAuthorization, String> {
        if self.block_authorization.len() > 256 {
            return Err("block authorization exceeds 256 bytes".into());
        }
        crate::wire_config(256)
            .deserialize(&self.block_authorization)
            .map_err(|error| format!("block authorization decode failed: {error}"))
    }

    pub fn deserialise_limited(data: &[u8], max_size: usize) -> Result<Self, rustbinary::Error> {
        crate::wire_config(max_size).deserialize(data)
    }
}

pub fn merkle_root(hashes: &[Hash256]) -> Hash256 {
    merkle_root_iter(hashes.iter().copied())
}

/// Completed subtrees in descending order of height. An unmatched right
/// subtree advances unchanged until it can be joined to its left sibling.
pub fn merkle_root_iter(hashes: impl IntoIterator<Item = Hash256>) -> Hash256 {
    let join = |left: Hash256, right: Hash256| {
        hyphen_crypto::blake3_hash_many(&[left.as_bytes(), right.as_bytes()])
    };
    let mut subtrees = Vec::new();
    for (index, mut root) in hashes.into_iter().enumerate() {
        for _ in 0..index.trailing_ones() {
            root = join(subtrees.pop().expect("one subtree per set bit"), root);
        }
        subtrees.push(root);
    }
    subtrees
        .into_iter()
        .rev()
        .reduce(|right, left| join(left, right))
        .unwrap_or(Hash256::ZERO)
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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
        let data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(self)
            .expect("receipt serialisation infallible");
        hyphen_crypto::blake3_hash(&data)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct ReceiptLog {
    pub contract: [u8; 32],
    pub topics: Vec<Hash256>,
    pub data: Vec<u8>,
}

pub fn compute_receipt_root(receipts: &[TransactionReceipt]) -> Hash256 {
    merkle_root_iter(receipts.iter().map(TransactionReceipt::hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_root_preserves_odd_leaf_promotion() {
        let leaves: Vec<_> = (0u16..257)
            .map(|n| hyphen_crypto::blake3_hash(&n.to_le_bytes()))
            .collect();
        for count in 0..=leaves.len() {
            let mut level = leaves[..count].to_vec();
            while level.len() > 1 {
                level = level
                    .chunks(2)
                    .map(|pair| match pair {
                        [left, right] => {
                            hyphen_crypto::blake3_hash_many(&[left.as_bytes(), right.as_bytes()])
                        }
                        _ => pair[0],
                    })
                    .collect();
            }
            assert_eq!(
                merkle_root(&leaves[..count]),
                level.first().copied().unwrap_or_default()
            );
        }
    }
}
