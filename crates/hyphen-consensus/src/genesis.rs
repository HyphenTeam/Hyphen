use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::ChainConfig;
use hyphen_crypto::Hash256;

pub fn build_genesis_block(cfg: &ChainConfig) -> Block {
    let epoch_seed = hyphen_crypto::blake3_hash(b"Hyphen_genesis_epoch_seed");

    let header = BlockHeader {
        version: 1,
        height: 0,
        timestamp: 1_750_000_000,
        prev_hash: Hash256::ZERO,
        tx_root: Hash256::ZERO,
        commitment_root: Hash256::ZERO,
        nullifier_root: Hash256::ZERO,
        pow_commitment: Hash256::ZERO,
        epoch_seed,
        difficulty: cfg.genesis_difficulty,
        nonce: 0,
        extra_nonce: [0u8; 32],
    };

    Block {
        header,
        transactions: Vec::new(),
    }
}
