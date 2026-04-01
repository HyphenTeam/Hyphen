use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::ChainConfig;
use hyphen_core::timestamp;
use hyphen_crypto::Hash256;

pub fn build_genesis_block(cfg: &ChainConfig) -> Block {
    let epoch_seed = hyphen_crypto::blake3_hash(b"Hyphen_genesis_epoch_seed");

    let header = BlockHeader {
        version: 1,
        height: 0,
        timestamp: timestamp::ntp_adjusted_timestamp_ms(),
        prev_hash: Hash256::ZERO,
        tx_root: Hash256::ZERO,
        commitment_root: Hash256::ZERO,
        nullifier_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
        receipt_root: Hash256::ZERO,
        uncle_root: Hash256::ZERO,
        pow_commitment: Hash256::ZERO,
        epoch_seed,
        difficulty: cfg.genesis_difficulty,
        nonce: 0,
        extra_nonce: [0u8; 32],
        miner_pubkey: [0u8; 32],
        total_fee: 0,
        reward: cfg.initial_reward,
        view_tag: 0,
        block_size: 0,
    };

    Block {
        header,
        transactions: Vec::new(),
        uncle_headers: Vec::new(),
        pq_signature: Vec::new(),
    }
}
