use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::{ChainConfig, GENESIS_TIMESTAMP_MS};
use hyphen_core::FROZEN_BLOCK_VERSION;
use hyphen_crypto::Hash256;

pub fn genesis_epoch_seed(cfg: &ChainConfig) -> Hash256 {
    let params_hash = cfg.consensus_params_hash();
    hyphen_crypto::blake3_hash_many(&[b"HyphenGenesisEpoch/v2", &cfg.network_magic, &params_hash])
}

pub fn build_genesis_block(cfg: &ChainConfig) -> Block {
    let epoch_seed = genesis_epoch_seed(cfg);

    let header = BlockHeader {
        version: FROZEN_BLOCK_VERSION,
        height: 0,
        timestamp: GENESIS_TIMESTAMP_MS,
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
        block_authorization: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_deterministic_and_network_scoped() {
        let mainnet = ChainConfig::mainnet();
        let testnet = ChainConfig::testnet();
        let first = build_genesis_block(&mainnet);
        let second = build_genesis_block(&mainnet);

        assert_eq!(first.hash(), second.hash());
        assert_eq!(first.header.timestamp, GENESIS_TIMESTAMP_MS);
        assert_ne!(first.hash(), build_genesis_block(&testnet).hash());
        assert_ne!(genesis_epoch_seed(&mainnet), genesis_epoch_seed(&testnet));
    }
}
