//! Deterministic genesis block.
//!
//! The genesis block is a pure function of the chain configuration, so it lives
//! next to the configuration instead of in the consensus crate. Every tool that
//! must agree on a chain identity — node, pool, miner, wallet — can derive the
//! parameters hash and the genesis hash from `ChainConfig` rather than pinning
//! literals that silently go stale when the protocol changes.

use hyphen_crypto::{blake3_hash_many, Hash256};

use crate::block::{Block, BlockHeader};
use crate::config::{ChainConfig, GENESIS_TIMESTAMP_MS};
use crate::FROZEN_BLOCK_VERSION;

/// Epoch seed of the first epoch, bound to the consensus parameters.
pub fn genesis_epoch_seed(cfg: &ChainConfig) -> Hash256 {
    let params_hash = cfg.consensus_params_hash();
    blake3_hash_many(&[b"HyphenGenesisEpoch/v2", &cfg.network_magic, &params_hash])
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
        pow_witnesses: Vec::new(),
        transactions: Vec::new(),
        uncle_headers: Vec::new(),
        block_authorization: Vec::new(),
    }
}

/// Consensus and genesis identity a peer must agree with before it exchanges
/// blocks or jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainIdentity {
    pub network_magic: [u8; 4],
    pub consensus_params_hash: [u8; 32],
    pub genesis_hash: Hash256,
}

impl ChainIdentity {
    /// Derives the identity from the configuration. Never pin literals: a
    /// consensus change must reach every participant automatically.
    pub fn of(cfg: &ChainConfig) -> Self {
        Self {
            network_magic: cfg.network_magic,
            consensus_params_hash: cfg.consensus_params_hash(),
            genesis_hash: build_genesis_block(cfg).hash(),
        }
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

    #[test]
    fn identity_tracks_the_configuration() {
        let devnet = ChainIdentity::of(&ChainConfig::devnet());
        assert_eq!(devnet.network_magic, ChainConfig::devnet().network_magic);
        assert_eq!(
            devnet.consensus_params_hash,
            ChainConfig::devnet().consensus_params_hash()
        );
        assert_eq!(
            devnet.genesis_hash,
            build_genesis_block(&ChainConfig::devnet()).hash()
        );

        let mut mutated = ChainConfig::devnet();
        mutated.epoch_length += 1;
        assert_ne!(
            ChainIdentity::of(&mutated).consensus_params_hash,
            devnet.consensus_params_hash
        );
    }
}
