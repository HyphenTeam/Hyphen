use serde::{Deserialize, Serialize};

use hyphen_core::{Block, ChainConfig};
use hyphen_crypto::Hash256;

use crate::{build_genesis_block, BlockValidator, Blockchain};

pub const CHAIN_ARCHIVE_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainArchive {
    pub version: u16,
    pub network_magic: [u8; 4],
    pub consensus_params_hash: [u8; 32],
    pub genesis_hash: Hash256,
    /// Contiguous post-genesis blocks in ascending height order.
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayReport {
    pub blocks_applied: u64,
    pub final_height: u64,
    pub final_hash: Hash256,
}

pub fn export_archive(blockchain: &Blockchain) -> Result<ChainArchive, String> {
    let tip = blockchain.tip().map_err(|error| error.to_string())?;
    let mut blocks = Vec::with_capacity(tip.height as usize);
    for height in 1..=tip.height {
        blocks.push(
            blockchain
                .blocks
                .get_block_by_height(height)
                .map_err(|error| format!("read block {height}: {error}"))?,
        );
    }
    Ok(ChainArchive {
        version: CHAIN_ARCHIVE_VERSION,
        network_magic: blockchain.cfg.network_magic,
        consensus_params_hash: blockchain.cfg.consensus_params_hash(),
        genesis_hash: build_genesis_block(&blockchain.cfg).hash(),
        blocks,
    })
}

/// Lightweight reference verification for archive framing, linkage, roots,
/// timestamps and miner authorization. Full PoW, transaction and state
/// verification is intentionally performed by `replay_archive`.
pub fn verify_archive_envelopes(
    cfg: &ChainConfig,
    archive: &ChainArchive,
    now_ms: u64,
) -> Result<ReplayReport, String> {
    verify_archive_identity(cfg, archive)?;
    let genesis = build_genesis_block(cfg);
    let validator = BlockValidator::new(cfg);
    let mut previous_height = 0;
    let mut previous_hash = genesis.hash();
    let mut previous_timestamp = genesis.header.timestamp;

    for block in &archive.blocks {
        validator
            .validate_header(
                &block.header,
                previous_height,
                &previous_hash,
                previous_timestamp,
                now_ms,
            )
            .map_err(|error| format!("height {}: {error}", block.header.height))?;
        validator
            .validate_tx_root(block)
            .map_err(|error| format!("height {}: {error}", block.header.height))?;
        validator
            .validate_uncle_root(block)
            .map_err(|error| format!("height {}: {error}", block.header.height))?;
        validator
            .validate_block_authorization(block, genesis.hash())
            .map_err(|error| format!("height {}: {error}", block.header.height))?;

        previous_height = block.header.height;
        previous_hash = block.hash();
        previous_timestamp = block.header.timestamp;
    }

    Ok(ReplayReport {
        blocks_applied: archive.blocks.len() as u64,
        final_height: previous_height,
        final_hash: previous_hash,
    })
}

/// Replays every archived block through the authoritative state transition.
/// The target database must contain only the matching genesis block.
pub fn replay_archive(
    blockchain: &Blockchain,
    archive: &ChainArchive,
) -> Result<ReplayReport, String> {
    verify_archive_identity(&blockchain.cfg, archive)?;
    let tip = blockchain.tip().map_err(|error| error.to_string())?;
    if tip.height != 0 {
        return Err(format!(
            "replay target is not fresh: expected height 0, got {}",
            tip.height
        ));
    }

    for block in &archive.blocks {
        blockchain
            .accept_block(block)
            .map_err(|error| format!("replay rejected height {}: {error}", block.header.height))?;
    }
    let tip = blockchain.tip().map_err(|error| error.to_string())?;
    Ok(ReplayReport {
        blocks_applied: archive.blocks.len() as u64,
        final_height: tip.height,
        final_hash: tip.hash,
    })
}

fn verify_archive_identity(cfg: &ChainConfig, archive: &ChainArchive) -> Result<(), String> {
    if archive.version != CHAIN_ARCHIVE_VERSION {
        return Err(format!(
            "unsupported chain archive version {}",
            archive.version
        ));
    }
    if archive.network_magic != cfg.network_magic
        || archive.consensus_params_hash != cfg.consensus_params_hash()
        || archive.genesis_hash != build_genesis_block(cfg).hash()
    {
        return Err("chain archive identity does not match the selected network".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::{BlockAuthorization, FROZEN_BLOCK_VERSION};
    use hyphen_crypto::SecretKey;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ChainIdentityVector {
        profile: String,
        network_magic: String,
        consensus_params_hash: String,
        genesis_hash: String,
    }

    fn signed_child(cfg: &ChainConfig) -> Block {
        let genesis = build_genesis_block(cfg);
        let miner = SecretKey([41u8; 32]);
        let mut header = genesis.header.clone();
        header.version = FROZEN_BLOCK_VERSION;
        header.height = 1;
        header.timestamp = genesis.header.timestamp + 1;
        header.prev_hash = genesis.hash();
        header.miner_pubkey = *miner.public_key().as_bytes();
        let authorization = BlockAuthorization::sign(
            &header,
            cfg.network_magic,
            cfg.consensus_params_hash(),
            genesis.hash(),
            [42u8; 32],
            [43u8; 32],
            &miner,
        )
        .unwrap();
        Block {
            header,
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: hyphen_codec::serialize(&authorization).unwrap(),
        }
    }

    #[test]
    fn empty_archive_is_a_valid_genesis_replay_vector() {
        let cfg = ChainConfig::testnet();
        let genesis = build_genesis_block(&cfg);
        let archive = ChainArchive {
            version: CHAIN_ARCHIVE_VERSION,
            network_magic: cfg.network_magic,
            consensus_params_hash: cfg.consensus_params_hash(),
            genesis_hash: genesis.hash(),
            blocks: Vec::new(),
        };
        let report = verify_archive_envelopes(&cfg, &archive, u64::MAX).unwrap();
        assert_eq!(report.blocks_applied, 0);
        assert_eq!(report.final_height, 0);
        assert_eq!(report.final_hash, genesis.hash());
    }

    #[test]
    fn published_chain_identity_vectors_match_the_implementation() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/chain-identity-v2.json"
        );
        let bytes = std::fs::read(path).expect("read published chain identity vectors");
        let vectors: Vec<ChainIdentityVector> =
            serde_json::from_slice(&bytes).expect("parse published chain identity vectors");
        assert_eq!(vectors.len(), 3);

        for vector in vectors {
            let cfg = match vector.profile.as_str() {
                "devnet-v2" => ChainConfig::devnet(),
                "testnet-research" => ChainConfig::testnet(),
                "mainnet-research" => ChainConfig::mainnet(),
                other => panic!("unknown chain identity vector profile {other}"),
            };
            assert_eq!(hex::encode(cfg.network_magic), vector.network_magic);
            assert_eq!(
                hex::encode(cfg.consensus_params_hash()),
                vector.consensus_params_hash
            );
            assert_eq!(
                build_genesis_block(&cfg).hash().to_string(),
                vector.genesis_hash
            );
        }
    }

    #[test]
    fn archive_is_network_bound() {
        let testnet = ChainConfig::testnet();
        let mainnet = ChainConfig::mainnet();
        let archive = ChainArchive {
            version: CHAIN_ARCHIVE_VERSION,
            network_magic: testnet.network_magic,
            consensus_params_hash: testnet.consensus_params_hash(),
            genesis_hash: build_genesis_block(&testnet).hash(),
            blocks: Vec::new(),
        };
        assert!(verify_archive_envelopes(&mainnet, &archive, u64::MAX)
            .unwrap_err()
            .contains("identity"));
    }

    #[test]
    fn reference_verifier_rejects_height_gaps() {
        let cfg = ChainConfig::devnet();
        let genesis = build_genesis_block(&cfg);
        let mut child = signed_child(&cfg);
        child.header.height = 2;
        let archive = ChainArchive {
            version: CHAIN_ARCHIVE_VERSION,
            network_magic: cfg.network_magic,
            consensus_params_hash: cfg.consensus_params_hash(),
            genesis_hash: genesis.hash(),
            blocks: vec![child],
        };
        assert!(verify_archive_envelopes(&cfg, &archive, u64::MAX)
            .unwrap_err()
            .contains("invalid block height"));
    }

    #[test]
    fn reference_verifier_rejects_transaction_root_tampering() {
        let cfg = ChainConfig::devnet();
        let genesis = build_genesis_block(&cfg);
        let mut child = signed_child(&cfg);
        child.transactions.push(vec![0xde, 0xad, 0xbe, 0xef]);
        let archive = ChainArchive {
            version: CHAIN_ARCHIVE_VERSION,
            network_magic: cfg.network_magic,
            consensus_params_hash: cfg.consensus_params_hash(),
            genesis_hash: genesis.hash(),
            blocks: vec![child],
        };
        assert!(verify_archive_envelopes(&cfg, &archive, u64::MAX)
            .unwrap_err()
            .contains("tx root mismatch"));
    }

    #[test]
    fn reference_verifier_rejects_authorization_tampering() {
        let cfg = ChainConfig::devnet();
        let genesis = build_genesis_block(&cfg);
        let mut child = signed_child(&cfg);
        let last = child.block_authorization.last_mut().unwrap();
        *last ^= 0x80;
        let archive = ChainArchive {
            version: CHAIN_ARCHIVE_VERSION,
            network_magic: cfg.network_magic,
            consensus_params_hash: cfg.consensus_params_hash(),
            genesis_hash: genesis.hash(),
            blocks: vec![child],
        };
        assert!(verify_archive_envelopes(&cfg, &archive, u64::MAX)
            .unwrap_err()
            .contains("authorization"));
    }
}
