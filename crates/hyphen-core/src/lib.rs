pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::Config {
    rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
}

pub mod authorization;
pub mod block;
pub mod config;
pub mod error;
pub mod timestamp;

pub use authorization::{
    authorization_digest, AuthorizationError, BlockAuthorization, FROZEN_BLOCK_VERSION,
};
pub use block::{
    compute_receipt_root, merkle_root, Block, BlockHeader, ReceiptLog, TransactionReceipt,
};
pub use config::{
    ChainConfig, DifficultyAlgorithm, DEFAULT_EXPLORER_PORT, DEFAULT_POOL_PORT,
    DEFAULT_SEED_DOMAIN, DEFAULT_STRATUM_PORT, DEFAULT_TEMPLATE_PORT, DEVNET_DISCOVERY_PORT,
    DEVNET_P2P_PORT, DEVNET_RPC_PORT, FEATURE_CANONICAL_TX_ORDER, FEATURE_H_WES, FEATURE_MSE,
    FEATURE_TERA, FEATURE_UNCLES, FEATURE_USEFUL_WORK, FEATURE_VRE, FEATURE_WASM,
    MAINNET_DISCOVERY_PORT, MAINNET_P2P_PORT, MAINNET_RPC_PORT, RESEARCH_CONSENSUS_FEATURES,
    TESTNET_DISCOVERY_PORT, TESTNET_P2P_PORT, TESTNET_RPC_PORT,
};
pub use error::CoreError;

#[cfg(test)]
mod wire_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct WireFixture {
        tag: u8,
        count: u64,
        bytes: Vec<u8>,
        optional: Option<u32>,
    }

    #[test]
    fn rustbinary_profile_preserves_the_frozen_wire_vector() {
        let fixture = WireFixture {
            tag: 7,
            count: 0x0102,
            bytes: vec![3, 4],
            optional: Some(9),
        };
        let expected = vec![
            7, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 4, 1, 9, 0, 0, 0,
        ];

        assert_eq!(
            crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&fixture)
                .unwrap(),
            expected
        );
        assert_eq!(
            crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .deserialize::<WireFixture>(&expected)
                .unwrap(),
            fixture
        );

        let mut trailing = expected;
        trailing.push(0);
        assert!(crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .deserialize::<WireFixture>(&trailing)
            .is_err());
    }

    #[test]
    fn rustbinary_profile_enforces_byte_and_collection_limits() {
        assert!(crate::wire_config(7).serialize(&u64::MAX).is_err());
        assert!(crate::wire_config(64).serialize(&vec![(); 65]).is_err());
    }
}
