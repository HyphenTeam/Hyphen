// The wire profile and its container adapters live in `hyphen-wire` so the
// node, pool, miner and wallet cannot drift apart by re-implementing them.
pub use hyphen_wire::{wire_config, CanonicalSet, DEFAULT_WIRE_BYTES, MAX_WIRE_COLLECTION_ITEMS};

pub mod authorization;
pub mod block;
pub mod config;
pub mod error;
pub mod genesis;
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
pub use genesis::{build_genesis_block, genesis_epoch_seed, ChainIdentity};

#[cfg(test)]
mod wire_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize, rustbinary::CompactBinary)]
    struct WireFixture {
        tag: u8,
        count: u64,
        bytes: Vec<u8>,
        optional: Option<u32>,
    }

    /// Freezes the chain's byte image.
    ///
    /// The expected bytes are the *only* encoding this fixture may have: fields
    /// in declaration order with no names and no tags, `count` as a canonical
    /// little-endian varint (`251 2 1` = `0x0102`), `Vec<u8>` as a length-prefixed
    /// blob, `Some(9)` as a presence byte plus a varint. Any change here is a
    /// consensus change and must arrive with a new chain identity vector.
    #[test]
    fn rustbinary_profile_preserves_the_frozen_wire_vector() {
        let fixture = WireFixture {
            tag: 7,
            count: 0x0102,
            bytes: vec![3, 4],
            optional: Some(9),
        };
        let expected = vec![7, 251, 2, 1, 2, 3, 4, 1, 9];

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

    /// Both budgets bind: a caller's byte budget and the element budget derived
    /// from it. `Option::None` is a single presence byte, so the encoder cannot
    /// dodge either budget by writing nothing.
    #[test]
    fn wire_profile_enforces_byte_and_element_budgets() {
        assert!(crate::wire_config(7).serialize(&u64::MAX).is_err());
        assert!(crate::wire_config(64).serialize(&vec![0u8; 65]).is_err());
        assert!(crate::wire_config(64).serialize(&vec![0u8; 32]).is_ok());
        assert!(crate::wire_config(64)
            .serialize(&vec![Some(1u16); 65])
            .is_err());
    }
}
