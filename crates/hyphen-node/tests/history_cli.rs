use std::{path::Path, process::Command};

use hyphen_consensus::{CHAIN_ARCHIVE_VERSION, ChainArchive};
use hyphen_core::{Block, BlockAuthorization, ChainConfig, build_genesis_block};
use hyphen_crypto::SecretKey;
use hyphen_wire::{DEFAULT_WIRE_BYTES, wire_config};

#[test]
fn future_archive_has_distinct_historical_and_live_results() {
    let cfg = ChainConfig::devnet();
    let genesis = build_genesis_block(&cfg).hash();
    let suites: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/consensus-transitions-v1.json"
    ))
    .unwrap();
    let sample = suites["devnet"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["name"] == "first claim")
        .unwrap();
    let bytes = hyphen_crypto::hex_decode(sample["bytes"][0].as_str().unwrap()).unwrap();
    let mut block = Block::deserialise_limited(&bytes, cfg.max_block_size).unwrap();
    let miner = SecretKey([97; 32]);
    let keys = block.decode_authorization().unwrap();
    block.header.miner_pubkey = *miner.public_key().as_bytes();
    block.header.timestamp = hyphen_core::timestamp::ntp_adjusted_timestamp_ms() + 86_400_000;
    let signature = BlockAuthorization::sign(
        &block.header,
        cfg.network_magic,
        cfg.consensus_params_hash(),
        genesis,
        keys.reward_view_public,
        keys.reward_spend_public,
        &miner,
    )
    .unwrap();
    let wire = wire_config(DEFAULT_WIRE_BYTES);
    block.block_authorization = wire.serialize(&signature).unwrap();
    let tip = block.hash();
    let archive = ChainArchive {
        version: CHAIN_ARCHIVE_VERSION,
        network_magic: cfg.network_magic,
        consensus_params_hash: cfg.consensus_params_hash(),
        genesis_hash: genesis,
        blocks: vec![block],
    };
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("chain");
    let input = dir.path().join("future.archive");
    std::fs::write(&input, wire.serialize(&archive).unwrap()).unwrap();
    let run = |action: &str, file: &Path| {
        Command::new(env!("CARGO_BIN_EXE_hyphen-node"))
            .args(["--network", "devnet", "--data-dir"])
            .arg(&db)
            .arg(action)
            .arg(file)
            .env("RUST_LOG", "error")
            .output()
            .unwrap()
    };

    let historical = run("--verify-history", &input);
    assert!(
        historical.status.success(),
        "{}",
        String::from_utf8_lossy(&historical.stderr)
    );
    assert!(
        String::from_utf8_lossy(&historical.stdout)
            .contains(&format!("final_height=1 final_hash={tip}"))
    );
    assert!(!db.exists());

    let live = run("--replay-history", &input);
    let reason = String::from_utf8_lossy(&live.stderr);
    assert!(!live.status.success());
    assert!(
        reason.contains("archive admission at ")
            && reason.contains("height 1: timestamp too far in future"),
        "{reason}"
    );

    let exported = dir.path().join("after.archive");
    assert!(run("--export-history", &exported).status.success());
    let after: ChainArchive = wire.deserialize(&std::fs::read(exported).unwrap()).unwrap();
    assert_eq!(after.genesis_hash, genesis);
    assert!(after.blocks.is_empty());
}
