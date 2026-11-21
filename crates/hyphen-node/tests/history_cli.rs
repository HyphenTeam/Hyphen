use std::{path::Path, process::Command};

use hyphen_consensus::{CHAIN_ARCHIVE_VERSION, ChainArchive};
use hyphen_core::{BlockAuthorization, ChainConfig, build_genesis_block};
use hyphen_crypto::SecretKey;
use hyphen_wire::{DEFAULT_WIRE_BYTES, wire_config};

#[test]
fn future_archive_has_distinct_historical_and_live_results() {
    let cfg = ChainConfig::neural_devnet();
    let mut block = build_genesis_block(&cfg);
    let genesis = block.hash();
    let scratch = tempfile::tempdir().unwrap();
    let chain =
        hyphen_consensus::Blockchain::open(scratch.path().to_str().unwrap(), cfg.clone()).unwrap();
    let template = chain.prepare_template(&mut Vec::new()).unwrap();
    block.header.height = 1;
    block.header.prev_hash = genesis;
    block.header.difficulty = template.difficulty;
    block.header.reward = hyphen_economics::emission::block_reward(1, &cfg);
    block.header.commitment_root = template.commitment_root;
    block.header.nullifier_root = template.nullifier_root;
    block.header.state_root = template.state_root;
    let miner = SecretKey([97; 32]);
    let (_, _, keys) = hyphen_crypto::stealth::generate_keys();
    block.header.extra_nonce =
        hyphen_core::authorization::reward_commitment(&keys.view_public, &keys.spend_public);
    block.header.miner_pubkey = *miner.public_key().as_bytes();
    let work = hyphen_neural::WorkDescriptor {
        epoch: 1,
        spec: hyphen_neural::PROFILE_SPEC,
        threshold: template.difficulty,
        chain_seed: *hyphen_core::neural_work_seed(&genesis, 1, &block.header.miner_pubkey)
            .as_bytes(),
    };
    let mut weights = vec![0; work.spec.weight_count()];
    work.derive_weights(&mut weights).unwrap();
    let nonce = (0..1_000_000)
        .find(|&n| {
            let score = hyphen_neural::block_work::nonce_score(&work, &weights, n).unwrap();
            hyphen_neural::block_work::qualifies(&work, n, score).unwrap()
        })
        .unwrap();
    block.pow_witnesses = vec![nonce];
    block.header.pow_commitment = hyphen_core::neural_work_commitment(
        &genesis,
        1,
        template.difficulty,
        &block.header.miner_pubkey,
        &[nonce],
    );
    block.header.timestamp = hyphen_core::timestamp::ntp_adjusted_timestamp_ms() + 86_400_000;
    let signature = BlockAuthorization::sign(
        &block.header,
        cfg.network_magic,
        cfg.consensus_params_hash(),
        genesis,
        keys.view_public,
        keys.spend_public,
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
            .args(["--network", "neural-devnet", "--data-dir"])
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
