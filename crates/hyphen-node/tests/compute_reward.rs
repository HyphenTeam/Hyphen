use std::{fs, path::Path, process::Command};

use hyphen_compute::{
    ArithmeticProfile, ComputeTransaction, MIN_CHALLENGE_BLOCKS, MIN_RETENTION_BLOCKS,
    ScientificDomain, SignedResult, SignedTask, TaskSpec, inline, neural_challenge_program_hash,
};
use hyphen_consensus::{Blockchain, export_archive, replay_archive, verify_historical_archive};
use hyphen_core::{
    Block, BlockAuthorization, ChainConfig, authorization::reward_commitment, build_genesis_block,
    neural_work_commitment, neural_work_seed,
};
use hyphen_crypto::{SecretKey, StealthAddress};
use hyphen_neural::{
    ChallengeDescriptor, DESCRIPTOR_BYTES, PROFILE_SPEC, WorkDescriptor, block_work,
    encode_descriptor,
};
use hyphen_wallet::{HyphenAddress, Wallet};

fn mine(db: &Blockchain, mut blobs: Vec<Vec<u8>>, address: StealthAddress) -> Block {
    let count = blobs.len();
    let template = db.prepare_template(&mut blobs).unwrap();
    assert_eq!(
        count,
        blobs.len(),
        "template excluded a requested transaction"
    );
    let mut block = build_genesis_block(&db.cfg);
    let miner = SecretKey([31; 32]);
    let h = &mut block.header;
    h.height = template.height;
    h.prev_hash = template.parent.hash();
    h.timestamp = template.parent.timestamp + 30_000;
    h.epoch_seed = template.epoch_seed;
    h.commitment_root = template.commitment_root;
    h.nullifier_root = template.nullifier_root;
    h.state_root = template.state_root;
    h.difficulty = template.difficulty;
    h.total_fee = template.total_fee;
    h.reward = hyphen_economics::emission::lcd_base_reward(h.height, &db.cfg);
    h.miner_pubkey = miner.public_key().0;
    h.extra_nonce = reward_commitment(&address.view_public, &address.spend_public);
    let work = WorkDescriptor {
        spec: PROFILE_SPEC,
        epoch: h.height,
        threshold: h.difficulty,
        chain_seed: neural_work_seed(&h.prev_hash, h.height, &h.miner_pubkey).0,
    };
    let mut weights = [0; PROFILE_SPEC.weight_count()];
    work.derive_weights(&mut weights).unwrap();
    let nonce = (0..1_000_000)
        .find(|&n| {
            let score = block_work::nonce_score(&work, &weights, n).unwrap();
            block_work::qualifies(&work, n, score).unwrap()
        })
        .unwrap();
    block.pow_witnesses.push(nonce);
    h.pow_commitment = neural_work_commitment(
        &h.prev_hash,
        h.height,
        h.difficulty,
        &h.miner_pubkey,
        &[nonce],
    );
    block.transactions = blobs;
    block.header.tx_root = block.compute_tx_root();
    let auth = BlockAuthorization::sign(
        &block.header,
        db.cfg.network_magic,
        db.cfg.consensus_params_hash(),
        db.chain_id(),
        address.view_public,
        address.spend_public,
        &miner,
    )
    .unwrap();
    block.block_authorization = hyphen_wire::wire_config(256).serialize(&auth).unwrap();
    db.accept_block(&block).unwrap();
    block
}

fn cli(dir: &Path, task: &str, args: &[&str], success: bool) -> String {
    let result = Command::new(env!("CARGO_BIN_EXE_hyphen-compute"))
        .current_dir(dir)
        .args(["reward", task, "--data-dir", "chain"])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert_eq!(
        result.status.success(),
        success,
        "{args:?} stdout={stdout} stderr={stderr}"
    );
    if success { stdout } else { stderr }
}

#[test]
fn worker_invoice_native_payout_follows_the_canonical_task_and_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChainConfig::neural_devnet();
    let path = dir.path().join("chain");
    let open = || Blockchain::open(path.to_str().unwrap(), cfg.clone()).unwrap();
    let db = open();
    let scientist = SecretKey([14; 32]);
    let worker = SecretKey([15; 32]);
    fs::write(dir.path().join("publisher.key"), scientist.0).unwrap();
    fs::write(dir.path().join("worker.key"), worker.0).unwrap();
    let mut wallet = Wallet::from_seed([53; 32]);
    let miner_address = Wallet::from_seed([57; 32]).stealth_address();
    let payout_address = wallet.address(false).to_string();
    let descriptor = ChallengeDescriptor::new(1, PROFILE_SPEC, [44; 32]).unwrap();
    let fee = 1_000_000;
    let reward = hyphen_economics::emission::lcd_base_reward(2, &cfg) - fee;
    let spec = TaskSpec {
        chain_id: db.chain_id(),
        scientist: scientist.public_key(),
        nonce: 1,
        domain: ScientificDomain::Connectomics,
        arithmetic: ArithmeticProfile::DeterministicFixedPointV1,
        circuit_id: inline::inline_circuit_id(),
        program_hash: neural_challenge_program_hash(&descriptor).unwrap(),
        input: inline::inline_input(&descriptor).unwrap(),
        max_operations: inline::forward_operations(PROFILE_SPEC),
        challenge_blocks: MIN_CHALLENGE_BLOCKS,
        retention_blocks: MIN_RETENTION_BLOCKS,
        reward,
        publish_deadline: 64,
    };
    let id = spec.id();
    let publish = ComputeTransaction::Publish(SignedTask::sign(spec.clone(), &scientist).unwrap())
        .encode()
        .unwrap();
    mine(&db, vec![publish], miner_address);
    drop(db);
    let run = |args: &[&str], ok| cli(dir.path(), &id.to_string(), args, ok);
    let reserve = run(&["reserve", "1000000"], true);
    let address = HyphenAddress::decode(
        reserve
            .split_whitespace()
            .next()
            .unwrap()
            .strip_prefix("address=")
            .unwrap(),
    )
    .unwrap();
    assert!(
        run(
            &[
                "invoice",
                &payout_address,
                "--key-file",
                "worker.key",
                "--out",
                "early"
            ],
            false
        )
        .contains("finalized")
    );
    let db = open();
    let mut bytes = [0; DESCRIPTOR_BYTES];
    encode_descriptor(&descriptor, &mut bytes).unwrap();
    let mut proof = bytes.to_vec();
    let mut solution = [0; 16];
    descriptor.derive_preimage(&mut solution).unwrap();
    proof.extend(solution.into_iter().flat_map(i64::to_le_bytes));
    let claim = inline::inline_claim(&spec, worker.public_key(), &proof).unwrap();
    let submit = ComputeTransaction::Submit(SignedResult::sign(claim, &worker).unwrap())
        .encode()
        .unwrap();
    let index = db.tip().unwrap().total_outputs.to_string();
    mine(
        &db,
        vec![submit],
        StealthAddress {
            view_public: address.view_public,
            spend_public: address.spend_public,
        },
    );
    for _ in 0..MIN_CHALLENGE_BLOCKS {
        mine(&db, Vec::new(), miner_address);
    }
    mine(
        &db,
        vec![
            ComputeTransaction::Finalize { task_id: id }
                .encode()
                .unwrap(),
        ],
        miner_address,
    );
    let common = export_archive(&db).unwrap();
    drop(db);
    run(
        &[
            "invoice",
            &payout_address,
            "--key-file",
            "worker.key",
            "--out",
            "invoice",
        ],
        true,
    );
    let pay = |invoice, index: &str, ok| {
        run(
            &[
                "pay",
                invoice,
                index,
                "1000000",
                "--key-file",
                "publisher.key",
                "--journal",
                "publisher-journal",
                "--out",
                "claim",
            ],
            ok,
        )
    };
    assert!(pay("invoice", "0", false).contains("canonical output differs"));
    let signed = pay("invoice", &index, true);
    assert_eq!(pay("invoice", &index, true), signed);
    let image = signed.trim().split_once("reserve_spend=").unwrap().1;
    run(
        &[
            "invoice",
            &Wallet::from_seed([52; 32]).address(false).to_string(),
            "--key-file",
            "worker.key",
            "--out",
            "second",
        ],
        true,
    );
    assert!(pay("second", &index, false).contains("different payment"));
    let confirm = |ok| run(&["confirm", "invoice", image], ok);
    assert!(confirm(false).contains("no canonical reserve payout"));
    let bytes = fs::read(dir.path().join("claim")).unwrap();
    let db = open();
    mine(&db, vec![bytes.clone()], miner_address);
    drop(db);
    assert!(confirm(true).contains(&format!("net_atomic={reward}")));
    assert!(
        run(
            &["confirm", "invoice", image, "--min-confirmations", "2"],
            false
        )
        .contains("required depth")
    );
    assert!(run(&["confirm", "second", image], false).contains("payout differs"));
    let alt = Blockchain::open(dir.path().join("fork").to_str().unwrap(), cfg.clone()).unwrap();
    replay_archive(&alt, &common).unwrap();
    let replacement = [
        mine(&alt, vec![], miner_address),
        mine(&alt, vec![], miner_address),
    ];
    let db = open();
    db.accept_peer_branch(&replacement, alt.tip().unwrap().cumulative_difficulty)
        .unwrap();
    drop(db);
    assert!(confirm(false).contains("no canonical reserve payout"));
    let db = open();
    let payout_index = db.tip().unwrap().total_outputs;
    let payout = mine(&db, vec![bytes], miner_address);
    let entry = db.canonical_output(payout_index).unwrap();
    let out = &entry.transaction.outputs[entry.output_index as usize];
    assert_eq!(
        wallet
            .try_own_output(
                out.commitment.0,
                &out.one_time_pubkey,
                &out.ephemeral_pubkey,
                &out.encrypted_amount,
                payout_index,
                payout.header.height,
                0
            )
            .unwrap(),
        Some(reward)
    );
    assert_eq!(wallet.balance(), reward);
    let archive = export_archive(&db).unwrap();
    assert_eq!(
        verify_historical_archive(&cfg, &archive)
            .unwrap()
            .final_hash,
        payout.hash()
    );
    drop(db);
    let receipt = confirm(true);
    println!("{receipt}");
    if let Some(path) = std::env::var_os("HYPHEN_REWARD_TEST_ARCHIVE") {
        use std::io::Write;
        let mut file = fs::File::create_new(path).unwrap();
        file.write_all(
            &hyphen_wire::wire_config(hyphen_wire::DEFAULT_WIRE_BYTES)
                .serialize(&archive)
                .unwrap(),
        )
        .unwrap();
    }
}
