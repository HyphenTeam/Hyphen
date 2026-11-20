use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Suite {
    profile: String,
    genesis: String,
    observation_ms: u64,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    name: String,
    parent: String,
    operation: String,
    bytes: Vec<String>,
    prefix_hash: Option<String>,
    work: Option<u128>,
    error: Option<String>,
    post: serde_json::Value,
}

fn state(chain: &Blockchain) -> serde_json::Value {
    let tip = chain.tip().unwrap();
    serde_json::json!({"tip":tip.hash.to_string(),"height":tip.height,"cumulative_weight":tip.cumulative_difficulty,
        "protocol_root":chain.state_root().unwrap().to_string(),"output_root":chain.commitment_tree.read().root().to_string(),
        "nullifier_root":chain.nullifiers.root_hash().unwrap().to_string(),"claims":chain.witnesses.claimed_count(),
        "work_commitment":chain.blocks.get_block_by_height(tip.height).unwrap().header.pow_commitment.to_string()})
}

fn apply(
    chain: &Blockchain,
    op: &str,
    bytes: &[Vec<u8>],
    work: Option<u128>,
    observation_ms: u64,
) -> Result<(), CoreError> {
    if op == "check_transactions" {
        return chain
            .validate_transaction_blobs_for_height(bytes, chain.height()? + 1)
            .map(|_| ());
    }
    let blocks: Vec<_> = bytes
        .iter()
        .map(|raw| Block::deserialise_limited(raw, chain.cfg.max_block_size).unwrap())
        .collect();
    match op {
        "accept" => {
            assert_eq!(blocks.len(), 1);
            chain.accept_block_at(&blocks[0], observation_ms)
        }
        "reorg" => chain
            .accept_peer_branch_at(&blocks, work.unwrap(), observation_ms)
            .map(|_| ()),
        _ => panic!("unknown operation {op}"),
    }
}

#[test]
fn frozen_transition_vectors() {
    let suites: BTreeMap<String, Suite> = serde_json::from_str(include_str!(
        "../../../test-vectors/consensus-transitions-v1.json"
    ))
    .unwrap();
    assert_eq!(suites.len(), 3);
    for suite in suites.values() {
        let cfg = match suite.profile.as_str() {
            "devnet" => ChainConfig::devnet(),
            "offline-devnet" => ChainConfig::offline_devnet(),
            "compute-devnet" => ChainConfig::compute_devnet(),
            p => panic!("unknown profile {p}"),
        };
        let chain =
            Blockchain::open_db(sled::Config::new().temporary(true).open().unwrap(), cfg).unwrap();
        assert_eq!(chain.chain_id().to_string(), suite.genesis);
        for step in &suite.steps {
            assert_eq!(chain.tip().unwrap().hash.to_string(), step.parent);
            let bytes = step
                .bytes
                .iter()
                .map(|v| hyphen_crypto::hex_decode(v).unwrap())
                .collect::<Vec<_>>();
            if let Some(expected) = &step.prefix_hash {
                assert_eq!(step.operation, "check_transactions");
                assert_eq!(bytes.len(), 1);
                let tx = Transaction::deserialise_limited(&bytes[0]).unwrap();
                assert_eq!(&tx.prefix_hash().to_string(), expected);
            }
            let observed = apply(
                &chain,
                &step.operation,
                &bytes,
                step.work,
                suite.observation_ms,
            )
            .err()
            .map(|e| e.to_string());
            assert_eq!(observed, step.error, "{}", step.name);
            assert_eq!(state(&chain), step.post, "{}", step.name);
        }
    }
}

#[test]
fn profile_table_matches_node_verifiers_and_parameters() {
    use hyphen_compute::{neural_circuit_id, neural_work_circuit_id};
    use hyphen_core::config::{DifficultyAlgorithm, STATE_TRANSITION_VERSION};
    let table = include_str!("../../../wiki/Consensus-Profiles.md");
    let profiles = [
        ("mainnet", ChainConfig::mainnet()),
        ("testnet", ChainConfig::testnet()),
        ("devnet", ChainConfig::devnet()),
        ("contract-devnet", ChainConfig::contract_devnet()),
        ("compute-devnet", ChainConfig::compute_devnet()),
        ("offline-devnet", ChainConfig::offline_devnet()),
        ("neural-devnet", ChainConfig::neural_devnet()),
    ];
    for (name, cfg) in profiles {
        let row = table
            .lines()
            .find(|s| s.starts_with(&format!("| `{name}` /")))
            .unwrap();
        let cols = row
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert!(cols[0].contains(std::str::from_utf8(&cfg.network_magic).unwrap()));
        assert_eq!(
            cols[1],
            format!(
                "{} / {}",
                hyphen_core::FROZEN_BLOCK_VERSION,
                STATE_TRANSITION_VERSION
            )
        );
        let mask = cols[2].split('`').nth(1).unwrap();
        assert_eq!(
            u32::from_str_radix(mask.trim_start_matches("0x"), 16).unwrap(),
            cfg.consensus_features
        );
        if cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            assert!(cols[3].starts_with("Parent-derived neural"));
            assert_eq!(cfg.neural_work_initial_threshold, 1 << 56);
        } else {
            let algorithm = match cfg.difficulty_algorithm {
                DifficultyAlgorithm::LwmaV1 => "LWMA",
                DifficultyAlgorithm::MomentumDampedLwmaV2 => "momentum LWMA",
            };
            assert_eq!(cols[3], format!("C{}, {algorithm}", cfg.pouw_chain_length));
            assert_eq!(
                cols[4],
                format!(
                    "{} / {} / {}",
                    cfg.block_time.as_secs(),
                    cfg.difficulty_window,
                    cfg.genesis_difficulty
                )
            );
        }
        let chain =
            Blockchain::open_db(sled::Config::new().temporary(true).open().unwrap(), cfg).unwrap();
        let verifier = &chain.compute_verifier;
        assert!(!verifier.supports(neural_circuit_id(), 1));
        assert_eq!(
            verifier.supports(neural_work_circuit_id(), 2),
            cols[5] == "Work v1, system 2"
        );
        assert_eq!(
            verifier.supports(inline_circuit_id(), 3),
            cols[5] == "Inline Alice v1, system 3"
        );
    }
}

#[test]
fn retarget_boundary_vectors() {
    #[derive(Deserialize)]
    struct Vector {
        profile: String,
        timestamps: Vec<u64>,
        difficulties: Vec<u64>,
        expected_raw: u64,
        expected_count: u64,
    }
    let data: Vec<Vector> = serde_json::from_str(include_str!(
        "../../../test-vectors/retarget-boundaries-v1.json"
    ))
    .unwrap();
    for v in data {
        let cfg = match v.profile.as_str() {
            "mainnet" => ChainConfig::mainnet(),
            "devnet" => ChainConfig::devnet(),
            _ => panic!("unknown profile"),
        };
        let raw = next_difficulty(&v.timestamps, &v.difficulties, &cfg);
        assert_eq!(raw, v.expected_raw, "{:?}", v.timestamps);
        assert_eq!(raw.clamp(1, MAX_WITNESSES_PER_BLOCK), v.expected_count);
    }
}

#[test]
fn payment_boundary_vectors() {
    use curve25519_dalek::scalar::Scalar;
    use hyphen_crypto::{Commitment, PedersenGens, hex_decode};
    use hyphen_proof::AggregatedRangeProof;

    #[derive(Deserialize)]
    struct RangeCase {
        amount: String,
        mask_le: String,
        proof: String,
        commitment: String,
        outside_amount: String,
        outside_commitment: String,
    }
    #[derive(Deserialize)]
    struct ClaimCase {
        bytes: String,
        canonical_index: u64,
        key: String,
        commitment: String,
        valid_genesis: String,
        foreign_genesis: String,
        foreign_error: String,
    }
    #[derive(Deserialize)]
    struct Cases {
        range: Vec<RangeCase>,
        claim: ClaimCase,
    }

    let cases: Cases = serde_json::from_str(include_str!(
        "../../../test-vectors/payment-boundaries-v1.json"
    ))
    .unwrap();
    let field = |s: &str| -> [u8; 32] { hex_decode(s).unwrap().try_into().unwrap() };
    for case in cases.range {
        let proof: AggregatedRangeProof = hyphen_core::wire_config(4096)
            .deserialize(&hex_decode(&case.proof).unwrap())
            .unwrap();
        let mask = Scalar::from_canonical_bytes(field(&case.mask_le)).unwrap();
        let amount = case.amount.parse::<u64>().unwrap();
        let point = Commitment::create(amount, mask);
        assert_eq!(point.0, field(&case.commitment));
        proof.verify(&[point.to_point().unwrap()]).unwrap();
        let outside = match case.outside_amount.as_str() {
            "-1" => -Scalar::ONE,
            "18446744073709551616" => Scalar::from(u64::MAX) + Scalar::ONE,
            value => panic!("unexpected boundary {value}"),
        };
        let invalid = PedersenGens::default().commit(outside, mask);
        assert_eq!(
            invalid.compress().to_bytes(),
            field(&case.outside_commitment)
        );
        assert!(proof.verify(&[invalid]).is_err());
    }
    let c = cases.claim;
    assert_eq!(
        c.valid_genesis,
        build_genesis_block(&ChainConfig::offline_devnet())
            .hash()
            .to_string()
    );
    assert_eq!(
        c.foreign_genesis,
        build_genesis_block(&ChainConfig::devnet())
            .hash()
            .to_string()
    );
    let tx = Transaction::deserialise_limited(&hex_decode(&c.bytes).unwrap()).unwrap();
    let check = |genesis: &str| {
        hyphen_tx::offline::verify_claim(
            &tx,
            Hash256(field(genesis)),
            c.canonical_index,
            field(&c.key),
            Commitment(field(&c.commitment)),
        )
    };
    check(&c.valid_genesis).unwrap();
    assert_eq!(check(&c.foreign_genesis), Err(c.foreign_error.as_str()));
}
