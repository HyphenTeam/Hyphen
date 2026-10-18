//! Executes the real Alice contract module in the chain's own VM.
//!
//! The module is built from `contracts/alice-neural` and read from its release
//! target directory so this test runs without a nested Cargo invocation. CI
//! builds the module first and sets `HYPHEN_REQUIRE_ALICE_WASM=1`, which turns a
//! missing artifact into a hard failure instead of a skip.

use std::path::PathBuf;

use hyphen_neural::{
    encode_open, encode_submit, solve, ChallengeDescriptor, MlpSpec, SolveConfig, DESCRIPTOR_BYTES,
};
use hyphen_vm::types::{ContractCall, ContractResult, DeployParams};
use hyphen_vm::{Contract, VmEngine};

const GAS: u64 = 50_000_000;

fn wasm_path() -> PathBuf {
    if let Ok(path) = std::env::var("ALICE_NEURAL_WASM") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../contracts/alice-neural/target/wasm32-unknown-unknown/release/alice_neural_contract.wasm",
    )
}

fn load_wasm() -> Option<Vec<u8>> {
    let path = wasm_path();
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            let required = std::env::var("HYPHEN_REQUIRE_ALICE_WASM").as_deref() == Ok("1");
            assert!(
                !required,
                "Alice contract artifact is required but unreadable at {}: {error}",
                path.display()
            );
            eprintln!(
                "skipping Alice contract integration test: {} is absent ({error}); \
                 build it with scripts/build-alice-contract.ps1",
                path.display()
            );
            None
        }
    }
}

fn descriptor() -> ChallengeDescriptor {
    // Deliberately narrower than the maximum: the settlement record then has a
    // length that is not the full buffer, which is what the status path must
    // decode correctly.
    ChallengeDescriptor::new(
        1,
        MlpSpec {
            input_dim: 8,
            hidden_dim: 16,
            output_dim: 8,
        },
        [0x44; 32],
    )
    .unwrap()
}

#[test]
fn the_contract_opens_verifies_and_settles_an_epoch() {
    let Some(wasm) = load_wasm() else {
        return;
    };
    let descriptor = descriptor();
    let mut engine = VmEngine::new();
    let (contract, deployed) = engine
        .deploy(
            &DeployParams {
                deployer: [7u8; 32],
                code: wasm,
                constructor_args: Vec::new(),
                gas_limit: GAS,
                nonce: 0,
            },
            1,
        )
        .expect("deployment must validate and instantiate");
    assert!(deployed.success);

    // 1. Open the epoch.
    let mut open_request = [0u8; 1 + DESCRIPTOR_BYTES];
    encode_open(&descriptor, &mut open_request).unwrap();
    let opened = execute(&mut engine, &contract, &open_request, [1u8; 32]);
    assert_eq!(opened.return_data[0], 1, "open must be accepted");

    // 2. The epoch reports itself open before any solution exists.
    let status = query(&mut engine, &contract, &status_request(descriptor.epoch));
    assert_eq!(status.return_data[0], 3, "epoch must report open");

    // 3. A wrong answer is rejected with a non-zero residual.
    let outcome = solve(&descriptor, SolveConfig::default()).unwrap();
    assert!(outcome.accepted);
    let mut wrong = outcome.input.clone();
    wrong[0] = wrong[0].saturating_add(hyphen_neural::fixed::ONE / 8);
    let rejected = execute(
        &mut engine,
        &contract,
        &submit_request(&descriptor, &wrong),
        [2u8; 32],
    );
    assert_eq!(rejected.return_data[0], 0, "wrong answer must be rejected");
    assert!(
        u64::from_le_bytes(rejected.return_data[1..9].try_into().unwrap())
            > descriptor.tolerance_ulp
    );

    // 4. The real answer settles the epoch.
    let accepted = execute(
        &mut engine,
        &contract,
        &submit_request(&descriptor, &outcome.input),
        [3u8; 32],
    );
    assert_eq!(
        accepted.return_data[0], 1,
        "correct answer must be accepted"
    );
    assert_eq!(accepted.state_changes.len(), 1);

    // 5. A second answer, even a correct one, cannot settle twice.
    let duplicate = execute(
        &mut engine,
        &contract,
        &submit_request(&descriptor, &outcome.input),
        [4u8; 32],
    );
    assert_eq!(duplicate.return_data[0], 2, "epoch is already settled");
    assert!(duplicate.state_changes.is_empty());

    // 6. The query path observes the settlement without mutating state.
    let status = query(&mut engine, &contract, &status_request(descriptor.epoch));
    assert_eq!(status.return_data[0], 2, "epoch must report settled");
    let reported = u64::from_le_bytes(status.return_data[1..9].try_into().unwrap());
    let accepted_error = u64::from_le_bytes(accepted.return_data[1..9].try_into().unwrap());
    assert_eq!(
        reported, accepted_error,
        "status must report the stored residual, not a shorter record's padding"
    );

    // 7. Re-opening the same epoch with a different shape is a conflict.
    let mut conflicting = descriptor;
    conflicting.spec.hidden_dim = 32;
    let mut conflict_request = [0u8; 1 + DESCRIPTOR_BYTES];
    encode_open(&conflicting, &mut conflict_request).unwrap();
    let conflict = execute(&mut engine, &contract, &conflict_request, [5u8; 32]);
    assert_eq!(
        conflict.return_data[0],
        hyphen_neural::NeuralError::EpochConflict.code()
    );
}

#[test]
fn the_query_path_refuses_to_mutate_state() {
    let Some(wasm) = load_wasm() else {
        return;
    };
    let descriptor = descriptor();
    let mut engine = VmEngine::new();
    let (contract, _) = engine
        .deploy(
            &DeployParams {
                deployer: [8u8; 32],
                code: wasm,
                constructor_args: Vec::new(),
                gas_limit: GAS,
                nonce: 0,
            },
            1,
        )
        .unwrap();

    let mut open_request = [0u8; 1 + DESCRIPTOR_BYTES];
    encode_open(&descriptor, &mut open_request).unwrap();
    let response = query(&mut engine, &contract, &open_request);
    assert_eq!(
        response.return_data[0],
        hyphen_neural::NeuralError::UnknownOperation.code(),
        "a query may not execute Open"
    );
    assert!(response.state_changes.is_empty());
}

#[test]
fn the_largest_profiled_width_executes_within_the_gas_limit() {
    let Some(wasm) = load_wasm() else {
        return;
    };
    let descriptor = ChallengeDescriptor::new(
        1,
        MlpSpec {
            input_dim: hyphen_neural::DEFAULT_INPUT_DIM,
            hidden_dim: hyphen_neural::MAX_HIDDEN_DIM,
            output_dim: hyphen_neural::DEFAULT_OUTPUT_DIM,
        },
        [0x77; 32],
    )
    .unwrap();
    let mut engine = VmEngine::new();
    let (contract, _) = engine
        .deploy(
            &DeployParams {
                deployer: [9u8; 32],
                code: wasm,
                constructor_args: Vec::new(),
                gas_limit: GAS,
                nonce: 0,
            },
            1,
        )
        .unwrap();

    let mut open_request = [0u8; 1 + DESCRIPTOR_BYTES];
    encode_open(&descriptor, &mut open_request).unwrap();
    assert_eq!(
        execute(&mut engine, &contract, &open_request, [1u8; 32]).return_data[0],
        1
    );

    let outcome = solve(&descriptor, SolveConfig::default()).unwrap();
    assert!(outcome.accepted);
    let accepted = execute(
        &mut engine,
        &contract,
        &submit_request(&descriptor, &outcome.input),
        [2u8; 32],
    );
    assert_eq!(accepted.return_data[0], 1);
    assert!(
        accepted.gas_used < GAS,
        "the widest profile must fit the contract gas limit"
    );
}

fn status_request(epoch: u64) -> Vec<u8> {
    let mut request = Vec::with_capacity(9);
    request.push(3u8);
    request.extend_from_slice(&epoch.to_le_bytes());
    request
}

fn submit_request(descriptor: &ChallengeDescriptor, solution: &[i64]) -> Vec<u8> {
    let mut request = vec![0u8; hyphen_neural::SUBMISSION_HEADER_BYTES + solution.len() * 8];
    let length = encode_submit(descriptor.epoch, solution, &mut request).unwrap();
    request.truncate(length);
    request
}

fn execute(
    engine: &mut VmEngine,
    contract: &Contract,
    args: &[u8],
    caller: [u8; 32],
) -> ContractResult {
    let result = engine
        .call(
            contract,
            &ContractCall {
                caller,
                contract: contract.address,
                function: "hyphen_execute".into(),
                args: args.to_vec(),
                gas_limit: GAS,
                value: 0,
            },
        )
        .expect("call must not trap at the VM level");
    assert!(
        result.success,
        "contract call failed: {:?}",
        result.return_data
    );
    result
}

fn query(engine: &mut VmEngine, contract: &Contract, args: &[u8]) -> ContractResult {
    let result = engine
        .call(
            contract,
            &ContractCall {
                caller: [9u8; 32],
                contract: contract.address,
                function: "hyphen_query".into(),
                args: args.to_vec(),
                gas_limit: GAS,
                value: 0,
            },
        )
        .expect("query must not trap at the VM level");
    assert!(
        result.success,
        "contract query failed: {:?}",
        result.return_data
    );
    result
}
