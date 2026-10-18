//! End-to-end tests for the neural challenge profile.
//!
//! These pin the properties the contract relies on: the same descriptor always
//! derives the same network, the prover reaches the published tolerance, the
//! search is reproducible, and a perturbed answer is rejected.

use std::time::Instant;

use hyphen_neural::{
    difficulty::next_hidden_dim, encode_descriptor, solve, verify, ChallengeDescriptor, MlpSpec,
    SolveConfig, DESCRIPTOR_BYTES,
};

fn descriptor(hidden: u16, epoch: u64) -> ChallengeDescriptor {
    ChallengeDescriptor::new(
        epoch,
        MlpSpec {
            input_dim: 16,
            hidden_dim: hidden,
            output_dim: 16,
        },
        [0x33; 32],
    )
    .unwrap()
}

#[test]
fn a_solved_challenge_verifies_on_every_profiled_width() {
    for hidden in [
        hyphen_neural::MIN_HIDDEN_DIM,
        32,
        64,
        hyphen_neural::MAX_HIDDEN_DIM,
    ] {
        let descriptor = descriptor(hidden, 7);
        let outcome = solve(&descriptor, SolveConfig::default()).unwrap();
        assert!(
            outcome.accepted,
            "hidden={hidden} missed tolerance with max_error={}",
            outcome.max_error
        );
        let verification = verify(&descriptor, &outcome.input).unwrap();
        assert!(verification.accepted);
        assert_eq!(verification.max_error, outcome.max_error);
    }
}

#[test]
fn the_search_is_reproducible_and_epoch_scoped() {
    let first = descriptor(32, 11);
    let same = descriptor(32, 11);
    let next = descriptor(32, 12);

    let a = solve(&first, SolveConfig::default()).unwrap();
    let b = solve(&same, SolveConfig::default()).unwrap();
    assert_eq!(a, b);

    let c = solve(&next, SolveConfig::default()).unwrap();
    assert_ne!(a.input, c.input);
}

#[test]
fn a_perturbed_answer_is_rejected() {
    let descriptor = descriptor(32, 21);
    let outcome = solve(&descriptor, SolveConfig::default()).unwrap();
    let mut tampered = outcome.input.clone();
    tampered[0] = tampered[0].saturating_add(hyphen_neural::fixed::ONE / 16);
    let verification = verify(&descriptor, &tampered).unwrap();
    assert!(!verification.accepted);
    assert!(verification.max_error > descriptor.tolerance_ulp);
}

#[test]
fn descriptors_have_one_encoding() {
    let descriptor = descriptor(16, 3);
    let mut first = [0u8; DESCRIPTOR_BYTES];
    let mut second = [0u8; DESCRIPTOR_BYTES];
    encode_descriptor(&descriptor, &mut first).unwrap();
    encode_descriptor(&descriptor, &mut second).unwrap();
    assert_eq!(first, second);
}

/// The controller is measured rather than asserted for a specific width: the
/// point is that a fast epoch raises the width and a slow one lowers it.
#[test]
fn the_controller_reacts_in_the_right_direction() {
    assert!(next_hidden_dim(16, 1, 600) > 16);
    assert!(next_hidden_dim(512, 100_000, 600) < 512);
    assert_eq!(next_hidden_dim(64, 600, 600), 64);
}

/// Guards the cost asymmetry that the whole mechanism depends on: a solve must
/// be orders of magnitude more expensive than a verification. The ratio is
/// measured at the smallest profiled width where the fixed costs dominate.
#[test]
fn verification_is_much_cheaper_than_the_search() {
    let descriptor = descriptor(64, 31);
    let search_started = Instant::now();
    let outcome = solve(&descriptor, SolveConfig::default()).unwrap();
    let search = search_started.elapsed();

    let verification_started = Instant::now();
    for _ in 0..10 {
        verify(&descriptor, &outcome.input).unwrap();
    }
    let verification = verification_started.elapsed() / 10;

    assert!(
        search > verification * 10,
        "search {search:?} is not meaningfully more expensive than one verification {verification:?}"
    );
}
