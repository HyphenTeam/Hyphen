//! Measures the cost envelope the difficulty controller works with.
//!
//! Run it after changing the solver, the activation or the dimension bounds; the
//! numbers in `docs/research/neural-cryptography.md` come from this harness. It
//! is an example rather than a test because wall-clock time on a shared runner is
//! not a property the test suite should assert on.
//!
//! ```text
//! cargo run --release -p hyphen-neural --example envelope
//! ```

use std::time::Instant;

use hyphen_neural::{solve, ChallengeDescriptor, MlpSpec, SolveConfig};

fn main() {
    let seed = [0x5au8; 32];
    let config = SolveConfig::default();
    println!(
        "profile: input=16 output=16 iterations={} restarts={}",
        config.max_iterations, config.restarts
    );
    for hidden in [16u16, 64, 128, 256, 512] {
        let descriptor = ChallengeDescriptor::new(
            1,
            MlpSpec {
                input_dim: 16,
                hidden_dim: hidden,
                output_dim: 16,
            },
            seed,
        )
        .expect("the profiled widths are valid");

        let started = Instant::now();
        let outcome = solve(&descriptor, config).expect("the descriptor is solvable");
        let elapsed = started.elapsed();

        let verification_started = Instant::now();
        let verification = hyphen_neural::verify(&descriptor, &outcome.input).expect("valid");
        let verification_elapsed = verification_started.elapsed();

        println!(
            "hidden={hidden:>3} accepted={:<5} iterations={:<3} max_error={:<6} solve={:>8.3}ms verify={:>7.3}ms ratio={:>6.1}x",
            verification.accepted,
            outcome.iterations,
            verification.max_error,
            elapsed.as_secs_f64() * 1_000.0,
            verification_elapsed.as_secs_f64() * 1_000.0,
            elapsed.as_secs_f64() / verification_elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
        );
    }
}
