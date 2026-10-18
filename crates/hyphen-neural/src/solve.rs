//! Deterministic prover for the inverse challenge.
//!
//! The forward map is a composition of two affine maps and two `tanh`
//! activations, so the inverse problem is a nonlinear least-squares problem with
//! an analytic Jacobian. The prover therefore runs Levenberg–Marquardt rather
//! than plain gradient descent: the residual must reach a one-in-a-million
//! tolerance, and first-order steps stall several orders of magnitude above it.
//!
//! Everything is Q32.32 with a fixed operation order, so two miners starting
//! from the same descriptor produce byte-identical candidates and an auditor can
//! replay the search. The point of the challenge is the cost asymmetry: one
//! verification is a single forward pass, while the search runs many iterations
//! with an `output_dim * hidden_dim * input_dim` Jacobian each.

use std::vec::Vec;

use crate::challenge::{ChallengeDescriptor, Verification, DOMAIN_SOLVER};
use crate::error::NeuralError;
use crate::fixed::{self, ONE};
use crate::linalg;
use crate::mlp::{self, Layout, MlpSpec};
use crate::rng::ChaCha20;

/// Damping growth factor when a step is rejected.
const DAMPING_GROWTH: i64 = 4;

/// Lower bound on damping; below this the normal equations lose conditioning.
const DAMPING_FLOOR: i64 = 1;

/// Rejected steps tried before a restart is abandoned.
const DAMPING_ATTEMPTS: u32 = 12;

/// Prover configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolveConfig {
    /// Levenberg–Marquardt iterations per restart.
    pub max_iterations: u64,
    /// Initial damping in Q32.32.
    pub damping: i64,
    /// Deterministic restarts before the best candidate is reported.
    pub restarts: u32,
}

impl Default for SolveConfig {
    fn default() -> Self {
        Self {
            max_iterations: 256,
            damping: ONE / 32,
            restarts: 32,
        }
    }
}

impl SolveConfig {
    /// Rejects configurations that cannot make progress.
    pub fn validate(&self) -> Result<(), NeuralError> {
        if self.max_iterations == 0 || self.damping <= 0 || self.restarts == 0 {
            return Err(NeuralError::InvalidSpec);
        }
        Ok(())
    }
}

/// Best candidate found by one call to [`solve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolveOutcome {
    /// Candidate preimage.
    pub input: Vec<i64>,
    /// Iterations spent on the successful or best restart.
    pub iterations: u64,
    /// Restart that produced the candidate, zero-based.
    pub restart: u32,
    /// Worst per-component error of the candidate.
    pub max_error: u64,
    /// Mean squared error of the candidate.
    pub mean_squared_error: u128,
    /// Whether the candidate meets the descriptor tolerance.
    pub accepted: bool,
}

/// Searches for a preimage of the epoch's target.
///
/// Returns the best candidate seen even when it misses the tolerance, so a miner
/// can report progress and a test can assert on the residual instead of on an
/// error type.
pub fn solve(
    descriptor: &ChallengeDescriptor,
    config: SolveConfig,
) -> Result<SolveOutcome, NeuralError> {
    descriptor.validate()?;
    config.validate()?;
    let spec = descriptor.spec;
    let layout = spec.weight_layout();
    let input_dim = spec.input_dim as usize;
    let hidden_dim = spec.hidden_dim as usize;
    let output_dim = spec.output_dim as usize;

    let mut weights = vec![0i64; layout.total];
    descriptor.derive_weights(&mut weights)?;
    let mut preimage = vec![0i64; input_dim];
    descriptor.derive_preimage(&mut preimage)?;

    let mut hidden = vec![0i64; hidden_dim];
    let mut target = vec![0i64; output_dim];
    descriptor.derive_target(&weights, &preimage, &mut hidden, &mut target)?;

    let mut output = vec![0i64; output_dim];
    let mut residual = vec![0i64; output_dim];
    let mut jacobian = vec![0i128; output_dim * input_dim];
    let mut normal = vec![0i128; input_dim * input_dim];
    let mut damped = vec![0i128; input_dim * input_dim];
    let mut right = vec![0i128; input_dim];
    let mut local_right = vec![0i128; input_dim];
    let mut trial = vec![0i64; input_dim];

    let mut best: Option<SolveOutcome> = None;

    for restart in 0..config.restarts {
        let mut candidate = initial_candidate(descriptor, restart);
        let mut damping = config.damping;

        for iteration in 0..config.max_iterations {
            mlp::forward(&spec, &weights, &candidate, &mut hidden, &mut output)?;
            let max_error = mlp::max_abs_difference(&output, &target);
            let mean_squared_error = mlp::mean_squared_error(&output, &target);
            let accepted = max_error <= descriptor.tolerance_ulp;
            let outcome = SolveOutcome {
                input: candidate.clone(),
                iterations: iteration,
                restart,
                max_error,
                mean_squared_error,
                accepted,
            };
            if best
                .as_ref()
                .is_none_or(|current| outcome.max_error < current.max_error)
            {
                best = Some(outcome.clone());
            }
            if accepted {
                return Ok(outcome);
            }

            for (slot, (left, right_value)) in
                residual.iter_mut().zip(output.iter().zip(target.iter()))
            {
                *slot = left.saturating_sub(*right_value);
            }
            build_jacobian(&spec, &layout, &weights, &hidden, &output, &mut jacobian);
            build_normal_equations(
                &jacobian,
                &residual,
                &mut normal,
                &mut right,
                input_dim,
                output_dim,
            );

            let mut improved = false;
            for _ in 0..DAMPING_ATTEMPTS {
                damped.copy_from_slice(&normal);
                local_right.copy_from_slice(&right);
                add_damping(&mut damped, damping, input_dim);
                if !linalg::solve(&mut damped, &mut local_right, input_dim) {
                    damping = damping.saturating_mul(DAMPING_GROWTH);
                    continue;
                }
                for (value, (base, step)) in trial
                    .iter_mut()
                    .zip(candidate.iter().zip(local_right.iter()))
                {
                    *value = base.saturating_add(linalg::narrow(*step)).clamp(-ONE, ONE);
                }
                mlp::forward(&spec, &weights, &trial, &mut hidden, &mut output)?;
                let trial_error = mlp::max_abs_difference(&output, &target);
                if trial_error < max_error {
                    candidate.copy_from_slice(&trial);
                    damping = (damping / DAMPING_GROWTH).max(DAMPING_FLOOR);
                    improved = true;
                    break;
                }
                damping = damping.saturating_mul(DAMPING_GROWTH);
            }

            if !improved {
                // The step cannot be improved at this point; another restart is
                // cheaper than grinding a saturated region.
                break;
            }
        }
    }

    best.ok_or(NeuralError::BudgetExhausted)
}

/// Replays verification for a candidate, for tests and CLI reporting.
pub fn verify(
    descriptor: &ChallengeDescriptor,
    solution: &[i64],
) -> Result<Verification, NeuralError> {
    let layout = descriptor.spec.weight_layout();
    let mut weights = vec![0i64; layout.total];
    let mut input = vec![0i64; descriptor.spec.input_dim as usize];
    let mut target = vec![0i64; descriptor.spec.output_dim as usize];
    let mut hidden = vec![0i64; descriptor.spec.hidden_dim as usize];
    let mut output = vec![0i64; descriptor.spec.output_dim as usize];
    descriptor.evaluate(
        solution,
        &mut weights,
        &mut input,
        &mut target,
        &mut hidden,
        &mut output,
    )
}

fn initial_candidate(descriptor: &ChallengeDescriptor, restart: u32) -> Vec<i64> {
    let input_dim = descriptor.spec.input_dim as usize;
    let mut candidate = vec![0i64; input_dim];
    if restart == 0 {
        return candidate;
    }
    let mut generator = ChaCha20::domain(
        &descriptor.chain_seed,
        descriptor.epoch,
        DOMAIN_SOLVER + restart,
    );
    for value in candidate.iter_mut() {
        let word = generator.next_u32() as i128;
        *value = (((word * (2 * ONE) as i128) >> 32) - ONE as i128) as i64;
    }
    candidate
}

/// Builds `dy/dx` for the current point, row-major `output_dim x input_dim`.
fn build_jacobian(
    spec: &MlpSpec,
    layout: &Layout,
    weights: &[i64],
    hidden: &[i64],
    output: &[i64],
    jacobian: &mut [i128],
) {
    let input_dim = spec.input_dim as usize;
    let hidden_dim = spec.hidden_dim as usize;
    let output_dim = spec.output_dim as usize;

    for output_index in 0..output_dim {
        let output_slope = linalg::widen(fixed::tanh_grad(output[output_index]));
        for input_index in 0..input_dim {
            let mut accumulator = 0i128;
            for hidden_index in 0..hidden_dim {
                let hidden_slope = linalg::widen(fixed::tanh_grad(hidden[hidden_index]));
                let second_layer =
                    linalg::widen(weights[layout.w2 + output_index * hidden_dim + hidden_index]);
                let first_layer =
                    linalg::widen(weights[layout.w1 + hidden_index * input_dim + input_index]);
                accumulator = accumulator.saturating_add(linalg::scale_mul(
                    linalg::scale_mul(second_layer, hidden_slope),
                    first_layer,
                ));
            }
            jacobian[output_index * input_dim + input_index] =
                linalg::scale_mul(output_slope, accumulator);
        }
    }
}

/// Builds `J^T J` and `-J^T r` without the damping term.
fn build_normal_equations(
    jacobian: &[i128],
    residual: &[i64],
    normal: &mut [i128],
    right: &mut [i128],
    input_dim: usize,
    output_dim: usize,
) {
    for row in 0..input_dim {
        for column in 0..input_dim {
            let mut accumulator = 0i128;
            for index in 0..output_dim {
                accumulator = accumulator.saturating_add(linalg::scale_mul(
                    jacobian[index * input_dim + row],
                    jacobian[index * input_dim + column],
                ));
            }
            normal[row * input_dim + column] = accumulator;
        }
        let mut accumulator = 0i128;
        for index in 0..output_dim {
            accumulator = accumulator.saturating_add(linalg::scale_mul(
                jacobian[index * input_dim + row],
                linalg::widen(residual[index]),
            ));
        }
        right[row] = -accumulator;
    }
}

fn add_damping(normal: &mut [i128], damping: i64, input_dim: usize) {
    let damping = linalg::widen(damping);
    for index in 0..input_dim {
        let position = index * input_dim + index;
        normal[position] = normal[position].saturating_add(damping);
    }
}
