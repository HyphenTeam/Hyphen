//! Challenge derivation and verification.
//!
//! An epoch is defined by one 32-byte chain seed, one epoch number and one
//! network shape. Everything else is derived from those values with a
//! domain-separated ChaCha20 stream, so the contract stores 56 bytes per epoch
//! and every participant reconstructs identical weights.
//!
//! The task is the inverse problem, not weight copying. Alice publishes the
//! network `A` and a target `y* = A(x*)`; the prover must find any `x` with
//! `A(x)` inside the published tolerance of `y*`. Publishing `A` is harmless
//! here: knowing the function does not reveal a preimage, and the verifier does
//! exactly one forward pass. The earlier "learn Alice's weights" framing is not
//! used because Alice's weights are public, so copying them would satisfy any
//! loss threshold without doing work.

use crate::error::NeuralError;
use crate::fixed::{self, ONE};
use crate::mlp::{self, MlpSpec};
use crate::rng::ChaCha20;

/// Wire version of the descriptor and therefore of the whole challenge profile.
pub const DESCRIPTOR_VERSION: u16 = 1;

/// Input width of the default profile.
pub const DEFAULT_INPUT_DIM: u16 = 16;

/// Output width of the default profile.
pub const DEFAULT_OUTPUT_DIM: u16 = 16;

/// Smallest hidden width the difficulty controller may select.
pub const MIN_HIDDEN_DIM: u16 = 16;

/// Largest hidden width the difficulty controller may select.
pub const MAX_HIDDEN_DIM: u16 = 512;

/// Default acceptance tolerance: one millionth of the Q32.32 unit range.
pub const DEFAULT_TOLERANCE_ULP: u64 = 4_295;

/// Largest tolerance a descriptor may declare. A loose tolerance would let an
/// untrained constant approximating the target pass.
pub const MAX_TOLERANCE_ULP: u64 = ONE as u64 / 1_000;

const DOMAIN_WEIGHTS: u32 = 1;
const DOMAIN_PREIMAGE: u32 = 2;
/// Domain used by the solver for deterministic restarts.
pub const DOMAIN_SOLVER: u32 = 3;

/// Complete, self-contained description of one epoch's challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeDescriptor {
    /// Encoding version.
    pub version: u16,
    /// Epoch index, normally `unix_time / CHALLENGE_INTERVAL_SECS`.
    pub epoch: u64,
    /// Network shape.
    pub spec: MlpSpec,
    /// Per-component acceptance tolerance in Q32.32 ulps.
    pub tolerance_ulp: u64,
    /// Public seed every participant derives the network and preimage from.
    pub chain_seed: [u8; 32],
}

impl ChallengeDescriptor {
    /// Builds a descriptor for `epoch` with the default tolerance.
    pub fn new(epoch: u64, spec: MlpSpec, chain_seed: [u8; 32]) -> Result<Self, NeuralError> {
        let descriptor = Self {
            version: DESCRIPTOR_VERSION,
            epoch,
            spec,
            tolerance_ulp: DEFAULT_TOLERANCE_ULP,
            chain_seed,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Validates every field a peer could have tampered with.
    pub fn validate(&self) -> Result<(), NeuralError> {
        if self.version != DESCRIPTOR_VERSION {
            return Err(NeuralError::InvalidDescriptor);
        }
        self.spec.validate()?;
        if self.tolerance_ulp == 0 || self.tolerance_ulp > MAX_TOLERANCE_ULP {
            return Err(NeuralError::InvalidTolerance);
        }
        Ok(())
    }

    /// Derives the Q32.32 weights of Alice's network into `weights`.
    ///
    /// `weights.len()` must equal [`MlpSpec::weight_count`]. The distribution is
    /// uniform in `±1/sqrt(width)` per layer, which keeps preactivations in the
    /// linear part of `tanh` and makes the inverse problem well conditioned for
    /// the smallest dimensions.
    pub fn derive_weights(&self, weights: &mut [i64]) -> Result<(), NeuralError> {
        self.validate()?;
        let spec = self.spec;
        if weights.len() != spec.weight_count() {
            return Err(NeuralError::InvalidWeights);
        }
        let layout = spec.weight_layout();
        let mut generator = ChaCha20::domain(&self.chain_seed, self.epoch, DOMAIN_WEIGHTS);

        let input_scale = layer_scale(spec.input_dim);
        let hidden_scale = layer_scale(spec.hidden_dim);

        for value in weights
            [layout.w1..layout.w1 + spec.hidden_dim as usize * spec.input_dim as usize]
            .iter_mut()
        {
            *value = sample(&mut generator, input_scale);
        }
        for value in weights[layout.b1..layout.b1 + spec.hidden_dim as usize].iter_mut() {
            *value = sample(&mut generator, input_scale);
        }
        for value in weights
            [layout.w2..layout.w2 + spec.output_dim as usize * spec.hidden_dim as usize]
            .iter_mut()
        {
            *value = sample(&mut generator, hidden_scale);
        }
        for value in weights[layout.b2..layout.b2 + spec.output_dim as usize].iter_mut() {
            *value = 0;
        }
        Ok(())
    }

    /// Derives the hidden preimage Alice used to produce the target.
    pub fn derive_preimage(&self, input: &mut [i64]) -> Result<(), NeuralError> {
        self.validate()?;
        if input.len() != self.spec.input_dim as usize {
            return Err(NeuralError::InvalidBuffer);
        }
        let mut generator = ChaCha20::domain(&self.chain_seed, self.epoch, DOMAIN_PREIMAGE);
        for value in input.iter_mut() {
            let word = generator.next_u32() as i128;
            *value = (((word * (2 * ONE) as i128) >> 32) - ONE as i128) as i64;
        }
        Ok(())
    }

    /// Computes `A(x*)`, the target a solution must match.
    pub fn derive_target(
        &self,
        weights: &[i64],
        input: &[i64],
        hidden: &mut [i64],
        target: &mut [i64],
    ) -> Result<(), NeuralError> {
        self.validate()?;
        mlp::forward(&self.spec, weights, input, hidden, target)
    }

    /// Verifies a candidate preimage with exactly one forward pass.
    ///
    /// All buffers are caller-owned so this runs unchanged inside a `no_std`
    /// contract: `weights` must hold at least [`MlpSpec::weight_count`] values,
    /// `input` the derived preimage, and `target`, `hidden` and `output` the
    /// declared widths. Larger scratch buffers are accepted and only the
    /// declared prefix is used.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        solution: &[i64],
        weights: &mut [i64],
        input: &mut [i64],
        target: &mut [i64],
        hidden: &mut [i64],
        output: &mut [i64],
    ) -> Result<Verification, NeuralError> {
        self.validate()?;
        if solution.len() != self.spec.input_dim as usize {
            return Err(NeuralError::InvalidSolution);
        }
        let input_dim = self.spec.input_dim as usize;
        let hidden_dim = self.spec.hidden_dim as usize;
        let output_dim = self.spec.output_dim as usize;
        let weight_count = self.spec.weight_count();
        if weights.len() < weight_count
            || input.len() < input_dim
            || target.len() < output_dim
            || hidden.len() < hidden_dim
            || output.len() < output_dim
        {
            return Err(NeuralError::InvalidBuffer);
        }
        self.derive_weights(&mut weights[..weight_count])?;
        self.derive_preimage(&mut input[..input_dim])?;
        self.derive_target(
            &weights[..weight_count],
            &input[..input_dim],
            &mut hidden[..hidden_dim],
            &mut target[..output_dim],
        )?;
        mlp::forward(
            &self.spec,
            &weights[..weight_count],
            solution,
            &mut hidden[..hidden_dim],
            &mut output[..output_dim],
        )?;
        let max_error = mlp::max_abs_difference(&output[..output_dim], &target[..output_dim]);
        Ok(Verification {
            accepted: max_error <= self.tolerance_ulp,
            max_error,
            mean_squared_error: mlp::mean_squared_error(
                &output[..output_dim],
                &target[..output_dim],
            ),
        })
    }
}

/// Outcome of checking one candidate preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verification {
    /// Whether every output component met the descriptor tolerance.
    pub accepted: bool,
    /// Worst per-component distance, in Q32.32 ulps.
    pub max_error: u64,
    /// Mean squared distance, in Q32.32 ulps squared.
    pub mean_squared_error: u128,
}

/// Returns `±1/sqrt(width)` in Q32.32, floored at one ulp.
pub fn layer_scale(width: u16) -> i64 {
    let root = fixed::isqrt(u64::from(width));
    (ONE as u64).checked_div(root).unwrap_or(0).max(1) as i64
}

fn sample(generator: &mut ChaCha20, scale: i64) -> i64 {
    let span = 2 * scale as i128;
    let word = generator.next_u32() as i128;
    (((word * span) >> 32) - scale as i128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlp::MAX_WEIGHTS;

    fn descriptor(epoch: u64, hidden: u16) -> ChallengeDescriptor {
        ChallengeDescriptor::new(
            epoch,
            MlpSpec {
                input_dim: 4,
                hidden_dim: hidden,
                output_dim: 4,
            },
            [0x5a; 32],
        )
        .unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_epoch_scoped() {
        let first = descriptor(1, 16);
        let same = descriptor(1, 16);
        let next = descriptor(2, 16);

        let mut weights = vec![0i64; first.spec.weight_count()];
        let mut other = vec![0i64; first.spec.weight_count()];
        first.derive_weights(&mut weights).unwrap();
        same.derive_weights(&mut other).unwrap();
        assert_eq!(weights, other);

        next.derive_weights(&mut other).unwrap();
        assert_ne!(weights, other);
    }

    #[test]
    fn preimage_is_in_the_unit_interval() {
        let challenge = descriptor(7, 32);
        let mut input = vec![0i64; challenge.spec.input_dim as usize];
        challenge.derive_preimage(&mut input).unwrap();
        for value in input {
            assert!((-ONE..=ONE).contains(&value));
        }
    }

    #[test]
    fn the_hidden_preimage_solves_the_challenge() {
        let challenge = descriptor(11, 32);
        let layout = challenge.spec.weight_layout();
        let mut weights = vec![0i64; layout.total];
        let mut input = vec![0i64; challenge.spec.input_dim as usize];
        let mut target = vec![0i64; challenge.spec.output_dim as usize];
        let mut hidden = vec![0i64; challenge.spec.hidden_dim as usize];
        let mut output = vec![0i64; challenge.spec.output_dim as usize];
        challenge.derive_weights(&mut weights).unwrap();
        challenge.derive_preimage(&mut input).unwrap();
        challenge
            .derive_target(&weights, &input, &mut hidden, &mut target)
            .unwrap();
        let verification = challenge
            .evaluate(
                &input,
                &mut weights,
                &mut input.clone(),
                &mut target,
                &mut hidden,
                &mut output,
            )
            .unwrap();
        assert!(verification.accepted);
        assert_eq!(verification.max_error, 0);
    }

    #[test]
    fn a_perturbed_preimage_is_rejected_at_the_default_tolerance() {
        let challenge = descriptor(12, 32);
        let mut weights = vec![0i64; challenge.spec.weight_count()];
        let mut input = vec![0i64; challenge.spec.input_dim as usize];
        let mut target = vec![0i64; challenge.spec.output_dim as usize];
        let mut hidden = vec![0i64; challenge.spec.hidden_dim as usize];
        let mut output = vec![0i64; challenge.spec.output_dim as usize];
        challenge.derive_preimage(&mut input).unwrap();
        let mut solution = input.clone();
        solution[0] += ONE / 100;
        let verification = challenge
            .evaluate(
                &solution,
                &mut weights,
                &mut input,
                &mut target,
                &mut hidden,
                &mut output,
            )
            .unwrap();
        assert!(!verification.accepted);
    }

    #[test]
    fn evaluate_accepts_oversized_scratch_buffers() {
        // The contract keeps every scratch buffer at its compile-time maximum.
        // `evaluate` must therefore slice them to the declared shape instead of
        // requiring exact lengths.
        let challenge = descriptor(14, 16);
        let mut weights = vec![0i64; MAX_WEIGHTS];
        let mut input = vec![0i64; crate::mlp::MAX_INPUT_DIM];
        let mut target = vec![0i64; crate::mlp::MAX_OUTPUT_DIM];
        let mut hidden = vec![0i64; crate::mlp::MAX_HIDDEN_DIM];
        let mut output = vec![0i64; crate::mlp::MAX_OUTPUT_DIM];
        let mut preimage = vec![0i64; challenge.spec.input_dim as usize];
        challenge.derive_preimage(&mut preimage).unwrap();
        let verification = challenge
            .evaluate(
                &preimage,
                &mut weights,
                &mut input,
                &mut target,
                &mut hidden,
                &mut output,
            )
            .unwrap();
        assert!(verification.accepted);
    }

    #[test]
    fn shape_bounds_are_enforced() {
        let too_wide = ChallengeDescriptor::new(
            0,
            MlpSpec {
                input_dim: 64,
                hidden_dim: 16,
                output_dim: 16,
            },
            [0; 32],
        );
        assert_eq!(too_wide, Err(NeuralError::InvalidSpec));
        let zero_tolerance = ChallengeDescriptor {
            version: DESCRIPTOR_VERSION,
            epoch: 0,
            spec: MlpSpec {
                input_dim: 16,
                hidden_dim: 16,
                output_dim: 16,
            },
            tolerance_ulp: 0,
            chain_seed: [0; 32],
        };
        assert_eq!(
            zero_tolerance.validate(),
            Err(NeuralError::InvalidTolerance)
        );
    }

    #[test]
    fn the_largest_profile_fits_the_static_buffer() {
        let spec = MlpSpec {
            input_dim: crate::mlp::MAX_INPUT_DIM as u16,
            hidden_dim: crate::mlp::MAX_HIDDEN_DIM as u16,
            output_dim: crate::mlp::MAX_OUTPUT_DIM as u16,
        };
        assert_eq!(spec.weight_count(), MAX_WEIGHTS);
    }
}
