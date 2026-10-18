//! Two-layer MLP forward pass in Q32.32.
//!
//! The challenge network is deliberately tiny and fully specified: no framework,
//! no dynamic dispatch, no allocator. The same `forward` runs in the on-chain
//! contract, in the miner and in the test harness, so a verifier and a prover
//! cannot disagree about the meaning of a solution.

use crate::error::NeuralError;
use crate::fixed;

/// Largest accepted input width.
pub const MAX_INPUT_DIM: usize = 16;

/// Largest accepted output width.
pub const MAX_OUTPUT_DIM: usize = 16;

/// Largest accepted hidden width. The difficulty controller never exceeds it.
pub const MAX_HIDDEN_DIM: usize = 512;

/// Largest weight buffer required by any accepted profile.
pub const MAX_WEIGHTS: usize = MAX_HIDDEN_DIM * MAX_INPUT_DIM
    + MAX_HIDDEN_DIM
    + MAX_OUTPUT_DIM * MAX_HIDDEN_DIM
    + MAX_OUTPUT_DIM;

/// Shape of a two-layer perceptron.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlpSpec {
    /// Width of the input vector.
    pub input_dim: u16,
    /// Width of the hidden layer, which is the difficulty axis.
    pub hidden_dim: u16,
    /// Width of the output vector.
    pub output_dim: u16,
}

impl MlpSpec {
    /// Validates the shape against the compile-time bounds.
    pub const fn validate(self) -> Result<(), NeuralError> {
        if self.input_dim == 0
            || self.output_dim == 0
            || self.hidden_dim == 0
            || self.input_dim as usize > MAX_INPUT_DIM
            || self.output_dim as usize > MAX_OUTPUT_DIM
            || self.hidden_dim as usize > MAX_HIDDEN_DIM
        {
            return Err(NeuralError::InvalidSpec);
        }
        Ok(())
    }

    /// Number of Q32.32 values in [`MlpSpec::weight_layout`].
    pub const fn weight_count(self) -> usize {
        let input = self.input_dim as usize;
        let hidden = self.hidden_dim as usize;
        let output = self.output_dim as usize;
        hidden * input + hidden + output * hidden + output
    }

    /// Offsets of the four weight tensors inside the flat buffer.
    pub const fn weight_layout(self) -> Layout {
        let input = self.input_dim as usize;
        let hidden = self.hidden_dim as usize;
        let w1 = 0;
        let b1 = w1 + hidden * input;
        let w2 = b1 + hidden;
        let b2 = w2 + self.output_dim as usize * hidden;
        Layout {
            w1,
            b1,
            w2,
            b2,
            total: b2 + self.output_dim as usize,
        }
    }
}

/// Offsets of the weight tensors inside one flat slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// `hidden_dim * input_dim` row-major matrix.
    pub w1: usize,
    /// `hidden_dim` bias vector.
    pub b1: usize,
    /// `output_dim * hidden_dim` row-major matrix.
    pub w2: usize,
    /// `output_dim` bias vector.
    pub b2: usize,
    /// Total number of values.
    pub total: usize,
}

/// Runs the forward pass.
///
/// `hidden` is scratch space and must hold at least `spec.hidden_dim` values;
/// `output` must hold at least `spec.output_dim`. The caller owns both buffers
/// so the contract can keep everything on the stack.
pub fn forward(
    spec: &MlpSpec,
    weights: &[i64],
    input: &[i64],
    hidden: &mut [i64],
    output: &mut [i64],
) -> Result<(), NeuralError> {
    spec.validate()?;
    let input_dim = spec.input_dim as usize;
    let hidden_dim = spec.hidden_dim as usize;
    let output_dim = spec.output_dim as usize;
    if input.len() != input_dim || hidden.len() < hidden_dim || output.len() < output_dim {
        return Err(NeuralError::InvalidBuffer);
    }
    if weights.len() != spec.weight_count() {
        return Err(NeuralError::InvalidWeights);
    }
    let layout = spec.weight_layout();

    for row in 0..hidden_dim {
        let mut accumulator = weights[layout.b1 + row];
        let weights_row = &weights[layout.w1 + row * input_dim..layout.w1 + (row + 1) * input_dim];
        for (weight, value) in weights_row.iter().zip(input.iter()) {
            accumulator = fixed::add(accumulator, fixed::mul(*weight, *value));
        }
        hidden[row] = fixed::tanh(accumulator);
    }

    for row in 0..output_dim {
        let mut accumulator = weights[layout.b2 + row];
        let weights_row =
            &weights[layout.w2 + row * hidden_dim..layout.w2 + (row + 1) * hidden_dim];
        for (weight, value) in weights_row.iter().zip(hidden.iter().take(hidden_dim)) {
            accumulator = fixed::add(accumulator, fixed::mul(*weight, *value));
        }
        output[row] = fixed::tanh(accumulator);
    }
    Ok(())
}

/// Largest absolute difference between two output vectors, in Q32.32 ulps.
pub fn max_abs_difference(left: &[i64], right: &[i64]) -> u64 {
    left.iter()
        .zip(right.iter())
        .map(|(a, b)| a.abs_diff(*b))
        .max()
        .unwrap_or(u64::MAX)
}

/// Mean squared error in Q32.32 ulps squared, divided by the width.
pub fn mean_squared_error(left: &[i64], right: &[i64]) -> u128 {
    if left.is_empty() || left.len() != right.len() {
        return u128::MAX;
    }
    let sum: u128 = left
        .iter()
        .zip(right.iter())
        .map(|(a, b)| {
            let difference = (*a as i128 - *b as i128).unsigned_abs();
            difference * difference
        })
        .sum();
    sum / left.len() as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::ONE;

    fn spec() -> MlpSpec {
        MlpSpec {
            input_dim: 2,
            hidden_dim: 3,
            output_dim: 2,
        }
    }

    fn weights(spec: &MlpSpec) -> Vec<i64> {
        let layout = spec.weight_layout();
        let mut values = vec![0i64; spec.weight_count()];
        // Identity-ish hidden layer: h0 = tanh(x0), h1 = tanh(x1), h2 = 0.
        values[layout.w1] = ONE;
        values[layout.w1 + 3] = ONE;
        // Output copies the first two hidden units.
        values[layout.w2] = ONE;
        values[layout.w2 + 4] = ONE;
        values
    }

    #[test]
    fn layout_is_contiguous_and_complete() {
        let spec = spec();
        let layout = spec.weight_layout();
        assert_eq!(layout.w1, 0);
        assert_eq!(layout.b1, 6);
        assert_eq!(layout.w2, 9);
        assert_eq!(layout.b2, 15);
        assert_eq!(layout.total, 17);
        assert_eq!(layout.total, spec.weight_count());
    }

    #[test]
    fn forward_propagates_through_both_layers() {
        let spec = spec();
        let weights = weights(&spec);
        let mut hidden = [0i64; MAX_HIDDEN_DIM];
        let mut output = [0i64; MAX_OUTPUT_DIM];
        forward(
            &spec,
            &weights,
            &[ONE / 2, -ONE / 4],
            &mut hidden,
            &mut output,
        )
        .unwrap();
        assert_eq!(hidden[0], fixed::tanh(ONE / 2));
        assert_eq!(hidden[1], fixed::tanh(-ONE / 4));
        assert_eq!(output[0], fixed::tanh(hidden[0]));
        assert_eq!(output[1], fixed::tanh(hidden[1]));
    }

    #[test]
    fn forward_rejects_wrong_sizes() {
        let spec = spec();
        let weights = weights(&spec);
        let mut hidden = [0i64; MAX_HIDDEN_DIM];
        let mut output = [0i64; MAX_OUTPUT_DIM];
        assert_eq!(
            forward(&spec, &weights, &[ONE], &mut hidden, &mut output),
            Err(NeuralError::InvalidBuffer)
        );
        assert_eq!(
            forward(&spec, &weights[..3], &[ONE, ONE], &mut hidden, &mut output),
            Err(NeuralError::InvalidWeights)
        );
    }

    #[test]
    fn metrics_are_exact() {
        assert_eq!(max_abs_difference(&[ONE, 2], &[0, 5]), ONE as u64);
        assert_eq!(mean_squared_error(&[3, 4], &[0, 0]), (25 / 2) as u128);
        assert_eq!(mean_squared_error(&[1], &[1]), 0);
        assert_eq!(mean_squared_error(&[], &[]), u128::MAX);
    }
}
