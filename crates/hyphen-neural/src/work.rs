//! One-way neural work: a threshold puzzle whose per-attempt cost is a
//! deterministic forward pass.
//!
//! # Why this exists
//!
//! [`crate::ChallengeDescriptor`] is an *inverse* task: the target is `A(x*)`
//! and `x*` is derived from the public `chain_seed`, so a prover recomputes the
//! answer instead of searching for it. That is fine for settling a task whose
//! result someone declared, and it is unusable as a proof of work: a block
//! gated on it would be free to produce.
//!
//! This module supplies the missing predicate:
//!
//! ```text
//! weights = PRF(chain_seed, epoch)      // public, one network per epoch
//! y       = A_weights(x)                // Q32.32 forward pass
//! accept <=> score(y) < threshold        // threshold sets the difficulty
//! ```
//!
//! The seed fixes the *network*, never the *answer*. Every attempt costs one
//! forward pass, every check costs one forward pass, and because the weights
//! change with the seed no work found for one epoch is worth anything in the
//! next. A miner cannot skip the network: the predicate reads `A(x)`.
//!
//! # What it is not
//!
//! `y` is discarded by the puzzle itself. This is a hash-gated computation, not
//! useful work: its per-attempt cost is a network forward pass, so it is *less*
//! energy-efficient per bit of security than a BLAKE3 hash threshold. It exists
//! to make a *task result* verifiable and non-derivable — a block that requires
//! one of these results is backed by real, per-block-fresh computation, and a
//! task consumer is what makes the output useful.

use crate::error::NeuralError;
use crate::fixed::ONE;
use crate::mlp::{self, MlpSpec};
use crate::wire::DESCRIPTOR_BYTES;

/// Wire version that marks a descriptor as a work challenge instead of an
/// inverse challenge. The 56-byte layout is shared; the tolerance field carries
/// the acceptance `threshold`.
pub const WORK_DESCRIPTOR_VERSION: u16 = 3;

/// Network shape used by every participant of the neural work profile.
///
/// It lives here, next to the challenge, because the node, the pool and the
/// miner must derive the exact same tensor. A duplicated constant in any of them
/// would silently fork the chain.
pub const PROFILE_SPEC: MlpSpec = MlpSpec {
    input_dim: 16,
    hidden_dim: 64,
    output_dim: 16,
};

/// Domain tag mixed into candidate derivation, distinct from the weight domain.
const CANDIDATE_DOMAIN: u64 = 0x4859_5048_454e_5731;

/// Epoch offset that keeps a work network from coinciding with the inverse
/// challenge network derived for the same seed and epoch.
const WORK_EPOCH_MASK: u64 = 0x8000_0000_0000_0000;

/// Seed for the score mixer.
const SCORE_DOMAIN: u64 = 0x9e37_79b9_7f4a_7c15;

/// SplitMix64 finalizer. A puzzle gate needs a uniform, deterministic 64-bit
/// read of the network output; it carries no collision-resistance claim.
fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Everything a verifier needs to re-check one solution.
///
/// The seed is public by construction: it is the value every participant
/// derives the network from. Nothing here is secret, and nothing here reveals a
/// solution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkDescriptor {
    /// Epoch index, normally the block height this work is bound to.
    pub epoch: u64,
    /// Network shape.
    pub spec: MlpSpec,
    /// Accept when `score < threshold`. Expected attempts are `2^64 / threshold`.
    pub threshold: u64,
    /// Public seed the network is derived from, normally the parent block hash.
    pub chain_seed: [u8; 32],
}

impl WorkDescriptor {
    /// Rejects descriptors a peer could have tampered with.
    pub fn validate(&self) -> Result<(), NeuralError> {
        self.spec.validate()?;
        if self.threshold == 0 {
            return Err(NeuralError::InvalidTolerance);
        }
        Ok(())
    }

    /// Expected number of forward passes per accepted solution.
    pub fn expected_attempts(&self) -> u64 {
        if self.threshold == 0 {
            return u64::MAX;
        }
        u64::MAX / self.threshold
    }

    /// Derives the Q32.32 weights of this epoch's network.
    pub fn derive_weights(&self, weights: &mut [i64]) -> Result<(), NeuralError> {
        self.validate()?;
        let spec = self.spec;
        if weights.len() != spec.weight_count() {
            return Err(NeuralError::InvalidWeights);
        }
        let inverse = crate::ChallengeDescriptor {
            version: crate::DESCRIPTOR_VERSION,
            epoch: self.epoch ^ WORK_EPOCH_MASK,
            spec,
            tolerance_ulp: crate::DEFAULT_TOLERANCE_ULP,
            chain_seed: self.chain_seed,
        };
        inverse.derive_weights(weights)
    }

    /// Deterministic candidate `counter` in `[-ONE, ONE]`.
    ///
    /// Any vector in range is a valid candidate; this helper only gives
    /// independent searchers disjoint, reproducible streams so two miners never
    /// test the same candidate by accident.
    pub fn candidate(&self, counter: u64, out: &mut [i64]) -> Result<(), NeuralError> {
        let input_dim = self.spec.input_dim as usize;
        if out.len() != input_dim {
            return Err(NeuralError::InvalidBuffer);
        }
        for (index, value) in out.iter_mut().enumerate() {
            let word = u64::from(u32::from_le_bytes(
                self.chain_seed[(index % 8) * 4..(index % 8) * 4 + 4]
                    .try_into()
                    .map_err(|_| NeuralError::InvalidDescriptor)?,
            ));
            let noise =
                mix64(word ^ CANDIDATE_DOMAIN ^ counter.wrapping_mul(0x9e37_79b9) ^ (index as u64));
            let unit = (noise >> 32) as i128;
            *value = (((unit * (2 * ONE as i128)) >> 32) - ONE as i128) as i64;
        }
        Ok(())
    }

    /// Runs the network on `solution` and returns the puzzle score.
    pub fn score(
        &self,
        weights: &[i64],
        solution: &[i64],
        hidden: &mut [i64],
        output: &mut [i64],
    ) -> Result<u64, NeuralError> {
        self.validate()?;
        let weight_count = self.spec.weight_count();
        if weights.len() < weight_count {
            return Err(NeuralError::InvalidWeights);
        }
        mlp::forward(
            &self.spec,
            &weights[..weight_count],
            solution,
            hidden,
            output,
        )?;
        let output_dim = self.spec.output_dim as usize;
        let mut accumulator = SCORE_DOMAIN;
        for value in &output[..output_dim] {
            accumulator = mix64(accumulator ^ (*value as u64));
        }
        Ok(mix64(accumulator))
    }

    /// One-call verification: a single forward pass plus the score fold.
    pub fn verify(
        &self,
        weights: &[i64],
        solution: &[i64],
        hidden: &mut [i64],
        output: &mut [i64],
    ) -> Result<bool, NeuralError> {
        if solution.len() != self.spec.input_dim as usize {
            return Err(NeuralError::InvalidSolution);
        }
        Ok(self.score(weights, solution, hidden, output)? < self.threshold)
    }

    /// Encodes the descriptor into the shared 56-byte layout.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, NeuralError> {
        self.validate()?;
        if out.len() < DESCRIPTOR_BYTES {
            return Err(NeuralError::InvalidBuffer);
        }
        out[0..2].copy_from_slice(&WORK_DESCRIPTOR_VERSION.to_le_bytes());
        out[2..10].copy_from_slice(&self.epoch.to_le_bytes());
        out[10..12].copy_from_slice(&self.spec.input_dim.to_le_bytes());
        out[12..14].copy_from_slice(&self.spec.hidden_dim.to_le_bytes());
        out[14..16].copy_from_slice(&self.spec.output_dim.to_le_bytes());
        out[16..24].copy_from_slice(&self.threshold.to_le_bytes());
        out[24..56].copy_from_slice(&self.chain_seed);
        Ok(DESCRIPTOR_BYTES)
    }

    /// Decodes exactly [`DESCRIPTOR_BYTES`] bytes, rejecting other versions.
    pub fn decode(bytes: &[u8]) -> Result<Self, NeuralError> {
        if bytes.len() != DESCRIPTOR_BYTES {
            return Err(NeuralError::InvalidEncoding);
        }
        if u16::from_le_bytes([bytes[0], bytes[1]]) != WORK_DESCRIPTOR_VERSION {
            return Err(NeuralError::InvalidDescriptor);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[24..56]);
        let descriptor = Self {
            epoch: u64::from_le_bytes(
                bytes[2..10]
                    .try_into()
                    .map_err(|_| NeuralError::InvalidEncoding)?,
            ),
            spec: MlpSpec {
                input_dim: u16::from_le_bytes([bytes[10], bytes[11]]),
                hidden_dim: u16::from_le_bytes([bytes[12], bytes[13]]),
                output_dim: u16::from_le_bytes([bytes[14], bytes[15]]),
            },
            threshold: u64::from_le_bytes(
                bytes[16..24]
                    .try_into()
                    .map_err(|_| NeuralError::InvalidEncoding)?,
            ),
            chain_seed: seed,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }
}

/// Outcome of one bounded search.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkSearch {
    /// Candidates scored.
    pub attempts: u64,
    /// Whether `solution` holds an accepted candidate.
    pub found: bool,
}

/// Scores candidates `start, start + stride, …` until one is accepted or
/// `max_candidates` attempts are spent.
///
/// `solution` is overwritten only on success, so a failed search never leaves a
/// partial answer behind. Two searchers using different `start` values and the
/// same `stride` never test the same candidate.
#[allow(clippy::too_many_arguments)]
pub fn search(
    descriptor: &WorkDescriptor,
    weights: &[i64],
    start: u64,
    stride: u64,
    max_candidates: u64,
    solution: &mut [i64],
    hidden: &mut [i64],
    output: &mut [i64],
    scratch: &mut [i64],
) -> Result<WorkSearch, NeuralError> {
    descriptor.validate()?;
    if stride == 0 || max_candidates == 0 {
        return Err(NeuralError::InvalidSpec);
    }
    let mut counter = start;
    for attempt in 0..max_candidates {
        descriptor.candidate(counter, scratch)?;
        if descriptor.verify(weights, scratch, hidden, output)? {
            solution.copy_from_slice(scratch);
            return Ok(WorkSearch {
                attempts: attempt + 1,
                found: true,
            });
        }
        counter = counter.wrapping_add(stride);
    }
    Ok(WorkSearch {
        attempts: max_candidates,
        found: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: MlpSpec = MlpSpec {
        input_dim: 16,
        hidden_dim: 24,
        output_dim: 16,
    };

    fn descriptor(threshold: u64) -> WorkDescriptor {
        WorkDescriptor {
            epoch: 9,
            spec: SPEC,
            threshold,
            chain_seed: [5; 32],
        }
    }

    /// `(weights, hidden, output)` buffers sized for [`SPEC`].
    fn buffers() -> ([i64; 1024], [i64; 24], [i64; 16]) {
        ([0; 1024], [0; 24], [0; 16])
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let original = descriptor(1 << 20);
        let mut bytes = [0u8; DESCRIPTOR_BYTES];
        assert_eq!(original.encode(&mut bytes).unwrap(), DESCRIPTOR_BYTES);
        assert_eq!(WorkDescriptor::decode(&bytes).unwrap(), original);
    }

    #[test]
    fn an_inverse_challenge_descriptor_is_not_a_work_descriptor() {
        let inverse = crate::ChallengeDescriptor {
            version: crate::DESCRIPTOR_VERSION,
            epoch: 1,
            spec: SPEC,
            tolerance_ulp: crate::DEFAULT_TOLERANCE_ULP,
            chain_seed: [1; 32],
        };
        let mut bytes = [0u8; DESCRIPTOR_BYTES];
        crate::encode_descriptor(&inverse, &mut bytes).unwrap();
        assert_eq!(
            WorkDescriptor::decode(&bytes),
            Err(NeuralError::InvalidDescriptor)
        );
    }

    /// The seed fixes the network only. Nothing derives a solution from it, so
    /// candidate zero is not accepted by a hard threshold.
    #[test]
    fn a_derived_candidate_is_not_a_solution() {
        let descriptor = descriptor(1);
        let (mut weights, mut hidden, mut output) = buffers();
        descriptor
            .derive_weights(&mut weights[..SPEC.weight_count()])
            .unwrap();
        let mut candidate = [0i64; 16];
        descriptor.candidate(0, &mut candidate).unwrap();
        assert!(!descriptor
            .verify(&weights, &candidate, &mut hidden, &mut output)
            .unwrap());
    }

    #[test]
    fn weights_change_with_the_seed_so_work_never_carries_over() {
        let first = descriptor(u64::MAX);
        let mut second = first;
        second.chain_seed[0] ^= 1;
        let (mut weights_a, _, _) = buffers();
        let (mut weights_b, _, _) = buffers();
        first
            .derive_weights(&mut weights_a[..SPEC.weight_count()])
            .unwrap();
        second
            .derive_weights(&mut weights_b[..SPEC.weight_count()])
            .unwrap();
        assert_ne!(
            &weights_a[..SPEC.weight_count()],
            &weights_b[..SPEC.weight_count()]
        );
    }

    #[test]
    fn search_finds_and_verifies_a_solution() {
        let descriptor = descriptor(u64::MAX / 4);
        let (mut weights, mut hidden, mut output) = buffers();
        descriptor
            .derive_weights(&mut weights[..SPEC.weight_count()])
            .unwrap();
        let mut solution = [0i64; 16];
        let mut scratch = [0i64; 16];
        let outcome = search(
            &descriptor,
            &weights,
            0,
            1,
            256,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        assert!(outcome.found, "an easy threshold must be found quickly");
        assert!(outcome.attempts <= 256);
        assert!(descriptor
            .verify(&weights, &solution, &mut hidden, &mut output)
            .unwrap());
    }

    #[test]
    fn a_failed_search_leaves_no_solution_behind() {
        let descriptor = descriptor(1);
        let (mut weights, mut hidden, mut output) = buffers();
        descriptor
            .derive_weights(&mut weights[..SPEC.weight_count()])
            .unwrap();
        let mut solution = [-7i64; 16];
        let mut scratch = [0i64; 16];
        let outcome = search(
            &descriptor,
            &weights,
            0,
            1,
            8,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        assert!(!outcome.found);
        assert_eq!(solution, [-7i64; 16]);
    }

    #[test]
    fn disjoint_strides_never_share_candidates() {
        let descriptor = descriptor(1);
        let mut left = [0i64; 16];
        let mut right = [0i64; 16];
        for counter in 0..32u64 {
            descriptor.candidate(2 * counter, &mut left).unwrap();
            descriptor.candidate(2 * counter + 1, &mut right).unwrap();
            assert_ne!(left, right);
        }
    }
}
