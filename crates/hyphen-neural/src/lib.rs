//! Deterministic neural proof-of-work challenge.
//!
//! Alice is a two-layer perceptron whose weights are derived from a public chain
//! seed; the task is to invert it. The contract publishes `A` and one target
//! `y* = A(x*)` and accepts any `x` with `A(x)` inside a published tolerance of
//! `y*`. Verification is a single `O(input_dim * hidden_dim)` forward pass, while
//! finding `x` requires searching a non-convex integer landscape, which is the
//! asymmetry the mechanism depends on.
//!
//! # Why the numbers are integers
//!
//! A verifier that runs on every node cannot use floating point. Different
//! hosts contract `a*b+c` differently, NaN payloads are not portable, and libm
//! is not a specification. Every value here is Q32.32 fixed point, every
//! operation has one rounding rule, and the activation is a rational
//! approximation with a fixed evaluation order. A solution accepted on one host
//! is accepted on all of them, bit for bit.
//!
//! # Why the challenge is an inverse problem
//!
//! Publishing Alice's weights is unavoidable — the contract must verify with
//! them, so they are public. A task phrased as "learn Alice's weights from her
//! outputs" is therefore solved by copying the weights. The inverse formulation
//! keeps the public function and withholds only the preimage, so the only way to
//! answer is to search.
//!
//! # Layout
//!
//! - [`fixed`] — Q32.32 arithmetic and the activation function.
//! - [`rng`] — domain-separated ChaCha20 derivation.
//! - [`mlp`] — the allocation-free forward pass.
//! - [`challenge`] — descriptor derivation, verification, and the acceptance
//!   rule.
//! - [`difficulty`] — the bounded hidden-width controller.
//! - [`wire`] — the fixed-width contract encoding.
//! - [`mod@solve`] — the deterministic Levenberg–Marquardt prover (`std` only).
//!
//! The crate is `no_std` with no allocator by default so the same code compiles
//! into the Alice contract. `std` only adds the prover, the CLI and `Vec`
//! conveniences.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod challenge;
pub mod difficulty;
pub mod error;
pub mod fixed;
pub mod mlp;
pub mod rng;
pub mod wire;

#[cfg(feature = "std")]
mod linalg;

#[cfg(feature = "std")]
pub mod solve;

pub use challenge::{
    layer_scale, ChallengeDescriptor, Verification, DEFAULT_INPUT_DIM, DEFAULT_OUTPUT_DIM,
    DEFAULT_TOLERANCE_ULP, DESCRIPTOR_VERSION, MAX_HIDDEN_DIM, MAX_TOLERANCE_ULP, MIN_HIDDEN_DIM,
};
pub use difficulty::{epoch_of, epoch_start, next_hidden_dim, TARGET_EPOCH_SECONDS};
pub use error::NeuralError;
pub use mlp::{forward, max_abs_difference, mean_squared_error, MlpSpec};
pub use rng::ChaCha20;
pub use wire::{
    decode_descriptor, decode_open, decode_status, decode_submit, decode_values_into,
    encode_descriptor, encode_open, encode_submit, Operation, DESCRIPTOR_BYTES,
    SUBMISSION_HEADER_BYTES,
};

#[cfg(feature = "std")]
pub use solve::{solve, verify, SolveConfig, SolveOutcome};
