//! Deterministic fixed-point neural evaluation for block work and compute tasks.
//!
//! Alice is a two-layer perceptron whose weights are derived from a public chain
//! seed; the task is to invert it. The contract publishes `A` and one target
//! `y* = A(x*)` and accepts any `x` with `A(x)` inside a published tolerance of
//! `y*`. The descriptor derives `x*` from the public seed. Verification evaluates
//! both the reference input and the candidate. HYN3 block admission instead
//! derives an input from a nonce and checks the neural gate and scratchpad.
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
//! Disable the default `std` feature to build the allocation-free Alice verifier
//! for Wasm. The host build also provides the solver, CLI and block scratchpad.

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
pub mod work;

#[cfg(feature = "std")]
pub mod block_work;

#[cfg(feature = "std")]
mod linalg;

#[cfg(feature = "std")]
pub mod solve;

pub use challenge::{
    ChallengeDescriptor, DEFAULT_INPUT_DIM, DEFAULT_OUTPUT_DIM, DEFAULT_TOLERANCE_ULP,
    DESCRIPTOR_VERSION, MAX_HIDDEN_DIM, MAX_TOLERANCE_ULP, MIN_HIDDEN_DIM, Verification,
    layer_scale,
};
pub use difficulty::{TARGET_EPOCH_SECONDS, epoch_of, epoch_start, next_hidden_dim};
pub use error::NeuralError;
pub use mlp::{MlpSpec, forward, max_abs_difference, mean_squared_error};
pub use rng::ChaCha20;
pub use wire::{
    DESCRIPTOR_BYTES, Operation, SUBMISSION_HEADER_BYTES, decode_descriptor, decode_open,
    decode_status, decode_submit, decode_values_into, encode_descriptor, encode_open,
    encode_submit,
};
pub use work::{
    PROFILE_SPEC, WORK_DESCRIPTOR_VERSION, WorkDescriptor, WorkSearch, search as search_work,
};

#[cfg(feature = "std")]
pub use solve::{SolveConfig, SolveOutcome, solve, verify};
