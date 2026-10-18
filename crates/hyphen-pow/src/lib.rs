#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod difficulty;
pub mod vms;

#[cfg(feature = "std")]
pub use difficulty::next_difficulty;
pub use vms::{
    chain_element, chain_is_valid, chain_is_valid_after_sieve, is_prime_u64,
    passes_small_prime_sieve, search, verify_witnesses, SearchOutcome, SearchParams, VmsError,
    MAX_CHAIN_LENGTH, MAX_WITNESSES_PER_BLOCK, MIN_CHAIN_LENGTH, SMALL_PRIME_SIEVE_LIMIT,
};

pub const POUW_PROTOCOL_VERSION: u16 = 3;
