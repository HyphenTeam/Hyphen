pub mod difficulty;
pub mod vms;

pub use difficulty::next_difficulty;
pub use vms::{
    chain_element, chain_is_valid, is_prime_u64, search, verify_witnesses, SearchOutcome,
    SearchParams, VmsError, MAX_CHAIN_LENGTH, MAX_WITNESSES_PER_BLOCK, MIN_CHAIN_LENGTH,
};

/// Protocol version of the workload itself. Bumped whenever the witness
/// predicate, the commitment rule or the accepted parameter ranges change; it
/// is part of the chain's public identity and of the pool template.
pub const POUW_PROTOCOL_VERSION: u16 = 3;
