//! Operating-system randomness used by cryptographic operations.

use rand_core::{Rng, UnwrapErr};

/// Infallible adapter over the operating system CSPRNG.
///
/// The existing cryptographic APIs are infallible. Entropy-source failure is
/// therefore fatal instead of silently falling back to a deterministic PRNG.
pub type SystemRng = UnwrapErr<rand::rngs::SysRng>;

pub fn system_rng() -> SystemRng {
    UnwrapErr(rand::rngs::SysRng)
}

pub fn fill_system_random(destination: &mut [u8]) {
    system_rng().fill_bytes(destination);
}
