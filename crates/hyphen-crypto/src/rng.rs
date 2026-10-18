//! Operating-system randomness used by cryptographic operations.

use rand_core::{Rng, UnwrapErr};

pub type SystemRng = UnwrapErr<rand::rngs::SysRng>;

pub fn system_rng() -> SystemRng {
    UnwrapErr(rand::rngs::SysRng)
}

pub fn fill_system_random(destination: &mut [u8]) {
    system_rng().fill_bytes(destination);
}
