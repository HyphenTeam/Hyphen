//! Shared derivations for the one-way neural work profile.
//!
//! These two functions are the only parts of the block work rule that the node,
//! the pool and the miner must all compute identically. Keeping a single
//! definition here is what stops a client from deriving a different network or
//! committing a different header than the chain expects; the arithmetic itself
//! lives in `hyphen-neural`, which is dependency-free and compiles for wasm.

use hyphen_crypto::{blake3_hash_many, Hash256};

/// Domain tag of the per-miner seed derivation.
pub const NEURAL_WORK_SEED_DOMAIN: &[u8] = b"Hyphen/neural-work-seed/v1";

/// Domain tag of the header commitment.
pub const NEURAL_WORK_COMMITMENT_DOMAIN: &[u8] = b"Hyphen/neural-work-commitment/v1";

/// Seed the block's network is derived from.
///
/// Mixing in the miner's public key is what makes a solution non-transferable:
/// without it, a solution found for one miner's block is valid for every other
/// miner's block at the same height and could be copied out of the mempool.
pub fn neural_work_seed(parent_hash: &Hash256, height: u64, miner_pubkey: &[u8; 32]) -> Hash256 {
    blake3_hash_many(&[
        NEURAL_WORK_SEED_DOMAIN,
        parent_hash.as_bytes(),
        &height.to_le_bytes(),
        miner_pubkey,
    ])
}

/// Value the block header stores in `pow_commitment`.
///
/// It binds the parent hash, the height, the acceptance threshold, the miner and
/// the exact solution, so none of them can change after the search.
pub fn neural_work_commitment(
    parent_hash: &Hash256,
    height: u64,
    threshold: u64,
    miner_pubkey: &[u8; 32],
    solution: &[u64],
) -> Hash256 {
    let mut encoded = Vec::with_capacity(solution.len() * 8);
    for value in solution {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    blake3_hash_many(&[
        NEURAL_WORK_COMMITMENT_DOMAIN,
        parent_hash.as_bytes(),
        &height.to_le_bytes(),
        &threshold.to_le_bytes(),
        miner_pubkey,
        &encoded,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> Hash256 {
        Hash256::from_bytes([7; 32])
    }

    #[test]
    fn the_seed_binds_the_miner() {
        assert_ne!(
            neural_work_seed(&parent(), 1, &[1; 32]),
            neural_work_seed(&parent(), 1, &[2; 32])
        );
    }

    #[test]
    fn the_seed_binds_the_height_and_the_parent() {
        assert_ne!(
            neural_work_seed(&parent(), 1, &[1; 32]),
            neural_work_seed(&parent(), 2, &[1; 32])
        );
        assert_ne!(
            neural_work_seed(&parent(), 1, &[1; 32]),
            neural_work_seed(&Hash256::from_bytes([8; 32]), 1, &[1; 32])
        );
    }

    #[test]
    fn the_commitment_binds_every_field_it_covers() {
        let base = neural_work_commitment(&parent(), 1, 9, &[1; 32], &[3, 4]);
        assert_eq!(
            base,
            neural_work_commitment(&parent(), 1, 9, &[1; 32], &[3, 4])
        );
        assert_ne!(
            base,
            neural_work_commitment(&parent(), 2, 9, &[1; 32], &[3, 4])
        );
        assert_ne!(
            base,
            neural_work_commitment(&parent(), 1, 8, &[1; 32], &[3, 4])
        );
        assert_ne!(
            base,
            neural_work_commitment(&parent(), 1, 9, &[2; 32], &[3, 4])
        );
        assert_ne!(
            base,
            neural_work_commitment(&parent(), 1, 9, &[1; 32], &[4, 3])
        );
    }
}
