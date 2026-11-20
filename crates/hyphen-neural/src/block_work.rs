//! Neural block work v2. The wire witness is a single little-endian nonce.

use crate::{NeuralError, PROFILE_SPEC, WorkDescriptor};
use argon2::{Algorithm, Argon2, Params, Version};

/// Neural scores below this fixed cutoff enter the memory-hard stage.
pub const NEURAL_GATE: u64 = 1 << 60;

/// Recompute the consensus MLP score from the public challenge and nonce.
pub fn nonce_score(work: &WorkDescriptor, weights: &[i64], nonce: u64) -> Result<u64, NeuralError> {
    if work.spec != PROFILE_SPEC {
        return Err(NeuralError::InvalidSpec);
    }
    let mut input = [0; 16];
    work.candidate(nonce, &mut input)?;
    work.score(weights, &input, &mut [0; 64], &mut [0; 16])
}

/// Rejection at the neural gate avoids allocating the Argon2 buffer. Callers
/// verifying untrusted work must independently recompute `score` for this nonce.
pub fn qualifies(work: &WorkDescriptor, nonce: u64, score: u64) -> Result<bool, NeuralError> {
    if score >= NEURAL_GATE {
        return Ok(false);
    }
    Ok(memory_score(&work.chain_seed, nonce, score)? < work.threshold)
}

fn memory_score(seed: &[u8; 32], nonce: u64, score: u64) -> Result<u64, NeuralError> {
    const DOMAIN: &[u8] = b"Hyphen/neural-memory/v2\0";
    let offset = DOMAIN.len();
    let mut input = [0; DOMAIN.len() + 16];
    input[..offset].copy_from_slice(DOMAIN);
    input[offset..offset + 8].copy_from_slice(&nonce.to_le_bytes());
    input[offset + 8..].copy_from_slice(&score.to_le_bytes());
    let params = Params::new(1024, 2, 1, Some(32)).map_err(|_| NeuralError::InvalidSpec)?;
    let mut digest = [0; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&input, seed, &mut digest)
        .map_err(|_| NeuralError::HostFailure)?;
    Ok(u64::from_le_bytes(digest[..8].try_into().unwrap()))
}

/// Verify a wire nonce using locally derived weights and both acceptance gates.
pub fn verify_nonce(work: &WorkDescriptor, nonce: u64) -> Result<bool, NeuralError> {
    let mut weights = vec![0; PROFILE_SPEC.weight_count()];
    work.derive_weights(&mut weights)?;
    qualifies(work, nonce, nonce_score(work, &weights, nonce)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_gate_matches_reference_argon2id() {
        let seed = core::array::from_fn(|i| i as u8);
        // Reference libargon2 v19, raw 32-byte digest begins ff1847bdbdac5428.
        let expected = 0x2854_acbd_bd47_18ff;
        assert_eq!(memory_score(&seed, 123, 456).unwrap(), expected);
        let mut work = WorkDescriptor {
            chain_seed: seed,
            epoch: 1,
            spec: PROFILE_SPEC,
            threshold: expected,
        };
        assert!(!qualifies(&work, 123, 456).unwrap());
        work.threshold += 1;
        assert!(qualifies(&work, 123, 456).unwrap());
        assert!(!qualifies(&work, 123, NEURAL_GATE).unwrap());
    }
}
