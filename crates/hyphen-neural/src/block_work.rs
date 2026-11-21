//! HYN3 nonce verification and BLAKE3 scratchpad evaluation.

use crate::{NeuralError, PROFILE_SPEC, WorkDescriptor};

/// Exclusive gate cutoff applied before allocating the scratchpad.
pub const NEURAL_GATE: u64 = 1 << 60;
/// Number of full digests retained by the reference evaluator.
pub const MEMORY_CELLS: usize = 32_768;
const _: () = assert!(MEMORY_CELLS.is_power_of_two());

/// Integer output fold shared with the CUDA evaluator.
pub fn nonce_score(work: &WorkDescriptor, weights: &[i64], nonce: u64) -> Result<u64, NeuralError> {
    if work.spec != PROFILE_SPEC {
        return Err(NeuralError::InvalidSpec);
    }
    let mut input = [0; 16];
    work.candidate(nonce, &mut input)?;
    work.score(weights, &input, &mut [0; 64], &mut [0; 16])
}

/// Bind the public challenge, nonce and folded MLP output before sampling.
pub fn gate_digest(seed: &[u8; 32], nonce: u64, score: u64) -> blake3::Hash {
    let mut hash = blake3::Hasher::new();
    hash.update(b"Hyphen/neural-gate/v3\0");
    hash.update(seed);
    hash.update(&nonce.to_le_bytes());
    hash.update(&score.to_le_bytes());
    hash.finalize()
}

/// First eight digest bytes interpreted as a little-endian integer.
pub fn low_word(hash: &blake3::Hash) -> u64 {
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
}

/// Each cell stores a complete 32-byte digest. A distinct public key (the
/// gate digest) separates the traversal for each candidate. The 32-byte fill
/// inputs and 64-byte read inputs cannot alias within keyed BLAKE3.
pub fn memory_digest(gate: blake3::Hash) -> blake3::Hash {
    memory_digest_with_cells(gate, &mut Vec::with_capacity(MEMORY_CELLS))
}

fn memory_digest_with_cells(gate: blake3::Hash, cells: &mut Vec<blake3::Hash>) -> blake3::Hash {
    cells.clear();
    let key = gate.as_bytes();
    let mut state = blake3::keyed_hash(key, b"Hyphen/neural-memory/v3\0");
    for _ in 0..MEMORY_CELLS {
        cells.push(state);
        state = blake3::keyed_hash(key, state.as_bytes());
    }
    let mut pair = [0; 64];
    for _ in 0..MEMORY_CELLS {
        let index = (low_word(&state) & (MEMORY_CELLS as u64 - 1)) as usize;
        pair[..32].copy_from_slice(state.as_bytes());
        pair[32..].copy_from_slice(cells[index].as_bytes());
        state = blake3::keyed_hash(key, &pair);
    }
    let mut final_hash = blake3::Hasher::new();
    final_hash.update(b"Hyphen/neural-final/v3\0");
    final_hash.update(key);
    final_hash.update(state.as_bytes());
    final_hash.finalize()
}

/// Mining fast path. Validators recompute `score` via `verify_nonce`.
pub fn qualifies(work: &WorkDescriptor, nonce: u64, score: u64) -> Result<bool, NeuralError> {
    let gate = gate_digest(&work.chain_seed, nonce, score);
    if low_word(&gate) >= NEURAL_GATE {
        return Ok(false);
    }
    // One allocation per active mining thread, first touched by a finalist.
    thread_local! {
        static CELLS: std::cell::RefCell<Vec<blake3::Hash>> =
            std::cell::RefCell::new(Vec::with_capacity(MEMORY_CELLS));
    }
    Ok(
        CELLS.with_borrow_mut(|cells| low_word(&memory_digest_with_cells(gate, cells)))
            < work.threshold,
    )
}

/// Verify a wire nonce from the public descriptor alone.
pub fn verify_nonce(work: &WorkDescriptor, nonce: u64) -> Result<bool, NeuralError> {
    let mut weights = [0; PROFILE_SPEC.weight_count()];
    work.derive_weights(&mut weights)?;
    let gate = gate_digest(&work.chain_seed, nonce, nonce_score(work, &weights, nonce)?);
    Ok(low_word(&gate) < NEURAL_GATE && low_word(&memory_digest(gate)) < work.threshold)
}
