use hyphen_crypto::{Hash256, PublicKey, blake3_hash};
use hyphen_neural::{
    ChallengeDescriptor, DESCRIPTOR_BYTES, decode_descriptor, decode_values_into, encode_descriptor,
};

use crate::{
    DataCommitment, ExecutionClaim, FraudClaim, ProofVerifier, RetentionAttestation, TaskSpec,
    hash, hash_many, neural_challenge_program_hash,
};

pub const INLINE_NEURAL_SYSTEM: u16 = 3;
pub const MAX_INLINE_TASKS: usize = 2048;
pub const MAX_INLINE_ENVELOPE: usize = 4096;
pub const MAX_INLINE_TRANSITIONS_PER_BLOCK: usize = 32;

pub fn inline_circuit_id() -> Hash256 {
    hash(b"AETHER_INLINE_ALICE_V1", &[])
}

fn commitment(locator: &str, bytes: &[u8]) -> DataCommitment {
    let digest = blake3_hash(bytes);
    DataCommitment {
        object_hash: digest,
        byte_len: bytes.len() as u64,
        chunk_size: bytes.len() as u32,
        chunk_count: 1,
        chunk_root: digest,
        locator: locator.into(),
    }
}

/// The task signs a digest of the exact descriptor that must accompany the result.
pub fn inline_input(descriptor: &ChallengeDescriptor) -> Result<DataCommitment, String> {
    let mut bytes = [0; DESCRIPTOR_BYTES];
    encode_descriptor(descriptor, &mut bytes).map_err(|e| e.to_string())?;
    Ok(commitment("inline:descriptor", &bytes))
}

fn values_bytes(values: &[i64]) -> Vec<u8> {
    values.iter().flat_map(|n| n.to_le_bytes()).collect()
}

pub fn forward_operations(spec: hyphen_neural::MlpSpec) -> u64 {
    2 * u64::from(spec.hidden_dim) * (u64::from(spec.input_dim) + u64::from(spec.output_dim))
}

/// Recompute the signed statement. Operations count dense multiply-accumulates
/// in the two forward passes, one for the target and one for the candidate.
pub fn inline_claim(
    task: &TaskSpec,
    worker: PublicKey,
    proof: &[u8],
) -> Result<ExecutionClaim, String> {
    let (bytes, values) = proof
        .split_at_checked(DESCRIPTOR_BYTES)
        .ok_or("missing inline descriptor")?;
    let descriptor = decode_descriptor(bytes).map_err(|e| e.to_string())?;
    let spec = descriptor.spec;
    if task.circuit_id != inline_circuit_id()
        || task.program_hash != neural_challenge_program_hash(&descriptor)?
        || task.input != commitment("inline:descriptor", bytes)
    {
        return Err("published circuit, program or input differs from descriptor".into());
    }
    let operations = forward_operations(spec);
    if operations > task.max_operations || values.len() != usize::from(spec.input_dim) * 8 {
        return Err("operation limit or solution width differs".into());
    }
    let mut solution = vec![0; usize::from(spec.input_dim)];
    decode_values_into(values, &mut solution).map_err(|e| e.to_string())?;
    if solution
        .iter()
        .any(|v| !(-hyphen_neural::fixed::ONE..=hyphen_neural::fixed::ONE).contains(v))
    {
        return Err("solution outside the Q32.32 challenge domain".into());
    }
    let mut weights = vec![0; spec.weight_count()];
    let mut preimage = vec![0; solution.len()];
    let mut target = vec![0; usize::from(spec.output_dim)];
    let mut hidden = vec![0; usize::from(spec.hidden_dim)];
    let mut output = vec![0; target.len()];
    let check = descriptor
        .evaluate(
            &solution,
            &mut weights,
            &mut preimage,
            &mut target,
            &mut hidden,
            &mut output,
        )
        .map_err(|e| e.to_string())?;
    if !check.accepted {
        return Err("solution outside the published tolerance".into());
    }
    Ok(ExecutionClaim {
        task_id: task.id(),
        worker,
        output: commitment("inline:solution", values),
        operations,
        trace_root: hash_many(
            b"AETHER_INLINE_TRACE_V1",
            &[&values_bytes(&hidden), &values_bytes(&output)],
        ),
        checkpoint_root: hash(b"AETHER_INLINE_TARGET_V1", &values_bytes(&target)),
        proof_system: INLINE_NEURAL_SYSTEM,
        proof: proof.to_vec(),
    })
}

pub struct InlineNeuralVerifier;

impl ProofVerifier for InlineNeuralVerifier {
    fn supports(&self, circuit: Hash256, system: u16) -> bool {
        circuit == inline_circuit_id() && system == INLINE_NEURAL_SYSTEM
    }
    fn verify_execution(&self, task: &TaskSpec, claim: &ExecutionClaim) -> Result<(), String> {
        let checked = inline_claim(task, claim.worker, &claim.proof)?;
        if &checked != claim {
            return Err("submitted statement differs from deterministic execution".into());
        }
        Ok(())
    }
    fn verify_fraud(&self, _: &TaskSpec, _: &ExecutionClaim, _: &FraudClaim) -> Result<(), String> {
        Err("inline execution is fully checked on submission".into())
    }
    fn verify_retention(&self, _: &DataCommitment, _: &RetentionAttestation) -> Result<(), String> {
        Err("inline results are retained in the canonical task record".into())
    }
    fn has_inline_output(&self, task: &TaskSpec, claim: &ExecutionClaim) -> bool {
        self.supports(task.circuit_id, claim.proof_system)
            && claim
                .proof
                .get(DESCRIPTOR_BYTES..)
                .is_some_and(|v| !v.is_empty() && claim.output == commitment("inline:solution", v))
    }
}
