//! Settlement for the fixed-point neural circuits.
//!
//! The block proof of work is PoUW v3 and stays in `hyphen-pow`; this module is
//! only the AetherCompute path. Two circuits live here: the inverse challenge
//! the Alice contract publishes, and the one-way work challenge that is safe to
//! gate a block on.
//!
//! # Proof layout
//!
//! ```text
//! descriptor(56 bytes) || solution(input_dim * 8 bytes, little-endian Q32.32)
//! ```
//!
//! # What this proves, and what it does not
//!
//! [`NeuralChallengeVerifier`] re-checks one forward pass against a target that
//! `ChallengeDescriptor::derive_preimage` recomputes from the public
//! `chain_seed`. That makes the result *deterministic* but not *worked for*: a
//! prover can derive `x*` instead of searching, so that circuit must never gate
//! a block.
//!
//! [`NeuralWorkVerifier`] is the one-way counterpart: the seed fixes the
//! network, a threshold fixes the difficulty, and only a candidate whose
//! `score(A(x))` falls below the threshold is accepted. The task commits to the
//! exact descriptor through its `program_hash`, so the threshold cannot be
//! relaxed after publication.

use hyphen_crypto::Hash256;
use hyphen_neural::{decode_descriptor, decode_values_into, WorkDescriptor, DESCRIPTOR_BYTES};

use crate::{
    DataCommitment, ExecutionClaim, FraudClaim, ProofVerifier, RetentionAttestation, TaskSpec,
};

/// Proof-system identifier for a neural preimage.
pub const NEURAL_PROOF_SYSTEM: u16 = 1;

/// Proof-system identifier for a one-way neural work solution.
pub const NEURAL_WORK_PROOF_SYSTEM: u16 = 2;

const D_NEURAL_CIRCUIT: &[u8] = b"HYPHEN_NEURAL_ALICE_V1";
const D_NEURAL_WORK_CIRCUIT: &[u8] = b"HYPHEN_NEURAL_WORK_V1";
const D_NEURAL_WORK_PARAMS: &[u8] = b"HYPHEN_NEURAL_WORK_PARAMS_V1";

/// Circuit identifier a task must name to settle through this verifier.
pub fn neural_circuit_id() -> Hash256 {
    crate::hash(D_NEURAL_CIRCUIT, &[])
}

/// Circuit identifier of the one-way neural work challenge.
pub fn neural_work_circuit_id() -> Hash256 {
    crate::hash(D_NEURAL_WORK_CIRCUIT, &[])
}

/// Commitment a task must carry in `program_hash` to pin one exact work
/// descriptor — shape, acceptance threshold and seed. Without it a miner could
/// pick a trivial threshold after the task was published.
pub fn neural_work_program_hash(descriptor: &WorkDescriptor) -> Result<Hash256, String> {
    let mut bytes = [0_u8; DESCRIPTOR_BYTES];
    descriptor
        .encode(&mut bytes)
        .map_err(|error| format!("neural work descriptor rejected: {error}"))?;
    Ok(crate::hash(D_NEURAL_WORK_PARAMS, &bytes))
}

/// Settles tasks whose circuit is the one-way neural work challenge.
///
/// The proof is `descriptor(56) || solution(input_dim * 8)`. The seed determines
/// the network and the task commits to the descriptor, so the only way to
/// produce an accepted solution is to run forward passes until the score drops
/// below the committed threshold. Verification is exactly one forward pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeuralWorkVerifier;

impl ProofVerifier for NeuralWorkVerifier {
    fn supports(&self, circuit_id: Hash256, proof_system: u16) -> bool {
        circuit_id == neural_work_circuit_id() && proof_system == NEURAL_WORK_PROOF_SYSTEM
    }

    fn verify_execution(&self, task: &TaskSpec, claim: &ExecutionClaim) -> Result<(), String> {
        if !self.supports(task.circuit_id, claim.proof_system) {
            return Err("task does not name the neural work circuit".into());
        }
        let (descriptor_bytes, values_bytes) = claim
            .proof
            .split_at_checked(DESCRIPTOR_BYTES)
            .ok_or_else(|| "neural work proof is shorter than its descriptor".to_string())?;
        let descriptor = WorkDescriptor::decode(descriptor_bytes)
            .map_err(|error| format!("neural work descriptor rejected: {error}"))?;
        if task.program_hash != neural_work_program_hash(&descriptor)? {
            return Err("task does not commit to this work descriptor".into());
        }

        let input_dim = descriptor.spec.input_dim as usize;
        let mut solution = vec![0_i64; input_dim];
        let decoded = decode_values_into(values_bytes, &mut solution)
            .map_err(|error| format!("neural work solution rejected: {error}"))?;
        if decoded != input_dim {
            return Err(format!(
                "neural work solution carries {decoded} values, descriptor wants {input_dim}"
            ));
        }

        let mut weights = vec![0_i64; descriptor.spec.weight_count()];
        descriptor
            .derive_weights(&mut weights)
            .map_err(|error| format!("neural work weight derivation failed: {error}"))?;
        let mut hidden = vec![0_i64; descriptor.spec.hidden_dim as usize];
        let mut output = vec![0_i64; descriptor.spec.output_dim as usize];
        if !descriptor
            .verify(&weights, &solution, &mut hidden, &mut output)
            .map_err(|error| format!("neural work verification failed: {error}"))?
        {
            return Err("neural work solution does not meet the committed threshold".into());
        }
        Ok(())
    }

    fn verify_fraud(
        &self,
        _task: &TaskSpec,
        _result: &ExecutionClaim,
        _fraud: &FraudClaim,
    ) -> Result<(), String> {
        Err("neural work is re-verified on submission; no fraud proof is accepted".into())
    }

    fn verify_retention(
        &self,
        _output: &DataCommitment,
        _attestation: &RetentionAttestation,
    ) -> Result<(), String> {
        Err("proof of custody is not implemented for retained neural outputs".into())
    }
}

/// Settles tasks whose circuit is the Alice neural challenge.
///
/// Every submission is re-verified locally with one forward pass, so a node
/// accepts only solutions inside the descriptor's tolerance. Execution is
/// fully deterministic, which is why no fraud or retention proof is accepted:
/// there is nothing left for a challenger to prove that this node did not
/// already check, and proof of custody is not implemented for retained
/// outputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeuralChallengeVerifier;

impl ProofVerifier for NeuralChallengeVerifier {
    fn supports(&self, circuit_id: Hash256, proof_system: u16) -> bool {
        circuit_id == neural_circuit_id() && proof_system == NEURAL_PROOF_SYSTEM
    }

    fn verify_execution(&self, task: &TaskSpec, claim: &ExecutionClaim) -> Result<(), String> {
        if !self.supports(task.circuit_id, claim.proof_system) {
            return Err("task does not name the neural challenge circuit".into());
        }
        let (descriptor_bytes, values_bytes) = claim
            .proof
            .split_at_checked(DESCRIPTOR_BYTES)
            .ok_or_else(|| "neural proof is shorter than its descriptor".to_string())?;
        let descriptor = decode_descriptor(descriptor_bytes)
            .map_err(|error| format!("neural descriptor rejected: {error}"))?;

        let input_dim = descriptor.spec.input_dim as usize;
        let mut weights = vec![0_i64; descriptor.spec.weight_count()];
        let mut input = vec![0_i64; input_dim];
        let mut target = vec![0_i64; descriptor.spec.output_dim as usize];
        let mut hidden = vec![0_i64; descriptor.spec.hidden_dim as usize];
        let mut output = vec![0_i64; descriptor.spec.output_dim as usize];
        let mut solution = vec![0_i64; input_dim];

        let decoded = decode_values_into(values_bytes, &mut solution)
            .map_err(|error| format!("neural solution rejected: {error}"))?;
        if decoded != input_dim {
            return Err(format!(
                "neural solution carries {decoded} values, descriptor wants {input_dim}"
            ));
        }

        let verification = descriptor
            .evaluate(
                &solution,
                &mut weights,
                &mut input,
                &mut target,
                &mut hidden,
                &mut output,
            )
            .map_err(|error| format!("neural forward pass failed: {error}"))?;
        if !verification.accepted {
            return Err(format!(
                "neural solution is outside tolerance: max_error={} ulp",
                verification.max_error
            ));
        }
        Ok(())
    }

    fn verify_fraud(
        &self,
        _task: &TaskSpec,
        _result: &ExecutionClaim,
        _fraud: &FraudClaim,
    ) -> Result<(), String> {
        Err("the neural circuit is re-verified on submission; no fraud proof is accepted".into())
    }

    fn verify_retention(
        &self,
        _output: &DataCommitment,
        _attestation: &RetentionAttestation,
    ) -> Result<(), String> {
        Err("proof of custody is not implemented for retained neural outputs".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_neural::{encode_descriptor, ChallengeDescriptor, MlpSpec, DEFAULT_TOLERANCE_ULP};

    use crate::{ArithmeticProfile, ScientificDomain, TaskSpec};

    fn descriptor() -> ChallengeDescriptor {
        ChallengeDescriptor {
            version: hyphen_neural::DESCRIPTOR_VERSION,
            epoch: 7,
            spec: MlpSpec {
                input_dim: 16,
                hidden_dim: 24,
                output_dim: 16,
            },
            tolerance_ulp: DEFAULT_TOLERANCE_ULP,
            chain_seed: [3; 32],
        }
    }

    fn proof(descriptor: &ChallengeDescriptor, solution: &[i64]) -> Vec<u8> {
        let mut proof = vec![0_u8; DESCRIPTOR_BYTES + solution.len() * 8];
        let written = encode_descriptor(descriptor, &mut proof).unwrap();
        for (index, value) in solution.iter().enumerate() {
            let offset = written + index * 8;
            proof[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        proof
    }

    /// The solution the descriptor's own seed derives. Settlement checks the
    /// forward pass, not the search, so this is a valid witness.
    fn derived_solution(descriptor: &ChallengeDescriptor) -> Vec<i64> {
        let mut solution = vec![0_i64; descriptor.spec.input_dim as usize];
        descriptor.derive_preimage(&mut solution).unwrap();
        solution
    }

    fn task() -> TaskSpec {
        TaskSpec {
            chain_id: Hash256::from_bytes([9; 32]),
            scientist: hyphen_crypto::SecretKey([1; 32]).public_key(),
            nonce: 1,
            domain: ScientificDomain::Connectomics,
            arithmetic: ArithmeticProfile::DeterministicFixedPointV1,
            circuit_id: neural_circuit_id(),
            program_hash: Hash256::from_bytes([5; 32]),
            input: DataCommitment {
                object_hash: Hash256::from_bytes([6; 32]),
                byte_len: 64,
                chunk_size: 64,
                chunk_count: 1,
                chunk_root: Hash256::from_bytes([7; 32]),
                locator: "ipfs://neural".into(),
            },
            max_operations: 1_000,
            challenge_blocks: crate::MIN_CHALLENGE_BLOCKS,
            retention_blocks: crate::MIN_RETENTION_BLOCKS,
            reward: 1,
            publish_deadline: 100,
        }
    }

    fn claim(proof: Vec<u8>, proof_system: u16) -> ExecutionClaim {
        ExecutionClaim {
            task_id: Hash256::from_bytes([8; 32]),
            worker: hyphen_crypto::SecretKey([2; 32]).public_key(),
            output: DataCommitment {
                object_hash: Hash256::from_bytes([11; 32]),
                byte_len: 64,
                chunk_size: 64,
                chunk_count: 1,
                chunk_root: Hash256::from_bytes([12; 32]),
                locator: "ipfs://result".into(),
            },
            operations: 32,
            trace_root: Hash256::from_bytes([13; 32]),
            checkpoint_root: Hash256::from_bytes([14; 32]),
            proof_system,
            proof,
        }
    }

    #[test]
    fn the_derived_preimage_is_accepted() {
        let descriptor = descriptor();
        let solution = derived_solution(&descriptor);
        let verifier = NeuralChallengeVerifier;
        assert!(verifier
            .verify_execution(
                &task(),
                &claim(proof(&descriptor, &solution), NEURAL_PROOF_SYSTEM)
            )
            .is_ok());
    }

    #[test]
    fn a_perturbed_preimage_is_rejected() {
        let descriptor = descriptor();
        let mut solution = derived_solution(&descriptor);
        for value in &mut solution {
            *value = value.saturating_add(hyphen_neural::MAX_TOLERANCE_ULP as i64 * 4);
        }
        let verifier = NeuralChallengeVerifier;
        assert!(verifier
            .verify_execution(
                &task(),
                &claim(proof(&descriptor, &solution), NEURAL_PROOF_SYSTEM)
            )
            .is_err());
    }

    #[test]
    fn another_proof_system_or_circuit_is_not_supported() {
        let verifier = NeuralChallengeVerifier;
        assert!(verifier.supports(neural_circuit_id(), NEURAL_PROOF_SYSTEM));
        assert!(!verifier.supports(neural_circuit_id(), NEURAL_PROOF_SYSTEM + 1));
        assert!(!verifier.supports(Hash256::from_bytes([1; 32]), NEURAL_PROOF_SYSTEM));
    }

    #[test]
    fn a_truncated_proof_is_rejected() {
        let verifier = NeuralChallengeVerifier;
        assert!(verifier
            .verify_execution(
                &task(),
                &claim(vec![0_u8; DESCRIPTOR_BYTES - 1], NEURAL_PROOF_SYSTEM)
            )
            .is_err());
    }

    fn work_descriptor(threshold: u64) -> WorkDescriptor {
        WorkDescriptor {
            epoch: 3,
            spec: hyphen_neural::MlpSpec {
                input_dim: 16,
                hidden_dim: 20,
                output_dim: 16,
            },
            threshold,
            chain_seed: [4; 32],
        }
    }

    fn work_task(descriptor: &WorkDescriptor) -> TaskSpec {
        TaskSpec {
            circuit_id: neural_work_circuit_id(),
            program_hash: neural_work_program_hash(descriptor).unwrap(),
            ..task()
        }
    }

    /// Searches one accepted solution and returns `descriptor || solution`.
    fn work_proof(descriptor: &WorkDescriptor) -> Vec<u8> {
        let mut weights = vec![0_i64; descriptor.spec.weight_count()];
        descriptor.derive_weights(&mut weights).unwrap();
        let mut solution = vec![0_i64; descriptor.spec.input_dim as usize];
        let mut hidden = vec![0_i64; descriptor.spec.hidden_dim as usize];
        let mut output = vec![0_i64; descriptor.spec.output_dim as usize];
        let mut scratch = vec![0_i64; descriptor.spec.input_dim as usize];
        let outcome = hyphen_neural::search_work(
            descriptor,
            &weights,
            0,
            1,
            4_096,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        assert!(outcome.found, "an easy threshold must be reachable");

        let mut proof = vec![0_u8; DESCRIPTOR_BYTES + solution.len() * 8];
        descriptor.encode(&mut proof).unwrap();
        for (index, value) in solution.iter().enumerate() {
            let offset = DESCRIPTOR_BYTES + index * 8;
            proof[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        proof
    }

    #[test]
    fn a_searched_work_solution_is_accepted() {
        let descriptor = work_descriptor(u64::MAX / 8);
        let verifier = NeuralWorkVerifier;
        assert!(verifier
            .verify_execution(
                &work_task(&descriptor),
                &claim(work_proof(&descriptor), NEURAL_WORK_PROOF_SYSTEM)
            )
            .is_ok());
    }

    /// The task commits to the descriptor, so a prover cannot swap in a softer
    /// threshold after the task was published.
    #[test]
    fn a_relaxed_threshold_is_rejected() {
        let committed = work_descriptor(u64::MAX / 8);
        let relaxed = work_descriptor(u64::MAX);
        let verifier = NeuralWorkVerifier;
        assert!(verifier
            .verify_execution(
                &work_task(&committed),
                &claim(work_proof(&relaxed), NEURAL_WORK_PROOF_SYSTEM)
            )
            .is_err());
    }

    #[test]
    fn a_solution_for_a_different_seed_is_rejected() {
        let committed = work_descriptor(u64::MAX / 8);
        let mut other = committed;
        other.chain_seed[0] ^= 0xFF;
        let verifier = NeuralWorkVerifier;
        assert!(verifier
            .verify_execution(
                &work_task(&committed),
                &claim(work_proof(&other), NEURAL_WORK_PROOF_SYSTEM)
            )
            .is_err());
    }

    #[test]
    fn the_work_verifier_refuses_the_inverse_circuit() {
        let verifier = NeuralWorkVerifier;
        assert!(verifier.supports(neural_work_circuit_id(), NEURAL_WORK_PROOF_SYSTEM));
        assert!(!verifier.supports(neural_circuit_id(), NEURAL_WORK_PROOF_SYSTEM));
        assert!(!verifier.supports(neural_work_circuit_id(), NEURAL_PROOF_SYSTEM));
        assert!(verifier
            .verify_execution(
                &task(),
                &claim(
                    work_proof(&work_descriptor(u64::MAX / 8)),
                    NEURAL_WORK_PROOF_SYSTEM
                )
            )
            .is_err());
    }
}
