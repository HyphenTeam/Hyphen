#![forbid(unsafe_code)]

//! Consensus objects and state machine for AetherCompute.
//!
//! This crate deliberately separates the lifecycle protocol from proof-system
//! implementations. A result is accepted only when a node-configured verifier
//! recognizes the task's versioned circuit. No signature, checkpoint sample,
//! or storage certificate is treated as proof of correct execution.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::{blake3_hash_many, Hash256, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

fn wire_config(max_bytes: usize) -> rustbinary::Config {
    rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
}

pub const ENVELOPE_MAGIC: &[u8; 8] = b"AETHWRK1";
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 768 * 1024;
pub const MAX_URI_BYTES: usize = 2048;
pub const MIN_CHALLENGE_BLOCKS: u64 = 16;
pub const MAX_CHALLENGE_BLOCKS: u64 = 100_000;
pub const MIN_RETENTION_BLOCKS: u64 = 256;
pub const MAX_RETENTION_BLOCKS: u64 = 10_000_000;
pub const MAX_DA_ATTESTATIONS: usize = 512;

const D_TASK: &[u8] = b"AETHER_COMPUTE_TASK_V1";
const D_RESULT: &[u8] = b"AETHER_COMPUTE_RESULT_V1";
const D_CHALLENGE: &[u8] = b"AETHER_COMPUTE_CHALLENGE_V1";
const D_RETENTION: &[u8] = b"AETHER_COMPUTE_RETENTION_V1";
const D_STATE_LEAF: &[u8] = b"AETHER_COMPUTE_STATE_LEAF_V1";
const D_STATE_NODE: &[u8] = b"AETHER_COMPUTE_STATE_NODE_V1";
const D_STATE_ROOT: &[u8] = b"AETHER_COMPUTE_STATE_ROOT_V1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum ScientificDomain {
    QuantumChromodynamics = 1,
    ManifoldDynamics = 2,
    Connectomics = 3,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum ArithmeticProfile {
    /// Bit-exact integer and fixed-point semantics. Floating-point contraction,
    /// NaN payloads, host math libraries, clocks, randomness and host I/O are
    /// forbidden by the referenced program profile.
    DeterministicFixedPointV1 = 1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataCommitment {
    pub object_hash: Hash256,
    pub byte_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub chunk_root: Hash256,
    /// UTF-8 locator hint. Integrity comes from the hashes, never the URI.
    pub locator: String,
}

impl DataCommitment {
    pub fn validate(&self) -> Result<(), ComputeError> {
        if self.byte_len == 0
            || self.chunk_size == 0
            || self.chunk_count == 0
            || self.object_hash == Hash256::ZERO
            || self.chunk_root == Hash256::ZERO
            || self.locator.is_empty()
            || self.locator.len() > MAX_URI_BYTES
        {
            return Err(ComputeError::InvalidDataCommitment);
        }
        let capacity = u64::from(self.chunk_size)
            .checked_mul(u64::from(self.chunk_count))
            .ok_or(ComputeError::InvalidDataCommitment)?;
        let minimum = u64::from(self.chunk_size)
            .checked_mul(u64::from(self.chunk_count.saturating_sub(1)))
            .ok_or(ComputeError::InvalidDataCommitment)?;
        if self.byte_len <= minimum || self.byte_len > capacity {
            return Err(ComputeError::InvalidDataCommitment);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80 + self.locator.len());
        bytes.extend_from_slice(self.object_hash.as_bytes());
        bytes.extend_from_slice(&self.byte_len.to_be_bytes());
        bytes.extend_from_slice(&self.chunk_size.to_be_bytes());
        bytes.extend_from_slice(&self.chunk_count.to_be_bytes());
        bytes.extend_from_slice(self.chunk_root.as_bytes());
        bytes.extend_from_slice(&(self.locator.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.locator.as_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskSpec {
    pub chain_id: Hash256,
    pub scientist: PublicKey,
    pub nonce: u64,
    pub domain: ScientificDomain,
    pub arithmetic: ArithmeticProfile,
    /// Hash of a governance-approved verifier key plus deterministic program.
    pub circuit_id: Hash256,
    pub program_hash: Hash256,
    pub input: DataCommitment,
    pub max_operations: u64,
    pub challenge_blocks: u64,
    pub retention_blocks: u64,
    pub reward: u64,
    pub publish_deadline: u64,
}

impl TaskSpec {
    pub fn validate(&self, at_height: u64) -> Result<(), ComputeError> {
        self.input.validate()?;
        if self.chain_id == Hash256::ZERO
            || self.circuit_id == Hash256::ZERO
            || self.program_hash == Hash256::ZERO
            || self.max_operations == 0
            || self.reward == 0
            || !(MIN_CHALLENGE_BLOCKS..=MAX_CHALLENGE_BLOCKS).contains(&self.challenge_blocks)
            || !(MIN_RETENTION_BLOCKS..=MAX_RETENTION_BLOCKS).contains(&self.retention_blocks)
            || self.publish_deadline <= at_height
        {
            return Err(ComputeError::InvalidTask);
        }
        Ok(())
    }

    pub fn digest(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(267 + self.input.locator.len());
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(self.scientist.as_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes.push(self.domain as u8);
        bytes.push(self.arithmetic as u8);
        bytes.extend_from_slice(self.circuit_id.as_bytes());
        bytes.extend_from_slice(self.program_hash.as_bytes());
        bytes.extend_from_slice(&self.input.canonical_bytes());
        bytes.extend_from_slice(&self.max_operations.to_be_bytes());
        bytes.extend_from_slice(&self.challenge_blocks.to_be_bytes());
        bytes.extend_from_slice(&self.retention_blocks.to_be_bytes());
        bytes.extend_from_slice(&self.reward.to_be_bytes());
        bytes.extend_from_slice(&self.publish_deadline.to_be_bytes());
        hash(D_TASK, &bytes)
    }

    pub fn id(&self) -> Hash256 {
        self.digest()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTask {
    pub spec: TaskSpec,
    pub signature: Signature,
}

impl SignedTask {
    pub fn sign(spec: TaskSpec, secret: &SecretKey) -> Result<Self, ComputeError> {
        if spec.scientist != secret.public_key() {
            return Err(ComputeError::WrongSigner);
        }
        let signature = secret.sign(spec.digest().as_bytes());
        Ok(Self { spec, signature })
    }

    fn verify(&self, chain_id: Hash256, at_height: u64) -> Result<(), ComputeError> {
        if self.spec.chain_id != chain_id {
            return Err(ComputeError::WrongChain);
        }
        self.spec.validate(at_height)?;
        self.spec
            .scientist
            .verify(self.spec.digest().as_bytes(), &self.signature)
            .map_err(|_| ComputeError::InvalidSignature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionClaim {
    pub task_id: Hash256,
    pub worker: PublicKey,
    pub output: DataCommitment,
    pub operations: u64,
    pub trace_root: Hash256,
    pub checkpoint_root: Hash256,
    pub proof_system: u16,
    pub proof: Vec<u8>,
}

impl ExecutionClaim {
    pub fn statement_digest(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(192 + self.output.locator.len());
        bytes.extend_from_slice(self.task_id.as_bytes());
        bytes.extend_from_slice(self.worker.as_bytes());
        bytes.extend_from_slice(&self.output.canonical_bytes());
        bytes.extend_from_slice(&self.operations.to_be_bytes());
        bytes.extend_from_slice(self.trace_root.as_bytes());
        bytes.extend_from_slice(self.checkpoint_root.as_bytes());
        bytes.extend_from_slice(&self.proof_system.to_be_bytes());
        bytes.extend_from_slice(hash(b"AETHER_PROOF_BYTES_V1", &self.proof).as_bytes());
        hash(D_RESULT, &bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedResult {
    pub claim: ExecutionClaim,
    pub signature: Signature,
}

impl SignedResult {
    pub fn sign(claim: ExecutionClaim, secret: &SecretKey) -> Result<Self, ComputeError> {
        if claim.worker != secret.public_key() {
            return Err(ComputeError::WrongSigner);
        }
        let signature = secret.sign(claim.statement_digest().as_bytes());
        Ok(Self { claim, signature })
    }

    fn verify_signature(&self) -> Result<(), ComputeError> {
        self.claim
            .worker
            .verify(self.claim.statement_digest().as_bytes(), &self.signature)
            .map_err(|_| ComputeError::InvalidSignature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FraudClaim {
    pub task_id: Hash256,
    pub result_digest: Hash256,
    pub challenger: PublicKey,
    pub verifier_version: u16,
    pub evidence: Vec<u8>,
}

impl FraudClaim {
    pub fn digest(&self) -> Hash256 {
        let evidence_hash = hash(b"AETHER_FRAUD_EVIDENCE_V1", &self.evidence);
        let mut bytes = Vec::with_capacity(130);
        bytes.extend_from_slice(self.task_id.as_bytes());
        bytes.extend_from_slice(self.result_digest.as_bytes());
        bytes.extend_from_slice(self.challenger.as_bytes());
        bytes.extend_from_slice(&self.verifier_version.to_be_bytes());
        bytes.extend_from_slice(evidence_hash.as_bytes());
        hash(D_CHALLENGE, &bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedFraudClaim {
    pub claim: FraudClaim,
    pub signature: Signature,
}

impl SignedFraudClaim {
    pub fn sign(claim: FraudClaim, secret: &SecretKey) -> Result<Self, ComputeError> {
        if claim.challenger != secret.public_key() {
            return Err(ComputeError::WrongSigner);
        }
        let signature = secret.sign(claim.digest().as_bytes());
        Ok(Self { claim, signature })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionAttestation {
    pub task_id: Hash256,
    pub result_digest: Hash256,
    pub provider: PublicKey,
    pub observed_height: u64,
    pub retain_until_height: u64,
    pub nonce: Hash256,
    pub response_hash: Hash256,
}

impl RetentionAttestation {
    pub fn digest(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(176);
        bytes.extend_from_slice(self.task_id.as_bytes());
        bytes.extend_from_slice(self.result_digest.as_bytes());
        bytes.extend_from_slice(self.provider.as_bytes());
        bytes.extend_from_slice(&self.observed_height.to_be_bytes());
        bytes.extend_from_slice(&self.retain_until_height.to_be_bytes());
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(self.response_hash.as_bytes());
        hash(D_RETENTION, &bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRetentionAttestation {
    pub attestation: RetentionAttestation,
    pub signature: Signature,
}

impl SignedRetentionAttestation {
    pub fn sign(
        attestation: RetentionAttestation,
        secret: &SecretKey,
    ) -> Result<Self, ComputeError> {
        if attestation.provider != secret.public_key() {
            return Err(ComputeError::WrongSigner);
        }
        let signature = secret.sign(attestation.digest().as_bytes());
        Ok(Self {
            attestation,
            signature,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComputeTransaction {
    Publish(SignedTask),
    Submit(SignedResult),
    Challenge(SignedFraudClaim),
    AttestRetention(SignedRetentionAttestation),
    Finalize { task_id: Hash256 },
}

impl ComputeTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, ComputeError> {
        let payload = wire_config(MAX_ENVELOPE_BYTES)
            .serialize(self)
            .map_err(|error| ComputeError::Encoding(error.to_string()))?;
        let mut bytes = Vec::with_capacity(ENVELOPE_MAGIC.len() + payload.len());
        bytes.extend_from_slice(ENVELOPE_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, ComputeError> {
        if !bytes.starts_with(ENVELOPE_MAGIC) {
            return Ok(None);
        }
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ComputeError::EnvelopeTooLarge);
        }
        let value = wire_config(MAX_ENVELOPE_BYTES - ENVELOPE_MAGIC.len())
            .deserialize(&bytes[ENVELOPE_MAGIC.len()..])
            .map_err(|error| ComputeError::Encoding(error.to_string()))?;
        Ok(Some(value))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Open,
    Submitted {
        result: SignedResult,
        submitted_height: u64,
        challenge_deadline: u64,
    },
    Rejected {
        result_digest: Hash256,
        challenger: PublicKey,
        rejected_height: u64,
    },
    Finalized {
        result: SignedResult,
        finalized_height: u64,
        retain_until_height: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    pub task: SignedTask,
    pub published_height: u64,
    pub status: TaskStatus,
    pub retention: BTreeMap<PublicKey, RetentionAttestation>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputeState {
    tasks: BTreeMap<Hash256, TaskRecord>,
    scientist_nonces: BTreeSet<(PublicKey, u64)>,
}

pub trait ProofVerifier: Send + Sync {
    fn supports(&self, circuit_id: Hash256, proof_system: u16) -> bool;
    fn verify_execution(&self, task: &TaskSpec, claim: &ExecutionClaim) -> Result<(), String>;
    fn verify_fraud(
        &self,
        task: &TaskSpec,
        result: &ExecutionClaim,
        fraud: &FraudClaim,
    ) -> Result<(), String>;
    fn verify_retention(
        &self,
        output: &DataCommitment,
        attestation: &RetentionAttestation,
    ) -> Result<(), String>;
}

/// Secure default: useful-work result settlement is unavailable until a node
/// operator installs the exact verifier required by the chain profile.
#[derive(Default)]
pub struct RejectingVerifier;

impl ProofVerifier for RejectingVerifier {
    fn supports(&self, _circuit_id: Hash256, _proof_system: u16) -> bool {
        false
    }
    fn verify_execution(&self, _task: &TaskSpec, _claim: &ExecutionClaim) -> Result<(), String> {
        Err("no activated scientific proof verifier".into())
    }
    fn verify_fraud(
        &self,
        _task: &TaskSpec,
        _result: &ExecutionClaim,
        _fraud: &FraudClaim,
    ) -> Result<(), String> {
        Err("no activated fraud-proof verifier".into())
    }
    fn verify_retention(
        &self,
        _output: &DataCommitment,
        _attestation: &RetentionAttestation,
    ) -> Result<(), String> {
        Err("no activated proof-of-custody verifier".into())
    }
}

impl ComputeState {
    pub fn task(&self, task_id: Hash256) -> Option<&TaskRecord> {
        self.tasks.get(&task_id)
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Returns a deterministic page ordered by task ID. The caller owns the
    /// records, so storage locks never escape the state boundary.
    pub fn tasks_page(&self, offset: usize, limit: usize) -> Vec<(Hash256, TaskRecord)> {
        self.tasks
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(task_id, record)| (*task_id, record.clone()))
            .collect()
    }

    pub fn is_available_through(&self, task_id: Hash256, height: u64) -> bool {
        self.tasks.get(&task_id).is_some_and(|record| {
            matches!(
                record.status,
                TaskStatus::Finalized {
                    retain_until_height,
                    ..
                } if retain_until_height >= height
            )
        })
    }

    pub fn root(&self) -> Hash256 {
        if self.tasks.is_empty() {
            return Hash256::ZERO;
        }
        let leaves = self
            .tasks
            .iter()
            .map(|(id, record)| {
                let encoded = wire_config(DEFAULT_WIRE_BYTES)
                    .serialize(record)
                    .expect("bounded in-memory task records always serialize");
                hash_many(D_STATE_LEAF, &[id.as_bytes(), &encoded])
            })
            .collect::<Vec<_>>();
        let tree_root = merkle_root(&leaves);
        hash_many(
            D_STATE_ROOT,
            &[
                &(self.tasks.len() as u64).to_be_bytes(),
                tree_root.as_bytes(),
            ],
        )
    }

    pub fn apply(
        &mut self,
        chain_id: Hash256,
        at_height: u64,
        transaction: &ComputeTransaction,
        verifier: &dyn ProofVerifier,
    ) -> Result<(), ComputeError> {
        match transaction {
            ComputeTransaction::Publish(task) => self.publish(chain_id, at_height, task),
            ComputeTransaction::Submit(result) => self.submit(at_height, result, verifier),
            ComputeTransaction::Challenge(fraud) => self.challenge(at_height, fraud, verifier),
            ComputeTransaction::AttestRetention(attestation) => {
                self.attest_retention(at_height, attestation, verifier)
            }
            ComputeTransaction::Finalize { task_id } => self.finalize(at_height, *task_id),
        }
    }

    fn publish(
        &mut self,
        chain_id: Hash256,
        at_height: u64,
        signed: &SignedTask,
    ) -> Result<(), ComputeError> {
        signed.verify(chain_id, at_height)?;
        let id = signed.spec.id();
        if self.tasks.contains_key(&id) {
            return Err(ComputeError::DuplicateTask);
        }
        let nonce_key = (signed.spec.scientist, signed.spec.nonce);
        if !self.scientist_nonces.insert(nonce_key) {
            return Err(ComputeError::DuplicateNonce);
        }
        self.tasks.insert(
            id,
            TaskRecord {
                task: signed.clone(),
                published_height: at_height,
                status: TaskStatus::Open,
                retention: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn submit(
        &mut self,
        at_height: u64,
        signed: &SignedResult,
        verifier: &dyn ProofVerifier,
    ) -> Result<(), ComputeError> {
        signed.verify_signature()?;
        if signed.claim.proof.is_empty() || signed.claim.proof.len() > MAX_PROOF_BYTES {
            return Err(ComputeError::InvalidProof);
        }
        signed.claim.output.validate()?;
        if signed.claim.trace_root == Hash256::ZERO || signed.claim.checkpoint_root == Hash256::ZERO
        {
            return Err(ComputeError::InvalidResult);
        }
        let record = self
            .tasks
            .get_mut(&signed.claim.task_id)
            .ok_or(ComputeError::UnknownTask)?;
        if !matches!(record.status, TaskStatus::Open) {
            return Err(ComputeError::WrongStatus);
        }
        let spec = &record.task.spec;
        if at_height > spec.publish_deadline || signed.claim.operations > spec.max_operations {
            return Err(ComputeError::InvalidResult);
        }
        if !verifier.supports(spec.circuit_id, signed.claim.proof_system) {
            return Err(ComputeError::UnsupportedVerifier);
        }
        verifier
            .verify_execution(spec, &signed.claim)
            .map_err(ComputeError::ProofRejected)?;
        let challenge_deadline = at_height
            .checked_add(spec.challenge_blocks)
            .ok_or(ComputeError::HeightOverflow)?;
        record.status = TaskStatus::Submitted {
            result: signed.clone(),
            submitted_height: at_height,
            challenge_deadline,
        };
        Ok(())
    }

    fn challenge(
        &mut self,
        at_height: u64,
        signed: &SignedFraudClaim,
        verifier: &dyn ProofVerifier,
    ) -> Result<(), ComputeError> {
        signed
            .claim
            .challenger
            .verify(signed.claim.digest().as_bytes(), &signed.signature)
            .map_err(|_| ComputeError::InvalidSignature)?;
        if signed.claim.evidence.is_empty() || signed.claim.evidence.len() > MAX_PROOF_BYTES {
            return Err(ComputeError::InvalidFraudProof);
        }
        let record = self
            .tasks
            .get_mut(&signed.claim.task_id)
            .ok_or(ComputeError::UnknownTask)?;
        let (result, deadline) = match &record.status {
            TaskStatus::Submitted {
                result,
                challenge_deadline,
                ..
            } => (result, *challenge_deadline),
            _ => return Err(ComputeError::WrongStatus),
        };
        if at_height > deadline || result.claim.statement_digest() != signed.claim.result_digest {
            return Err(ComputeError::InvalidFraudProof);
        }
        verifier
            .verify_fraud(&record.task.spec, &result.claim, &signed.claim)
            .map_err(ComputeError::FraudProofRejected)?;
        record.status = TaskStatus::Rejected {
            result_digest: signed.claim.result_digest,
            challenger: signed.claim.challenger,
            rejected_height: at_height,
        };
        Ok(())
    }

    fn attest_retention(
        &mut self,
        at_height: u64,
        signed: &SignedRetentionAttestation,
        verifier: &dyn ProofVerifier,
    ) -> Result<(), ComputeError> {
        let attestation = &signed.attestation;
        attestation
            .provider
            .verify(attestation.digest().as_bytes(), &signed.signature)
            .map_err(|_| ComputeError::InvalidSignature)?;
        if attestation.observed_height != at_height
            || attestation.retain_until_height <= at_height
            || attestation.nonce == Hash256::ZERO
            || attestation.response_hash == Hash256::ZERO
        {
            return Err(ComputeError::InvalidRetention);
        }
        let record = self
            .tasks
            .get_mut(&attestation.task_id)
            .ok_or(ComputeError::UnknownTask)?;
        let result = match &record.status {
            TaskStatus::Submitted { result, .. } | TaskStatus::Finalized { result, .. } => result,
            _ => return Err(ComputeError::WrongStatus),
        };
        if result.claim.statement_digest() != attestation.result_digest {
            return Err(ComputeError::InvalidRetention);
        }
        verifier
            .verify_retention(&result.claim.output, attestation)
            .map_err(ComputeError::RetentionProofRejected)?;
        if record.retention.len() >= MAX_DA_ATTESTATIONS
            && !record.retention.contains_key(&attestation.provider)
        {
            return Err(ComputeError::TooManyAttestations);
        }
        if record
            .retention
            .get(&attestation.provider)
            .is_some_and(|old| old.observed_height >= attestation.observed_height)
        {
            return Err(ComputeError::StaleAttestation);
        }
        record
            .retention
            .insert(attestation.provider, attestation.clone());
        if let TaskStatus::Finalized {
            retain_until_height,
            ..
        } = &mut record.status
        {
            let mut coverage = record
                .retention
                .values()
                .map(|item| item.retain_until_height)
                .collect::<Vec<_>>();
            coverage.sort_unstable_by(|left, right| right.cmp(left));
            if let Some(third_provider_height) = coverage.get(2) {
                *retain_until_height = (*retain_until_height).max(*third_provider_height);
            }
        }
        Ok(())
    }

    fn finalize(&mut self, at_height: u64, task_id: Hash256) -> Result<(), ComputeError> {
        let record = self
            .tasks
            .get_mut(&task_id)
            .ok_or(ComputeError::UnknownTask)?;
        let (result, challenge_deadline) = match &record.status {
            TaskStatus::Submitted {
                result,
                challenge_deadline,
                ..
            } => (result.clone(), *challenge_deadline),
            _ => return Err(ComputeError::WrongStatus),
        };
        if at_height <= challenge_deadline {
            return Err(ComputeError::ChallengePeriodOpen);
        }
        let required_until = at_height
            .checked_add(record.task.spec.retention_blocks)
            .ok_or(ComputeError::HeightOverflow)?;
        let independent = record
            .retention
            .values()
            .filter(|attestation| attestation.retain_until_height >= required_until)
            .count();
        // This is a decentralization floor, not a claim of permanent storage.
        if independent < 3 {
            return Err(ComputeError::InsufficientRetention);
        }
        record.status = TaskStatus::Finalized {
            result,
            finalized_height: at_height,
            retain_until_height: required_until,
        };
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ComputeError {
    #[error("compute envelope exceeds the protocol limit")]
    EnvelopeTooLarge,
    #[error("compute encoding error: {0}")]
    Encoding(String),
    #[error("transaction belongs to another chain")]
    WrongChain,
    #[error("secret key does not own the declared public key")]
    WrongSigner,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("invalid task specification")]
    InvalidTask,
    #[error("invalid data commitment")]
    InvalidDataCommitment,
    #[error("task already exists")]
    DuplicateTask,
    #[error("scientist nonce already used")]
    DuplicateNonce,
    #[error("unknown task")]
    UnknownTask,
    #[error("transaction is not valid in the task's current state")]
    WrongStatus,
    #[error("invalid result claim")]
    InvalidResult,
    #[error("proof is empty or exceeds the protocol limit")]
    InvalidProof,
    #[error("circuit/proof system is not activated")]
    UnsupportedVerifier,
    #[error("execution proof rejected: {0}")]
    ProofRejected(String),
    #[error("invalid fraud proof")]
    InvalidFraudProof,
    #[error("fraud proof rejected: {0}")]
    FraudProofRejected(String),
    #[error("invalid retention attestation")]
    InvalidRetention,
    #[error("retention proof rejected: {0}")]
    RetentionProofRejected(String),
    #[error("retention attestation is stale")]
    StaleAttestation,
    #[error("too many retention attestations")]
    TooManyAttestations,
    #[error("challenge period is still open")]
    ChallengePeriodOpen,
    #[error("fewer than three independent long-retention providers")]
    InsufficientRetention,
    #[error("height arithmetic overflow")]
    HeightOverflow,
}

fn hash(domain: &[u8], bytes: &[u8]) -> Hash256 {
    hash_many(domain, &[bytes])
}

fn hash_many(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let length = parts.iter().map(|part| part.len()).sum::<usize>();
    let mut framed = Vec::with_capacity(domain.len() + length + 16 + parts.len() * 8);
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain);
    for part in parts {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part);
    }
    blake3_hash_many(&[&framed])
}

fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return hash(D_STATE_NODE, b"empty");
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(hash_many(
                D_STATE_NODE,
                &[pair[0].as_bytes(), right.as_bytes()],
            ));
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerifier;
    impl ProofVerifier for TestVerifier {
        fn supports(&self, circuit_id: Hash256, proof_system: u16) -> bool {
            circuit_id == h(9) && proof_system == 1
        }
        fn verify_execution(&self, task: &TaskSpec, claim: &ExecutionClaim) -> Result<(), String> {
            (claim.operations == task.max_operations && claim.proof == b"valid-proof")
                .then_some(())
                .ok_or_else(|| "invalid execution".into())
        }
        fn verify_fraud(
            &self,
            _task: &TaskSpec,
            _result: &ExecutionClaim,
            fraud: &FraudClaim,
        ) -> Result<(), String> {
            (fraud.evidence == b"valid-fraud")
                .then_some(())
                .ok_or_else(|| "invalid fraud".into())
        }
        fn verify_retention(
            &self,
            _output: &DataCommitment,
            attestation: &RetentionAttestation,
        ) -> Result<(), String> {
            (attestation.response_hash == h(7))
                .then_some(())
                .ok_or_else(|| "invalid custody response".into())
        }
    }

    fn h(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn data(byte: u8) -> DataCommitment {
        DataCommitment {
            object_hash: h(byte),
            byte_len: 1024,
            chunk_size: 1024,
            chunk_count: 1,
            chunk_root: h(byte.wrapping_add(1)),
            locator: format!("ar://object-{byte}"),
        }
    }

    fn task(chain_id: Hash256, scientist: &SecretKey) -> SignedTask {
        SignedTask::sign(
            TaskSpec {
                chain_id,
                scientist: scientist.public_key(),
                nonce: 1,
                domain: ScientificDomain::ManifoldDynamics,
                arithmetic: ArithmeticProfile::DeterministicFixedPointV1,
                circuit_id: h(9),
                program_hash: h(10),
                input: data(11),
                max_operations: 1_000_000,
                challenge_blocks: MIN_CHALLENGE_BLOCKS,
                retention_blocks: MIN_RETENTION_BLOCKS,
                reward: 10_000,
                publish_deadline: 100,
            },
            scientist,
        )
        .unwrap()
    }

    fn result(task_id: Hash256, worker: &SecretKey) -> SignedResult {
        SignedResult::sign(
            ExecutionClaim {
                task_id,
                worker: worker.public_key(),
                output: data(21),
                operations: 1_000_000,
                trace_root: h(22),
                checkpoint_root: h(23),
                proof_system: 1,
                proof: b"valid-proof".to_vec(),
            },
            worker,
        )
        .unwrap()
    }

    #[test]
    fn signed_envelope_round_trips_and_cross_chain_publish_fails() {
        let scientist = SecretKey([1; 32]);
        let tx = ComputeTransaction::Publish(task(h(1), &scientist));
        let encoded = tx.encode().unwrap();
        assert_eq!(
            ComputeTransaction::decode(&encoded).unwrap(),
            Some(tx.clone())
        );
        assert_eq!(
            ComputeTransaction::decode(b"ordinary-payment").unwrap(),
            None
        );
        let mut state = ComputeState::default();
        assert_eq!(
            state.apply(h(2), 1, &tx, &TestVerifier),
            Err(ComputeError::WrongChain)
        );
    }

    #[test]
    fn proof_challenge_and_state_root_are_consensus_bound() {
        let chain_id = h(1);
        let scientist = SecretKey([1; 32]);
        let worker = SecretKey([2; 32]);
        let challenger = SecretKey([3; 32]);
        let signed_task = task(chain_id, &scientist);
        let task_id = signed_task.spec.id();
        let mut state = ComputeState::default();
        let empty = state.root();
        state
            .apply(
                chain_id,
                1,
                &ComputeTransaction::Publish(signed_task),
                &TestVerifier,
            )
            .unwrap();
        assert_ne!(empty, state.root());
        let signed_result = result(task_id, &worker);
        let result_digest = signed_result.claim.statement_digest();
        state
            .apply(
                chain_id,
                2,
                &ComputeTransaction::Submit(signed_result),
                &TestVerifier,
            )
            .unwrap();
        let fraud = SignedFraudClaim::sign(
            FraudClaim {
                task_id,
                result_digest,
                challenger: challenger.public_key(),
                verifier_version: 1,
                evidence: b"valid-fraud".to_vec(),
            },
            &challenger,
        )
        .unwrap();
        state
            .apply(
                chain_id,
                3,
                &ComputeTransaction::Challenge(fraud),
                &TestVerifier,
            )
            .unwrap();
        assert!(matches!(
            state.task(task_id).unwrap().status,
            TaskStatus::Rejected { .. }
        ));
    }

    #[test]
    fn finalization_requires_elapsed_challenge_and_three_custodians() {
        let chain_id = h(1);
        let scientist = SecretKey([1; 32]);
        let worker = SecretKey([2; 32]);
        let signed_task = task(chain_id, &scientist);
        let task_id = signed_task.spec.id();
        let signed_result = result(task_id, &worker);
        let digest = signed_result.claim.statement_digest();
        let mut state = ComputeState::default();
        state
            .apply(
                chain_id,
                1,
                &ComputeTransaction::Publish(signed_task),
                &TestVerifier,
            )
            .unwrap();
        state
            .apply(
                chain_id,
                2,
                &ComputeTransaction::Submit(signed_result),
                &TestVerifier,
            )
            .unwrap();
        let finalize_height = 2 + MIN_CHALLENGE_BLOCKS + 1;
        assert_eq!(
            state.apply(
                chain_id,
                finalize_height,
                &ComputeTransaction::Finalize { task_id },
                &TestVerifier
            ),
            Err(ComputeError::InsufficientRetention)
        );
        for byte in 31..34 {
            let provider = SecretKey([byte; 32]);
            let attestation = SignedRetentionAttestation::sign(
                RetentionAttestation {
                    task_id,
                    result_digest: digest,
                    provider: provider.public_key(),
                    observed_height: finalize_height,
                    retain_until_height: finalize_height + MIN_RETENTION_BLOCKS,
                    nonce: h(byte),
                    response_hash: h(7),
                },
                &provider,
            )
            .unwrap();
            state
                .apply(
                    chain_id,
                    finalize_height,
                    &ComputeTransaction::AttestRetention(attestation),
                    &TestVerifier,
                )
                .unwrap();
        }
        state
            .apply(
                chain_id,
                finalize_height,
                &ComputeTransaction::Finalize { task_id },
                &TestVerifier,
            )
            .unwrap();
        assert!(matches!(
            state.task(task_id).unwrap().status,
            TaskStatus::Finalized { .. }
        ));
    }
}
