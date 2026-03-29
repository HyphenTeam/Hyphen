use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use thiserror::Error;

use hyphen_crypto::clsag;
use hyphen_crypto::pedersen::{Commitment, PedersenGens};
use hyphen_crypto::stealth::{
    self, StealthAddress,
    encrypt_amount,
};
use hyphen_proof::range_proof::AggregatedRangeProof;

use crate::note::OwnedNote;
use crate::nullifier;
use crate::transaction::*;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("no inputs")]
    NoInputs,
    #[error("no outputs")]
    NoOutputs,
    #[error("input/output value mismatch (inputs {inputs}, outputs {outputs}, fee {fee})")]
    ValueMismatch { inputs: u64, outputs: u64, fee: u64 },
    #[error("ring size mismatch on input {0}")]
    RingSizeMismatch(usize),
    #[error("stealth address error: {0}")]
    Stealth(String),
    #[error("CLSAG signing error: {0}")]
    Clsag(String),
    #[error("range proof error: {0}")]
    RangeProof(String),
}

pub struct InputSpec {
    pub owned: OwnedNote,
    pub decoys: Vec<(RistrettoPoint, RistrettoPoint)>,
    pub real_index: usize,
}

pub struct OutputSpec {
    pub address: StealthAddress,
    pub value: u64,
}

pub struct TransactionBuilder {
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    fee: u64,
}

impl Default for TransactionBuilder {
    fn default() -> Self { Self::new() }
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
        }
    }

    pub fn add_input(&mut self, spec: InputSpec) -> &mut Self {
        self.inputs.push(spec);
        self
    }

    pub fn add_output(&mut self, address: StealthAddress, value: u64) -> &mut Self {
        self.outputs.push(OutputSpec { address, value });
        self
    }

    pub fn set_fee(&mut self, fee: u64) -> &mut Self {
        self.fee = fee;
        self
    }

    pub fn build(self) -> Result<Transaction, BuilderError> {
        if self.inputs.is_empty() {
            return Err(BuilderError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(BuilderError::NoOutputs);
        }

        let total_in: u64 = self.inputs.iter().map(|i| i.owned.value).sum();
        let total_out: u64 = self.outputs.iter().map(|o| o.value).sum();
        if total_in != total_out + self.fee {
            return Err(BuilderError::ValueMismatch {
                inputs: total_in,
                outputs: total_out,
                fee: self.fee,
            });
        }

        let gens = PedersenGens::default();

        let mut tx_outputs = Vec::with_capacity(self.outputs.len());
        let mut out_blindings = Vec::with_capacity(self.outputs.len());
        let mut out_values = Vec::with_capacity(self.outputs.len());

        for (idx, ospec) in self.outputs.iter().enumerate() {
            let (eph, one_time_pk, shared_secret) =
                stealth::derive_one_time_key(&ospec.address, idx as u64)
                    .map_err(|e| BuilderError::Stealth(e.to_string()))?;

            let blinding = Scalar::random(&mut OsRng);
            let commitment = gens.commit(Scalar::from(ospec.value), blinding);

            let enc_amount = encrypt_amount(ospec.value, &shared_secret);

            tx_outputs.push(TxOutput {
                commitment: Commitment::from_point(&commitment),
                one_time_pubkey: one_time_pk.compress().to_bytes(),
                ephemeral_pubkey: eph.0,
                encrypted_amount: enc_amount,
            });
            out_blindings.push(blinding);
            out_values.push(ospec.value);
        }

        // ∑ pseudo_blindings = ∑ out_blindings
        let sum_out_blind: Scalar = out_blindings.iter().sum();
        let mut pseudo_blindings = Vec::with_capacity(self.inputs.len());
        for _i in 0..self.inputs.len() - 1 {
            pseudo_blindings.push(Scalar::random(&mut OsRng));
        }
        let sum_pseudo_partial: Scalar = pseudo_blindings.iter().sum();
        pseudo_blindings.push(sum_out_blind - sum_pseudo_partial);

        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        let mut clsag_sigs = Vec::with_capacity(self.inputs.len());

        let _temp_inputs: Vec<TxInput> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(i, ispec)| {
                let pseudo_commit = gens.commit(
                    Scalar::from(ispec.owned.value),
                    pseudo_blindings[i],
                );
                TxInput {
                    ring: ispec
                        .owned
                        .note
                        .global_index
                        .to_le_bytes()
                        .iter()
                        .map(|_| OutputRef { global_index: 0 })
                        .take(1 + ispec.decoys.len())
                        .collect(),
                    key_image: [0u8; 32],
                    pseudo_output: Commitment::from_point(&pseudo_commit),
                }
            })
            .collect();

        let mut prefix_data = Vec::new();
        prefix_data.push(1u8);
        for out in &tx_outputs {
            prefix_data.extend_from_slice(out.commitment.as_bytes());
        }
        prefix_data.extend_from_slice(&self.fee.to_le_bytes());
        let msg = hyphen_crypto::blake3_hash(&prefix_data);

        for (i, ispec) in self.inputs.iter().enumerate() {
            let spend_sk = ispec.owned.spend_scalar();
            let real_blind = ispec.owned.blinding_scalar();
            let pseudo_blind = pseudo_blindings[i];

            let real_pk = spend_sk * G;
            let real_commit = gens.commit(Scalar::from(ispec.owned.value), real_blind);
            let pseudo_commit = gens.commit(Scalar::from(ispec.owned.value), pseudo_blind);

            let ring_size = 1 + ispec.decoys.len();
            let mut ring_keys = Vec::with_capacity(ring_size);
            let mut ring_commits = Vec::with_capacity(ring_size);
            let mut ring_refs = Vec::with_capacity(ring_size);

            let mut decoy_iter = ispec.decoys.iter();
            for pos in 0..ring_size {
                if pos == ispec.real_index {
                    ring_keys.push(real_pk);
                    ring_commits.push(real_commit);
                    ring_refs.push(OutputRef {
                        global_index: ispec.owned.note.global_index,
                    });
                } else {
                    let (dk, dc) = decoy_iter
                        .next()
                        .ok_or(BuilderError::RingSizeMismatch(i))?;
                    ring_keys.push(*dk);
                    ring_commits.push(*dc);
                    ring_refs.push(OutputRef { global_index: 0 });
                }
            }

            let ki = nullifier::compute_nullifier(&spend_sk, &real_pk);

            let sig = clsag::clsag_sign(
                msg.as_bytes(),
                &ring_keys,
                &ring_commits,
                &pseudo_commit,
                ispec.real_index,
                &spend_sk,
                &(real_blind - pseudo_blind),
            )
            .map_err(|e| BuilderError::Clsag(e.to_string()))?;

            tx_inputs.push(TxInput {
                ring: ring_refs,
                key_image: ki.compress().to_bytes(),
                pseudo_output: Commitment::from_point(&pseudo_commit),
            });
            clsag_sigs.push(sig);
        }

        let (agg_proof, _commitments) =
            AggregatedRangeProof::prove(&out_values, &out_blindings)
                .map_err(|e| BuilderError::RangeProof(e.to_string()))?;

        Ok(Transaction {
            version: 1,
            inputs: tx_inputs,
            outputs: tx_outputs,
            fee: self.fee,
            extra: Vec::new(),
            prunable: TxPrunable {
                clsag_signatures: clsag_sigs,
                range_proof: agg_proof,
            },
        })
    }
}
