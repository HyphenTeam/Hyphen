use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use thiserror::Error;

use hyphen_crypto::clsag;
use hyphen_crypto::pedersen::{Commitment, PedersenGens};
use hyphen_crypto::stealth::{
    self, StealthAddress,
    encrypt_amount, derive_commitment_blinding, compute_view_tag,
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
    #[error("point decompression failed on input {0}")]
    Decompression(usize),
}

pub struct InputSpec {
    pub owned: OwnedNote,
    pub decoys: Vec<(RistrettoPoint, RistrettoPoint, u64)>,
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
    /// TERA epoch context: blake3("TERA_v1" || epoch_seed)
    epoch_context: [u8; 32],
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
            epoch_context: [0u8; 32],
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

    /// Set the TERA epoch context. Callers must supply the *current* epoch
    /// seed so the builder can derive the binding.  The epoch_seed is
    /// typically obtained from `Blockchain::epoch_seed_for_height`.
    pub fn set_epoch_seed(&mut self, epoch_seed: &[u8; 32]) -> &mut Self {
        self.epoch_context = *hyphen_crypto::blake3_keyed(
            b"TERA_v1_context__Hyphen_2025_ctx",
            epoch_seed,
        ).as_bytes();
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

            let blinding = derive_commitment_blinding(&shared_secret);
            let commitment = gens.commit(Scalar::from(ospec.value), blinding);
            let enc_amount = encrypt_amount(ospec.value, &shared_secret);
            let view_tag = compute_view_tag(&shared_secret);

            tx_outputs.push(TxOutput {
                commitment: Commitment::from_point(&commitment),
                one_time_pubkey: one_time_pk.compress().to_bytes(),
                ephemeral_pubkey: eph.0,
                encrypted_amount: enc_amount,
                view_tag,
            });
            out_blindings.push(blinding);
            out_values.push(ospec.value);
        }

        let sum_out_blind: Scalar = out_blindings.iter().sum();
        let mut pseudo_blindings = Vec::with_capacity(self.inputs.len());
        for _i in 0..self.inputs.len() - 1 {
            pseudo_blindings.push(Scalar::random(&mut OsRng));
        }
        let sum_pseudo_partial: Scalar = pseudo_blindings.iter().sum();
        pseudo_blindings.push(sum_out_blind - sum_pseudo_partial);

        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        let mut clsag_sigs = Vec::with_capacity(self.inputs.len());

        // Phase 1: Build all TxInput structures and collect signing data
        struct SigningData {
            ring_keys: Vec<RistrettoPoint>,
            ring_commits: Vec<RistrettoPoint>,
            pseudo_commit: RistrettoPoint,
            real_index: usize,
            spend_sk: Scalar,
            blinding_diff: Scalar,
        }
        let mut signing_data = Vec::with_capacity(self.inputs.len());

        for (i, ispec) in self.inputs.iter().enumerate() {
            let spend_sk = ispec.owned.spend_scalar();
            let real_blind = ispec.owned.blinding_scalar();
            let pseudo_blind = pseudo_blindings[i];

            let real_pk = CompressedRistretto::from_slice(&ispec.owned.note.one_time_pubkey)
                .map_err(|_| BuilderError::Decompression(i))?
                .decompress()
                .ok_or(BuilderError::Decompression(i))?;
            let real_commit = ispec
                .owned
                .note
                .commitment
                .to_point()
                .map_err(|_| BuilderError::Decompression(i))?;
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
                    let (dk, dc, di) = decoy_iter
                        .next()
                        .ok_or(BuilderError::RingSizeMismatch(i))?;
                    ring_keys.push(*dk);
                    ring_commits.push(*dc);
                    ring_refs.push(OutputRef { global_index: *di });
                }
            }

            let ki = nullifier::compute_nullifier(&spend_sk, &real_pk);

            // ── TERA: compute temporal nonce and causal binding ──
            let temporal_nonce = *hyphen_crypto::hash::hash_to_scalar(
                b"TERA_nonce",
                &[spend_sk.as_bytes().as_slice(), &self.epoch_context].concat(),
            ).as_bytes();

            let note_hash = ispec.owned.note.note_hash();
            let causal_binding = *hyphen_crypto::blake3_hash_many(&[
                b"TERA_causal",
                spend_sk.as_bytes(),
                note_hash.as_bytes(),
                &self.epoch_context,
            ]).as_bytes();

            tx_inputs.push(TxInput {
                ring: ring_refs,
                key_image: ki.compress().to_bytes(),
                pseudo_output: Commitment::from_point(&pseudo_commit),
                epoch_context: self.epoch_context,
                temporal_nonce,
                causal_binding,
            });
            signing_data.push(SigningData {
                ring_keys,
                ring_commits,
                pseudo_commit,
                real_index: ispec.real_index,
                spend_sk,
                blinding_diff: real_blind - pseudo_blind,
            });
        }

        let (agg_proof, _commitments) =
            AggregatedRangeProof::prove(&out_values, &out_blindings)
                .map_err(|e| BuilderError::RangeProof(e.to_string()))?;

        // Phase 2: Build the Transaction shell to compute prefix_hash
        // using the authoritative Transaction::prefix_hash() method —
        // avoids duplicating the hash logic.
        let mut tx = Transaction {
            version: 1,
            inputs: tx_inputs,
            outputs: tx_outputs,
            fee: self.fee,
            extra: Vec::new(),
            prunable: TxPrunable {
                clsag_signatures: Vec::new(),
                range_proof: agg_proof,
            },
        };

        let msg = tx.prefix_hash();

        // Phase 3: Sign each input with CLSAG
        for sd in &signing_data {
            let sig = clsag::clsag_sign(
                msg.as_bytes(),
                &sd.ring_keys,
                &sd.ring_commits,
                &sd.pseudo_commit,
                sd.real_index,
                &sd.spend_sk,
                &sd.blinding_diff,
            )
            .map_err(|e| BuilderError::Clsag(e.to_string()))?;

            // Self-verify immediately — if this fails, the data is inconsistent
            clsag::clsag_verify(
                msg.as_bytes(),
                &sd.ring_keys,
                &sd.ring_commits,
                &sd.pseudo_commit,
                &sig,
            )
            .map_err(|e| {
                BuilderError::Clsag(format!(
                    "self-verification failed (builder data inconsistency): {e}"
                ))
            })?;

            clsag_sigs.push(sig);
        }

        tx.prunable.clsag_signatures = clsag_sigs;
        Ok(tx)
    }
}

/// Build a coinbase transaction (version 0) that creates a shielded output
/// paying the block reward to the miner's stealth address.
///
/// The output uses the same stealth address protocol as normal transactions
/// so the miner's wallet scanner can detect and spend it.
pub fn build_coinbase_tx(
    view_public: [u8; 32],
    spend_public: [u8; 32],
    amount: u64,
    height: u64,
) -> Result<Transaction, BuilderError> {
    let addr = StealthAddress { view_public, spend_public };
    let gens = PedersenGens::default();

    let (eph, one_time_pk, shared_secret) =
        stealth::derive_one_time_key(&addr, 0)
            .map_err(|e| BuilderError::Stealth(e.to_string()))?;

    let blinding = derive_commitment_blinding(&shared_secret);
    let commitment = gens.commit(Scalar::from(amount), blinding);
    let enc_amount = encrypt_amount(amount, &shared_secret);
    let view_tag = compute_view_tag(&shared_secret);

    let output = TxOutput {
        commitment: Commitment::from_point(&commitment),
        one_time_pubkey: one_time_pk.compress().to_bytes(),
        ephemeral_pubkey: eph.0,
        encrypted_amount: enc_amount,
        view_tag,
    };

    let (range_proof, _) =
        AggregatedRangeProof::prove(&[amount], &[blinding])
            .map_err(|e| BuilderError::RangeProof(e.to_string()))?;

    // Encode block height in extra field for uniqueness per block
    let extra = height.to_le_bytes().to_vec();

    Ok(Transaction {
        version: 0,
        inputs: Vec::new(),
        outputs: vec![output],
        fee: 0,
        extra,
        prunable: TxPrunable {
            clsag_signatures: Vec::new(),
            range_proof,
        },
    })
}
