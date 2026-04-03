use hyphen_crypto::clsag::ClsagSignature;
use hyphen_crypto::pedersen::Commitment;
use hyphen_crypto::Hash256;
use hyphen_proof::range_proof::AggregatedRangeProof;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutputRef {
    pub global_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub ring: Vec<OutputRef>,
    pub key_image: [u8; 32],
    pub pseudo_output: Commitment,
    // ── TERA: Temporal Entangled Ring Authorization ────────────────────────
    /// Deterministic binding to the current epoch:  
    ///   epoch_context = blake3("TERA_v1" ‖ epoch_seed)
    /// Validators reject inputs whose epoch_context does not match any
    /// epoch within ±tera_epoch_tolerance of the tip.
    pub epoch_context: [u8; 32],
    /// Per-spend temporal nonce derived from the signing secret AND epoch:
    ///   temporal_nonce = Hs("TERA_nonce" ‖ spend_sk ‖ epoch_context)
    /// Within a single epoch the nullifier set rejects duplicate nonces
    /// for the same key_image, providing epoch-scoped double-spend
    /// detection *without* cross-epoch linkability.
    pub temporal_nonce: [u8; 32],
    /// Causal binding that ties the authorization to the specific output
    /// being spent AND the epoch:
    ///   causal_binding = blake3("TERA_causal" ‖ spend_sk ‖ note_hash ‖ epoch_context)
    /// Included in the CLSAG message hash so the ring signature
    /// transitively proves it was produced by the true owner.
    pub causal_binding: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub commitment: Commitment,
    pub one_time_pubkey: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub encrypted_amount: [u8; 32],
    pub view_tag: u8,
}

impl TxOutput {
    pub fn note_hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash_many(&[
            self.commitment.as_bytes(),
            &self.one_time_pubkey,
            &self.ephemeral_pubkey,
            &self.encrypted_amount,
            &[self.view_tag],
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoinbaseOutput {
    pub commitment: Commitment,
    pub one_time_pubkey: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub encrypted_amount: [u8; 32],
    pub block_height: u64,
}

impl CoinbaseOutput {
    pub fn note_hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash_many(&[
            self.commitment.as_bytes(),
            &self.one_time_pubkey,
            &self.ephemeral_pubkey,
            &self.encrypted_amount,
            &self.block_height.to_le_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxPrunable {
    pub clsag_signatures: Vec<ClsagSignature>,
    pub range_proof: AggregatedRangeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u8,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    pub extra: Vec<u8>,
    pub prunable: TxPrunable,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.version == 0 && self.inputs.is_empty()
    }

    pub fn serialise(&self) -> Vec<u8> {
        bincode::serialize(self).expect("tx serialization infallible")
    }

    pub fn hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash(&self.serialise())
    }

    pub fn prefix_hash(&self) -> Hash256 {
        let mut data = Vec::new();
        data.push(self.version);
        for inp in &self.inputs {
            data.extend_from_slice(&bincode::serialize(inp).unwrap());
        }
        for out in &self.outputs {
            data.extend_from_slice(&bincode::serialize(out).unwrap());
        }
        data.extend_from_slice(&self.fee.to_le_bytes());
        data.extend_from_slice(&self.extra);
        hyphen_crypto::blake3_hash(&data)
    }

    // ∑ pseudo_outputs == ∑ output_commitments + fee · H
    pub fn check_balance(&self) -> bool {
        use curve25519_dalek::scalar::Scalar;
        use hyphen_crypto::pedersen::G_VALUE;

        let fee_point = Scalar::from(self.fee) * *G_VALUE;

        let sum_pseudo: Option<curve25519_dalek::ristretto::RistrettoPoint> = self
            .inputs
            .iter()
            .try_fold(
                curve25519_dalek::ristretto::RistrettoPoint::default(),
                |acc, inp| inp.pseudo_output.to_point().ok().map(|p| acc + p),
            );

        let sum_out: Option<curve25519_dalek::ristretto::RistrettoPoint> = self
            .outputs
            .iter()
            .try_fold(
                curve25519_dalek::ristretto::RistrettoPoint::default(),
                |acc, out| out.commitment.to_point().ok().map(|p| acc + p),
            );

        match (sum_pseudo, sum_out) {
            (Some(sp), Some(so)) => sp == so + fee_point,
            _ => false,
        }
    }
}
