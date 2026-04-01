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

    // ∑ pseudo_outputs == ∑ output_commitments + fee · G
    pub fn check_balance(&self) -> bool {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        use curve25519_dalek::scalar::Scalar;

        let fee_point = Scalar::from(self.fee) * G;

        let sum_pseudo: curve25519_dalek::ristretto::RistrettoPoint = self
            .inputs
            .iter()
            .map(|inp| {
                inp.pseudo_output
                    .to_point()
                    .expect("invalid pseudo-output commitment")
            })
            .sum();

        let sum_out: curve25519_dalek::ristretto::RistrettoPoint = self
            .outputs
            .iter()
            .map(|out| {
                out.commitment
                    .to_point()
                    .expect("invalid output commitment")
            })
            .sum();

        sum_pseudo == sum_out + fee_point
    }
}
