use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use hyphen_crypto::Hash256;
use hyphen_crypto::pedersen::Commitment;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub commitment: Commitment,
    pub one_time_pubkey: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub encrypted_amount: [u8; 32],
    pub global_index: u64,
    pub block_height: u64,
}

impl Note {
    pub fn note_hash(&self) -> Hash256 {
        hyphen_crypto::blake3_hash_many(&[
            self.commitment.as_bytes(),
            &self.one_time_pubkey,
            &self.ephemeral_pubkey,
            &self.encrypted_amount,
        ])
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OwnedNote {
    pub note: Note,
    pub value: u64,
    pub blinding: [u8; 32],
    pub spend_sk: [u8; 32],
}

impl OwnedNote {
    pub fn blinding_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.blinding)
    }

    pub fn spend_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.spend_sk)
    }
}
