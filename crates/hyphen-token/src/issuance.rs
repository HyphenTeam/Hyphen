use curve25519_dalek::scalar::Scalar;
use hyphen_crypto::pedersen::Commitment;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::asset::AssetId;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("supply exceeds max")]
    SupplyExceeded,
    #[error("unauthorized issuer")]
    Unauthorized,
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuancePolicy {
    Fixed,
    Mintable { authority: [u8; 32] },
    Capped { max_supply: u64, authority: [u8; 32] },
}

impl IssuancePolicy {
    pub fn can_mint(&self, minter: &[u8; 32]) -> bool {
        match self {
            IssuancePolicy::Fixed => false,
            IssuancePolicy::Mintable { authority } => authority == minter,
            IssuancePolicy::Capped { authority, .. } => authority == minter,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintRecord {
    pub asset_id: AssetId,
    pub amount: u64,
    pub commitment: Commitment,
    pub blinding: [u8; 32],
    pub issuer_signature: Vec<u8>,
    pub block_height: u64,
    pub nonce: u64,
}

impl MintRecord {
    pub fn new(
        asset_id: AssetId,
        amount: u64,
        blinding: Scalar,
        issuer_signature: Vec<u8>,
        block_height: u64,
        nonce: u64,
    ) -> Self {
        let commitment = Commitment::create(amount, blinding);
        Self {
            asset_id,
            amount,
            commitment,
            blinding: blinding.to_bytes(),
            issuer_signature,
            block_height,
            nonce,
        }
    }

    pub fn verify_commitment(&self) -> bool {
        let expected = Commitment::create(
            self.amount,
            Scalar::from_bytes_mod_order(self.blinding),
        );
        self.commitment == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn issuance_policy_fixed() {
        let policy = IssuancePolicy::Fixed;
        assert!(!policy.can_mint(&[0u8; 32]));
    }

    #[test]
    fn issuance_policy_mintable() {
        let auth = [1u8; 32];
        let policy = IssuancePolicy::Mintable { authority: auth };
        assert!(policy.can_mint(&auth));
        assert!(!policy.can_mint(&[2u8; 32]));
    }

    #[test]
    fn mint_record_commitment_verify() {
        let blinding = Scalar::random(&mut OsRng);
        let record = MintRecord::new(
            AssetId::NATIVE,
            1000,
            blinding,
            vec![0u8; 64],
            0,
            0,
        );
        assert!(record.verify_commitment());
    }
}
