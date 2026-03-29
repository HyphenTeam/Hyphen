use hyphen_crypto::pedersen::Commitment;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::asset::AssetId;

#[derive(Debug, Error)]
pub enum TokenTxError {
    #[error("asset mismatch in transfer")]
    AssetMismatch,
    #[error("balance check failed")]
    BalanceFailed,
    #[error("empty transfer")]
    EmptyTransfer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenInput {
    pub asset_id: AssetId,
    pub commitment: Commitment,
    pub nullifier: [u8; 32],
    pub ring_members: Vec<Commitment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenOutput {
    pub asset_id: AssetId,
    pub commitment: Commitment,
    pub encrypted_amount: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub output_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub asset_id: AssetId,
    pub inputs: Vec<TokenInput>,
    pub outputs: Vec<TokenOutput>,
    pub fee: u64,
    pub proof: Vec<u8>,
}

impl TokenTransfer {
    pub fn validate_structure(&self) -> Result<(), TokenTxError> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(TokenTxError::EmptyTransfer);
        }
        for input in &self.inputs {
            if input.asset_id != self.asset_id {
                return Err(TokenTxError::AssetMismatch);
            }
        }
        for output in &self.outputs {
            if output.asset_id != self.asset_id {
                return Err(TokenTxError::AssetMismatch);
            }
        }
        Ok(())
    }

    pub fn input_commitments(&self) -> Vec<Commitment> {
        self.inputs.iter().map(|i| i.commitment).collect()
    }

    pub fn output_commitments(&self) -> Vec<Commitment> {
        self.outputs.iter().map(|o| o.commitment).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn make_commitment(value: u64) -> Commitment {
        Commitment::create(value, Scalar::random(&mut OsRng))
    }

    #[test]
    fn validate_structure_ok() {
        let asset = AssetId::from_issuance(&[1u8; 32], 0);
        let transfer = TokenTransfer {
            asset_id: asset,
            inputs: vec![TokenInput {
                asset_id: asset,
                commitment: make_commitment(100),
                nullifier: [0u8; 32],
                ring_members: vec![],
            }],
            outputs: vec![TokenOutput {
                asset_id: asset,
                commitment: make_commitment(100),
                encrypted_amount: [0u8; 32],
                ephemeral_key: [0u8; 32],
                output_index: 0,
            }],
            fee: 0,
            proof: vec![],
        };
        transfer.validate_structure().unwrap();
    }

    #[test]
    fn validate_structure_asset_mismatch() {
        let asset1 = AssetId::from_issuance(&[1u8; 32], 0);
        let asset2 = AssetId::from_issuance(&[2u8; 32], 0);
        let transfer = TokenTransfer {
            asset_id: asset1,
            inputs: vec![TokenInput {
                asset_id: asset2,
                commitment: make_commitment(100),
                nullifier: [0u8; 32],
                ring_members: vec![],
            }],
            outputs: vec![TokenOutput {
                asset_id: asset1,
                commitment: make_commitment(100),
                encrypted_amount: [0u8; 32],
                ephemeral_key: [0u8; 32],
                output_index: 0,
            }],
            fee: 0,
            proof: vec![],
        };
        assert!(transfer.validate_structure().is_err());
    }

    #[test]
    fn validate_structure_empty() {
        let asset = AssetId::NATIVE;
        let transfer = TokenTransfer {
            asset_id: asset,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            proof: vec![],
        };
        assert!(transfer.validate_structure().is_err());
    }
}
