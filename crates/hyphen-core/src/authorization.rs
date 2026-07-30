use serde::{Deserialize, Serialize};
use thiserror::Error;

use hyphen_crypto::{Hash256, PublicKey, SecretKey, Signature};

use crate::block::BlockHeader;

pub const FROZEN_BLOCK_VERSION: u32 = 2;
pub const BLOCK_AUTHORIZATION_VERSION: u16 = 1;
const AUTHORIZATION_DOMAIN: &[u8] = b"Hyphen/NCAP/block-authorization/v1";

/// Miner-controlled authorization for a solved block.
///
/// The pool may relay this object, but cannot change the final header or the
/// reward keys without invalidating the miner signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockAuthorization {
    pub version: u16,
    pub reward_view_public: [u8; 32],
    pub reward_spend_public: [u8; 32],
    pub miner_signature: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("unsupported block version {0}")]
    UnsupportedBlockVersion(u32),
    #[error("unsupported block authorization version {0}")]
    UnsupportedAuthorizationVersion(u16),
    #[error("miner authorization public key is zero")]
    ZeroMinerPublicKey,
    #[error("reward key is zero")]
    ZeroRewardKey,
    #[error("miner signature must be exactly 64 bytes")]
    InvalidSignatureLength,
    #[error("miner block authorization signature is invalid")]
    InvalidSignature,
}

impl BlockAuthorization {
    pub fn sign(
        header: &BlockHeader,
        network_magic: [u8; 4],
        consensus_params_hash: [u8; 32],
        genesis_hash: Hash256,
        reward_view_public: [u8; 32],
        reward_spend_public: [u8; 32],
        miner_secret: &SecretKey,
    ) -> Result<Self, AuthorizationError> {
        if header.version != FROZEN_BLOCK_VERSION {
            return Err(AuthorizationError::UnsupportedBlockVersion(header.version));
        }
        if header.miner_pubkey != *miner_secret.public_key().as_bytes() {
            return Err(AuthorizationError::InvalidSignature);
        }
        validate_reward_keys(reward_view_public, reward_spend_public)?;

        let digest = authorization_digest(
            header,
            network_magic,
            consensus_params_hash,
            genesis_hash,
            reward_view_public,
            reward_spend_public,
        );
        let signature = miner_secret.sign(digest.as_bytes());
        Ok(Self {
            version: BLOCK_AUTHORIZATION_VERSION,
            reward_view_public,
            reward_spend_public,
            miner_signature: signature.as_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        header: &BlockHeader,
        network_magic: [u8; 4],
        consensus_params_hash: [u8; 32],
        genesis_hash: Hash256,
    ) -> Result<(), AuthorizationError> {
        if header.version != FROZEN_BLOCK_VERSION {
            return Err(AuthorizationError::UnsupportedBlockVersion(header.version));
        }
        if self.version != BLOCK_AUTHORIZATION_VERSION {
            return Err(AuthorizationError::UnsupportedAuthorizationVersion(
                self.version,
            ));
        }
        if header.miner_pubkey == [0u8; 32] {
            return Err(AuthorizationError::ZeroMinerPublicKey);
        }
        validate_reward_keys(self.reward_view_public, self.reward_spend_public)?;

        let signature_bytes: [u8; 64] = self
            .miner_signature
            .as_slice()
            .try_into()
            .map_err(|_| AuthorizationError::InvalidSignatureLength)?;
        let digest = authorization_digest(
            header,
            network_magic,
            consensus_params_hash,
            genesis_hash,
            self.reward_view_public,
            self.reward_spend_public,
        );
        PublicKey(header.miner_pubkey)
            .verify(digest.as_bytes(), &Signature(signature_bytes))
            .map_err(|_| AuthorizationError::InvalidSignature)
    }
}

pub fn authorization_digest(
    header: &BlockHeader,
    network_magic: [u8; 4],
    consensus_params_hash: [u8; 32],
    genesis_hash: Hash256,
    reward_view_public: [u8; 32],
    reward_spend_public: [u8; 32],
) -> Hash256 {
    hyphen_crypto::blake3_hash_many(&[
        AUTHORIZATION_DOMAIN,
        &BLOCK_AUTHORIZATION_VERSION.to_le_bytes(),
        &network_magic,
        &consensus_params_hash,
        genesis_hash.as_bytes(),
        header.hash().as_bytes(),
        &reward_view_public,
        &reward_spend_public,
    ])
}

fn validate_reward_keys(
    reward_view_public: [u8; 32],
    reward_spend_public: [u8; 32],
) -> Result<(), AuthorizationError> {
    if reward_view_public == [0u8; 32] || reward_spend_public == [0u8; 32] {
        return Err(AuthorizationError::ZeroRewardKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;

    fn header(miner_pubkey: [u8; 32]) -> BlockHeader {
        BlockHeader {
            version: FROZEN_BLOCK_VERSION,
            height: 7,
            timestamp: 1_700_000_000_000,
            prev_hash: Hash256::from_bytes([1u8; 32]),
            tx_root: Hash256::from_bytes([2u8; 32]),
            commitment_root: Hash256::from_bytes([3u8; 32]),
            nullifier_root: Hash256::from_bytes([4u8; 32]),
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: Hash256::from_bytes([5u8; 32]),
            epoch_seed: Hash256::from_bytes([6u8; 32]),
            difficulty: 1_000,
            nonce: 42,
            extra_nonce: [7u8; 32],
            miner_pubkey,
            total_fee: 9,
            reward: 10,
            view_tag: 0,
            block_size: 1_024,
        }
    }

    #[test]
    fn authorization_binds_header_chain_and_reward_keys() {
        let secret = SecretKey([11u8; 32]);
        let mut changed_header = header(*secret.public_key().as_bytes());
        let magic = *b"HYDV";
        let params = [12u8; 32];
        let genesis = Hash256::from_bytes([13u8; 32]);
        let auth = BlockAuthorization::sign(
            &changed_header,
            magic,
            params,
            genesis,
            [14u8; 32],
            [15u8; 32],
            &secret,
        )
        .unwrap();

        auth.verify(&changed_header, magic, params, genesis)
            .unwrap();

        changed_header.tx_root = Hash256::from_bytes([16u8; 32]);
        assert_eq!(
            auth.verify(&changed_header, magic, params, genesis),
            Err(AuthorizationError::InvalidSignature)
        );
        let original_header = header(miner_key(&secret));
        assert_eq!(
            auth.verify(&original_header, *b"HYE1", params, genesis),
            Err(AuthorizationError::InvalidSignature)
        );
    }

    #[test]
    fn pool_cannot_redirect_reward_after_authorization() {
        let secret = SecretKey([21u8; 32]);
        let header = header(*secret.public_key().as_bytes());
        let mut auth = BlockAuthorization::sign(
            &header,
            *b"HYDV",
            [22u8; 32],
            Hash256::from_bytes([23u8; 32]),
            [24u8; 32],
            [25u8; 32],
            &secret,
        )
        .unwrap();
        auth.reward_spend_public = [26u8; 32];
        assert_eq!(
            auth.verify(
                &header,
                *b"HYDV",
                [22u8; 32],
                Hash256::from_bytes([23u8; 32])
            ),
            Err(AuthorizationError::InvalidSignature)
        );
    }

    fn miner_key(secret: &SecretKey) -> [u8; 32] {
        *secret.public_key().as_bytes()
    }
}
