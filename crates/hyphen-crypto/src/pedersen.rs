use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::hash_to_point;

// C = value*H + blinding*G, H has unknown DL w.r.t. G
pub static G_VALUE: Lazy<RistrettoPoint> =
    Lazy::new(|| hash_to_point(b"Hyphen_pedersen_value_generator_v1"));

pub const G_BLIND: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

#[derive(Clone, Debug)]
pub struct PedersenGens {
    pub g_value: RistrettoPoint,
    pub g_blind: RistrettoPoint,
}

impl Default for PedersenGens {
    fn default() -> Self {
        Self {
            g_value: *G_VALUE,
            g_blind: G_BLIND,
        }
    }
}

impl PedersenGens {
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        value * self.g_value + blinding * self.g_blind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("point decompression failed")]
    DecompressionFailed,
}

impl Commitment {
    pub fn create(value: u64, blinding: Scalar) -> Self {
        let gens = PedersenGens::default();
        let point = gens.commit(Scalar::from(value), blinding);
        Self(point.compress().to_bytes())
    }

    pub fn from_point(p: &RistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }

    pub fn to_point(&self) -> Result<RistrettoPoint, CommitmentError> {
        CompressedRistretto::from_slice(&self.0)
            .map_err(|_| CommitmentError::DecompressionFailed)?
            .decompress()
            .ok_or(CommitmentError::DecompressionFailed)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<RistrettoPoint> for Commitment {
    fn from(p: RistrettoPoint) -> Self {
        Self::from_point(&p)
    }
}
