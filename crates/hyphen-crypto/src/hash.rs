use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[inline]
pub fn blake3_hash(data: &[u8]) -> Hash256 {
    Hash256(blake3::hash(data).into())
}

pub fn blake3_hash_many(parts: &[&[u8]]) -> Hash256 {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    Hash256(h.finalize().into())
}

pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> Hash256 {
    Hash256(*blake3::keyed_hash(key, data).as_bytes())
}

// Domain-separated scalar: blake3 XOF -> 64-byte output, reduced mod l
pub fn hash_to_scalar(domain: &[u8], data: &[u8]) -> curve25519_dalek::Scalar {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(data);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn hash_to_point(data: &[u8]) -> curve25519_dalek::ristretto::RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(b"Hyphen_h2p_v1");
    h.update(data);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&wide)
}
