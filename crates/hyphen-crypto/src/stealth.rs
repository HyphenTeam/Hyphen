use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use crate::hash::{hash_to_scalar, blake3_hash_many};

const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

#[derive(Debug, Error)]
pub enum StealthError {
    #[error("point decompression failed")]
    DecompressionFailed,
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct ViewKey(pub [u8; 32]);

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SpendKey(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralKey(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress {
    pub view_public: [u8; 32],
    pub spend_public: [u8; 32],
}

impl std::fmt::Debug for StealthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HYP:{}{}",
            hex::encode(self.view_public),
            hex::encode(self.spend_public)
        )
    }
}

impl std::fmt::Display for StealthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HYP:{}{}",
            hex::encode(self.view_public),
            hex::encode(self.spend_public)
        )
    }
}


impl ViewKey {
    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }

    pub fn public_point(&self) -> RistrettoPoint {
        self.as_scalar() * G
    }
}

impl SpendKey {
    pub fn as_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }

    pub fn public_point(&self) -> RistrettoPoint {
        self.as_scalar() * G
    }
}

pub fn generate_keys() -> (ViewKey, SpendKey, StealthAddress) {
    let a = Scalar::random(&mut OsRng);
    let b = Scalar::random(&mut OsRng);
    let view = ViewKey(a.to_bytes());
    let spend = SpendKey(b.to_bytes());
    let addr = StealthAddress {
        view_public: (a * G).compress().to_bytes(),
        spend_public: (b * G).compress().to_bytes(),
    };
    (view, spend, addr)
}


fn decompress(bytes: &[u8; 32]) -> Result<RistrettoPoint, StealthError> {
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| StealthError::DecompressionFailed)?
        .decompress()
        .ok_or(StealthError::DecompressionFailed)
}

// Sender: derive ephemeral R, one-time public key P, shared secret
pub fn derive_one_time_key(
    addr: &StealthAddress,
    output_index: u64,
) -> Result<(EphemeralKey, RistrettoPoint, Scalar), StealthError> {
    let r = Scalar::random(&mut OsRng);
    let big_r = r * G;

    let big_a = decompress(&addr.view_public)?;
    let big_b = decompress(&addr.spend_public)?;

    // ss = Hs("Hyphen_ECDH" || r*A || idx)
    let r_a = r * big_a;
    let encoded_idx = output_index.to_le_bytes();
    let ss = hash_to_scalar(
        b"Hyphen_ECDH",
        &[r_a.compress().as_bytes().as_slice(), &encoded_idx].concat(),
    );

    // P = ss*G + B
    let p = ss * G + big_b;

    Ok((
        EphemeralKey(big_r.compress().to_bytes()),
        p,
        ss,
    ))
}

// Receiver: recover one-time private key
pub fn recover_one_time_key(
    view: &ViewKey,
    spend: &SpendKey,
    ephemeral: &EphemeralKey,
    output_index: u64,
) -> Result<(Scalar, RistrettoPoint), StealthError> {
    let big_r = decompress(&ephemeral.0)?;
    let a = view.as_scalar();
    let b = spend.as_scalar();

    let a_r = a * big_r;
    let encoded_idx = output_index.to_le_bytes();
    let ss = hash_to_scalar(
        b"Hyphen_ECDH",
        &[a_r.compress().as_bytes().as_slice(), &encoded_idx].concat(),
    );

    // p = ss + b
    let p = ss + b;
    let big_p = p * G;

    Ok((p, big_p))
}

pub fn is_output_ours(
    view: &ViewKey,
    spend_public: &[u8; 32],
    ephemeral: &EphemeralKey,
    output_index: u64,
    one_time_pk: &RistrettoPoint,
) -> Result<bool, StealthError> {
    let big_r = decompress(&ephemeral.0)?;
    let big_b = decompress(spend_public)?;
    let a = view.as_scalar();

    let a_r = a * big_r;
    let encoded_idx = output_index.to_le_bytes();
    let ss = hash_to_scalar(
        b"Hyphen_ECDH",
        &[a_r.compress().as_bytes().as_slice(), &encoded_idx].concat(),
    );

    let expected = ss * G + big_b;
    Ok(&expected == one_time_pk)
}

pub fn encrypt_amount(value: u64, shared_secret: &Scalar) -> [u8; 32] {
    let mask = blake3_hash_many(&[b"Hyphen_amount_mask", shared_secret.as_bytes()]);
    let mut buf = [0u8; 32];
    buf[..8].copy_from_slice(&value.to_le_bytes());
    for (b, m) in buf.iter_mut().zip(mask.as_bytes().iter()) {
        *b ^= *m;
    }
    buf
}

pub fn decrypt_amount(encrypted: &[u8; 32], shared_secret: &Scalar) -> u64 {
    let mask = blake3_hash_many(&[b"Hyphen_amount_mask", shared_secret.as_bytes()]);
    let mut buf = [0u8; 8];
    for i in 0..8 {
        buf[i] = encrypted[i] ^ mask.as_bytes()[i];
    }
    u64::from_le_bytes(buf)
}
