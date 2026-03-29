use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{hash_to_point, hash_to_scalar};

#[derive(Debug, Error)]
pub enum ClsagError {
    #[error("ring is empty")]
    EmptyRing,
    #[error("secret index out of range")]
    IndexOutOfRange,
    #[error("ring members have inconsistent lengths")]
    InconsistentRing,
    #[error("point decompression failed")]
    Decompression,
    #[error("signature verification failed")]
    VerificationFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClsagSignature {
    pub c0: [u8; 32],
    pub s: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
    pub commitment_key_image: [u8; 32],
}

impl ClsagSignature {
    pub fn ring_size(&self) -> usize {
        self.s.len()
    }

    pub fn key_image_point(&self) -> Result<RistrettoPoint, ClsagError> {
        decompress(&self.key_image)
    }
}

fn decompress(b: &[u8; 32]) -> Result<RistrettoPoint, ClsagError> {
    CompressedRistretto::from_slice(b)
        .map_err(|_| ClsagError::Decompression)?
        .decompress()
        .ok_or(ClsagError::Decompression)
}

fn hash_point_to_point(p: &RistrettoPoint) -> RistrettoPoint {
    hash_to_point(p.compress().as_bytes())
}

/// Compute aggregation coefficients mu_P, mu_C
fn aggregation_coefficients(
    ring_keys: &[RistrettoPoint],
    ring_commits: &[RistrettoPoint],
    key_image: &RistrettoPoint,
    commit_image: &RistrettoPoint,
    pseudo_out: &RistrettoPoint,
    msg: &[u8],
) -> (Scalar, Scalar) {
    let mut data = Vec::with_capacity(ring_keys.len() * 64 + 128 + msg.len());
    data.extend_from_slice(b"CLSAG_agg_");
    data.extend_from_slice(msg);
    for (pk, ck) in ring_keys.iter().zip(ring_commits.iter()) {
        data.extend_from_slice(pk.compress().as_bytes());
        data.extend_from_slice(ck.compress().as_bytes());
    }
    data.extend_from_slice(key_image.compress().as_bytes());
    data.extend_from_slice(commit_image.compress().as_bytes());
    data.extend_from_slice(pseudo_out.compress().as_bytes());

    let mu_p = hash_to_scalar(b"CLSAG_agg_0", &data);
    let mu_c = hash_to_scalar(b"CLSAG_agg_1", &data);
    (mu_p, mu_c)
}

/// H_n(msg || L || R)
fn clsag_round_hash(
    prefix: &[u8],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    let mut data = Vec::with_capacity(prefix.len() + 64);
    data.extend_from_slice(prefix);
    data.extend_from_slice(l.compress().as_bytes());
    data.extend_from_slice(r.compress().as_bytes());
    hash_to_scalar(b"CLSAG_round", &data)
}

fn round_prefix(msg: &[u8], w_image: &RistrettoPoint) -> Vec<u8> {
    let mut p = Vec::with_capacity(msg.len() + 32);
    p.extend_from_slice(msg);
    p.extend_from_slice(w_image.compress().as_bytes());
    p
}

pub fn clsag_sign(
    msg: &[u8],
    ring_keys: &[RistrettoPoint],
    ring_commits: &[RistrettoPoint],
    pseudo_out: &RistrettoPoint,
    secret_index: usize,
    spend_sk: &Scalar,
    blinding_diff: &Scalar,
) -> Result<ClsagSignature, ClsagError> {
    let n = ring_keys.len();
    if n == 0 {
        return Err(ClsagError::EmptyRing);
    }
    if secret_index >= n {
        return Err(ClsagError::IndexOutOfRange);
    }
    if ring_commits.len() != n {
        return Err(ClsagError::InconsistentRing);
    }

    let hp_l = hash_point_to_point(&ring_keys[secret_index]);
    let key_image = spend_sk * hp_l;
    let commit_image = blinding_diff * hp_l;

    // Adjusted commitments
    let adjusted: Vec<RistrettoPoint> = ring_commits.iter().map(|c| c - pseudo_out).collect();

    let (mu_p, mu_c) = aggregation_coefficients(
        ring_keys,
        &adjusted,
        &key_image,
        &commit_image,
        pseudo_out,
        msg,
    );

    let w_image = mu_p * key_image + mu_c * commit_image;
    let prefix = round_prefix(msg, &w_image);

    let alpha = Scalar::random(&mut OsRng);
    let l_init = alpha * G;
    let r_init = alpha * hp_l;

    // s values
    let mut s_values: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let mut c_values: Vec<Scalar> = vec![Scalar::ZERO; n];

    // c_{l+1}
    let c_next = clsag_round_hash(&prefix, &l_init, &r_init);
    c_values[(secret_index + 1) % n] = c_next;

    // go around the ring
    for j in 1..n {
        let i = (secret_index + j) % n;
        let i_next = (i + 1) % n;

        let hp_i = hash_point_to_point(&ring_keys[i]);
        let w_i = mu_p * ring_keys[i] + mu_c * adjusted[i];

        let l_i = s_values[i] * G + c_values[i] * w_i;
        let r_i = s_values[i] * hp_i + c_values[i] * w_image;

        c_values[i_next] = clsag_round_hash(&prefix, &l_i, &r_i);
    }

    // close the ring: compute s_l
    let c_l = c_values[secret_index];
    s_values[secret_index] = alpha - c_l * (mu_p * spend_sk + mu_c * blinding_diff);

    Ok(ClsagSignature {
        c0: c_values[0].to_bytes(),
        s: s_values.iter().map(|s| s.to_bytes()).collect(),
        key_image: key_image.compress().to_bytes(),
        commitment_key_image: commit_image.compress().to_bytes(),
    })
}

pub fn clsag_verify(
    msg: &[u8],
    ring_keys: &[RistrettoPoint],
    ring_commits: &[RistrettoPoint],
    pseudo_out: &RistrettoPoint,
    sig: &ClsagSignature,
) -> Result<(), ClsagError> {
    let n = ring_keys.len();
    if n == 0 || sig.s.len() != n || ring_commits.len() != n {
        return Err(ClsagError::InconsistentRing);
    }

    let key_image = decompress(&sig.key_image)?;
    let commit_image = decompress(&sig.commitment_key_image)?;

    let adjusted: Vec<RistrettoPoint> = ring_commits.iter().map(|c| c - pseudo_out).collect();

    let (mu_p, mu_c) = aggregation_coefficients(
        ring_keys,
        &adjusted,
        &key_image,
        &commit_image,
        pseudo_out,
        msg,
    );

    let w_image = mu_p * key_image + mu_c * commit_image;
    let prefix = round_prefix(msg, &w_image);

    let c0 = Scalar::from_bytes_mod_order(sig.c0);
    let mut c_cur = c0;

    for i in 0..n {
        let s_i = Scalar::from_bytes_mod_order(sig.s[i]);
        let hp_i = hash_point_to_point(&ring_keys[i]);
        let w_i = mu_p * ring_keys[i] + mu_c * adjusted[i];

        let l_i = s_i * G + c_cur * w_i;
        let r_i = s_i * hp_i + c_cur * w_image;

        c_cur = clsag_round_hash(&prefix, &l_i, &r_i);
    }

    if c_cur == c0 {
        Ok(())
    } else {
        Err(ClsagError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_ring_1() {
        let sk = Scalar::random(&mut OsRng);
        let pk = sk * G;

        let blind = Scalar::random(&mut OsRng);
        let gens = crate::pedersen::PedersenGens::default();
        let commit = gens.commit(Scalar::from(1000u64), blind);

        let blind2 = Scalar::random(&mut OsRng);
        let pseudo = gens.commit(Scalar::from(1000u64), blind2);

        let sig = clsag_sign(
            b"test_msg",
            &[pk],
            &[commit],
            &pseudo,
            0,
            &sk,
            &(blind - blind2),
        )
        .unwrap();

        clsag_verify(b"test_msg", &[pk], &[commit], &pseudo, &sig).unwrap();
    }

    #[test]
    fn sign_and_verify_ring_4() {
        let gens = crate::pedersen::PedersenGens::default();
        let real_idx = 2usize;

        let mut ring_keys = Vec::new();
        let mut ring_commits = Vec::new();
        let mut real_sk = Scalar::ZERO;
        let mut real_blind = Scalar::ZERO;

        for i in 0..4 {
            let sk = Scalar::random(&mut OsRng);
            let pk = sk * G;
            let b = Scalar::random(&mut OsRng);
            let c = gens.commit(Scalar::from(500u64), b);
            ring_keys.push(pk);
            ring_commits.push(c);
            if i == real_idx {
                real_sk = sk;
                real_blind = b;
            }
        }

        let blind2 = Scalar::random(&mut OsRng);
        let pseudo = gens.commit(Scalar::from(500u64), blind2);

        let sig = clsag_sign(
            b"ring4",
            &ring_keys,
            &ring_commits,
            &pseudo,
            real_idx,
            &real_sk,
            &(real_blind - blind2),
        )
        .unwrap();

        clsag_verify(b"ring4", &ring_keys, &ring_commits, &pseudo, &sig).unwrap();
    }
}
