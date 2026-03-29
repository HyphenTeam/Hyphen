use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::generators::{BP_GENS, MAX_RANGE_BITS};
use crate::inner_product;
use crate::inner_product::InnerProductProof;
use hyphen_crypto::pedersen::{G_BLIND, G_VALUE, PedersenGens};

// V = v·H + gamma·G
fn h_gen() -> RistrettoPoint {
    *G_VALUE
}

fn g_gen() -> RistrettoPoint {
    G_BLIND
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("value out of range")]
    ValueOutOfRange,
    #[error("invalid proof length")]
    InvalidProofLength,
    #[error("verification failed")]
    VerificationFailed,
    #[error("too many values for aggregation")]
    TooManyValues,
    #[error("point decompression failed")]
    Decompression,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub t_hat: [u8; 32],
    pub ipp: InnerProductProof,
}

fn transcript_scalar(t: &mut Transcript, label: &'static [u8], s: &Scalar) {
    t.append_message(label, s.as_bytes());
}

fn transcript_point(t: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) {
    t.append_message(label, p.compress().as_bytes());
}

fn transcript_challenge(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

// Powers 1, base, base^2, …, base^{n-1}
fn scalar_powers(base: &Scalar, n: usize) -> Vec<Scalar> {
    let mut v = Vec::with_capacity(n);
    let mut cur = Scalar::ONE;
    for _ in 0..n {
        v.push(cur);
        cur *= base;
    }
    v
}

// δ(y,z) = (z − z²)·⟨1ⁿ, yⁿ⟩ − z³·⟨1ⁿ, 2ⁿ⟩
fn delta(y: &Scalar, z: &Scalar, n: usize) -> Scalar {
    let y_powers = scalar_powers(y, n);
    let two = Scalar::from(2u64);
    let two_powers = scalar_powers(&two, n);

    let sum_y: Scalar = y_powers.iter().sum();
    let sum_2: Scalar = two_powers.iter().sum();

    let z2 = z * z;
    let z3 = z2 * z;

    (z - z2) * sum_y - z3 * sum_2
}

impl RangeProof {
    #[allow(clippy::needless_range_loop)]
    pub fn prove(v: u64, gamma: &Scalar) -> Result<(Self, RistrettoPoint), ProofError> {
        let n = MAX_RANGE_BITS; // 64
        let g_blind = g_gen();
        let gens = PedersenGens::default();
        let commitment = gens.commit(Scalar::from(v), *gamma);

        let mut transcript = Transcript::new(b"Hyphen_RangeProof");
        transcript_point(&mut transcript, b"V", &commitment);

        let g = BP_GENS.g(n);
        let h = BP_GENS.h(n);

        // Bit decomposition
        let mut a_l = vec![Scalar::ZERO; n];
        for i in 0..n {
            if (v >> i) & 1 == 1 {
                a_l[i] = Scalar::ONE;
            }
        }
        let a_r: Vec<Scalar> = a_l.iter().map(|a| a - Scalar::ONE).collect();

        // Blinding vectors
        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();

        // Commitments
        let alpha = Scalar::random(&mut OsRng);
        let rho = Scalar::random(&mut OsRng);

        let a_point = alpha * g_blind
            + RistrettoPoint::multiscalar_mul(a_l.iter().chain(a_r.iter()), g.iter().chain(h.iter()));

        let s_point = rho * g_blind
            + RistrettoPoint::multiscalar_mul(s_l.iter().chain(s_r.iter()), g.iter().chain(h.iter()));

        transcript_point(&mut transcript, b"A", &a_point);
        transcript_point(&mut transcript, b"S", &s_point);

        // Challenges y, z
        let y = transcript_challenge(&mut transcript, b"y");
        let z = transcript_challenge(&mut transcript, b"z");

        let y_powers = scalar_powers(&y, n);
        let two = Scalar::from(2u64);
        let two_powers = scalar_powers(&two, n);
        let z2 = z * z;

        // t(x) = <l(x), r(x)>
        // l(x) = (a_L - z·1) + s_L·x
        // r(x) = y^n ∘ (a_R + z·1 + s_R·x) + z²·2^n

        // t_1 and t_2
        let mut t1 = Scalar::ZERO;
        let mut t2 = Scalar::ZERO;

        for i in 0..n {
            let l0 = a_l[i] - z;
            let l1 = s_l[i];
            let r0 = y_powers[i] * (a_r[i] + z) + z2 * two_powers[i];
            let r1 = y_powers[i] * s_r[i];
            t1 += l0 * r1 + l1 * r0;
            t2 += l1 * r1;
        }

        let tau_1 = Scalar::random(&mut OsRng);
        let tau_2 = Scalar::random(&mut OsRng);
        let t1_point = t1 * h_gen() + tau_1 * g_blind;
        let t2_point = t2 * h_gen() + tau_2 * g_blind;

        transcript_point(&mut transcript, b"T1", &t1_point);
        transcript_point(&mut transcript, b"T2", &t2_point);

        // Challenge x
        let x = transcript_challenge(&mut transcript, b"x");

        // Evaluate l, r, t_hat at x
        let l_vec: Vec<Scalar> = (0..n).map(|i| a_l[i] - z + s_l[i] * x).collect();
        let r_vec: Vec<Scalar> = (0..n)
            .map(|i| y_powers[i] * (a_r[i] + z + s_r[i] * x) + z2 * two_powers[i])
            .collect();
        let t_hat: Scalar = l_vec.iter().zip(r_vec.iter()).map(|(l, r)| l * r).sum();

        let tau_x = tau_2 * (x * x) + tau_1 * x + z2 * gamma;
        let mu = alpha + rho * x;

        transcript_scalar(&mut transcript, b"tau_x", &tau_x);
        transcript_scalar(&mut transcript, b"mu", &mu);
        transcript_scalar(&mut transcript, b"t_hat", &t_hat);

        // Scale h generators: h'_i = h_i · y^{-i}
        let y_inv = y.invert();
        let y_inv_powers = scalar_powers(&y_inv, n);
        let h_prime: Vec<RistrettoPoint> = h
            .iter()
            .zip(y_inv_powers.iter())
            .map(|(hi, yi)| yi * hi)
            .collect();

        // Q for IPA
        let q_point = transcript_challenge(&mut transcript, b"Q_ipa");
        let q = q_point * h_gen();

        let ipp = inner_product::prove(&mut transcript, &q, g, &h_prime, l_vec, r_vec);

        Ok((
            RangeProof {
                a: a_point.compress().to_bytes(),
                s: s_point.compress().to_bytes(),
                t1: t1_point.compress().to_bytes(),
                t2: t2_point.compress().to_bytes(),
                tau_x: tau_x.to_bytes(),
                mu: mu.to_bytes(),
                t_hat: t_hat.to_bytes(),
                ipp,
            },
            commitment,
        ))
    }

    #[allow(clippy::needless_range_loop)]
    pub fn verify(&self, commitment: &RistrettoPoint) -> Result<(), ProofError> {
        let n = MAX_RANGE_BITS;
        let g_blind = g_gen();

        let mut transcript = Transcript::new(b"Hyphen_RangeProof");
        transcript_point(&mut transcript, b"V", commitment);

        let a_point = decompress_pt(&self.a)?;
        let s_point = decompress_pt(&self.s)?;
        let t1_point = decompress_pt(&self.t1)?;
        let t2_point = decompress_pt(&self.t2)?;

        transcript_point(&mut transcript, b"A", &a_point);
        transcript_point(&mut transcript, b"S", &s_point);

        let y = transcript_challenge(&mut transcript, b"y");
        let z = transcript_challenge(&mut transcript, b"z");

        transcript_point(&mut transcript, b"T1", &t1_point);
        transcript_point(&mut transcript, b"T2", &t2_point);

        let x = transcript_challenge(&mut transcript, b"x");

        let tau_x = Scalar::from_bytes_mod_order(self.tau_x);
        let mu = Scalar::from_bytes_mod_order(self.mu);
        let t_hat = Scalar::from_bytes_mod_order(self.t_hat);

        transcript_scalar(&mut transcript, b"tau_x", &tau_x);
        transcript_scalar(&mut transcript, b"mu", &mu);
        transcript_scalar(&mut transcript, b"t_hat", &t_hat);

        // Check 1: t_hat · G + tau_x · H =? z² · V + δ(y,z) · G + x · T₁ + x² · T₂
        let z2 = z * z;
        let dyz = delta(&y, &z, n);

        let lhs = t_hat * h_gen() + tau_x * g_blind;
        let rhs = z2 * commitment + dyz * h_gen() + x * t1_point + (x * x) * t2_point;

        if lhs != rhs {
            return Err(ProofError::VerificationFailed);
        }

        // Check 2: inner product proof
        let g = BP_GENS.g(n);
        let h = BP_GENS.h(n);

        let y_inv = y.invert();
        let y_inv_powers = scalar_powers(&y_inv, n);
        let h_prime: Vec<RistrettoPoint> = h
            .iter()
            .zip(y_inv_powers.iter())
            .map(|(hi, yi)| yi * hi)
            .collect();

        let y_powers = scalar_powers(&y, n);
        let two = Scalar::from(2u64);
        let two_powers = scalar_powers(&two, n);

        // P = A + x·S − z·⟨1,g⟩ + ⟨z·y^n + z²·2^n, h'⟩ − μ·H
        let neg_z = -z;
        let mut p_scalars: Vec<Scalar> = Vec::with_capacity(2 + 2 * n);
        let mut p_points: Vec<RistrettoPoint> = Vec::with_capacity(2 + 2 * n);

        p_scalars.push(Scalar::ONE);
        p_points.push(a_point);
        p_scalars.push(x);
        p_points.push(s_point);

        for i in 0..n {
            p_scalars.push(neg_z);
            p_points.push(g[i]);
        }
        for i in 0..n {
            p_scalars.push(z * y_powers[i] + z2 * two_powers[i]);
            p_points.push(h_prime[i]);
        }

        let p_commit = RistrettoPoint::multiscalar_mul(&p_scalars, &p_points) - mu * g_blind;

        let q_point = transcript_challenge(&mut transcript, b"Q_ipa");
        let q = q_point * h_gen();

        // The IPA commitment: P = <l,G> + <r,H'> + <l,r>·Q
        let p_total = p_commit + t_hat * q;

        let valid = inner_product::verify(
            &mut transcript,
            &self.ipp,
            &q,
            g,
            &h_prime,
            &p_total,
            &t_hat,
        );

        if valid {
            Ok(())
        } else {
            Err(ProofError::VerificationFailed)
        }
    }
}

fn decompress_pt(bytes: &[u8; 32]) -> Result<RistrettoPoint, ProofError> {
    curve25519_dalek::ristretto::CompressedRistretto(*bytes)
        .decompress()
        .ok_or(ProofError::Decompression)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedRangeProof {
    pub m: usize,
    pub proof: RangeProof,
}

impl AggregatedRangeProof {
    #[allow(clippy::needless_range_loop)]
    pub fn prove(
        values: &[u64],
        blindings: &[Scalar],
    ) -> Result<(Self, Vec<RistrettoPoint>), ProofError> {
        let m = values.len();
        if m == 0 || m > crate::generators::MAX_AGGREGATION {
            return Err(ProofError::TooManyValues);
        }
        let n_bits = MAX_RANGE_BITS;
        let nm = n_bits * m;
        let g_blind = g_gen();
        let gens = PedersenGens::default();

        let commitments: Vec<RistrettoPoint> = values
            .iter()
            .zip(blindings.iter())
            .map(|(v, b)| gens.commit(Scalar::from(*v), *b))
            .collect();

        let mut transcript = Transcript::new(b"Hyphen_AggRangeProof");
        for c in &commitments {
            transcript_point(&mut transcript, b"V", c);
        }

        let g = BP_GENS.g(nm);
        let h = BP_GENS.h(nm);

        // Bit decomposition for all values
        let mut a_l = vec![Scalar::ZERO; nm];
        let mut a_r = vec![Scalar::ZERO; nm];
        for (j, v) in values.iter().enumerate() {
            for i in 0..n_bits {
                let idx = j * n_bits + i;
                if (v >> i) & 1 == 1 {
                    a_l[idx] = Scalar::ONE;
                }
                a_r[idx] = a_l[idx] - Scalar::ONE;
            }
        }

        let s_l: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
        let s_r: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();

        let alpha = Scalar::random(&mut OsRng);
        let rho = Scalar::random(&mut OsRng);

        let a_point = alpha * g_blind
            + RistrettoPoint::multiscalar_mul(a_l.iter().chain(a_r.iter()), g.iter().chain(h.iter()));
        let s_point = rho * g_blind
            + RistrettoPoint::multiscalar_mul(s_l.iter().chain(s_r.iter()), g.iter().chain(h.iter()));

        transcript_point(&mut transcript, b"A", &a_point);
        transcript_point(&mut transcript, b"S", &s_point);

        let y = transcript_challenge(&mut transcript, b"y");
        let z = transcript_challenge(&mut transcript, b"z");

        let y_powers = scalar_powers(&y, nm);
        let two = Scalar::from(2u64);
        let two_powers = scalar_powers(&two, n_bits);
        let z_powers = scalar_powers(&z, m + 2); // z^0 .. z^{m+1}

        // Compute t_1, t_2
        let mut t1 = Scalar::ZERO;
        let mut t2 = Scalar::ZERO;

        for j in 0..m {
            let z_j2 = z_powers[j + 2]; // z^{j+2}
            for i in 0..n_bits {
                let idx = j * n_bits + i;
                let l0 = a_l[idx] - z;
                let l1 = s_l[idx];
                let r0 = y_powers[idx] * (a_r[idx] + z) + z_j2 * two_powers[i];
                let r1 = y_powers[idx] * s_r[idx];
                t1 += l0 * r1 + l1 * r0;
                t2 += l1 * r1;
            }
        }

        let tau_1 = Scalar::random(&mut OsRng);
        let tau_2 = Scalar::random(&mut OsRng);
        let t1_point = t1 * h_gen() + tau_1 * g_blind;
        let t2_point = t2 * h_gen() + tau_2 * g_blind;

        transcript_point(&mut transcript, b"T1", &t1_point);
        transcript_point(&mut transcript, b"T2", &t2_point);

        let x = transcript_challenge(&mut transcript, b"x");

        let l_vec: Vec<Scalar> = (0..nm).map(|i| a_l[i] - z + s_l[i] * x).collect();
        let r_vec: Vec<Scalar> = (0..nm)
            .map(|idx| {
                let j = idx / n_bits;
                let i = idx % n_bits;
                let z_j2 = z_powers[j + 2];
                y_powers[idx] * (a_r[idx] + z + s_r[idx] * x) + z_j2 * two_powers[i]
            })
            .collect();
        let t_hat: Scalar = l_vec.iter().zip(r_vec.iter()).map(|(l, r)| l * r).sum();

        let mut tau_x = tau_2 * (x * x) + tau_1 * x;
        for j in 0..m {
            tau_x += z_powers[j + 2] * blindings[j];
        }
        let mu = alpha + rho * x;

        transcript_scalar(&mut transcript, b"tau_x", &tau_x);
        transcript_scalar(&mut transcript, b"mu", &mu);
        transcript_scalar(&mut transcript, b"t_hat", &t_hat);

        // IPA
        let y_inv = y.invert();
        let y_inv_powers = scalar_powers(&y_inv, nm);
        let h_prime: Vec<RistrettoPoint> = h
            .iter()
            .zip(y_inv_powers.iter())
            .map(|(hi, yi)| yi * hi)
            .collect();

        let q_point = transcript_challenge(&mut transcript, b"Q_ipa");
        let q = q_point * h_gen();

        let ipp = inner_product::prove(&mut transcript, &q, g, &h_prime, l_vec, r_vec);

        Ok((
            AggregatedRangeProof {
                m,
                proof: RangeProof {
                    a: a_point.compress().to_bytes(),
                    s: s_point.compress().to_bytes(),
                    t1: t1_point.compress().to_bytes(),
                    t2: t2_point.compress().to_bytes(),
                    tau_x: tau_x.to_bytes(),
                    mu: mu.to_bytes(),
                    t_hat: t_hat.to_bytes(),
                    ipp,
                },
            },
            commitments,
        ))
    }

    #[allow(clippy::needless_range_loop)]
    pub fn verify(&self, commitments: &[RistrettoPoint]) -> Result<(), ProofError> {
        let m = self.m;
        if commitments.len() != m {
            return Err(ProofError::InvalidProofLength);
        }
        let n_bits = MAX_RANGE_BITS;
        let nm = n_bits * m;
        let g_blind = g_gen();

        let mut transcript = Transcript::new(b"Hyphen_AggRangeProof");
        for c in commitments {
            transcript_point(&mut transcript, b"V", c);
        }

        let a_point = decompress_pt(&self.proof.a)?;
        let s_point = decompress_pt(&self.proof.s)?;
        let t1_point = decompress_pt(&self.proof.t1)?;
        let t2_point = decompress_pt(&self.proof.t2)?;

        transcript_point(&mut transcript, b"A", &a_point);
        transcript_point(&mut transcript, b"S", &s_point);
        let y = transcript_challenge(&mut transcript, b"y");
        let z = transcript_challenge(&mut transcript, b"z");
        transcript_point(&mut transcript, b"T1", &t1_point);
        transcript_point(&mut transcript, b"T2", &t2_point);
        let x = transcript_challenge(&mut transcript, b"x");

        let tau_x = Scalar::from_bytes_mod_order(self.proof.tau_x);
        let mu = Scalar::from_bytes_mod_order(self.proof.mu);
        let t_hat = Scalar::from_bytes_mod_order(self.proof.t_hat);

        transcript_scalar(&mut transcript, b"tau_x", &tau_x);
        transcript_scalar(&mut transcript, b"mu", &mu);
        transcript_scalar(&mut transcript, b"t_hat", &t_hat);

        // δ(y,z) for aggregated proof
        let y_powers = scalar_powers(&y, nm);
        let two = Scalar::from(2u64);
        let two_powers = scalar_powers(&two, n_bits);
        let z_powers = scalar_powers(&z, m + 2);

        let sum_y: Scalar = y_powers.iter().sum();
        let sum_2: Scalar = two_powers.iter().sum();
        let z2 = z * z;
        let mut dyz = (z - z2) * sum_y;
        for j in 0..m {
            dyz -= z_powers[j + 2] * (z * sum_2); // z^{j+3}·⟨1,2^n⟩
        }

        // Check 1
        let lhs = t_hat * h_gen() + tau_x * g_blind;
        let mut rhs = dyz * h_gen() + x * t1_point + (x * x) * t2_point;
        for j in 0..m {
            rhs += z_powers[j + 2] * commitments[j];
        }
        if lhs != rhs {
            return Err(ProofError::VerificationFailed);
        }

        // IPA verification
        let g = BP_GENS.g(nm);
        let h = BP_GENS.h(nm);
        let y_inv = y.invert();
        let y_inv_powers = scalar_powers(&y_inv, nm);
        let h_prime: Vec<RistrettoPoint> = h
            .iter()
            .zip(y_inv_powers.iter())
            .map(|(hi, yi)| yi * hi)
            .collect();

        let neg_z = -z;
        let mut p_scalars = Vec::with_capacity(2 + 2 * nm);
        let mut p_points = Vec::with_capacity(2 + 2 * nm);
        p_scalars.push(Scalar::ONE);
        p_points.push(a_point);
        p_scalars.push(x);
        p_points.push(s_point);
        for _ in 0..nm {
            p_scalars.push(neg_z);
        }
        for i in 0..nm {
            p_points.push(g[i]);
        }
        for idx in 0..nm {
            let j = idx / n_bits;
            let i = idx % n_bits;
            p_scalars.push(z * y_powers[idx] + z_powers[j + 2] * two_powers[i]);
            p_points.push(h_prime[idx]);
        }
        let p_commit = RistrettoPoint::multiscalar_mul(&p_scalars, &p_points) - mu * g_blind;

        let q_point = transcript_challenge(&mut transcript, b"Q_ipa");
        let q = q_point * h_gen();

        let p_total = p_commit + t_hat * q;

        if inner_product::verify(&mut transcript, &self.proof.ipp, &q, g, &h_prime, &p_total, &t_hat) {
            Ok(())
        } else {
            Err(ProofError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_range_proof_round_trip() {
        let v = 42u64;
        let gamma = Scalar::random(&mut OsRng);
        let (proof, commitment) = RangeProof::prove(v, &gamma).unwrap();
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn aggregated_range_proof_round_trip() {
        let values = [100u64, 200u64];
        let blindings: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut OsRng)).collect();
        let (proof, commitments) = AggregatedRangeProof::prove(&values, &blindings).unwrap();
        proof.verify(&commitments).unwrap();
    }
}
