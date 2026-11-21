use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul};
use hyphen_crypto::system_rng;
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::generators::{BP_GENS, MAX_AGGREGATION, MAX_RANGE_BITS};
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

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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

impl RangeProof {
    fn responses(&self) -> Result<[Scalar; 3], ProofError> {
        let decode = |bytes| {
            Scalar::from_canonical_bytes(bytes)
                .into_option()
                .ok_or(ProofError::VerificationFailed)
        };
        Ok([decode(self.tau_x)?, decode(self.mu)?, decode(self.t_hat)?])
    }

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
        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut system_rng())).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut system_rng())).collect();

        // Commitments
        let alpha = Scalar::random(&mut system_rng());
        let rho = Scalar::random(&mut system_rng());

        let a_point = alpha * g_blind
            + RistrettoPoint::multiscalar_mul(
                a_l.iter().chain(a_r.iter()),
                g.iter().chain(h.iter()),
            );

        let s_point = rho * g_blind
            + RistrettoPoint::multiscalar_mul(
                s_l.iter().chain(s_r.iter()),
                g.iter().chain(h.iter()),
            );

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

        let tau_1 = Scalar::random(&mut system_rng());
        let tau_2 = Scalar::random(&mut system_rng());
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

    pub fn verify(&self, commitment: &RistrettoPoint) -> Result<(), ProofError> {
        self.verify_commitments(std::slice::from_ref(commitment), b"Hyphen_RangeProof")
    }
}

fn decompress_pt(bytes: &[u8; 32]) -> Result<RistrettoPoint, ProofError> {
    curve25519_dalek::ristretto::CompressedRistretto(*bytes)
        .decompress()
        .ok_or(ProofError::Decompression)
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct AggregatedRangeProof {
    /// Number of aggregated commitments. Stored as `u64` because the field is
    /// part of the transaction wire image: a platform-sized integer would let a
    /// 32-bit peer disagree with a 64-bit peer about the encoded length.
    pub m: u64,
    pub proof: RangeProof,
}

impl AggregatedRangeProof {
    #[allow(clippy::needless_range_loop)]
    pub fn prove(
        values: &[u64],
        blindings: &[Scalar],
    ) -> Result<(Self, Vec<RistrettoPoint>), ProofError> {
        let m = values.len();
        validate_aggregation(m, blindings.len())?;
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

        let s_l: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut system_rng())).collect();
        let s_r: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut system_rng())).collect();

        let alpha = Scalar::random(&mut system_rng());
        let rho = Scalar::random(&mut system_rng());

        let a_point = alpha * g_blind
            + RistrettoPoint::multiscalar_mul(
                a_l.iter().chain(a_r.iter()),
                g.iter().chain(h.iter()),
            );
        let s_point = rho * g_blind
            + RistrettoPoint::multiscalar_mul(
                s_l.iter().chain(s_r.iter()),
                g.iter().chain(h.iter()),
            );

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

        let tau_1 = Scalar::random(&mut system_rng());
        let tau_2 = Scalar::random(&mut system_rng());
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
                m: m as u64,
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

    pub fn verify(&self, commitments: &[RistrettoPoint]) -> Result<(), ProofError> {
        let m = commitments.len();
        if self.m != m as u64 {
            return Err(ProofError::InvalidProofLength);
        }
        validate_aggregation(m, m)?;
        self.proof
            .verify_commitments(commitments, b"Hyphen_AggRangeProof")
    }
}

impl RangeProof {
    fn verify_commitments(
        &self,
        commitments: &[RistrettoPoint],
        domain: &'static [u8],
    ) -> Result<(), ProofError> {
        let m = commitments.len();
        let n_bits = MAX_RANGE_BITS;
        let nm = n_bits * m;
        let g_blind = g_gen();
        if !self.ipp.has_dimension(nm) {
            return Err(ProofError::InvalidProofLength);
        }
        let [tau_x, mu, t_hat] = self.responses()?;
        let mut transcript = Transcript::new(domain);
        for c in commitments {
            transcript_point(&mut transcript, b"V", c);
        }

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

        transcript_scalar(&mut transcript, b"tau_x", &tau_x);
        transcript_scalar(&mut transcript, b"mu", &mu);
        transcript_scalar(&mut transcript, b"t_hat", &t_hat);

        // δ(y,z) for aggregated proof
        let two = Scalar::from(2u64);
        let two_powers = scalar_powers(&two, n_bits);
        let z_powers = scalar_powers(&z, m + 2);

        let sum_y = (0..nm).fold(Scalar::ZERO, |sum, _| Scalar::ONE + y * sum);
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

        let q = transcript_challenge(&mut transcript, b"Q_ipa");
        let terms = self
            .ipp
            .verification_terms(&mut transcript, nm)
            .ok_or(ProofError::VerificationFailed)?;
        // Subtract the folded IPA commitment from P + t_hat Q. Pull y^-i into
        // each H coefficient so the verifier can use the original generators.
        let g_scalars = terms.weights.iter().map(|s| -z - terms.a * s);
        let y_inverse = y.invert();
        // The original equation contains z*y^i*(1/y)^i. Preserve its value
        // even for a zero transcript challenge under Dalek's scalar arithmetic.
        let z_tail = if y == Scalar::ZERO { Scalar::ZERO } else { z };
        let mut y_power = Scalar::ONE;
        let h_scalars = terms
            .weights
            .iter()
            .rev()
            .enumerate()
            .map(|(i, inverse_weight)| {
                let bit_weight = z_powers[2 + i / n_bits] * two_powers[i % n_bits];
                let offset = if i == 0 { z } else { z_tail };
                let coefficient = offset + y_power * (bit_weight - terms.b * inverse_weight);
                y_power *= y_inverse;
                coefficient
            });
        let fixed_scalars = [Scalar::ONE, x, -mu, (t_hat - terms.a * terms.b) * q];
        let fixed_points = [a_point, s_point, g_blind, h_gen()];
        let scalars = fixed_scalars
            .into_iter()
            .chain(g_scalars)
            .chain(h_scalars)
            .chain(terms.round_scalars);
        let points = fixed_points
            .iter()
            .chain(BP_GENS.g(nm))
            .chain(BP_GENS.h(nm))
            .chain(&terms.round_points);
        if RistrettoPoint::vartime_multiscalar_mul(scalars, points).is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationFailed)
        }
    }
}

pub(crate) fn validate_aggregation(count: usize, other_count: usize) -> Result<(), ProofError> {
    if count > MAX_AGGREGATION {
        return Err(ProofError::TooManyValues);
    }
    if !count.is_power_of_two() || count != other_count {
        return Err(ProofError::InvalidProofLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_range_proof_round_trip() {
        let v = 42u64;
        let gamma = Scalar::random(&mut system_rng());
        let (proof, commitment) = RangeProof::prove(v, &gamma).unwrap();
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn aggregated_range_proof_round_trip() {
        let values = [0, u64::MAX];
        let blindings: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut system_rng())).collect();
        let (proof, commitments) = AggregatedRangeProof::prove(&values, &blindings).unwrap();
        proof.verify(&commitments).unwrap();
        assert!(proof.verify(&[commitments[1], commitments[0]]).is_err());

        let mut changed = proof.clone();
        changed.proof.ipp.b =
            (Scalar::from_canonical_bytes(changed.proof.ipp.b).unwrap() + Scalar::ONE).to_bytes();
        assert!(changed.verify(&commitments).is_err());
        let mut changed = proof.clone();
        changed.proof.ipp.l_vec.swap(0, 1);
        assert!(changed.verify(&commitments).is_err());
        let mut changed = proof;
        changed.proof.ipp.a = [0xff; 32];
        assert!(changed.verify(&commitments).is_err());
    }

    #[test]
    fn aggregation_requires_matching_power_of_two_dimensions() {
        for (values, blindings) in [(0, 0), (1, 0), (3, 3), (17, 17), (2, 3)] {
            assert!(
                AggregatedRangeProof::prove(&vec![0; values], &vec![Scalar::ONE; blindings])
                    .is_err()
            );
        }
        let (mut proof, commitments) = AggregatedRangeProof::prove(&[7], &[Scalar::ONE]).unwrap();
        proof.proof.ipp.r_vec.pop();
        assert!(proof.verify(&commitments).is_err());
    }
}
