use crate::generators::{BP_GENS, MAX_RANGE_BITS, MAX_AGGREGATION};
use crate::inner_product;
use crate::range_proof::{AggregatedRangeProof, ProofError, RangeProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use hyphen_crypto::pedersen::{G_BLIND, G_VALUE};
use merlin::Transcript;
use rand_core::{RngCore, CryptoRng};

fn h_gen() -> RistrettoPoint {
    *G_VALUE
}

fn g_gen() -> RistrettoPoint {
    G_BLIND
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

fn scalar_powers(base: &Scalar, n: usize) -> Vec<Scalar> {
    let mut v = Vec::with_capacity(n);
    let mut cur = Scalar::ONE;
    for _ in 0..n {
        v.push(cur);
        cur *= base;
    }
    v
}

pub fn batch_verify(proofs: &[(RangeProof, RistrettoPoint)]) -> Result<(), ProofError> {
    for (proof, commitment) in proofs {
        proof.verify(commitment)?;
    }
    Ok(())
}

pub fn batch_verify_aggregated(
    proofs: &[(AggregatedRangeProof, Vec<RistrettoPoint>)],
) -> Result<(), ProofError> {
    if proofs.is_empty() {
        return Ok(());
    }

    for (proof, commitments) in proofs {
        proof.verify(commitments)?;
    }
    Ok(())
}

pub fn batch_verify_mixed(
    singles: &[(RangeProof, RistrettoPoint)],
    aggregated: &[(AggregatedRangeProof, Vec<RistrettoPoint>)],
) -> Result<(), ProofError> {
    batch_verify(singles)?;
    batch_verify_aggregated(aggregated)?;
    Ok(())
}

#[allow(clippy::needless_range_loop)]
pub fn prove_multiple_with_rng<R: RngCore + CryptoRng>(
    values: &[u64],
    blindings: &[Scalar],
    rng: &mut R,
) -> Result<(AggregatedRangeProof, Vec<RistrettoPoint>), ProofError> {
    let m = values.len();
    if m == 0 || m > MAX_AGGREGATION {
        return Err(ProofError::TooManyValues);
    }
    let n_bits = MAX_RANGE_BITS;
    let nm = n_bits * m;
    let g_blind = g_gen();
    let gens = hyphen_crypto::pedersen::PedersenGens::default();

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

    let s_l: Vec<Scalar> = (0..nm).map(|_| Scalar::random(rng)).collect();
    let s_r: Vec<Scalar> = (0..nm).map(|_| Scalar::random(rng)).collect();

    let alpha = Scalar::random(rng);
    let rho = Scalar::random(rng);

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
    let z_powers = scalar_powers(&z, m + 2);

    let mut t1 = Scalar::ZERO;
    let mut t2 = Scalar::ZERO;

    for j in 0..m {
        let z_j2 = z_powers[j + 2];
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

    let tau_1 = Scalar::random(rng);
    let tau_2 = Scalar::random(rng);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn batch_prove_multiple_with_rng_roundtrip() {
        let values = [100u64, 200u64, 300u64, 400u64];
        let blindings: Vec<Scalar> = (0..4).map(|_| Scalar::random(&mut OsRng)).collect();
        let (proof, commitments) =
            prove_multiple_with_rng(&values, &blindings, &mut OsRng).unwrap();
        proof.verify(&commitments).unwrap();
    }

    #[test]
    fn batch_prove_single_value() {
        let values = [42u64];
        let blindings = [Scalar::random(&mut OsRng)];
        let (proof, commitments) =
            prove_multiple_with_rng(&values, &blindings, &mut OsRng).unwrap();
        proof.verify(&commitments).unwrap();
    }

    #[test]
    fn batch_prove_max_aggregation() {
        let values: Vec<u64> = (1..=16).map(|i| i * 1000).collect();
        let blindings: Vec<Scalar> = (0..16).map(|_| Scalar::random(&mut OsRng)).collect();
        let (proof, commitments) =
            prove_multiple_with_rng(&values, &blindings, &mut OsRng).unwrap();
        proof.verify(&commitments).unwrap();
    }

    #[test]
    fn batch_prove_too_many_fails() {
        let values: Vec<u64> = (0..17).map(|i| i).collect();
        let blindings: Vec<Scalar> = (0..17).map(|_| Scalar::random(&mut OsRng)).collect();
        assert!(prove_multiple_with_rng(&values, &blindings, &mut OsRng).is_err());
    }
}

