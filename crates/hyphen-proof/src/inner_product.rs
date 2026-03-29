use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerProductProof {
    pub l_vec: Vec<[u8; 32]>,
    pub r_vec: Vec<[u8; 32]>,
    pub a: [u8; 32],
    pub b: [u8; 32],
}

fn transcript_point(t: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) {
    t.append_message(label, p.compress().as_bytes());
}

fn transcript_challenge(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

// Multi-exponentiation: ∑ scalars[i] · points[i]
fn multiexp(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    use curve25519_dalek::traits::MultiscalarMul;
    RistrettoPoint::multiscalar_mul(scalars.iter(), points.iter())
}

// Inner product <a, b>
fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

pub fn prove(
    transcript: &mut Transcript,
    q: &RistrettoPoint,
    g_vec: &[RistrettoPoint],
    h_vec: &[RistrettoPoint],
    mut a_vec: Vec<Scalar>,
    mut b_vec: Vec<Scalar>,
) -> InnerProductProof {
    let mut n = a_vec.len();
    assert_eq!(n, b_vec.len());
    assert!(n.is_power_of_two());

    let mut g = g_vec.to_vec();
    let mut h = h_vec.to_vec();

    let mut l_vec = Vec::with_capacity(n.trailing_zeros() as usize);
    let mut r_vec = Vec::with_capacity(n.trailing_zeros() as usize);

    while n > 1 {
        let half = n / 2;
        let (a_lo, a_hi) = a_vec.split_at(half);
        let (b_lo, b_hi) = b_vec.split_at(half);
        let (g_lo, g_hi) = g.split_at(half);
        let (h_lo, h_hi) = h.split_at(half);

        let c_l = inner_product(a_lo, b_hi);
        let c_r = inner_product(a_hi, b_lo);

        // L_j = <a_lo, g_hi> + <b_hi, h_lo> + c_l * Q
        // R_j = <a_hi, g_lo> + <b_lo, h_hi> + c_r * Q
        let l_point = multiexp(a_lo, g_hi) + multiexp(b_hi, h_lo) + c_l * q;
        let r_point = multiexp(a_hi, g_lo) + multiexp(b_lo, h_hi) + c_r * q;

        transcript_point(transcript, b"L", &l_point);
        transcript_point(transcript, b"R", &r_point);
        l_vec.push(l_point.compress().to_bytes());
        r_vec.push(r_point.compress().to_bytes());

        let u = transcript_challenge(transcript, b"u");
        let u_inv = u.invert();

        // Fold
        let a_new: Vec<Scalar> = a_lo
            .iter()
            .zip(a_hi.iter())
            .map(|(lo, hi)| u * lo + u_inv * hi)
            .collect();
        let b_new: Vec<Scalar> = b_lo
            .iter()
            .zip(b_hi.iter())
            .map(|(lo, hi)| u_inv * lo + u * hi)
            .collect();

        let g_new: Vec<RistrettoPoint> = g_lo
            .iter()
            .zip(g_hi.iter())
            .map(|(lo, hi)| u_inv * lo + u * hi)
            .collect();
        let h_new: Vec<RistrettoPoint> = h_lo
            .iter()
            .zip(h_hi.iter())
            .map(|(lo, hi)| u * lo + u_inv * hi)
            .collect();

        a_vec = a_new;
        b_vec = b_new;
        g = g_new;
        h = h_new;
        n = half;
    }

    InnerProductProof {
        l_vec,
        r_vec,
        a: a_vec[0].to_bytes(),
        b: b_vec[0].to_bytes(),
    }
}

#[allow(clippy::needless_range_loop)]
pub fn verify(
    transcript: &mut Transcript,
    proof: &InnerProductProof,
    q: &RistrettoPoint,
    g_vec: &[RistrettoPoint],
    h_vec: &[RistrettoPoint],
    p: &RistrettoPoint,
    _c: &Scalar,
) -> bool {
    let rounds = proof.l_vec.len();
    let n = 1usize << rounds;
    if g_vec.len() < n || h_vec.len() < n {
        return false;
    }

    // Replay challenges
    let mut challenges = Vec::with_capacity(rounds);
    for i in 0..rounds {
        let l_pt = match curve25519_dalek::ristretto::CompressedRistretto(proof.l_vec[i]).decompress() {
            Some(p) => p,
            None => return false,
        };
        let r_pt = match curve25519_dalek::ristretto::CompressedRistretto(proof.r_vec[i]).decompress() {
            Some(p) => p,
            None => return false,
        };
        transcript_point(transcript, b"L", &l_pt);
        transcript_point(transcript, b"R", &r_pt);
        challenges.push(transcript_challenge(transcript, b"u"));
    }

    // Compute scalar factors for each generator (s_i)
    let a_final = Scalar::from_bytes_mod_order(proof.a);
    let b_final = Scalar::from_bytes_mod_order(proof.b);

    // Build s[i] and s_inv[i]
    let mut s = vec![Scalar::ONE; n];
    for (j, u_j) in challenges.iter().enumerate() {
        let u_j_inv = u_j.invert();
        let stride = 1 << (rounds - 1 - j);
        for i in 0..n {
            if (i / stride) & 1 == 0 {
                s[i] *= u_j_inv;
            } else {
                s[i] *= u_j;
            }
        }
    }

    // P_expected = a·b·Q + Σ (a·s_i)·g_i + Σ (b·s_i^{-1})·h_i − Σ u_j²·L_j − Σ u_j^{-2}·R_j
    let mut scalars = Vec::with_capacity(1 + 2 * n + 2 * rounds);
    let mut points = Vec::with_capacity(1 + 2 * n + 2 * rounds);

    // Q term
    scalars.push(a_final * b_final);
    points.push(*q);

    // g_i terms: a_final * s[i]
    for i in 0..n {
        scalars.push(a_final * s[i]);
        points.push(g_vec[i]);
    }

    // h_i terms: b_final * s[i]^{-1}
    for i in 0..n {
        scalars.push(b_final * s[i].invert());
        points.push(h_vec[i]);
    }

    // L, R terms
    for (j, u_j) in challenges.iter().enumerate() {
        let l_pt = curve25519_dalek::ristretto::CompressedRistretto(proof.l_vec[j])
            .decompress()
            .unwrap();
        let r_pt = curve25519_dalek::ristretto::CompressedRistretto(proof.r_vec[j])
            .decompress()
            .unwrap();
        scalars.push(-(u_j * u_j));
        points.push(l_pt);
        scalars.push(-(u_j.invert() * u_j.invert()));
        points.push(r_pt);
    }

    let expected = multiexp(&scalars, &points);
    &expected == p
}
