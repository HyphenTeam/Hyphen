use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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

/// Public coefficients of the IPA verification equation, in generator order.
pub(crate) struct VerificationTerms {
    pub a: Scalar,
    pub b: Scalar,
    pub weights: Vec<Scalar>,
    pub round_scalars: Vec<Scalar>,
    pub round_points: Vec<RistrettoPoint>,
}

impl InnerProductProof {
    pub(crate) fn has_dimension(&self, n: usize) -> bool {
        n.is_power_of_two()
            && self.l_vec.len() == n.ilog2() as usize
            && self.r_vec.len() == self.l_vec.len()
    }

    pub(crate) fn verification_terms(
        &self,
        transcript: &mut Transcript,
        n: usize,
    ) -> Option<VerificationTerms> {
        if !self.has_dimension(n) {
            return None;
        }
        let a = Scalar::from_canonical_bytes(self.a).into_option()?;
        let b = Scalar::from_canonical_bytes(self.b).into_option()?;
        let mut weights = vec![Scalar::ONE; n];
        let mut round_points = Vec::with_capacity(2 * self.l_vec.len());
        let mut round_scalars = Vec::with_capacity(2 * self.l_vec.len());
        for (j, (left, right)) in self.l_vec.iter().zip(&self.r_vec).enumerate() {
            let l = curve25519_dalek::ristretto::CompressedRistretto(*left).decompress()?;
            let r = curve25519_dalek::ristretto::CompressedRistretto(*right).decompress()?;
            transcript.append_message(b"L", left);
            transcript.append_message(b"R", right);
            let u = transcript_challenge(transcript, b"u");
            let inverse = u.invert();
            round_points.extend([l, r]);
            round_scalars.extend([u * u, inverse * inverse]);
            // Append one index bit. Descending order preserves unread parent weights.
            for i in (0..1 << j).rev() {
                let parent = weights[i];
                weights[2 * i] = parent * inverse;
                weights[2 * i + 1] = parent * u;
            }
        }
        Some(VerificationTerms {
            a,
            b,
            weights,
            round_scalars,
            round_points,
        })
    }
}

pub fn verify(
    transcript: &mut Transcript,
    proof: &InnerProductProof,
    q: &RistrettoPoint,
    g_vec: &[RistrettoPoint],
    h_vec: &[RistrettoPoint],
    p: &RistrettoPoint,
    _c: &Scalar,
) -> bool {
    let n = g_vec.len();
    if h_vec.len() != n {
        return false;
    }
    let Some(terms) = proof.verification_terms(transcript, n) else {
        return false;
    };
    // Complementing every index bit exchanges u and 1/u in every round.
    let scalars = std::iter::once(terms.a * terms.b)
        .chain(terms.weights.iter().map(|s| terms.a * s))
        .chain(terms.weights.iter().rev().map(|s| terms.b * s))
        .chain(terms.round_scalars.iter().map(|s| -s));
    let points = std::iter::once(q)
        .chain(g_vec)
        .chain(h_vec)
        .chain(&terms.round_points);
    RistrettoPoint::vartime_multiscalar_mul(scalars, points) == *p
}
