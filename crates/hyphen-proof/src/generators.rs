use curve25519_dalek::ristretto::RistrettoPoint;
use once_cell::sync::Lazy;

pub const MAX_RANGE_BITS: usize = 64;
pub const MAX_AGGREGATION: usize = 16;
pub const MAX_VEC_LEN: usize = MAX_RANGE_BITS * MAX_AGGREGATION;

fn make_generator(label: &[u8], index: u64) -> RistrettoPoint {
    let mut h = blake3::Hasher::new();
    h.update(label);
    h.update(&index.to_le_bytes());
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

pub static BP_GENS: Lazy<BulletproofGens> = Lazy::new(|| BulletproofGens::new(MAX_VEC_LEN));

pub struct BulletproofGens {
    pub g_vec: Vec<RistrettoPoint>,
    pub h_vec: Vec<RistrettoPoint>,
}

impl BulletproofGens {
    pub fn new(n: usize) -> Self {
        let g_vec: Vec<RistrettoPoint> = (0..n as u64)
            .map(|i| make_generator(b"Hyphen_BP_G", i))
            .collect();
        let h_vec: Vec<RistrettoPoint> = (0..n as u64)
            .map(|i| make_generator(b"Hyphen_BP_H", i))
            .collect();
        Self { g_vec, h_vec }
    }

    pub fn g(&self, n: usize) -> &[RistrettoPoint] {
        &self.g_vec[..n]
    }

    pub fn h(&self, n: usize) -> &[RistrettoPoint] {
        &self.h_vec[..n]
    }
}
