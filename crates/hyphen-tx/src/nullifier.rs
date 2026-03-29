use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use hyphen_crypto::hash::hash_to_point;

pub fn compute_nullifier(spend_sk: &Scalar, one_time_pk: &RistrettoPoint) -> RistrettoPoint {
    let hp = hash_to_point(one_time_pk.compress().as_bytes());
    spend_sk * hp
}

pub fn nullifier_to_bytes(nullifier: &RistrettoPoint) -> [u8; 32] {
    nullifier.compress().to_bytes()
}

pub fn nullifier_from_bytes(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    curve25519_dalek::ristretto::CompressedRistretto::from_slice(bytes)
        .ok()?
        .decompress()
}
