// Iterative Commitment Derivation (ICD) — novel key derivation using
// Pedersen commitment structure on the Ristretto curve.
//
// Unlike HKDF or BIP32-style derivation, ICD creates child keys by
// projecting the parent scalar through a Pedersen commit and hashing
// the resulting curve point.  Security relies on the Decisional
// Diffie-Hellman assumption on Ristretto255.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use hyphen_crypto::hash::{hash_to_point, hash_to_scalar};

static TWIST_GEN: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| hash_to_point(b"Hyphen_ICD_twist_generator_v1"));

#[derive(Clone, Serialize, Deserialize, Zeroize, rustbinary::CompactBinary)]
#[zeroize(drop)]
pub struct MasterKey {
    seed: [u8; 32],
}

#[derive(Clone)]
pub struct DerivedKeys {
    pub view_secret: Scalar,
    pub spend_secret: Scalar,
    pub view_public: RistrettoPoint,
    pub spend_public: RistrettoPoint,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.view_secret.zeroize();
        self.spend_secret.zeroize();
    }
}

impl MasterKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        hyphen_crypto::rng::fill_system_random(&mut seed);
        Self { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn master_scalar(&self) -> Scalar {
        hash_to_scalar(b"Hyphen_master_v1", &self.seed)
    }

    // ICD derivation: project parent_key through a Pedersen commitment
    // with a purpose-specific twist, then hash the resulting point.
    //
    //   chain_point = parent_key · G + H_s(purpose) · T
    //   child_key   = H_s(chain_point.compress())
    //
    // where T is a fixed twist generator unrelated to G.
    fn icd_derive(&self, purpose: &[u8]) -> Scalar {
        let parent = self.master_scalar();
        let twist_scalar = hash_to_scalar(b"Hyphen_ICD_purpose", purpose);
        let chain_point = parent * G + twist_scalar * *TWIST_GEN;
        hash_to_scalar(b"Hyphen_ICD_child", chain_point.compress().as_bytes())
    }

    pub fn derive(&self) -> DerivedKeys {
        let view_secret = self.icd_derive(b"view");
        let spend_secret = self.icd_derive(b"spend");
        DerivedKeys {
            view_secret,
            spend_secret,
            view_public: view_secret * G,
            spend_public: spend_secret * G,
        }
    }

    /// Derive v2 subaddress keys from the wallet seed and fixed-width path.
    /// Legacy subaddresses require their original key material for recovery.
    pub fn derive_subaddress(&self, account: u32, index: u32) -> DerivedKeys {
        let derive = |role: &[u8]| {
            let mut h = blake3::Hasher::new_keyed(&self.seed);
            h.update(b"Hyphen/wallet/subaddress/v2\0");
            h.update(&account.to_le_bytes());
            h.update(&index.to_le_bytes());
            h.update(role);
            let mut wide = zeroize::Zeroizing::new([0; 64]);
            h.finalize_xof().fill(wide.as_mut());
            Scalar::from_bytes_mod_order_wide(&wide)
        };
        let sub_view = derive(b"view");
        let sub_spend = derive(b"spend");
        DerivedKeys {
            view_secret: sub_view,
            spend_secret: sub_spend,
            view_public: sub_view * G,
            spend_public: sub_spend * G,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let mk = MasterKey::from_seed([0xAB; 32]);
        let k1 = mk.derive();
        let k2 = mk.derive();
        assert_eq!(k1.view_secret, k2.view_secret);
        assert_eq!(k1.spend_secret, k2.spend_secret);
    }

    #[test]
    fn view_and_spend_differ() {
        let mk = MasterKey::generate();
        let keys = mk.derive();
        assert_ne!(keys.view_secret, keys.spend_secret);
    }

    #[test]
    fn subaddress_uniqueness() {
        let mk = MasterKey::generate();
        let a = mk.derive_subaddress(0, 0);
        let b = mk.derive_subaddress(0, 1);
        assert_ne!(a.spend_public, b.spend_public);
        assert_ne!(a.view_public, b.view_public);
    }

    #[test]
    fn v2_subaddress_recovery_matches_public_vector() {
        let path = (0x0102_0304, 0x0506_0708);
        let key = MasterKey::from_seed([0xab; 32]);
        let child = key.derive_subaddress(path.0, path.1);
        assert_eq!(
            hyphen_crypto::hex_encode(child.view_public.compress().as_bytes()),
            "a651f158c5e30aed3f1c05c18f8d8eaf800add7d941581e05a99de036728176f"
        );
        assert_eq!(
            hyphen_crypto::hex_encode(child.spend_public.compress().as_bytes()),
            "3c956f24a14362237a22f4411dfd50c2be9db553a1586d49617bc13503f5c262"
        );
        let other = MasterKey::from_seed([0xac; 32]).derive_subaddress(path.0, path.1);
        assert_ne!(child.spend_secret, other.spend_secret);
        assert_ne!(child.view_secret, other.view_secret);
    }
}
