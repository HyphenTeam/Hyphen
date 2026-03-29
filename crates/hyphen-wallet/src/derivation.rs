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
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use hyphen_crypto::hash::{hash_to_point, hash_to_scalar};

static TWIST_GEN: once_cell::sync::Lazy<RistrettoPoint> = once_cell::sync::Lazy::new(|| {
    hash_to_point(b"Hyphen_ICD_twist_generator_v1")
});

#[derive(Clone, Serialize, Deserialize, Zeroize)]
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

impl MasterKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
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

    pub fn derive_subaddress(&self, account: u32, index: u32) -> DerivedKeys {
        let base = self.derive();
        let mut idx_data = Vec::with_capacity(8);
        idx_data.extend_from_slice(&account.to_le_bytes());
        idx_data.extend_from_slice(&index.to_le_bytes());
        let sub_scalar = hash_to_scalar(b"Hyphen_ICD_sub", &idx_data);
        let sub_point = sub_scalar * *TWIST_GEN;
        let sub_spend = hash_to_scalar(
            b"Hyphen_ICD_sub_spend",
            (base.spend_secret * G + sub_point).compress().as_bytes(),
        );
        let sub_view = hash_to_scalar(
            b"Hyphen_ICD_sub_view",
            (base.view_secret * G + sub_point).compress().as_bytes(),
        );
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
}
