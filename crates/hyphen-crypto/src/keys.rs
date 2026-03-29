use ed25519_dalek::{
    Signer, SigningKey, Verifier, VerifyingKey,
    Signature as Ed25519Sig,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid secret key bytes")]
    InvalidSecretKey,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    VerificationFailed,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey, KeyError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| KeyError::InvalidPublicKey)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), KeyError> {
        let vk = self.to_verifying_key()?;
        let s = Ed25519Sig::from_bytes(&sig.0);
        vk.verify(msg, &s).map_err(|_| KeyError::VerificationFailed)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PK({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        Self(sk.to_bytes())
    }

    pub fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sk = self.to_signing_key();
        let sig = sk.sign(msg);
        Signature(sig.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let sk = self.to_signing_key();
        PublicKey(sk.verifying_key().to_bytes())
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SK(**redacted**)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(de)?;
        let arr: [u8; 64] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Self(arr))
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sig({}…)", hex::encode(&self.0[..8]))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.secret.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), KeyError> {
        self.public.verify(msg, sig)
    }
}
