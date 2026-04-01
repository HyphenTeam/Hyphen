use crate::hash::{blake3_hash, blake3_hash_many};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const WOTS_W: usize = 16;
const WOTS_LOG_W: usize = 4;
const WOTS_LEN1: usize = 64;
const WOTS_LEN2: usize = 3;
const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
const WOTS_CHAIN_MAX: u8 = (WOTS_W - 1) as u8;

#[derive(Debug, Error)]
pub enum PqError {
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid public key length")]
    InvalidPublicKeyLength,
    #[error("verification failed")]
    VerificationFailed,
    #[error("invalid seed length")]
    InvalidSeedLength,
}

fn chain(value: &[u8; 32], start: u8, steps: u8, addr_seed: &[u8; 32], chain_idx: u16) -> [u8; 32] {
    let mut current = *value;
    for i in start..start.saturating_add(steps) {
        let h = blake3_hash_many(&[
            b"Hyphen_WOTS_chain",
            addr_seed,
            &chain_idx.to_le_bytes(),
            &[i],
            &current,
        ]);
        current = *h.as_bytes();
    }
    current
}

fn msg_base_w(msg_hash: &[u8; 32]) -> Vec<u8> {
    let mut base_w = Vec::with_capacity(WOTS_LEN1);
    for byte in msg_hash.iter() {
        base_w.push(byte >> WOTS_LOG_W);
        base_w.push(byte & 0x0F);
    }

    let mut checksum: u32 = 0;
    for &b in &base_w {
        checksum += (WOTS_CHAIN_MAX as u32) - (b as u32);
    }
    checksum <<= 4;

    let cs_bytes = checksum.to_be_bytes();
    base_w.push(cs_bytes[1] >> WOTS_LOG_W);
    base_w.push(cs_bytes[1] & 0x0F);
    base_w.push(cs_bytes[2] >> WOTS_LOG_W);

    base_w
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WotsPublicKey {
    pub key_hash: [u8; 32],
    pub addr_seed: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WotsSecretKey {
    pub seed: [u8; 32],
    pub addr_seed: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WotsSignature {
    pub chains: Vec<[u8; 32]>,
    pub addr_seed: [u8; 32],
}

impl WotsSecretKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut seed = [0u8; 32];
        let mut addr_seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut addr_seed);
        Self { seed, addr_seed }
    }

    pub fn from_seed(seed: [u8; 32], addr_seed: [u8; 32]) -> Self {
        Self { seed, addr_seed }
    }

    fn chain_secret(&self, idx: u16) -> [u8; 32] {
        let h = blake3_hash_many(&[
            b"Hyphen_WOTS_sk",
            &self.seed,
            &idx.to_le_bytes(),
        ]);
        *h.as_bytes()
    }

    pub fn public_key(&self) -> WotsPublicKey {
        let mut concat = Vec::with_capacity(WOTS_LEN * 32);
        for i in 0..WOTS_LEN as u16 {
            let sk_i = self.chain_secret(i);
            let pk_i = chain(&sk_i, 0, WOTS_CHAIN_MAX, &self.addr_seed, i);
            concat.extend_from_slice(&pk_i);
        }
        let key_hash = blake3_hash(&concat);
        WotsPublicKey {
            key_hash: *key_hash.as_bytes(),
            addr_seed: self.addr_seed,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> WotsSignature {
        let msg_hash = blake3_hash(msg);
        let base_w = msg_base_w(msg_hash.as_bytes());

        let mut chains = Vec::with_capacity(WOTS_LEN);
        for (i, &b) in base_w.iter().enumerate() {
            let sk_i = self.chain_secret(i as u16);
            let sig_i = chain(&sk_i, 0, b, &self.addr_seed, i as u16);
            chains.push(sig_i);
        }

        WotsSignature {
            chains,
            addr_seed: self.addr_seed,
        }
    }
}

impl std::fmt::Debug for WotsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WotsSecretKey(**redacted**)")
    }
}

impl WotsSignature {
    pub fn verify(&self, msg: &[u8], pk: &WotsPublicKey) -> Result<(), PqError> {
        if self.chains.len() != WOTS_LEN {
            return Err(PqError::InvalidSignatureLength);
        }
        if self.addr_seed != pk.addr_seed {
            return Err(PqError::VerificationFailed);
        }

        let msg_hash = blake3_hash(msg);
        let base_w = msg_base_w(msg_hash.as_bytes());

        let mut concat = Vec::with_capacity(WOTS_LEN * 32);
        for (i, (&sig_i, &b)) in self.chains.iter().zip(base_w.iter()).enumerate() {
            let remaining = WOTS_CHAIN_MAX - b;
            let pk_i = chain(&sig_i, b, remaining, &self.addr_seed, i as u16);
            concat.extend_from_slice(&pk_i);
        }

        let key_hash = blake3_hash(&concat);
        if key_hash.as_bytes() != &pk.key_hash {
            return Err(PqError::VerificationFailed);
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + WOTS_LEN * 32);
        out.extend_from_slice(&self.addr_seed);
        for c in &self.chains {
            out.extend_from_slice(c);
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PqError> {
        let expected = 32 + WOTS_LEN * 32;
        if data.len() != expected {
            return Err(PqError::InvalidSignatureLength);
        }
        let mut addr_seed = [0u8; 32];
        addr_seed.copy_from_slice(&data[..32]);
        let mut chains = Vec::with_capacity(WOTS_LEN);
        for i in 0..WOTS_LEN {
            let start = 32 + i * 32;
            let mut c = [0u8; 32];
            c.copy_from_slice(&data[start..start + 32]);
            chains.push(c);
        }
        Ok(Self { chains, addr_seed })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub ed25519: crate::keys::PublicKey,
    pub wots: WotsPublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSecretKey {
    pub ed25519: crate::keys::SecretKey,
    pub wots: WotsSecretKey,
}

impl HybridSecretKey {
    pub fn generate() -> Self {
        Self {
            ed25519: crate::keys::SecretKey::generate(),
            wots: WotsSecretKey::generate(),
        }
    }

    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519.public_key(),
            wots: self.wots.public_key(),
        }
    }
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSecretKey(**redacted**)")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519: crate::keys::Signature,
    pub wots: WotsSignature,
}

impl HybridSignature {
    pub fn sign(msg: &[u8], sk: &HybridSecretKey) -> Self {
        Self {
            ed25519: sk.ed25519.sign(msg),
            wots: sk.wots.sign(msg),
        }
    }

    pub fn verify(&self, msg: &[u8], pk: &HybridPublicKey) -> Result<(), PqError> {
        pk.ed25519
            .verify(msg, &self.ed25519)
            .map_err(|_| PqError::VerificationFailed)?;

        self.wots.verify(msg, &pk.wots)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let wots_bytes = self.wots.to_bytes();
        let mut out = Vec::with_capacity(64 + wots_bytes.len());
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(&wots_bytes);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wots_sign_verify() {
        let sk = WotsSecretKey::generate();
        let pk = sk.public_key();
        let msg = b"test message for WOTS+";
        let sig = sk.sign(msg);
        sig.verify(msg, &pk).unwrap();
    }

    #[test]
    fn wots_wrong_message_fails() {
        let sk = WotsSecretKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign(b"correct");
        assert!(sig.verify(b"wrong", &pk).is_err());
    }

    #[test]
    fn wots_serialisation_roundtrip() {
        let sk = WotsSecretKey::generate();
        let sig = sk.sign(b"roundtrip test");
        let bytes = sig.to_bytes();
        let recovered = WotsSignature::from_bytes(&bytes).unwrap();
        let pk = sk.public_key();
        recovered.verify(b"roundtrip test", &pk).unwrap();
    }

    #[test]
    fn hybrid_sign_verify() {
        let sk = HybridSecretKey::generate();
        let pk = sk.public_key();
        let msg = b"hybrid PQ test";
        let sig = HybridSignature::sign(msg, &sk);
        sig.verify(msg, &pk).unwrap();
    }

    #[test]
    fn hybrid_wrong_message_fails() {
        let sk = HybridSecretKey::generate();
        let pk = sk.public_key();
        let sig = HybridSignature::sign(b"correct", &sk);
        assert!(sig.verify(b"wrong", &pk).is_err());
    }
}
