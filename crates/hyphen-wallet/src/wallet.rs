use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

use hyphen_crypto::stealth::{self, derive_commitment_blinding, EphemeralKey, SpendKey, StealthAddress, ViewKey};
use hyphen_tx::note::OwnedNote;

use crate::address::HyphenAddress;
use crate::derivation::{DerivedKeys, MasterKey};

fn derive_wallet_key(password: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut state = hyphen_crypto::hash::blake3_hash(
        &[salt.as_slice(), password].concat(),
    );
    for _ in 0..100_000 {
        state = hyphen_crypto::hash::blake3_hash(state.as_bytes());
    }
    *state.as_bytes()
}

fn xof_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"Hyphen_wallet_stream");
    let mut stream = h.finalize_xof();
    let mut out = vec![0u8; data.len()];
    let mut keystream = vec![0u8; data.len()];
    stream.fill(&mut keystream);
    for (i, b) in data.iter().enumerate() {
        out[i] = b ^ keystream[i];
    }
    out
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serialize(String),
    #[error("stealth: {0}")]
    Stealth(String),
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    master: MasterKey,
    #[serde(default)]
    owned_notes: Vec<SerializableOwnedNote>,
    #[serde(default)]
    spent_indices: Vec<u64>,
    #[serde(default)]
    scan_height: u64,
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct SerializableOwnedNote {
    commitment: [u8; 32],
    one_time_pubkey: [u8; 32],
    ephemeral_pubkey: [u8; 32],
    encrypted_amount: [u8; 32],
    global_index: u64,
    block_height: u64,
    value: u64,
    blinding: [u8; 32],
    spend_sk: [u8; 32],
}

impl Wallet {
    pub fn create() -> Self {
        Self {
            master: MasterKey::generate(),
            owned_notes: Vec::new(),
            spent_indices: Vec::new(),
            scan_height: 0,
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            master: MasterKey::from_seed(seed),
            owned_notes: Vec::new(),
            spent_indices: Vec::new(),
            scan_height: 0,
        }
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master
    }

    pub fn keys(&self) -> DerivedKeys {
        self.master.derive()
    }

    pub fn address(&self, mainnet: bool) -> HyphenAddress {
        let dk = self.keys();
        let view_pub = dk.view_public.compress().to_bytes();
        let spend_pub = dk.spend_public.compress().to_bytes();
        if mainnet {
            HyphenAddress::new_mainnet(view_pub, spend_pub)
        } else {
            HyphenAddress::new_testnet(view_pub, spend_pub)
        }
    }

    pub fn stealth_address(&self) -> StealthAddress {
        let dk = self.keys();
        StealthAddress {
            view_public: dk.view_public.compress().to_bytes(),
            spend_public: dk.spend_public.compress().to_bytes(),
        }
    }

    pub fn view_key(&self) -> ViewKey {
        ViewKey(self.keys().view_secret.to_bytes())
    }

    pub fn spend_key(&self) -> SpendKey {
        SpendKey(self.keys().spend_secret.to_bytes())
    }

    pub fn scan_height(&self) -> u64 {
        self.scan_height
    }

    pub fn set_scan_height(&mut self, h: u64) {
        self.scan_height = h;
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_own_output(
        &mut self,
        commitment_bytes: [u8; 32],
        one_time_pubkey: &[u8; 32],
        ephemeral_pubkey: &[u8; 32],
        encrypted_amount: &[u8; 32],
        global_index: u64,
        block_height: u64,
        output_index: u64,
    ) -> Result<Option<u64>, WalletError> {
        let dk = self.keys();
        let vk = ViewKey(dk.view_secret.to_bytes());
        let addr = self.stealth_address();
        let eph = EphemeralKey(*ephemeral_pubkey);

        let otp = curve25519_dalek::ristretto::CompressedRistretto::from_slice(one_time_pubkey)
            .map_err(|e| WalletError::Stealth(e.to_string()))?
            .decompress()
            .ok_or_else(|| WalletError::Stealth("decompression failed".into()))?;

        let ours = stealth::is_output_ours(&vk, &addr.spend_public, &eph, output_index, &otp)
            .map_err(|e| WalletError::Stealth(e.to_string()))?;

        if !ours {
            return Ok(None);
        }

        let sk = SpendKey(dk.spend_secret.to_bytes());
        let (spend_scalar, _pk) = stealth::recover_one_time_key(&vk, &sk, &eph, output_index)
            .map_err(|e| WalletError::Stealth(e.to_string()))?;

        let ss = {
            let big_r = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&eph.0)
                .map_err(|e| WalletError::Stealth(e.to_string()))?
                .decompress()
                .ok_or_else(|| WalletError::Stealth("eph decompression".into()))?;
            let a_r = dk.view_secret * big_r;
            let idx_bytes = output_index.to_le_bytes();
            hyphen_crypto::hash::hash_to_scalar(
                b"Hyphen_ECDH",
                &[a_r.compress().as_bytes().as_slice(), &idx_bytes].concat(),
            )
        };
        let value = stealth::decrypt_amount(encrypted_amount, &ss);

        let blinding_scalar = derive_commitment_blinding(&ss);

        let note = SerializableOwnedNote {
            commitment: commitment_bytes,
            one_time_pubkey: *one_time_pubkey,
            ephemeral_pubkey: *ephemeral_pubkey,
            encrypted_amount: *encrypted_amount,
            global_index,
            block_height,
            value,
            blinding: blinding_scalar.to_bytes(),
            spend_sk: spend_scalar.to_bytes(),
        };
        self.owned_notes.push(note);
        Ok(Some(value))
    }

    pub fn mark_spent(&mut self, global_index: u64) {
        if !self.spent_indices.contains(&global_index) {
            self.spent_indices.push(global_index);
        }
    }

    pub fn balance(&self) -> u64 {
        self.owned_notes
            .iter()
            .filter(|n| !self.spent_indices.contains(&n.global_index))
            .map(|n| n.value)
            .sum()
    }

    pub fn unspent_notes(&self) -> Vec<OwnedNote> {
        self.owned_notes
            .iter()
            .filter(|n| !self.spent_indices.contains(&n.global_index))
            .map(|sn| OwnedNote {
                note: hyphen_tx::note::Note {
                    commitment: hyphen_crypto::pedersen::Commitment(sn.commitment),
                    one_time_pubkey: sn.one_time_pubkey,
                    ephemeral_pubkey: sn.ephemeral_pubkey,
                    encrypted_amount: sn.encrypted_amount,
                    global_index: sn.global_index,
                    block_height: sn.block_height,
                },
                value: sn.value,
                blinding: sn.blinding,
                spend_sk: sn.spend_sk,
            })
            .collect()
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), WalletError> {
        let data = bincode::serialize(self).map_err(|e| WalletError::Serialize(e.to_string()))?;
        std::fs::write(path, &data)?;
        Ok(())
    }

    pub fn save_encrypted(&self, path: &std::path::Path, password: &[u8]) -> Result<(), WalletError> {
        let data = bincode::serialize(self).map_err(|e| WalletError::Serialize(e.to_string()))?;
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let key = derive_wallet_key(password, &salt);
        let encrypted = xof_encrypt(&key, &data);
        let mac = hyphen_crypto::hash::blake3_keyed(&key, &encrypted);
        let mut out = Vec::with_capacity(32 + 32 + encrypted.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(mac.as_bytes());
        out.extend_from_slice(&encrypted);
        std::fs::write(path, &out)?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> Result<Self, WalletError> {
        let data = std::fs::read(path)?;
        let w: Self =
            bincode::deserialize(&data).map_err(|e| WalletError::Serialize(e.to_string()))?;
        Ok(w)
    }

    pub fn load_encrypted(path: &std::path::Path, password: &[u8]) -> Result<Self, WalletError> {
        let data = std::fs::read(path)?;
        if data.len() < 64 {
            return Err(WalletError::Serialize("wallet file too short".into()));
        }
        let salt: [u8; 32] = data[..32].try_into().unwrap();
        let stored_mac: [u8; 32] = data[32..64].try_into().unwrap();
        let ciphertext = &data[64..];
        let key = derive_wallet_key(password, &salt);
        let computed_mac = hyphen_crypto::hash::blake3_keyed(&key, ciphertext);
        if computed_mac.as_bytes() != &stored_mac {
            return Err(WalletError::Serialize("wrong password or corrupted file".into()));
        }
        let plaintext = xof_encrypt(&key, ciphertext);
        let w: Self =
            bincode::deserialize(&plaintext).map_err(|e| WalletError::Serialize(e.to_string()))?;
        Ok(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_address() {
        let w = Wallet::create();
        let addr = w.address(true);
        assert!(addr.encode().starts_with("hy1"));
        let addr2 = w.address(false);
        assert!(addr2.is_testnet());
    }

    #[test]
    fn save_load_roundtrip() {
        let w = Wallet::from_seed([0x42; 32]);
        let dir = std::env::temp_dir().join("hyphen_wallet_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.wallet");
        w.save(&path).unwrap();
        let w2 = Wallet::load(&path).unwrap();
        assert_eq!(w.address(true).encode(), w2.address(true).encode());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn balance_tracking() {
        let mut w = Wallet::from_seed([0x99; 32]);
        w.owned_notes.push(SerializableOwnedNote {
            commitment: [0; 32],
            one_time_pubkey: [0; 32],
            ephemeral_pubkey: [0; 32],
            encrypted_amount: [0; 32],
            global_index: 1,
            block_height: 10,
            value: 1000,
            blinding: [0; 32],
            spend_sk: [0; 32],
        });
        w.owned_notes.push(SerializableOwnedNote {
            commitment: [0; 32],
            one_time_pubkey: [0; 32],
            ephemeral_pubkey: [0; 32],
            encrypted_amount: [0; 32],
            global_index: 2,
            block_height: 11,
            value: 500,
            blinding: [0; 32],
            spend_sk: [0; 32],
        });
        assert_eq!(w.balance(), 1500);
        w.mark_spent(1);
        assert_eq!(w.balance(), 500);
    }

    #[test]
    fn encrypted_save_load_roundtrip() {
        let w = Wallet::from_seed([0x77; 32]);
        let dir = std::env::temp_dir().join("hyphen_wallet_enc_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_enc.wallet");
        w.save_encrypted(&path, b"test_password").unwrap();
        let w2 = Wallet::load_encrypted(&path, b"test_password").unwrap();
        assert_eq!(w.address(true).encode(), w2.address(true).encode());
        assert_eq!(w.balance(), w2.balance());
        let bad = Wallet::load_encrypted(&path, b"wrong_password");
        assert!(bad.is_err());
        let _ = std::fs::remove_file(&path);
    }
}
