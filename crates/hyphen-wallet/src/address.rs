use blake3;
use bs58;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const VERSION_MAINNET: u8 = 0x01;
const VERSION_TESTNET: u8 = 0x02;
const PREFIX: &str = "hy1";
const CHECKSUM_LEN: usize = 4;
const PUBKEY_LEN: usize = 32;
const PAYLOAD_LEN: usize = 1 + PUBKEY_LEN + PUBKEY_LEN + CHECKSUM_LEN; // 69

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("missing hy1 prefix")]
    MissingPrefix,
    #[error("base58 decode failed")]
    Base58Decode,
    #[error("invalid payload length (expected {PAYLOAD_LEN})")]
    InvalidLength,
    #[error("checksum mismatch")]
    ChecksumMismatch,
    #[error("unknown version byte 0x{0:02x}")]
    UnknownVersion(u8),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyphenAddress {
    pub version: u8,
    pub view_public: [u8; 32],
    pub spend_public: [u8; 32],
}

impl HyphenAddress {
    pub fn new_mainnet(view_public: [u8; 32], spend_public: [u8; 32]) -> Self {
        Self { version: VERSION_MAINNET, view_public, spend_public }
    }

    pub fn new_testnet(view_public: [u8; 32], spend_public: [u8; 32]) -> Self {
        Self { version: VERSION_TESTNET, view_public, spend_public }
    }

    fn checksum(version: u8, view: &[u8; 32], spend: &[u8; 32]) -> [u8; CHECKSUM_LEN] {
        let mut h = blake3::Hasher::new();
        h.update(&[version]);
        h.update(view);
        h.update(spend);
        let hash = h.finalize();
        let mut cs = [0u8; CHECKSUM_LEN];
        cs.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
        cs
    }

    pub fn encode(&self) -> String {
        let cs = Self::checksum(self.version, &self.view_public, &self.spend_public);
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.push(self.version);
        payload.extend_from_slice(&self.view_public);
        payload.extend_from_slice(&self.spend_public);
        payload.extend_from_slice(&cs);
        format!("{}{}", PREFIX, bs58::encode(&payload).into_string())
    }

    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let body = s.strip_prefix(PREFIX).ok_or(AddressError::MissingPrefix)?;
        let payload = bs58::decode(body).into_vec().map_err(|_| AddressError::Base58Decode)?;
        if payload.len() != PAYLOAD_LEN {
            return Err(AddressError::InvalidLength);
        }
        let version = payload[0];
        if version != VERSION_MAINNET && version != VERSION_TESTNET {
            return Err(AddressError::UnknownVersion(version));
        }
        let mut view = [0u8; 32];
        let mut spend = [0u8; 32];
        view.copy_from_slice(&payload[1..33]);
        spend.copy_from_slice(&payload[33..65]);
        let expected_cs = Self::checksum(version, &view, &spend);
        if payload[65..69] != expected_cs {
            return Err(AddressError::ChecksumMismatch);
        }
        Ok(Self { version, view_public: view, spend_public: spend })
    }

    pub fn is_mainnet(&self) -> bool { self.version == VERSION_MAINNET }
    pub fn is_testnet(&self) -> bool { self.version == VERSION_TESTNET }
}

impl std::fmt::Debug for HyphenAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl std::fmt::Display for HyphenAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mainnet() {
        let addr = HyphenAddress::new_mainnet([0xAA; 32], [0xBB; 32]);
        let encoded = addr.encode();
        assert!(encoded.starts_with("hy1"));
        let decoded = HyphenAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert!(decoded.is_mainnet());
    }

    #[test]
    fn roundtrip_testnet() {
        let addr = HyphenAddress::new_testnet([0x11; 32], [0x22; 32]);
        let encoded = addr.encode();
        assert!(encoded.starts_with("hy1"));
        let decoded = HyphenAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
        assert!(decoded.is_testnet());
    }

    #[test]
    fn bad_prefix() {
        assert!(HyphenAddress::decode("xx1AAAA").is_err());
    }

    #[test]
    fn bad_checksum() {
        let addr = HyphenAddress::new_mainnet([0xAA; 32], [0xBB; 32]);
        let mut encoded = addr.encode();
        let len = encoded.len();
        encoded.replace_range(len - 2..len, "ZZ");
        assert!(HyphenAddress::decode(&encoded).is_err());
    }
}
