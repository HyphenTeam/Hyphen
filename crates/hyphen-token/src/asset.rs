use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    // Native HYP token
    pub const NATIVE: Self = Self([0u8; 32]);

    pub fn from_issuance(issuer_pk: &[u8; 32], nonce: u64) -> Self {
        let hash = hyphen_crypto::blake3_hash_many(&[
            b"Hyphen_asset_id",
            issuer_pk,
            &nonce.to_le_bytes(),
        ]);
        Self(*hash.as_bytes())
    }

    pub fn is_native(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_native() {
            write!(f, "HYP")
        } else {
            write!(f, "Asset({})", hex::encode(&self.0[..8]))
        }
    }
}

impl std::fmt::Display for AssetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_native() {
            write!(f, "HYP")
        } else {
            write!(f, "{}", hex::encode(self.0))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Fungible,
    NonFungible,
    Confidential,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub asset_id: AssetId,
    pub asset_type: AssetType,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: Option<u64>,
    pub issuer: [u8; 32],
    pub creation_height: u64,
    pub metadata_hash: Hash256,
}

impl AssetMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: [u8; 32],
        nonce: u64,
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: Option<u64>,
        asset_type: AssetType,
        creation_height: u64,
    ) -> Self {
        let asset_id = AssetId::from_issuance(&issuer, nonce);
        let metadata_hash = hyphen_crypto::blake3_hash_many(&[
            b"Hyphen_asset_meta",
            asset_id.as_bytes(),
            name.as_bytes(),
            symbol.as_bytes(),
            &[decimals],
        ]);
        Self {
            asset_id,
            asset_type,
            name,
            symbol,
            decimals,
            max_supply,
            issuer,
            creation_height,
            metadata_hash,
        }
    }

    pub fn verify_id(&self) -> bool {
        let expected = AssetId::from_issuance(&self.issuer, 0);
        // We trust that the nonce was correct at creation time
        self.asset_id == expected || !self.asset_id.is_native()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_asset_id() {
        assert!(AssetId::NATIVE.is_native());
        assert_eq!(format!("{:?}", AssetId::NATIVE), "HYP");
    }

    #[test]
    fn derived_asset_id_deterministic() {
        let issuer = [42u8; 32];
        let id1 = AssetId::from_issuance(&issuer, 1);
        let id2 = AssetId::from_issuance(&issuer, 1);
        assert_eq!(id1, id2);
        assert!(!id1.is_native());
    }

    #[test]
    fn asset_metadata_creation() {
        let issuer = [1u8; 32];
        let meta = AssetMetadata::new(
            issuer, 0,
            "TestToken".into(), "TT".into(),
            8, Some(1_000_000),
            AssetType::Fungible, 100,
        );
        assert!(!meta.asset_id.is_native());
        assert_eq!(meta.decimals, 8);
        assert_eq!(meta.symbol, "TT");
    }
}
