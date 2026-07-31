pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::Config {
    rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
}

pub mod address;
pub mod audit;
pub mod derivation;
pub mod signer;
pub mod wallet;

pub use address::HyphenAddress;
pub use audit::{
    generate_disclosure, verify_disclosure, AuditError, AuditVerificationContext, DisclosedField,
    OwnershipProof, SelectiveDisclosure, DISCLOSED_FIELDS_V0, SELECTIVE_DISCLOSURE_VERSION,
};
pub use derivation::{DerivedKeys, MasterKey};
pub use signer::{
    verify_signing_response, DeviceFamily, ExternalSigner, KeyLocator, NetworkBinding,
    SignerCapabilities, SignerError, SignerTransport, SigningRequest, SigningResponse,
};
pub use wallet::Wallet;
