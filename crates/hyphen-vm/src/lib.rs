pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::CompactConfig {
    rustbinary::options()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
        .with_compact_format()
}

pub mod application;
pub mod contract;
pub mod engine;
pub mod gas;
pub mod host;
pub mod ledger;
pub mod state;
pub mod types;

pub use application::{AppCategory, AppManifest, AppManifestError, application_manifest};
pub use contract::Contract;
pub use engine::VmEngine;
pub use gas::GasMeter;
pub use ledger::{VM_ENVELOPE_MAGIC, VmLedger, VmLedgerError, VmTransaction};
pub use types::{ContractAddress, ContractResult};
