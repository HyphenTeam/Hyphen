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

pub mod contract;
pub mod engine;
pub mod gas;
pub mod host;
pub mod ledger;
pub mod state;
pub mod types;

pub use contract::Contract;
pub use engine::VmEngine;
pub use gas::GasMeter;
pub use ledger::{VmLedger, VmLedgerError, VmTransaction, VM_ENVELOPE_MAGIC};
pub use types::{ContractAddress, ContractResult};
