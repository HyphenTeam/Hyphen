// The wire profile lives in `hyphen-wire`; see the crate for the frozen
// profile, its byte/element budgets and the container adapters.
pub(crate) use hyphen_wire::wire_config;

pub mod behaviour;
pub mod bootstrap;
pub mod protocol;

pub use behaviour::HyphenNetwork;
pub use bootstrap::{SeedError, SeedResolver, is_dns_seed};
pub use protocol::{NetworkMessage, SyncRequest, SyncResponse};
pub const SYNC_BATCH_SIZE: u32 = 16;
