// The wire profile lives in `hyphen-wire`; see the crate for the frozen
// profile, its byte/element budgets and the container adapters.
pub(crate) use hyphen_wire::wire_config;

pub mod behaviour;
pub mod bootstrap;
pub mod protocol;
pub mod sync;

pub use behaviour::HyphenNetwork;
pub use bootstrap::{is_dns_seed, SeedError, SeedResolver};
pub use protocol::{NetworkMessage, SyncRequest, SyncResponse};
