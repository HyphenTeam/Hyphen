//! The frozen Hyphen chain wire contract.
//!
//! Everything that turns a Rust value into chain bytes — block headers,
//! transactions, receipts, miner/pool envelopes, archives, wallet state — goes
//! through [`wire_config`]. Keeping the profile in one crate means the node, the
//! pool, the miner and the wallet cannot drift apart by re-implementing it, and
//! that changing the profile is a change to exactly one file.
//!
//! ## Profile (chain identity v6)
//!
//! The profile is the *schema-guided compact* profile of `rustbinary`:
//!
//! * fields in declaration order, no field names and no type tags on the wire;
//! * canonical little-endian varints for integers, lengths and discriminants;
//! * length-prefixed containers, `Option` as a single presence byte;
//! * enums as their positional variant index;
//! * trailing bytes rejected, so every value has exactly one accepted encoding;
//! * a caller-supplied byte budget plus a hard element budget per container.
//!
//! ## Container adapters
//!
//! The profile encodes `Vec`, `VecDeque`, arrays, `BTreeMap` and `HashMap`
//! itself. [`CanonicalSet`] covers the remaining shape used by the chain model:
//! ordered sets, encoded as the canonical strictly-ascending sequence.

pub mod canonical_set;

pub use canonical_set::CanonicalSet;

/// Conservative default byte budget for one encoded value (64 MiB).
pub const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;

/// Hard ceiling on elements in a single container, independent of the byte
/// budget. A caller may ask for a large frame; it may never ask for an
/// unbounded element count.
pub const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

/// The one wire profile every Hyphen binary must use.
///
/// Frozen with chain identity v6 (see the crate docs for the exact profile).
/// `max_bytes` is the byte budget this decoder may spend on the value in front
/// of it; the element budget is additionally capped by
/// [`MAX_WIRE_COLLECTION_ITEMS`].
pub fn wire_config(max_bytes: usize) -> rustbinary::CompactConfig {
    rustbinary::options()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
        .with_compact_format()
}

#[cfg(test)]
mod tests {
    /// Both budgets bind: the caller's byte budget and the element budget
    /// derived from it. Elements that write nothing (`()`) would defeat the
    /// element check, so the probe uses an element that occupies a byte.
    #[test]
    fn profile_enforces_byte_and_element_budgets() {
        assert!(super::wire_config(7).serialize(&u64::MAX).is_err());
        assert!(super::wire_config(64).serialize(&vec![0u8; 65]).is_err());
        assert!(super::wire_config(64).serialize(&vec![0u8; 32]).is_ok());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let config = super::wire_config(1024);
        let mut encoded = config.serialize(&(7u32, 9u64)).unwrap();
        encoded.push(0);
        assert!(config.deserialize::<(u32, u64)>(&encoded).is_err());
    }
}
