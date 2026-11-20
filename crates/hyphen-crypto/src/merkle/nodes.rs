use super::{Hash256, MERKLE_DEPTH};
use rustbinary::{CompactCursor, CompactDecode, CompactEncode, EncodeWriter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

type Position = (u64, u64);

/// Append-only leaves fill each level contiguously. Keep only hashes in memory,
/// while preserving the ordered (level, index) map in snapshots and undo records.
#[derive(Clone, Debug)]
pub(super) struct Nodes([Vec<Hash256>; MERKLE_DEPTH + 1]);

impl Nodes {
    pub(super) fn new() -> Self {
        Self(std::array::from_fn(|_| Vec::new()))
    }

    pub(super) fn get(&self, level: usize, index: u64) -> Option<Hash256> {
        self.0[level].get(usize::try_from(index).ok()?).copied()
    }

    pub(super) fn matches_count(&self, leaves: u64) -> bool {
        self.0
            .iter()
            .enumerate()
            .all(|(level, row)| row.len() as u64 == leaves.div_ceil(1 << level))
    }

    pub(super) fn put(&mut self, level: usize, index: u64, hash: Hash256) {
        let row = &mut self.0[level];
        if index == row.len() as u64 {
            row.push(hash);
        } else {
            row[index as usize] = hash;
        }
    }

    fn entries(&self) -> impl Iterator<Item = (Position, &Hash256)> {
        self.0.iter().enumerate().flat_map(|(level, row)| {
            row.iter()
                .enumerate()
                .map(move |(index, hash)| ((level as u64, index as u64), hash))
        })
    }

    fn from_entries(
        entries: impl IntoIterator<Item = (Position, Hash256)>,
    ) -> Result<Self, &'static str> {
        let mut nodes = Self::new();
        for ((level, index), hash) in entries {
            let row = usize::try_from(level)
                .ok()
                .and_then(|i| nodes.0.get_mut(i))
                .ok_or("invalid Merkle tree level")?;
            if index != row.len() as u64 {
                return Err("non-contiguous Merkle tree nodes");
            }
            row.push(hash);
        }
        Ok(nodes)
    }
}

impl CompactEncode for Nodes {
    fn encode_compact<W: EncodeWriter + ?Sized>(&self, writer: &mut W) -> rustbinary::Result<()> {
        let count: u64 = self.0.iter().map(|row| row.len() as u64).sum();
        count.encode_compact(writer)?;
        writer.enter_container()?;
        let result = self.entries().try_for_each(|(position, hash)| {
            position.encode_compact(writer)?;
            hash.encode_compact(writer)
        });
        writer.exit_container();
        result
    }
}

impl<'de> CompactDecode<'de> for Nodes {
    fn decode_compact(cursor: &mut CompactCursor<'de>) -> rustbinary::Result<Self> {
        // Map entries and tuples share the compact encoding. The collection
        // decoder applies the caller's item, depth and byte limits.
        let entries = Vec::<(Position, Hash256)>::decode_compact(cursor)?;
        Self::from_entries(entries).map_err(|reason| rustbinary::Error::Custom(reason.into()))
    }
}

impl Serialize for Nodes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.entries())
    }
}

impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_entries(BTreeMap::<Position, Hash256>::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
