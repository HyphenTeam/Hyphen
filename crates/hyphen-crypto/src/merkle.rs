use crate::hash::{Hash256, blake3_hash_many};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};

mod nodes;
use nodes::Nodes;

pub const MERKLE_DEPTH: usize = 32;

static EMPTY_HASHES: LazyLock<[Hash256; MERKLE_DEPTH + 1]> = LazyLock::new(|| {
    let mut e = [Hash256::ZERO; MERKLE_DEPTH + 1];
    e[0] = blake3_hash_many(&[b"Hyphen_empty_leaf"]);
    for i in 1..=MERKLE_DEPTH {
        e[i] = blake3_hash_many(&[e[i - 1].as_bytes(), e[i - 1].as_bytes()]);
    }
    e
});

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<Hash256>, // length == MERKLE_DEPTH
}

impl MerkleProof {
    pub fn verify(&self, leaf: &Hash256, root: &Hash256) -> bool {
        if self.siblings.len() != MERKLE_DEPTH || self.leaf_index >> MERKLE_DEPTH != 0 {
            return false;
        }
        let mut cur = *leaf;
        let mut idx = self.leaf_index;
        for sib in &self.siblings {
            cur = if idx & 1 == 0 {
                blake3_hash_many(&[cur.as_bytes(), sib.as_bytes()])
            } else {
                blake3_hash_many(&[sib.as_bytes(), cur.as_bytes()])
            };
            idx >>= 1;
        }
        &cur == root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
#[serde(rename = "MerkleTree")]
struct TreeState {
    count: u64,
    frontier: Vec<Option<Hash256>>,
    root: Hash256,
    filled: Nodes,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "TreeState")]
pub struct MerkleTree(Arc<TreeState>);

impl Serialize for MerkleTree {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl TryFrom<TreeState> for MerkleTree {
    type Error = &'static str;

    fn try_from(state: TreeState) -> Result<Self, Self::Error> {
        if state.frontier.len() != MERKLE_DEPTH || !state.filled.matches_count(state.count) {
            return Err("invalid Merkle tree dimensions");
        }
        let root = state
            .count
            .checked_sub(1)
            .and_then(|last| state.filled.get(MERKLE_DEPTH, last >> MERKLE_DEPTH))
            .unwrap_or(EMPTY_HASHES[MERKLE_DEPTH]);
        if root != state.root {
            return Err("inconsistent Merkle tree root");
        }
        Ok(Self(Arc::new(state)))
    }
}

impl rustbinary::CompactEncode for MerkleTree {
    fn encode_compact<W: rustbinary::EncodeWriter + ?Sized>(
        &self,
        writer: &mut W,
    ) -> rustbinary::Result<()> {
        self.0.encode_compact(writer)
    }
}

impl<'de> rustbinary::CompactDecode<'de> for MerkleTree {
    fn decode_compact(cursor: &mut rustbinary::CompactCursor<'de>) -> rustbinary::Result<Self> {
        TreeState::decode_compact(cursor)?
            .try_into()
            .map_err(|reason: &str| rustbinary::Error::Custom(reason.into()))
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        Self(Arc::new(TreeState {
            count: 0,
            frontier: vec![None; MERKLE_DEPTH],
            root: EMPTY_HASHES[MERKLE_DEPTH],
            filled: Nodes::new(),
        }))
    }

    pub fn root(&self) -> Hash256 {
        self.0.root
    }

    pub fn count(&self) -> u64 {
        self.0.count
    }

    pub fn append(&mut self, leaf: Hash256) -> u64 {
        let state = Arc::make_mut(&mut self.0);
        let idx = state.count;
        state.count += 1;

        let mut cur = leaf;
        let mut pos = idx;

        for (level, &empty) in EMPTY_HASHES[..MERKLE_DEPTH].iter().enumerate() {
            state.filled.put(level, pos, cur);
            if pos & 1 == 0 {
                state.frontier[level] = Some(cur);
                cur = blake3_hash_many(&[cur.as_bytes(), empty.as_bytes()]);
            } else {
                let sibling = state.filled.get(level, pos - 1).unwrap_or(empty);
                cur = blake3_hash_many(&[sibling.as_bytes(), cur.as_bytes()]);
                state.frontier[level] = None;
            }
            pos >>= 1;
        }
        state.filled.put(MERKLE_DEPTH, pos, cur);
        state.root = cur;
        idx
    }

    pub fn prove(&self, leaf_index: u64) -> Option<MerkleProof> {
        if leaf_index >= self.0.count {
            return None;
        }
        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
        let mut pos = leaf_index;

        for (level, &empty) in EMPTY_HASHES[..MERKLE_DEPTH].iter().enumerate() {
            let sib = self.0.filled.get(level, pos ^ 1).unwrap_or(empty);
            siblings.push(sib);
            pos >>= 1;
        }

        Some(MerkleProof {
            leaf_index,
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_root_changes() {
        let mut tree = MerkleTree::new();
        let r0 = tree.root();
        let leaf = blake3_hash_many(&[b"leaf0"]);
        tree.append(leaf);
        assert_ne!(tree.root(), r0);
    }

    #[test]
    fn proof_round_trip() {
        let mut tree = MerkleTree::new();
        let mut leaves = Vec::new();
        for i in 0u64..8 {
            let l = blake3_hash_many(&[&i.to_le_bytes()[..]]);
            tree.append(l);
            leaves.push(l);
        }
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i as u64).unwrap();
            assert!(
                proof.verify(leaf, &tree.root()),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn proof_round_trip_for_non_power_of_two_leaf_count() {
        let mut tree = MerkleTree::new();
        let leaves = (0u64..20)
            .map(|index| blake3_hash_many(&[&index.to_be_bytes()]))
            .collect::<Vec<_>>();
        for leaf in &leaves {
            tree.append(*leaf);
        }
        for (index, leaf) in leaves.iter().enumerate() {
            assert!(tree.prove(index as u64).unwrap().verify(leaf, &tree.root()));
        }
    }

    #[test]
    fn snapshots_preserve_the_persisted_map_encoding() {
        let config = rustbinary::options()
            .reject_trailing_bytes()
            .with_compact_format();
        let mut tree = MerkleTree::new();
        for i in 0..257u64 {
            tree.append(crate::blake3_hash(&i.to_le_bytes()));
        }
        let bytes = config.serialize(&tree).unwrap();
        // Recorded from the original BTreeMap implementation, including all frontier nodes.
        assert_eq!(
            crate::blake3_hash(&bytes).to_string(),
            "e30e8ffe5b84c826c311d73a25b7da514c0c507c627f6439dcb33d745e6584e7"
        );
        let mut reopened: MerkleTree = config.deserialize(&bytes).unwrap();
        let leaf = crate::blake3_hash(b"after reopen");
        tree.append(leaf);
        reopened.append(leaf);
        assert_eq!(tree.root(), reopened.root());
        assert!(reopened.prove(257).unwrap().verify(&leaf, &tree.root()));

        Arc::make_mut(&mut tree.0).count += 1;
        assert!(
            config
                .deserialize::<MerkleTree>(&config.serialize(&tree).unwrap())
                .is_err()
        );
    }

    #[test]
    fn proof_index_must_fit_the_tree_depth() {
        let mut tree = MerkleTree::new();
        let leaf = blake3_hash_many(&[b"output"]);
        tree.append(leaf);
        let mut proof = tree.prove(0).unwrap();
        proof.leaf_index = 1 << MERKLE_DEPTH;
        assert!(!proof.verify(&leaf, &tree.root()));
    }
}
