use serde::{Deserialize, Serialize};
use crate::hash::{blake3_hash_many, Hash256};

pub const MERKLE_DEPTH: usize = 32;

fn empty_hashes() -> [Hash256; MERKLE_DEPTH + 1] {
    let mut e = [Hash256::ZERO; MERKLE_DEPTH + 1];
    e[0] = blake3_hash_many(&[b"Hyphen_empty_leaf"]);
    for i in 1..=MERKLE_DEPTH {
        e[i] = blake3_hash_many(&[e[i - 1].as_bytes(), e[i - 1].as_bytes()]);
    }
    e
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<Hash256>, // length == MERKLE_DEPTH
}

impl MerkleProof {
    pub fn verify(&self, leaf: &Hash256, root: &Hash256) -> bool {
        if self.siblings.len() != MERKLE_DEPTH {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTree {
    count: u64,
    frontier: Vec<Option<Hash256>>,
    root: Hash256,
    filled: std::collections::BTreeMap<(usize, u64), Hash256>,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        let empties = empty_hashes();
        Self {
            count: 0,
            frontier: vec![None; MERKLE_DEPTH],
            root: empties[MERKLE_DEPTH],
            filled: std::collections::BTreeMap::new(),
        }
    }

    pub fn root(&self) -> Hash256 {
        self.root
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    #[allow(clippy::needless_range_loop)]
    pub fn append(&mut self, leaf: Hash256) -> u64 {
        let idx = self.count;
        self.count += 1;

        let empties = empty_hashes();
        let mut cur = leaf;
        let mut pos = idx;

        for level in 0..MERKLE_DEPTH {
            // Store node for proof sibling lookups
            self.filled.insert((level, pos), cur);

            if pos & 1 == 0 {
                // left child waiting at this level
                self.frontier[level] = Some(cur);
                cur = blake3_hash_many(&[cur.as_bytes(), empties[level].as_bytes()]);
                pos >>= 1;
                // root path update
                for ll in (level + 1)..MERKLE_DEPTH {
                    cur = if (pos & 1) == 0 {
                        blake3_hash_many(&[cur.as_bytes(), empties[ll].as_bytes()])
                    } else {
                        let left = self.frontier[ll].unwrap_or(empties[ll]);
                        blake3_hash_many(&[left.as_bytes(), cur.as_bytes()])
                    };
                    pos >>= 1;
                }
                self.root = cur;
                return idx;
            } else {
                // right child: complete level
                let left = self.frontier[level].unwrap_or(empties[level]);
                cur = blake3_hash_many(&[left.as_bytes(), cur.as_bytes()]);
                self.frontier[level] = None;
                pos >>= 1;
            }
        }
        self.root = cur;
        idx
    }

    #[allow(clippy::needless_range_loop)]
    pub fn prove(&self, leaf_index: u64) -> Option<MerkleProof> {
        if leaf_index >= self.count {
            return None;
        }
        let empties = empty_hashes();
        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
        let mut pos = leaf_index;

        for level in 0..MERKLE_DEPTH {
            let sib_pos = pos ^ 1;
            let sib = self
                .filled
                .get(&(level, sib_pos))
                .copied()
                .unwrap_or(empties[level]);
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
            assert!(proof.verify(leaf, &tree.root()), "proof failed for leaf {i}");
        }
    }
}
