//! Executable reference model for Hyphen Witness-Carried Expiring State.
//!
//! This module is deliberately not wired into `hyphen-devnet-v2`. It fixes the
//! byte encoding and transition invariants needed to evaluate H-WES without
//! silently changing the existing chain. The authenticated containers favor
//! clarity over production performance; a production implementation may use
//! different storage as long as it reproduces these roots and transitions.

use std::collections::{BTreeMap, BTreeSet};

use hyphen_crypto::Hash256;
use thiserror::Error;

const RECORD_MAGIC: &[u8; 4] = b"HWSR";
const RECORD_ENCODING_VERSION: u8 = 0;
const NO_ARCHIVE_INDEX: u64 = u64::MAX;
const MAX_AUTH_PATH: usize = 64;
const MAX_POLICY_PROOF_BYTES: usize = 64 * 1024;

const D_RECORD: &[u8] = b"HYPHEN_WES_RECORD_V0";
const D_LATEST: &[u8] = b"HYPHEN_WES_LATEST_V0";
const D_LIVE_LEAF: &[u8] = b"HYPHEN_WES_LIVE_LEAF_V0";
const D_LIVE_NODE: &[u8] = b"HYPHEN_WES_LIVE_NODE_V0";
const D_LIVE_EMPTY: &[u8] = b"HYPHEN_WES_LIVE_EMPTY_V0";
const D_LIVE_ROOT: &[u8] = b"HYPHEN_WES_LIVE_ROOT_V0";
const D_LATEST_LEAF: &[u8] = b"HYPHEN_WES_LATEST_LEAF_V0";
const D_LATEST_NODE: &[u8] = b"HYPHEN_WES_LATEST_NODE_V0";
const D_LATEST_EMPTY: &[u8] = b"HYPHEN_WES_LATEST_EMPTY_V0";
const D_LATEST_ROOT: &[u8] = b"HYPHEN_WES_LATEST_ROOT_V0";
const D_NULLIFIER_LEAF: &[u8] = b"HYPHEN_WES_NULLIFIER_LEAF_V0";
const D_NULLIFIER_NODE: &[u8] = b"HYPHEN_WES_NULLIFIER_NODE_V0";
const D_NULLIFIER_EMPTY: &[u8] = b"HYPHEN_WES_NULLIFIER_EMPTY_V0";
const D_NULLIFIER_ROOT: &[u8] = b"HYPHEN_WES_NULLIFIER_ROOT_V0";
const D_NULLIFIER_PRESENT: &[u8] = b"HYPHEN_WES_NULLIFIER_PRESENT_V0";
const D_MMR_LEAF: &[u8] = b"HYPHEN_WES_MMR_LEAF_V0";
const D_MMR_NODE: &[u8] = b"HYPHEN_WES_MMR_NODE_V0";
const D_MMR_ROOT: &[u8] = b"HYPHEN_WES_MMR_ROOT_V0";
const D_STATE_ROOT: &[u8] = b"HYPHEN_STATE_V1";

/// State classes admitted by the first H-WES reference profile.
///
/// Shielded notes are intentionally absent: expiring them safely requires a
/// zero-knowledge relation that binds ownership and nullifier non-membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum StateClass {
    PublicAccount = 1,
    ContractStorage = 2,
    AssetMetadata = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum StateStatus {
    Live = 1,
    Expired = 2,
    Revoked = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRecord {
    pub chain_id: Hash256,
    pub class: StateClass,
    pub key: Hash256,
    pub version: u64,
    pub value_hash: Hash256,
    pub owner_policy: Hash256,
    pub created_at: u64,
    pub lease_end: u64,
    pub status: StateStatus,
}

impl StateRecord {
    /// Canonical, language-neutral encoding. Every integer is unsigned and
    /// big-endian; every other field is fixed width.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(159);
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_ENCODING_VERSION);
        out.extend_from_slice(self.chain_id.as_bytes());
        out.push(self.class as u8);
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(self.value_hash.as_bytes());
        out.extend_from_slice(self.owner_policy.as_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.lease_end.to_be_bytes());
        out.push(self.status as u8);
        out
    }

    pub fn hash(&self) -> Hash256 {
        hash_parts(D_RECORD, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestEntry {
    pub version: u64,
    pub status: StateStatus,
    pub archive_index: Option<u64>,
    pub value_hash: Hash256,
    pub record_hash: Hash256,
}

impl LatestEntry {
    fn hash(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(81);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.push(self.status as u8);
        bytes.extend_from_slice(&self.archive_index.unwrap_or(NO_ARCHIVE_INDEX).to_be_bytes());
        bytes.extend_from_slice(self.value_hash.as_bytes());
        bytes.extend_from_slice(self.record_hash.as_bytes());
        hash_parts(D_LATEST, &[&bytes])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipProof {
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Hash256>,
    pub peaks: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreWitness {
    pub archived_record: StateRecord,
    pub archive_proof: MmrProof,
    pub latest_entry: LatestEntry,
    pub latest_proof: MembershipProof,
    pub owner_proof: Vec<u8>,
    pub availability_proof: Vec<u8>,
}

/// External cryptographic checks that the state model cannot honestly invent.
///
/// A concrete research profile must bind these methods to a specified signature
/// or ZK system and to a specified data-availability certificate format.
pub trait RestorePolicy {
    fn verify_owner(&self, archived: &StateRecord, proof: &[u8]) -> bool;

    fn verify_availability(
        &self,
        restored: &StateRecord,
        availability_root: &Hash256,
        proof: &[u8],
    ) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRoots {
    pub live: Hash256,
    pub latest: Hash256,
    pub nullifiers: Hash256,
    pub archive: Hash256,
    pub availability: Hash256,
}

impl StateRoots {
    pub fn combined(&self) -> Hash256 {
        hash_parts(
            D_STATE_ROOT,
            &[
                self.live.as_bytes(),
                self.latest.as_bytes(),
                self.nullifiers.as_bytes(),
                self.archive.as_bytes(),
                self.availability.as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedRecord {
    pub index: u64,
    pub record: StateRecord,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WesError {
    #[error("record belongs to a different chain")]
    WrongChain,
    #[error("record is not live")]
    NotLive,
    #[error("lease must end after the transition height")]
    InvalidLease,
    #[error("state key already exists")]
    AlreadyExists,
    #[error("initial state version must be zero")]
    InvalidInitialVersion,
    #[error("state key does not exist")]
    NotFound,
    #[error("state version is exhausted")]
    VersionExhausted,
    #[error("restore record is not the current expired version")]
    StaleVersion,
    #[error("invalid archive inclusion proof")]
    InvalidArchiveProof,
    #[error("invalid latest-version proof")]
    InvalidLatestProof,
    #[error("ownership proof rejected")]
    InvalidOwnerProof,
    #[error("data-availability proof rejected")]
    InvalidAvailabilityProof,
    #[error("policy proof exceeds the protocol bound")]
    OversizedPolicyProof,
    #[error("duplicate nullifier")]
    DuplicateNullifier,
}

/// Pure H-WES transition model. It does not persist archived record bodies;
/// only their MMR hashes remain in validator state.
#[derive(Clone, Debug)]
pub struct ReferenceExpiringState {
    chain_id: Hash256,
    live: BTreeMap<Hash256, StateRecord>,
    latest: BTreeMap<Hash256, LatestEntry>,
    expiry_queue: BTreeMap<u64, BTreeSet<Hash256>>,
    archive: ArchiveMmr,
    nullifiers: BTreeSet<Hash256>,
    availability_root: Hash256,
}

impl ReferenceExpiringState {
    pub fn new(chain_id: Hash256, availability_root: Hash256) -> Self {
        Self {
            chain_id,
            live: BTreeMap::new(),
            latest: BTreeMap::new(),
            expiry_queue: BTreeMap::new(),
            archive: ArchiveMmr::default(),
            nullifiers: BTreeSet::new(),
            availability_root,
        }
    }

    pub fn insert_initial(&mut self, record: StateRecord, at_height: u64) -> Result<(), WesError> {
        if record.chain_id != self.chain_id {
            return Err(WesError::WrongChain);
        }
        if record.status != StateStatus::Live {
            return Err(WesError::NotLive);
        }
        if record.version != 0 {
            return Err(WesError::InvalidInitialVersion);
        }
        if record.created_at != at_height || record.lease_end <= at_height {
            return Err(WesError::InvalidLease);
        }
        if self.latest.contains_key(&record.key) {
            return Err(WesError::AlreadyExists);
        }

        let entry = LatestEntry {
            version: record.version,
            status: StateStatus::Live,
            archive_index: None,
            value_hash: record.value_hash,
            record_hash: record.hash(),
        };
        self.expiry_queue
            .entry(record.lease_end)
            .or_default()
            .insert(record.key);
        self.latest.insert(record.key, entry);
        self.live.insert(record.key, record);
        Ok(())
    }

    /// Expires at most `limit` records in canonical `(lease_end, key)` order.
    /// The returned bodies are for storage providers; validator state retains
    /// only their hashes and authenticated metadata.
    pub fn expire_due(&mut self, at_height: u64, limit: usize) -> Vec<ArchivedRecord> {
        let due: Vec<(u64, Hash256)> = self
            .expiry_queue
            .range(..=at_height)
            .flat_map(|(lease, keys)| keys.iter().map(|key| (*lease, *key)))
            .take(limit)
            .collect();
        let mut archived = Vec::with_capacity(due.len());

        for (lease, key) in due {
            let Some(mut record) = self.live.remove(&key) else {
                self.remove_from_expiry_queue(lease, key);
                continue;
            };
            record.status = StateStatus::Expired;
            let record_hash = record.hash();
            let index = self.archive.append(record_hash);
            self.latest.insert(
                key,
                LatestEntry {
                    version: record.version,
                    status: StateStatus::Expired,
                    archive_index: Some(index),
                    value_hash: record.value_hash,
                    record_hash,
                },
            );
            self.remove_from_expiry_queue(lease, key);
            archived.push(ArchivedRecord { index, record });
        }
        archived
    }

    pub fn build_restore_witness(
        &self,
        archived_record: StateRecord,
        archive_index: u64,
        owner_proof: Vec<u8>,
        availability_proof: Vec<u8>,
    ) -> Result<RestoreWitness, WesError> {
        let latest_entry = self
            .latest
            .get(&archived_record.key)
            .cloned()
            .ok_or(WesError::NotFound)?;
        let archive_proof = self
            .archive
            .prove(archive_index)
            .ok_or(WesError::NotFound)?;
        let latest_proof = map_membership_proof(&self.latest_entries(), &archived_record.key)
            .ok_or(WesError::NotFound)?;
        Ok(RestoreWitness {
            archived_record,
            archive_proof,
            latest_entry,
            latest_proof,
            owner_proof,
            availability_proof,
        })
    }

    pub fn verify_restore<P: RestorePolicy>(
        &self,
        at_height: u64,
        new_lease_end: u64,
        witness: &RestoreWitness,
        policy: &P,
    ) -> Result<StateRecord, WesError> {
        verify_restore_witness(
            self.chain_id,
            self.roots(),
            at_height,
            new_lease_end,
            witness,
            policy,
        )
    }

    pub fn apply_restore<P: RestorePolicy>(
        &mut self,
        at_height: u64,
        new_lease_end: u64,
        witness: &RestoreWitness,
        policy: &P,
    ) -> Result<StateRecord, WesError> {
        let restored = self.verify_restore(at_height, new_lease_end, witness, policy)?;
        self.expiry_queue
            .entry(restored.lease_end)
            .or_default()
            .insert(restored.key);
        self.latest.insert(
            restored.key,
            LatestEntry {
                version: restored.version,
                status: StateStatus::Live,
                archive_index: None,
                value_hash: restored.value_hash,
                record_hash: restored.hash(),
            },
        );
        self.live.insert(restored.key, restored.clone());
        Ok(restored)
    }

    pub fn insert_nullifier(&mut self, nullifier: Hash256) -> Result<(), WesError> {
        if !self.nullifiers.insert(nullifier) {
            return Err(WesError::DuplicateNullifier);
        }
        Ok(())
    }

    pub fn contains_nullifier(&self, nullifier: &Hash256) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn roots(&self) -> StateRoots {
        let live = self
            .live
            .iter()
            .map(|(key, record)| (*key, record.hash()))
            .collect::<Vec<_>>();
        let latest = self.latest_entries();
        let present = hash_parts(D_NULLIFIER_PRESENT, &[]);
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|key| (*key, present))
            .collect::<Vec<_>>();
        StateRoots {
            live: map_root(&live, D_LIVE_LEAF, D_LIVE_NODE, D_LIVE_EMPTY, D_LIVE_ROOT),
            latest: map_root(
                &latest,
                D_LATEST_LEAF,
                D_LATEST_NODE,
                D_LATEST_EMPTY,
                D_LATEST_ROOT,
            ),
            nullifiers: map_root(
                &nullifiers,
                D_NULLIFIER_LEAF,
                D_NULLIFIER_NODE,
                D_NULLIFIER_EMPTY,
                D_NULLIFIER_ROOT,
            ),
            archive: self.archive.root(),
            availability: self.availability_root,
        }
    }

    pub fn live_record(&self, key: &Hash256) -> Option<&StateRecord> {
        self.live.get(key)
    }

    fn latest_entries(&self) -> Vec<(Hash256, Hash256)> {
        self.latest
            .iter()
            .map(|(key, entry)| (*key, entry.hash()))
            .collect()
    }

    fn remove_from_expiry_queue(&mut self, lease: u64, key: Hash256) {
        let remove_bucket = if let Some(keys) = self.expiry_queue.get_mut(&lease) {
            keys.remove(&key);
            keys.is_empty()
        } else {
            false
        };
        if remove_bucket {
            self.expiry_queue.remove(&lease);
        }
    }
}

pub fn verify_restore_witness<P: RestorePolicy>(
    chain_id: Hash256,
    roots: StateRoots,
    at_height: u64,
    new_lease_end: u64,
    witness: &RestoreWitness,
    policy: &P,
) -> Result<StateRecord, WesError> {
    let archived = &witness.archived_record;
    if archived.chain_id != chain_id {
        return Err(WesError::WrongChain);
    }
    if archived.status != StateStatus::Expired {
        return Err(WesError::StaleVersion);
    }
    if new_lease_end <= at_height {
        return Err(WesError::InvalidLease);
    }
    if witness.owner_proof.len() > MAX_POLICY_PROOF_BYTES
        || witness.availability_proof.len() > MAX_POLICY_PROOF_BYTES
    {
        return Err(WesError::OversizedPolicyProof);
    }

    let archived_hash = archived.hash();
    if !verify_mmr_proof(archived_hash, &witness.archive_proof, roots.archive) {
        return Err(WesError::InvalidArchiveProof);
    }
    let latest = &witness.latest_entry;
    if latest.version != archived.version
        || latest.status != StateStatus::Expired
        || latest.archive_index != Some(witness.archive_proof.leaf_index)
        || latest.value_hash != archived.value_hash
        || latest.record_hash != archived_hash
    {
        return Err(WesError::StaleVersion);
    }
    if !verify_map_membership(
        archived.key,
        latest.hash(),
        &witness.latest_proof,
        roots.latest,
        D_LATEST_LEAF,
        D_LATEST_NODE,
        D_LATEST_ROOT,
    ) {
        return Err(WesError::InvalidLatestProof);
    }
    if !policy.verify_owner(archived, &witness.owner_proof) {
        return Err(WesError::InvalidOwnerProof);
    }

    let version = archived
        .version
        .checked_add(1)
        .ok_or(WesError::VersionExhausted)?;
    let restored = StateRecord {
        chain_id,
        class: archived.class,
        key: archived.key,
        version,
        value_hash: archived.value_hash,
        owner_policy: archived.owner_policy,
        created_at: at_height,
        lease_end: new_lease_end,
        status: StateStatus::Live,
    };
    if !policy.verify_availability(&restored, &roots.availability, &witness.availability_proof) {
        return Err(WesError::InvalidAvailabilityProof);
    }
    Ok(restored)
}

#[derive(Clone, Debug, Default)]
struct ArchiveMmr {
    leaves: Vec<Hash256>,
}

impl ArchiveMmr {
    fn append(&mut self, record_hash: Hash256) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(record_hash);
        index
    }

    fn root(&self) -> Hash256 {
        let peaks = mmr_peaks(&self.leaves);
        bag_mmr_peaks(self.leaves.len() as u64, &peaks)
    }

    fn prove(&self, leaf_index: u64) -> Option<MmrProof> {
        let index = usize::try_from(leaf_index).ok()?;
        if index >= self.leaves.len() {
            return None;
        }
        let leaf_hashes = self
            .leaves
            .iter()
            .map(|leaf| hash_parts(D_MMR_LEAF, &[leaf.as_bytes()]))
            .collect::<Vec<_>>();
        let sizes = mountain_sizes(leaf_hashes.len());
        let mut start = 0;
        let mut siblings = None;
        let mut peaks = Vec::with_capacity(sizes.len());
        for size in sizes {
            let local = index.checked_sub(start).filter(|local| *local < size);
            let (root, path) =
                perfect_tree_root_and_path(&leaf_hashes[start..start + size], local, D_MMR_NODE);
            peaks.push(root);
            if local.is_some() {
                siblings = path;
            }
            start += size;
        }
        Some(MmrProof {
            leaf_index,
            leaf_count: self.leaves.len() as u64,
            siblings: siblings?,
            peaks,
        })
    }
}

fn verify_mmr_proof(record_hash: Hash256, proof: &MmrProof, expected_root: Hash256) -> bool {
    if proof.leaf_count == 0
        || proof.leaf_index >= proof.leaf_count
        || proof.siblings.len() > MAX_AUTH_PATH
    {
        return false;
    }
    let Ok(count) = usize::try_from(proof.leaf_count) else {
        return false;
    };
    let Ok(index) = usize::try_from(proof.leaf_index) else {
        return false;
    };
    let sizes = mountain_sizes(count);
    if sizes.len() != proof.peaks.len() {
        return false;
    }
    let mut start = 0;
    let mut selected = None;
    for (peak_index, size) in sizes.iter().copied().enumerate() {
        if index >= start && index < start + size {
            selected = Some((peak_index, start, size));
            break;
        }
        start += size;
    }
    let Some((peak_index, start, size)) = selected else {
        return false;
    };
    let height = size.trailing_zeros() as usize;
    if proof.siblings.len() != height {
        return false;
    }

    let mut node = hash_parts(D_MMR_LEAF, &[record_hash.as_bytes()]);
    let mut local = index - start;
    for (level, sibling) in proof.siblings.iter().enumerate() {
        node = if local & 1 == 0 {
            tree_node_hash(D_MMR_NODE, level + 1, node, *sibling)
        } else {
            tree_node_hash(D_MMR_NODE, level + 1, *sibling, node)
        };
        local >>= 1;
    }
    if proof.peaks[peak_index] != node {
        return false;
    }
    bag_mmr_peaks(proof.leaf_count, &proof.peaks) == expected_root
}

fn mmr_peaks(leaves: &[Hash256]) -> Vec<Hash256> {
    let leaf_hashes = leaves
        .iter()
        .map(|leaf| hash_parts(D_MMR_LEAF, &[leaf.as_bytes()]))
        .collect::<Vec<_>>();
    let mut peaks = Vec::new();
    let mut start = 0;
    for size in mountain_sizes(leaf_hashes.len()) {
        peaks.push(
            perfect_tree_root_and_path(&leaf_hashes[start..start + size], None, D_MMR_NODE).0,
        );
        start += size;
    }
    peaks
}

fn mountain_sizes(count: usize) -> Vec<usize> {
    if count == 0 {
        return Vec::new();
    }
    let mut bit = 1usize << (usize::BITS - count.leading_zeros() - 1);
    let mut sizes = Vec::new();
    while bit != 0 {
        if count & bit != 0 {
            sizes.push(bit);
        }
        bit >>= 1;
    }
    sizes
}

fn bag_mmr_peaks(leaf_count: u64, peaks: &[Hash256]) -> Hash256 {
    let mut bytes = Vec::with_capacity(10 + peaks.len() * 32);
    bytes.extend_from_slice(&leaf_count.to_be_bytes());
    bytes.extend_from_slice(&(peaks.len() as u16).to_be_bytes());
    for peak in peaks {
        bytes.extend_from_slice(peak.as_bytes());
    }
    hash_parts(D_MMR_ROOT, &[&bytes])
}

fn map_membership_proof(entries: &[(Hash256, Hash256)], key: &Hash256) -> Option<MembershipProof> {
    let index = entries
        .binary_search_by_key(key, |(entry_key, _)| *entry_key)
        .ok()?;
    let leaves = map_leaves(entries, D_LATEST_LEAF, D_LATEST_EMPTY);
    let (_, path) = perfect_tree_root_and_path(&leaves, Some(index), D_LATEST_NODE);
    Some(MembershipProof {
        index: index as u64,
        leaf_count: entries.len() as u64,
        siblings: path?,
    })
}

fn verify_map_membership(
    key: Hash256,
    value_hash: Hash256,
    proof: &MembershipProof,
    expected_root: Hash256,
    leaf_domain: &[u8],
    node_domain: &[u8],
    root_domain: &[u8],
) -> bool {
    if proof.leaf_count == 0
        || proof.index >= proof.leaf_count
        || proof.siblings.len() > MAX_AUTH_PATH
    {
        return false;
    }
    let Some(capacity) = proof.leaf_count.checked_next_power_of_two() else {
        return false;
    };
    let expected_height = capacity.trailing_zeros() as usize;
    if proof.siblings.len() != expected_height {
        return false;
    }
    let mut node = hash_parts(leaf_domain, &[key.as_bytes(), value_hash.as_bytes()]);
    let mut index = proof.index;
    for (level, sibling) in proof.siblings.iter().enumerate() {
        node = if index & 1 == 0 {
            tree_node_hash(node_domain, level + 1, node, *sibling)
        } else {
            tree_node_hash(node_domain, level + 1, *sibling, node)
        };
        index >>= 1;
    }
    map_root_from_tree(proof.leaf_count, node, root_domain) == expected_root
}

fn map_root(
    entries: &[(Hash256, Hash256)],
    leaf_domain: &[u8],
    node_domain: &[u8],
    empty_domain: &[u8],
    root_domain: &[u8],
) -> Hash256 {
    let leaves = map_leaves(entries, leaf_domain, empty_domain);
    let tree_root = perfect_tree_root_and_path(&leaves, None, node_domain).0;
    map_root_from_tree(entries.len() as u64, tree_root, root_domain)
}

fn map_leaves(
    entries: &[(Hash256, Hash256)],
    leaf_domain: &[u8],
    empty_domain: &[u8],
) -> Vec<Hash256> {
    let capacity = entries.len().max(1).next_power_of_two();
    let mut leaves = entries
        .iter()
        .map(|(key, value)| hash_parts(leaf_domain, &[key.as_bytes(), value.as_bytes()]))
        .collect::<Vec<_>>();
    leaves.resize(capacity, hash_parts(empty_domain, &[]));
    leaves
}

fn map_root_from_tree(leaf_count: u64, tree_root: Hash256, root_domain: &[u8]) -> Hash256 {
    hash_parts(
        root_domain,
        &[&leaf_count.to_be_bytes(), tree_root.as_bytes()],
    )
}

fn perfect_tree_root_and_path(
    leaves: &[Hash256],
    selected: Option<usize>,
    node_domain: &[u8],
) -> (Hash256, Option<Vec<Hash256>>) {
    debug_assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut nodes = leaves.to_vec();
    let mut index = selected;
    let mut path = selected.map(|_| Vec::new());
    let mut level = 1;
    while nodes.len() > 1 {
        if let (Some(current), Some(siblings)) = (index, path.as_mut()) {
            siblings.push(nodes[current ^ 1]);
            index = Some(current / 2);
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| tree_node_hash(node_domain, level, pair[0], pair[1]))
            .collect();
        level += 1;
    }
    (nodes[0], path)
}

fn tree_node_hash(domain: &[u8], level: usize, left: Hash256, right: Hash256) -> Hash256 {
    hash_parts(
        domain,
        &[
            &(level as u16).to_be_bytes(),
            left.as_bytes(),
            right.as_bytes(),
        ],
    )
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExactPolicy;

    impl RestorePolicy for ExactPolicy {
        fn verify_owner(&self, archived: &StateRecord, proof: &[u8]) -> bool {
            proof == archived.owner_policy.as_bytes()
        }

        fn verify_availability(
            &self,
            restored: &StateRecord,
            availability_root: &Hash256,
            proof: &[u8],
        ) -> bool {
            proof
                == hash_parts(
                    b"HYPHEN_WES_TEST_DA_V0",
                    &[restored.hash().as_bytes(), availability_root.as_bytes()],
                )
                .as_bytes()
        }
    }

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn live_record(key: u8, lease_end: u64) -> StateRecord {
        StateRecord {
            chain_id: hash(0x11),
            class: StateClass::ContractStorage,
            key: hash(key),
            version: 0,
            value_hash: hash(key.wrapping_add(1)),
            owner_policy: hash(key.wrapping_add(2)),
            created_at: 10,
            lease_end,
            status: StateStatus::Live,
        }
    }

    fn restore_witness(
        state: &ReferenceExpiringState,
        archived: &ArchivedRecord,
        at_height: u64,
        new_lease_end: u64,
    ) -> RestoreWitness {
        let mut witness = state
            .build_restore_witness(
                archived.record.clone(),
                archived.index,
                archived.record.owner_policy.as_bytes().to_vec(),
                Vec::new(),
            )
            .expect("witness must exist");
        let restored = StateRecord {
            chain_id: archived.record.chain_id,
            class: archived.record.class,
            key: archived.record.key,
            version: archived.record.version + 1,
            value_hash: archived.record.value_hash,
            owner_policy: archived.record.owner_policy,
            created_at: at_height,
            lease_end: new_lease_end,
            status: StateStatus::Live,
        };
        witness.availability_proof = hash_parts(
            b"HYPHEN_WES_TEST_DA_V0",
            &[
                restored.hash().as_bytes(),
                state.roots().availability.as_bytes(),
            ],
        )
        .to_vec();
        witness
    }

    #[test]
    fn canonical_record_encoding_is_fixed_width_and_big_endian() {
        let record = live_record(0x22, 0x0102_0304_0506_0708);
        let bytes = record.canonical_bytes();
        assert_eq!(bytes.len(), 159);
        assert_eq!(&bytes[..5], b"HWSR\0");
        assert_eq!(&bytes[70..78], &[0; 8]);
        assert_eq!(&bytes[150..158], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(bytes[158], StateStatus::Live as u8);
    }

    #[test]
    fn expiry_order_and_limit_are_deterministic() {
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        state.insert_initial(live_record(3, 20), 10).unwrap();
        state.insert_initial(live_record(1, 20), 10).unwrap();
        state.insert_initial(live_record(2, 19), 10).unwrap();

        let first = state.expire_due(20, 2);
        assert_eq!(
            first.iter().map(|r| r.record.key).collect::<Vec<_>>(),
            vec![hash(2), hash(1)]
        );
        assert!(state.live_record(&hash(3)).is_some());
        assert_eq!(state.expire_due(20, 2)[0].record.key, hash(3));
    }

    #[test]
    fn mmr_proves_every_leaf_across_non_power_of_two_sizes() {
        let mut mmr = ArchiveMmr::default();
        for count in 1..=65u8 {
            mmr.append(hash(count));
            let root = mmr.root();
            for index in 0..count as u64 {
                let proof = mmr.prove(index).unwrap();
                assert!(verify_mmr_proof(hash(index as u8 + 1), &proof, root));
            }
        }
    }

    #[test]
    fn valid_expired_record_restores_with_incremented_version() {
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        state.insert_initial(live_record(7, 20), 10).unwrap();
        let archived = state.expire_due(20, 1).remove(0);
        let witness = restore_witness(&state, &archived, 21, 40);

        let restored = state
            .apply_restore(21, 40, &witness, &ExactPolicy)
            .expect("valid witness must restore");
        assert_eq!(restored.version, 1);
        assert_eq!(restored.status, StateStatus::Live);
        assert_eq!(state.live_record(&hash(7)), Some(&restored));
    }

    #[test]
    fn stale_archive_leaf_cannot_replace_a_newer_version() {
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        state.insert_initial(live_record(7, 20), 10).unwrap();
        let old = state.expire_due(20, 1).remove(0);
        let first_witness = restore_witness(&state, &old, 21, 30);
        state
            .apply_restore(21, 30, &first_witness, &ExactPolicy)
            .unwrap();
        let _new = state.expire_due(30, 1).remove(0);

        assert_eq!(
            state.verify_restore(31, 50, &first_witness, &ExactPolicy),
            Err(WesError::InvalidArchiveProof)
        );
    }

    #[test]
    fn tampered_archive_owner_and_availability_proofs_are_rejected() {
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        state.insert_initial(live_record(7, 20), 10).unwrap();
        let archived = state.expire_due(20, 1).remove(0);
        let witness = restore_witness(&state, &archived, 21, 40);

        let mut bad_archive = witness.clone();
        bad_archive.archived_record.value_hash = hash(0xee);
        assert_eq!(
            state.verify_restore(21, 40, &bad_archive, &ExactPolicy),
            Err(WesError::InvalidArchiveProof)
        );

        let mut bad_owner = witness.clone();
        bad_owner.owner_proof[0] ^= 1;
        assert_eq!(
            state.verify_restore(21, 40, &bad_owner, &ExactPolicy),
            Err(WesError::InvalidOwnerProof)
        );

        let mut bad_da = witness;
        bad_da.availability_proof[0] ^= 1;
        assert_eq!(
            state.verify_restore(21, 40, &bad_da, &ExactPolicy),
            Err(WesError::InvalidAvailabilityProof)
        );
    }

    #[test]
    fn nullifiers_are_monotonic_and_duplicates_fail() {
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        let nullifier = hash(0x55);
        let before = state.roots().nullifiers;
        state.insert_nullifier(nullifier).unwrap();
        assert!(state.contains_nullifier(&nullifier));
        assert_ne!(state.roots().nullifiers, before);
        assert_eq!(
            state.insert_nullifier(nullifier),
            Err(WesError::DuplicateNullifier)
        );
    }

    #[test]
    fn reference_vector_is_stable() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/h-wes-v0.json")).unwrap();
        assert_eq!(vector["schema"], "hyphen-h-wes-vector-v0");
        let mut state = ReferenceExpiringState::new(hash(0x11), hash(0xaa));
        let record = live_record(7, 20);
        state.insert_initial(record.clone(), 10).unwrap();
        let initial = state.roots();
        let archived = state.expire_due(20, 1).remove(0);
        let expired = state.roots();
        assert_eq!(
            hex::encode(record.canonical_bytes()),
            vector["record"]["canonical_encoding"].as_str().unwrap()
        );
        assert_eq!(
            record.hash().to_string(),
            vector["record"]["record_hash"].as_str().unwrap()
        );
        assert_eq!(
            initial.combined().to_string(),
            vector["initial_combined_state_root"].as_str().unwrap()
        );
        assert_eq!(
            archived.record.hash().to_string(),
            vector["expired_record_hash"].as_str().unwrap()
        );
        assert_eq!(
            expired.combined().to_string(),
            vector["expired_combined_state_root"].as_str().unwrap()
        );
    }
}
