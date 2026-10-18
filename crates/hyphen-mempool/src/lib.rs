//! Transaction admission pool for Hyphen.
//!
//! The pool is policy-only. Consensus validation happens before a [`Validated`]
//! or [`ValidatedProtocol`] token can be produced; the pool never re-validates
//! signatures or proofs. What it does own is bounded, deterministic admission:
//! fee and byte budgets, key-image conflict detection, replacement rules,
//! protocol-transaction isolation, and eviction of the least valuable payment
//! transaction when capacity is exhausted.
//!
//! The crate is `no_std + alloc`. It uses ordered collections throughout so
//! admission, eviction, and block-template selection are reproducible on every
//! platform and do not depend on a hasher seed.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use hyphen_crypto::Hash256;
use hyphen_tx::transaction::{Transaction, MAX_TRANSACTION_SIZE};

/// Default number of entries (payments plus protocol transactions).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
/// Default aggregate byte ceiling for the pool.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Highest VRE quality score the consensus validator emits.
pub const MAX_VRE_QUALITY: i64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolError {
    /// The exact transaction is already present.
    Duplicate,
    /// The pool cannot make room without evicting a better payment.
    Full,
    /// The protocol sub-pool or the aggregate byte budget is exhausted.
    ProtocolFull,
    /// An input spends a key image already spent by another pool transaction.
    DoubleSpend,
    /// The transaction does not pay the configured relay fee.
    FeeTooLow,
    /// A replacement does not improve on every transaction it displaces.
    ReplacementFeeTooLow,
    /// The serialised transaction or protocol payload exceeds the per-item cap.
    TooLarge,
    /// The transaction cannot be admitted for a structural policy reason.
    Invalid(&'static str),
}

impl fmt::Display for MempoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate => f.write_str("transaction already in mempool"),
            Self::Full => f.write_str("mempool full"),
            Self::ProtocolFull => f.write_str("mempool protocol capacity exhausted"),
            Self::DoubleSpend => f.write_str("double-spend: key image already in mempool"),
            Self::FeeTooLow => f.write_str("fee too low"),
            Self::ReplacementFeeTooLow => f.write_str("replacement fee too low"),
            Self::TooLarge => f.write_str("transaction exceeds the mempool size limit"),
            Self::Invalid(reason) => write!(f, "invalid pool transaction: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MempoolError {}

pub type Result<T> = core::result::Result<T, MempoolError>;

/// Proof that full consensus validation has been performed.
///
/// Callers MUST execute CLSAG + TERA + MD-VRE + balance + range-proof
/// validation before constructing this token. The mempool refuses transactions
/// without it, but cannot verify that claim itself.
#[derive(Clone, Copy, Debug)]
#[must_use = "validation proofs are consumed by Mempool::insert"]
pub struct Validated {
    vre_quality: i64,
}

impl Validated {
    /// Create a validation proof carrying the VRE quality score (0–10 000).
    /// Values outside the consensus range are clamped rather than trusted.
    pub fn new(vre_quality: i64) -> Self {
        Self {
            vre_quality: vre_quality.clamp(0, MAX_VRE_QUALITY),
        }
    }

    pub fn vre_quality(self) -> i64 {
        self.vre_quality
    }
}

/// Proof that a non-payment protocol transaction was checked by the canonical
/// chain state machine at the next height.
#[derive(Clone, Copy, Debug, Default)]
#[must_use = "validation proofs are consumed by Mempool::insert_protocol"]
pub struct ValidatedProtocol(());

impl ValidatedProtocol {
    pub fn new() -> Self {
        Self(())
    }
}

/// Static admission policy. The defaults are deliberately permissive about the
/// absolute fee so a devnet can submit zero-fee transactions; deployments set
/// `min_fee` / `min_fee_per_byte` to their relay policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_protocol_entries: usize,
    pub max_protocol_bytes: usize,
    pub max_tx_bytes: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    /// Absolute minimum fee, in the chain's base unit.
    pub min_fee: u64,
    /// Minimum fee per serialised byte, in the chain's base unit.
    pub min_fee_per_byte: u64,
    /// Extra fee, in basis points of the displaced total, a replacement must
    /// pay on top of matching the displaced transactions.
    pub replacement_bump_bps: u16,
    /// Maximum age of an entry that carried an arrival timestamp. Zero
    /// disables expiry; entries admitted through the timestamp-free methods
    /// never expire.
    pub max_entry_age_ms: u64,
}

impl MempoolConfig {
    pub fn new(max_entries: usize) -> Self {
        let max_bytes = max_entries
            .saturating_mul(8 * 1024)
            .clamp(MAX_TRANSACTION_SIZE, DEFAULT_MAX_BYTES);
        let max_protocol_entries = (max_entries / 4).max(usize::from(max_entries > 0));
        let max_protocol_bytes = (max_bytes / 4).max(max_bytes.min(MAX_TRANSACTION_SIZE));
        Self {
            max_entries,
            max_bytes,
            max_protocol_entries,
            max_protocol_bytes,
            max_tx_bytes: MAX_TRANSACTION_SIZE,
            max_inputs: 1_024,
            max_outputs: 4_096,
            min_fee: 0,
            min_fee_per_byte: 0,
            replacement_bump_bps: 1_000,
            max_entry_age_ms: 0,
        }
    }

    pub fn with_minimum_fee(mut self, min_fee: u64, min_fee_per_byte: u64) -> Self {
        self.min_fee = min_fee;
        self.min_fee_per_byte = min_fee_per_byte;
        self
    }

    pub fn with_limits(mut self, max_entries: usize, max_bytes: usize) -> Self {
        self.max_entries = max_entries;
        self.max_bytes = max_bytes;
        self
    }

    pub fn with_protocol_limits(mut self, max_entries: usize, max_bytes: usize) -> Self {
        self.max_protocol_entries = max_entries;
        self.max_protocol_bytes = max_bytes;
        self
    }

    pub fn with_replacement_bump_bps(mut self, bump_bps: u16) -> Self {
        self.replacement_bump_bps = bump_bps;
        self
    }

    pub fn with_max_entry_age(mut self, max_entry_age_ms: u64) -> Self {
        self.max_entry_age_ms = max_entry_age_ms;
        self
    }

    /// Clamp fields that would otherwise make admission behave in a way the
    /// caller did not intend (a per-item cap above the aggregate cap, a
    /// protocol sub-pool larger than the pool, a zero input limit).
    pub fn normalized(mut self) -> Self {
        self.max_protocol_entries = self.max_protocol_entries.min(self.max_entries);
        self.max_protocol_bytes = self.max_protocol_bytes.min(self.max_bytes);
        self.max_tx_bytes = self
            .max_tx_bytes
            .min(self.max_bytes)
            .max(usize::from(self.max_bytes > 0));
        self.max_inputs = self.max_inputs.max(1);
        self.max_outputs = self.max_outputs.max(1);
        self
    }

    /// Strict form of [`Self::normalized`] for configuration files and tests.
    pub fn validate(&self) -> core::result::Result<(), &'static str> {
        if self.max_tx_bytes > self.max_bytes {
            return Err("max_tx_bytes exceeds max_bytes");
        }
        if self.max_protocol_entries > self.max_entries {
            return Err("max_protocol_entries exceeds max_entries");
        }
        if self.max_protocol_bytes > self.max_bytes {
            return Err("max_protocol_bytes exceeds max_bytes");
        }
        if self.max_inputs == 0 {
            return Err("max_inputs must be positive");
        }
        if self.max_outputs == 0 {
            return Err("max_outputs must be positive");
        }
        Ok(())
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

/// Fee density in units of `fee * 1_000_000 / bytes`, so small transactions
/// cannot win priority merely because integer division truncated their rate.
#[inline]
fn fee_density(fee: u64, serialised_size: usize) -> u128 {
    (fee as u128)
        .saturating_mul(1_000_000)
        .checked_div(serialised_size.max(1) as u128)
        .unwrap_or(0)
}

/// Eviction order. Lower values are worse. Fee density dominates, VRE quality
/// breaks ties in favour of better ring entropy, and the hash makes the order
/// total so two nodes always choose the same victim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Priority {
    fee_density: u128,
    vre_quality: i64,
    tx_hash: Hash256,
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.fee_density
            .cmp(&other.fee_density)
            .then_with(|| self.vre_quality.cmp(&other.vre_quality))
            .then_with(|| self.tx_hash.cmp(&other.tx_hash))
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct PoolEntry {
    tx: Transaction,
    serialised_size: usize,
    fee: u64,
    priority: Priority,
    inserted_at_ms: u64,
}

struct ProtocolEntry {
    payload: Vec<u8>,
    inserted_at_ms: u64,
}

/// Bounded transaction pool.
pub struct Mempool {
    config: MempoolConfig,
    entries: BTreeMap<Hash256, PoolEntry>,
    by_priority: BTreeMap<Priority, Hash256>,
    key_images: BTreeMap<[u8; 32], Hash256>,
    protocol_entries: BTreeMap<Hash256, ProtocolEntry>,
    total_bytes: usize,
    protocol_bytes: usize,
    total_fees: u64,
}

/// Snapshot of pool occupancy. Cheap enough to compute on every RPC poll.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MempoolStats {
    pub transactions: usize,
    pub payment_transactions: usize,
    pub protocol_transactions: usize,
    pub bytes: usize,
    pub payment_bytes: usize,
    pub protocol_bytes: usize,
    pub key_images: usize,
    pub total_fees: u64,
}

impl Mempool {
    pub fn new(max_entries: usize) -> Self {
        Self::with_config(MempoolConfig::new(max_entries))
    }

    pub fn with_config(config: MempoolConfig) -> Self {
        // Aggregate limits are load-bearing: a per-item cap above the pool cap
        // or a protocol sub-pool larger than the pool would make admission
        // depend on field order rather than policy.
        let config = config.normalized();
        Self {
            config,
            entries: BTreeMap::new(),
            by_priority: BTreeMap::new(),
            key_images: BTreeMap::new(),
            protocol_entries: BTreeMap::new(),
            total_bytes: 0,
            protocol_bytes: 0,
            total_fees: 0,
        }
    }

    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    pub fn len(&self) -> usize {
        self.entries.len() + self.protocol_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.protocol_entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn stats(&self) -> MempoolStats {
        MempoolStats {
            transactions: self.len(),
            payment_transactions: self.entries.len(),
            protocol_transactions: self.protocol_entries.len(),
            bytes: self.total_bytes,
            payment_bytes: self.total_bytes.saturating_sub(self.protocol_bytes),
            protocol_bytes: self.protocol_bytes,
            key_images: self.key_images.len(),
            total_fees: self.total_fees,
        }
    }

    pub fn contains(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash) || self.protocol_entries.contains_key(hash)
    }

    pub fn get(&self, hash: &Hash256) -> Option<&Transaction> {
        self.entries.get(hash).map(|entry| &entry.tx)
    }

    pub fn get_protocol(&self, hash: &Hash256) -> Option<&[u8]> {
        self.protocol_entries
            .get(hash)
            .map(|entry| entry.payload.as_slice())
    }

    pub fn has_key_image(&self, key_image: &[u8; 32]) -> bool {
        self.key_images.contains_key(key_image)
    }

    /// Admit a consensus-validated payment transaction.
    pub fn insert(&mut self, tx: Transaction, proof: Validated) -> Result<Hash256> {
        self.insert_internal(tx, proof, 0)
    }

    /// Admit a payment transaction and record its arrival time for expiry.
    pub fn insert_at(&mut self, tx: Transaction, proof: Validated, now_ms: u64) -> Result<Hash256> {
        self.insert_internal(tx, proof, now_ms)
    }

    fn insert_internal(
        &mut self,
        tx: Transaction,
        proof: Validated,
        now_ms: u64,
    ) -> Result<Hash256> {
        self.validate_payment_shape(&tx)?;

        let raw = tx.serialise();
        if raw.is_empty()
            || raw.len() > self.config.max_tx_bytes
            || raw.len() > MAX_TRANSACTION_SIZE
        {
            return Err(MempoolError::TooLarge);
        }

        let tx_hash = hyphen_crypto::blake3_hash(&raw);
        if self.contains(&tx_hash) {
            return Err(MempoolError::Duplicate);
        }

        let serialised_size = raw.len();
        let fee = tx.fee;
        if fee < self.minimum_fee(serialised_size) {
            return Err(MempoolError::FeeTooLow);
        }

        let mut key_images = Vec::with_capacity(tx.inputs.len());
        let mut unique = BTreeSet::new();
        for input in &tx.inputs {
            if !unique.insert(input.key_image) {
                return Err(MempoolError::DoubleSpend);
            }
            key_images.push(input.key_image);
        }

        let priority = Priority {
            fee_density: fee_density(fee, serialised_size),
            vre_quality: proof.vre_quality,
            tx_hash,
        };

        let mut conflicts = BTreeSet::new();
        for key_image in &key_images {
            if let Some(conflicting) = self.key_images.get(key_image) {
                if self.entries.contains_key(conflicting) {
                    conflicts.insert(*conflicting);
                }
            }
        }
        self.check_replacement(fee, priority, &conflicts)?;

        let additional = self.plan_payment_capacity(serialised_size, priority, &conflicts)?;

        for hash in &conflicts {
            self.remove_internal(hash);
        }
        for hash in &additional {
            self.remove_internal(hash);
        }

        for key_image in key_images {
            self.key_images.insert(key_image, tx_hash);
        }
        self.by_priority.insert(priority, tx_hash);
        self.total_bytes = self.total_bytes.saturating_add(serialised_size);
        self.total_fees = self.total_fees.saturating_add(fee);
        self.entries.insert(
            tx_hash,
            PoolEntry {
                tx,
                serialised_size,
                fee,
                priority,
                inserted_at_ms: now_ms,
            },
        );

        Ok(tx_hash)
    }

    /// Admit a consensus-validated non-payment payload.
    ///
    /// Protocol transactions carry no fee metadata in this API, so they have a
    /// dedicated cap and may displace the worst payment transaction only when
    /// the aggregate pool is full. They never consume the payment fee index.
    pub fn insert_protocol(
        &mut self,
        payload: Vec<u8>,
        proof: ValidatedProtocol,
    ) -> Result<Hash256> {
        self.insert_protocol_internal(payload, proof, 0)
    }

    /// Admit a protocol payload and record its arrival time for expiry.
    pub fn insert_protocol_at(
        &mut self,
        payload: Vec<u8>,
        proof: ValidatedProtocol,
        now_ms: u64,
    ) -> Result<Hash256> {
        self.insert_protocol_internal(payload, proof, now_ms)
    }

    fn insert_protocol_internal(
        &mut self,
        payload: Vec<u8>,
        _proof: ValidatedProtocol,
        now_ms: u64,
    ) -> Result<Hash256> {
        if payload.is_empty() {
            return Err(MempoolError::Invalid("empty protocol payload"));
        }
        if payload.len() > self.config.max_tx_bytes {
            return Err(MempoolError::TooLarge);
        }

        let hash = hyphen_crypto::blake3_hash(&payload);
        if self.contains(&hash) {
            return Err(MempoolError::Duplicate);
        }

        if self.protocol_entries.len().saturating_add(1) > self.config.max_protocol_entries
            || self.protocol_bytes.saturating_add(payload.len()) > self.config.max_protocol_bytes
        {
            return Err(MempoolError::ProtocolFull);
        }

        let evictions = self.plan_protocol_capacity(payload.len())?;
        for hash in &evictions {
            self.remove_internal(hash);
        }

        self.protocol_bytes = self.protocol_bytes.saturating_add(payload.len());
        self.total_bytes = self.total_bytes.saturating_add(payload.len());
        self.protocol_entries.insert(
            hash,
            ProtocolEntry {
                payload,
                inserted_at_ms: now_ms,
            },
        );
        Ok(hash)
    }

    /// Remove a payment transaction, returning it when it was present.
    pub fn take(&mut self, hash: &Hash256) -> Option<Transaction> {
        self.remove_internal(hash)
    }

    pub fn remove(&mut self, hash: &Hash256) {
        self.remove_internal(hash);
    }

    pub fn remove_protocol(&mut self, hash: &Hash256) -> Option<Vec<u8>> {
        let entry = self.protocol_entries.remove(hash)?;
        let size = entry.payload.len();
        self.protocol_bytes = self.protocol_bytes.saturating_sub(size);
        self.total_bytes = self.total_bytes.saturating_sub(size);
        Some(entry.payload)
    }

    /// Best-first payment candidates that fit in `max_size`.
    pub fn get_block_candidates(&self, max_size: usize) -> Vec<&Transaction> {
        let mut result = Vec::new();
        let mut total_size = 0usize;
        for tx_hash in self.by_priority.values().rev() {
            let Some(entry) = self.entries.get(tx_hash) else {
                continue;
            };
            let next = total_size.saturating_add(entry.serialised_size);
            if next > max_size {
                continue;
            }
            total_size = next;
            result.push(&entry.tx);
        }
        result
    }

    /// Canonical bytes for block assembly. Payment transactions are emitted
    /// best-first; protocol payloads follow in hash order. The block builder
    /// applies its own canonical transaction ordering before committing.
    pub fn get_block_candidate_blobs(&self, max_size: usize) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut total_size = 0usize;

        for tx_hash in self.by_priority.values().rev() {
            let Some(entry) = self.entries.get(tx_hash) else {
                continue;
            };
            let next = total_size.saturating_add(entry.serialised_size);
            if next > max_size {
                continue;
            }
            total_size = next;
            result.push(entry.tx.serialise());
        }

        for entry in self.protocol_entries.values() {
            let next = total_size.saturating_add(entry.payload.len());
            if next > max_size {
                continue;
            }
            total_size = next;
            result.push(entry.payload.clone());
        }

        result
    }

    /// Drop every payment transaction spending any of the confirmed key images.
    pub fn purge_confirmed(&mut self, key_images: &[[u8; 32]]) {
        let mut removed = BTreeSet::new();
        for key_image in key_images {
            if let Some(hash) = self.key_images.get(key_image).copied() {
                if removed.insert(hash) {
                    self.remove_internal(&hash);
                }
            }
        }
    }

    pub fn purge_confirmed_protocol(&mut self, transaction_hashes: &[Hash256]) {
        for hash in transaction_hashes {
            self.remove_protocol(hash);
        }
    }

    /// Drop timestamped entries older than the configured maximum age.
    ///
    /// Entries admitted through [`Mempool::insert`] or
    /// [`Mempool::insert_protocol`] carry no arrival timestamp and are never
    /// expired by this method. Returns the number of removed entries.
    pub fn prune_expired(&mut self, now_ms: u64) -> usize {
        let max_age = self.config.max_entry_age_ms;
        if max_age == 0 {
            return 0;
        }

        let expired_payments: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.inserted_at_ms != 0 && now_ms.saturating_sub(entry.inserted_at_ms) > max_age
            })
            .map(|(hash, _)| *hash)
            .collect();
        let expired_protocol: Vec<Hash256> = self
            .protocol_entries
            .iter()
            .filter(|(_, entry)| {
                entry.inserted_at_ms != 0 && now_ms.saturating_sub(entry.inserted_at_ms) > max_age
            })
            .map(|(hash, _)| *hash)
            .collect();

        let mut removed = 0;
        for hash in expired_payments {
            if self.remove_internal(&hash).is_some() {
                removed += 1;
            }
        }
        for hash in expired_protocol {
            if self.remove_protocol(&hash).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Drop every payment transaction for which `keep` returns `false`.
    ///
    /// This is the revalidation hook a node uses after a reorg or a parameter
    /// change. Protocol payloads have their own lifecycle and are not passed to
    /// the predicate. Returns the number of removed payments.
    pub fn retain<F>(&mut self, mut keep: F) -> usize
    where
        F: FnMut(&Transaction) -> bool,
    {
        let rejected: Vec<Hash256> = self
            .entries
            .iter()
            .filter(|(_, entry)| !keep(&entry.tx))
            .map(|(hash, _)| *hash)
            .collect();
        let mut removed = 0;
        for hash in rejected {
            if self.remove_internal(&hash).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Drop every protocol payload for which `keep` returns `false`.
    ///
    /// Protocol transactions have their own revalidation lifecycle: a WES,
    /// AetherCompute or WASM payload can become invalid after a reorg even
    /// though no payment key image changed.
    pub fn retain_protocol<F>(&mut self, mut keep: F) -> usize
    where
        F: FnMut(&[u8]) -> bool,
    {
        let rejected: Vec<Hash256> = self
            .protocol_entries
            .iter()
            .filter(|(_, entry)| !keep(&entry.payload))
            .map(|(hash, _)| *hash)
            .collect();
        let mut removed = 0;
        for hash in rejected {
            if self.remove_protocol(&hash).is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_priority.clear();
        self.key_images.clear();
        self.protocol_entries.clear();
        self.total_bytes = 0;
        self.protocol_bytes = 0;
        self.total_fees = 0;
    }

    /// Iterate payment transactions in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.values().map(|entry| &entry.tx)
    }

    pub fn protocol_iter(&self) -> impl Iterator<Item = &[u8]> {
        self.protocol_entries
            .values()
            .map(|entry| entry.payload.as_slice())
    }

    pub fn hashes(&self) -> Vec<Hash256> {
        self.entries
            .keys()
            .chain(self.protocol_entries.keys())
            .copied()
            .collect()
    }

    fn validate_payment_shape(&self, tx: &Transaction) -> Result<()> {
        if tx.is_coinbase() {
            return Err(MempoolError::Invalid(
                "coinbase transactions are not pooled",
            ));
        }
        if tx.inputs.is_empty() {
            return Err(MempoolError::Invalid("transaction has no inputs"));
        }
        if tx.inputs.len() > self.config.max_inputs {
            return Err(MempoolError::Invalid("too many inputs"));
        }
        if tx.outputs.len() > self.config.max_outputs {
            return Err(MempoolError::Invalid("too many outputs"));
        }
        Ok(())
    }

    #[inline]
    fn minimum_fee(&self, serialised_size: usize) -> u64 {
        (serialised_size as u64)
            .saturating_mul(self.config.min_fee_per_byte)
            .max(self.config.min_fee)
    }

    fn check_replacement(
        &self,
        fee: u64,
        priority: Priority,
        conflicts: &BTreeSet<Hash256>,
    ) -> Result<()> {
        if conflicts.is_empty() {
            return Ok(());
        }

        let mut displaced_fee = 0u128;
        let mut displaced_density = 0u128;
        for hash in conflicts {
            let Some(entry) = self.entries.get(hash) else {
                continue;
            };
            displaced_fee = displaced_fee.saturating_add(entry.fee as u128);
            displaced_density = displaced_density.max(entry.priority.fee_density);
        }

        let bump = displaced_fee.saturating_mul(self.config.replacement_bump_bps as u128) / 10_000;
        let required = displaced_fee.saturating_add(bump.max(1));
        if (fee as u128) < required || priority.fee_density < displaced_density {
            return Err(MempoolError::ReplacementFeeTooLow);
        }
        Ok(())
    }

    fn plan_payment_capacity(
        &self,
        serialised_size: usize,
        priority: Priority,
        conflicts: &BTreeSet<Hash256>,
    ) -> Result<Vec<Hash256>> {
        let reserved_slots = self.protocol_entries.len();
        let slot_limit = self.config.max_entries.saturating_sub(reserved_slots);
        let mut entries = self.entries.len().saturating_sub(conflicts.len());
        let mut bytes = self.total_bytes;
        for hash in conflicts {
            if let Some(entry) = self.entries.get(hash) {
                bytes = bytes.saturating_sub(entry.serialised_size);
            }
        }

        let fits = |entries: usize, bytes: usize| {
            entries.saturating_add(1) <= slot_limit
                && bytes.saturating_add(serialised_size) <= self.config.max_bytes
        };

        if fits(entries, bytes) {
            return Ok(Vec::new());
        }

        let mut evictions = Vec::new();
        for (candidate_priority, candidate_hash) in &self.by_priority {
            if fits(entries, bytes) {
                break;
            }
            if conflicts.contains(candidate_hash) {
                continue;
            }
            let Some(entry) = self.entries.get(candidate_hash) else {
                continue;
            };
            if *candidate_priority >= priority {
                return Err(MempoolError::FeeTooLow);
            }
            evictions.push(*candidate_hash);
            entries = entries.saturating_sub(1);
            bytes = bytes.saturating_sub(entry.serialised_size);
        }

        if !fits(entries, bytes) {
            return Err(MempoolError::Full);
        }
        Ok(evictions)
    }

    fn plan_protocol_capacity(&self, payload_size: usize) -> Result<Vec<Hash256>> {
        let mut entries = self.len();
        let mut bytes = self.total_bytes;
        let mut evictions = Vec::new();
        let mut candidates = self.by_priority.iter();

        while entries.saturating_add(1) > self.config.max_entries
            || bytes.saturating_add(payload_size) > self.config.max_bytes
        {
            let Some((_, worst_hash)) = candidates.next() else {
                return Err(MempoolError::Full);
            };
            let Some(entry) = self.entries.get(worst_hash) else {
                continue;
            };
            evictions.push(*worst_hash);
            entries = entries.saturating_sub(1);
            bytes = bytes.saturating_sub(entry.serialised_size);
        }

        Ok(evictions)
    }

    fn remove_internal(&mut self, hash: &Hash256) -> Option<Transaction> {
        let entry = self.entries.remove(hash)?;
        self.by_priority.remove(&entry.priority);
        self.total_bytes = self.total_bytes.saturating_sub(entry.serialised_size);
        self.total_fees = self.total_fees.saturating_sub(entry.fee);
        for input in &entry.tx.inputs {
            if self.key_images.get(&input.key_image) == Some(hash) {
                self.key_images.remove(&input.key_image);
            }
        }
        Some(entry.tx)
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_crypto::pedersen::Commitment;
    use hyphen_crypto::{Hash256, SecretKey};
    use hyphen_proof::inner_product::InnerProductProof;
    use hyphen_proof::range_proof::{AggregatedRangeProof, RangeProof};
    use hyphen_state::{
        wes_owner_policy, SignedStateCreate, StateClass, StateRecord, StateStatus, WesTransaction,
    };
    use hyphen_tx::transaction::{TxInput, TxOutput, TxPrunable};

    fn dummy_proof() -> AggregatedRangeProof {
        AggregatedRangeProof {
            m: 1,
            proof: RangeProof {
                a: [0; 32],
                s: [0; 32],
                t1: [0; 32],
                t2: [0; 32],
                tau_x: [0; 32],
                mu: [0; 32],
                t_hat: [0; 32],
                ipp: InnerProductProof {
                    l_vec: Vec::new(),
                    r_vec: Vec::new(),
                    a: [0; 32],
                    b: [0; 32],
                },
            },
        }
    }

    fn payment(key_images: &[[u8; 32]], fee: u64, extra_len: usize) -> Transaction {
        Transaction {
            version: 1,
            inputs: key_images
                .iter()
                .map(|key_image| TxInput {
                    ring: Vec::new(),
                    key_image: *key_image,
                    pseudo_output: Commitment([0; 32]),
                    epoch_context: [0; 32],
                    temporal_nonce: [0; 32],
                    causal_binding: [0; 32],
                })
                .collect(),
            outputs: vec![TxOutput {
                commitment: Commitment([0; 32]),
                one_time_pubkey: [0; 32],
                ephemeral_pubkey: [0; 32],
                encrypted_amount: [0; 32],
                view_tag: 0,
            }],
            fee,
            extra: vec![0; extra_len],
            prunable: TxPrunable {
                clsag_signatures: Vec::new(),
                range_proof: dummy_proof(),
            },
        }
    }

    fn hashes(pool: &Mempool) -> Vec<Hash256> {
        pool.get_block_candidates(usize::MAX)
            .into_iter()
            .map(Transaction::hash)
            .collect()
    }

    #[test]
    fn candidates_are_best_fee_first() {
        let mut pool = Mempool::new(8);
        let low = payment(&[[1; 32]], 1_000, 0);
        let high = payment(&[[2; 32]], 5_000, 0);
        let low_hash = pool.insert(low, Validated::new(0)).unwrap();
        let high_hash = pool.insert(high, Validated::new(0)).unwrap();

        assert_eq!(hashes(&pool), vec![high_hash, low_hash]);
    }

    #[test]
    fn vre_quality_breaks_fee_density_ties() {
        let mut pool = Mempool::new(8);
        let plain = payment(&[[1; 32]], 1_000, 0);
        let private = payment(&[[2; 32]], 1_000, 0);
        let plain_hash = pool.insert(plain, Validated::new(10)).unwrap();
        let private_hash = pool.insert(private, Validated::new(9_000)).unwrap();

        assert_eq!(hashes(&pool), vec![private_hash, plain_hash]);
    }

    #[test]
    fn byte_budget_is_respected() {
        let mut pool = Mempool::with_config(MempoolConfig::new(8).with_limits(8, 4_096));
        let first = payment(&[[1; 32]], 5_000, 1_000);
        let second = payment(&[[2; 32]], 4_000, 1_000);
        let first_size = first.serialise().len();
        let second_size = second.serialise().len();

        pool.insert(first, Validated::new(0)).unwrap();
        pool.insert(second, Validated::new(0)).unwrap();

        let blobs = pool.get_block_candidate_blobs(first_size.max(second_size));
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].len() <= first_size.max(second_size));
    }

    #[test]
    fn duplicate_and_self_double_spend_are_rejected() {
        let mut pool = Mempool::new(8);
        let tx = payment(&[[1; 32]], 1_000, 0);
        pool.insert(tx.clone(), Validated::new(0)).unwrap();
        assert_eq!(
            pool.insert(tx, Validated::new(0)).unwrap_err(),
            MempoolError::Duplicate
        );

        let repeated = payment(&[[2; 32], [2; 32]], 1_000, 0);
        assert_eq!(
            pool.insert(repeated, Validated::new(0)).unwrap_err(),
            MempoolError::DoubleSpend
        );
    }

    #[test]
    fn replacement_must_beat_every_displaced_transaction() {
        let mut pool = Mempool::new(8);
        let original = payment(&[[1; 32]], 1_000, 0);
        let original_hash = pool.insert(original, Validated::new(0)).unwrap();

        let stingy = payment(&[[1; 32]], 1_050, 0);
        assert_eq!(
            pool.insert(stingy, Validated::new(0)).unwrap_err(),
            MempoolError::ReplacementFeeTooLow
        );

        let replacement = payment(&[[1; 32]], 1_100, 0);
        let replacement_hash = pool.insert(replacement, Validated::new(0)).unwrap();
        assert!(!pool.contains(&original_hash));
        assert!(pool.contains(&replacement_hash));
        assert!(pool.has_key_image(&[1; 32]));
    }

    #[test]
    fn capacity_evicts_the_cheapest_payment() {
        let mut pool = Mempool::new(2);
        let cheap = payment(&[[1; 32]], 1_000, 0);
        let middle = payment(&[[2; 32]], 2_000, 0);
        let expensive = payment(&[[3; 32]], 3_000, 0);

        let cheap_hash = pool.insert(cheap, Validated::new(0)).unwrap();
        let middle_hash = pool.insert(middle, Validated::new(0)).unwrap();
        let expensive_hash = pool.insert(expensive, Validated::new(0)).unwrap();

        assert_eq!(hashes(&pool), vec![expensive_hash, middle_hash]);
        assert!(!pool.contains(&cheap_hash));
        assert!(!pool.has_key_image(&[1; 32]));
    }

    #[test]
    fn a_worse_transaction_cannot_evict_a_better_one() {
        let mut pool = Mempool::new(1);
        pool.insert(payment(&[[1; 32]], 9_000, 0), Validated::new(0))
            .unwrap();
        assert_eq!(
            pool.insert(payment(&[[2; 32]], 1_000, 0), Validated::new(0))
                .unwrap_err(),
            MempoolError::FeeTooLow
        );
    }

    #[test]
    fn minimum_fee_policy_is_enforced() {
        let mut pool = Mempool::with_config(MempoolConfig::new(8).with_minimum_fee(10_000, 100));
        let tx = payment(&[[1; 32]], 10_000, 0);
        let minimum = 10_000u64.max(tx.serialise().len() as u64 * 100);
        if tx.fee < minimum {
            assert_eq!(
                pool.insert(tx, Validated::new(0)).unwrap_err(),
                MempoolError::FeeTooLow
            );
        } else {
            // The fixture happens to clear the per-byte floor; a zero-fee
            // transaction must still be refused.
            assert_eq!(
                pool.insert(payment(&[[2; 32]], 0, 0), Validated::new(0))
                    .unwrap_err(),
                MempoolError::FeeTooLow
            );
        }
    }

    #[test]
    fn purge_uses_the_key_image_index() {
        let mut pool = Mempool::new(8);
        let tx = payment(&[[1; 32], [2; 32]], 1_000, 0);
        let hash = pool.insert(tx, Validated::new(0)).unwrap();

        pool.purge_confirmed(&[[2; 32]]);
        assert!(!pool.contains(&hash));
        assert!(!pool.has_key_image(&[1; 32]));
        assert!(!pool.has_key_image(&[2; 32]));
        assert!(pool.is_empty());
    }

    #[test]
    fn protocol_capacity_is_isolated_and_reported() {
        let mut pool = Mempool::with_config(
            MempoolConfig::new(8)
                .with_protocol_limits(2, 1_024)
                .with_limits(8, 64 * 1024),
        );

        pool.insert_protocol(vec![1; 100], ValidatedProtocol::new())
            .unwrap();
        pool.insert_protocol(vec![2; 100], ValidatedProtocol::new())
            .unwrap();
        assert_eq!(
            pool.insert_protocol(vec![3; 100], ValidatedProtocol::new())
                .unwrap_err(),
            MempoolError::ProtocolFull
        );

        let stats = pool.stats();
        assert_eq!(stats.protocol_transactions, 2);
        assert_eq!(stats.protocol_bytes, 200);
        assert_eq!(stats.transactions, 2);
    }

    #[test]
    fn protocol_admission_can_displace_the_worst_payment() {
        let mut pool = Mempool::with_config(
            MempoolConfig::new(2)
                .with_protocol_limits(1, 1_024)
                .with_limits(2, 64 * 1024),
        );
        let cheap = payment(&[[1; 32]], 1_000, 0);
        let expensive = payment(&[[2; 32]], 2_000, 0);
        let cheap_hash = pool.insert(cheap, Validated::new(0)).unwrap();
        let expensive_hash = pool.insert(expensive, Validated::new(0)).unwrap();

        let protocol_hash = pool
            .insert_protocol(vec![7; 32], ValidatedProtocol::new())
            .unwrap();
        assert!(!pool.contains(&cheap_hash));
        assert!(pool.contains(&expensive_hash));
        assert!(pool.contains(&protocol_hash));
    }

    #[test]
    fn protocol_admission_evicts_every_payment_needed_for_the_byte_budget() {
        let first = payment(&[[1; 32]], 1_000, 400);
        let second = payment(&[[2; 32]], 900, 400);
        let first_size = first.serialise().len();
        let second_size = second.serialise().len();
        let budget = first_size + second_size;
        let mut pool = Mempool::with_config(
            MempoolConfig::new(10)
                .with_limits(10, budget)
                .with_protocol_limits(2, budget),
        );
        pool.insert(first, Validated::new(0)).unwrap();
        pool.insert(second, Validated::new(0)).unwrap();

        pool.insert_protocol(vec![7; budget], ValidatedProtocol::new())
            .unwrap();
        let stats = pool.stats();
        assert_eq!(stats.payment_transactions, 0);
        assert_eq!(stats.protocol_transactions, 1);
        assert!(stats.bytes <= budget);
    }

    #[test]
    fn expiry_uses_arrival_timestamps() {
        let mut pool = Mempool::with_config(MempoolConfig::new(8).with_max_entry_age(100));
        pool.insert_at(payment(&[[1; 32]], 1_000, 0), Validated::new(0), 1_000)
            .unwrap();
        pool.insert_protocol_at(vec![9; 32], ValidatedProtocol::new(), 1_000)
            .unwrap();

        assert_eq!(pool.prune_expired(1_050), 0);
        assert_eq!(pool.prune_expired(1_101), 2);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn timestamp_free_inserts_never_expire() {
        let mut pool = Mempool::with_config(MempoolConfig::new(8).with_max_entry_age(1));
        pool.insert(payment(&[[1; 32]], 1_000, 0), Validated::new(0))
            .unwrap();
        assert_eq!(pool.prune_expired(u64::MAX), 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn retain_is_a_revalidation_hook_for_payments() {
        let mut pool = Mempool::new(8);
        let keep = payment(&[[1; 32]], 5_000, 0);
        let drop = payment(&[[2; 32]], 1_000, 0);
        let keep_hash = pool.insert(keep, Validated::new(0)).unwrap();
        let drop_hash = pool.insert(drop, Validated::new(0)).unwrap();

        assert_eq!(pool.retain(|tx| tx.fee >= 2_000), 1);
        assert!(pool.contains(&keep_hash));
        assert!(!pool.contains(&drop_hash));
        assert!(!pool.has_key_image(&[2; 32]));
    }

    #[test]
    fn configuration_is_normalized_and_strict_validation_reports_drift() {
        let configured = MempoolConfig::new(4)
            .with_limits(4, 1_024)
            .with_protocol_limits(9, 4_096);
        assert!(configured.validate().is_err());

        let pool = Mempool::with_config(configured);
        assert_eq!(pool.config().max_protocol_entries, 4);
        assert_eq!(pool.config().max_protocol_bytes, 1_024);
        assert_eq!(pool.config().max_tx_bytes, 1_024);
    }

    #[test]
    fn total_fees_track_insert_remove_eviction_and_clear() {
        let mut pool = Mempool::new(2);
        let cheap = payment(&[[1; 32]], 1_000, 0);
        let expensive = payment(&[[2; 32]], 3_000, 0);
        let replacement = payment(&[[2; 32]], 4_000, 0);
        pool.insert(cheap, Validated::new(0)).unwrap();
        pool.insert(expensive, Validated::new(0)).unwrap();
        assert_eq!(pool.stats().total_fees, 4_000);

        pool.insert(replacement, Validated::new(0)).unwrap();
        assert_eq!(pool.stats().total_fees, 5_000);

        pool.insert_protocol(vec![9; 32], ValidatedProtocol::new())
            .unwrap();
        assert_eq!(pool.stats().total_fees, 4_000);

        pool.clear();
        assert_eq!(pool.stats().total_fees, 0);
    }

    #[test]
    fn retain_protocol_is_a_revalidation_hook() {
        let mut pool = Mempool::new(8);
        pool.insert_protocol(vec![1; 32], ValidatedProtocol::new())
            .unwrap();
        pool.insert_protocol(vec![2; 32], ValidatedProtocol::new())
            .unwrap();

        assert_eq!(pool.retain_protocol(|payload| payload[0] == 1), 1);
        assert_eq!(pool.stats().protocol_transactions, 1);
        assert_eq!(pool.stats().protocol_bytes, 32);
        assert_eq!(pool.protocol_iter().count(), 1);
    }

    #[test]
    fn h_wes_envelope_uses_protocol_capacity_ordering_and_purge() {
        let owner = SecretKey([41; 32]);
        let transaction = WesTransaction::Create(
            SignedStateCreate::sign(
                StateRecord {
                    chain_id: Hash256::from_bytes([42; 32]),
                    class: StateClass::ContractStorage,
                    key: Hash256::from_bytes([43; 32]),
                    version: 0,
                    value_hash: Hash256::from_bytes([44; 32]),
                    owner_policy: wes_owner_policy(owner.public_key()),
                    created_at: 1,
                    lease_end: 20,
                    status: StateStatus::Live,
                },
                &owner,
            )
            .unwrap(),
        );
        let payload = transaction.encode().unwrap();
        let hash = hyphen_crypto::blake3_hash(&payload);
        let mut pool = Mempool::new(1);

        assert_eq!(
            pool.insert_protocol(payload.clone(), ValidatedProtocol::new())
                .unwrap(),
            hash
        );
        assert!(matches!(
            pool.insert_protocol(payload.clone(), ValidatedProtocol::new()),
            Err(MempoolError::Duplicate)
        ));
        assert_eq!(pool.get_block_candidate_blobs(payload.len()), vec![payload]);
        assert_eq!(pool.stats().protocol_bytes, pool.total_bytes());

        pool.purge_confirmed_protocol(&[hash]);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }
}
