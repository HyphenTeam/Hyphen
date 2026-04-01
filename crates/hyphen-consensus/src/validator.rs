use curve25519_dalek::ristretto::RistrettoPoint;
use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::ChainConfig;
use hyphen_core::error::CoreError;
use hyphen_crypto::clsag;
use hyphen_tx::transaction::Transaction;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("core: {0}")]
    Core(#[from] CoreError),
    #[error("timestamp too old")]
    TimestampTooOld,
    #[error("timestamp too far in future")]
    TimestampFuture,
    #[error("invalid PoW")]
    InvalidPow,
    #[error("tx root mismatch")]
    TxRootMismatch,
    #[error("balance check failed")]
    BalanceFailed,
    #[error("CLSAG verification failed for input {0}: {1}")]
    ClsagFailed(usize, String),
    #[error("range proof failed: {0}")]
    RangeProofFailed(String),
    #[error("uncle root mismatch")]
    UncleRootMismatch,
    #[error("receipt root mismatch")]
    ReceiptRootMismatch,
    #[error("duplicate nullifier")]
    DuplicateNullifier,
    #[error("empty ring")]
    EmptyRing,
    #[error("ring size mismatch: expected {expected}, got {got}")]
    RingSizeMismatch { expected: usize, got: usize },
    #[error("ring entropy too low: span {span} < min {min_span}")]
    RingEntropyTooLow { span: u64, min_span: u64 },
    #[error("ring members not sufficiently distinct: {distinct}/{total}")]
    RingDiversityTooLow { distinct: usize, total: usize },
    #[error("decompression failed")]
    Decompression,
    #[error("no inputs")]
    NoInputs,
    #[error("too many uncles")]
    TooManyUncles,
    #[error("uncle too old")]
    UncleTooOld,
    #[error("uncle height invalid")]
    UncleHeightInvalid,
    #[error("duplicate uncle")]
    DuplicateUncle,
}

pub struct BlockValidator<'a> {
    pub cfg: &'a ChainConfig,
}

impl<'a> BlockValidator<'a> {
    pub fn new(cfg: &'a ChainConfig) -> Self {
        Self { cfg }
    }

    pub fn validate_header(
        &self,
        header: &BlockHeader,
        prev_height: u64,
        prev_hash: &hyphen_crypto::Hash256,
        now_ms: u64,
    ) -> Result<(), ValidationError> {
        if header.height != prev_height + 1 {
            return Err(CoreError::HeightMismatch {
                expected: prev_height + 1,
                got: header.height,
            }
            .into());
        }

        if header.prev_hash != *prev_hash {
            return Err(CoreError::Validation("prev_hash mismatch".into()).into());
        }

        let max_future = now_ms + self.cfg.timestamp_future_limit_ms;
        if header.timestamp > max_future {
            return Err(ValidationError::TimestampFuture);
        }

        Ok(())
    }

    pub fn validate_uncles(
        &self,
        block: &Block,
        get_header_at_height: &dyn Fn(u64) -> Option<BlockHeader>,
    ) -> Result<(), ValidationError> {
        if block.uncle_headers.len() > self.cfg.max_uncles {
            return Err(ValidationError::TooManyUncles);
        }

        let mut seen_hashes = std::collections::HashSet::new();

        for uncle in &block.uncle_headers {
            let uncle_hash = uncle.hash();

            if !seen_hashes.insert(uncle_hash) {
                return Err(ValidationError::DuplicateUncle);
            }

            if uncle.height >= block.header.height || uncle.height == 0 {
                return Err(ValidationError::UncleHeightInvalid);
            }

            let depth = block.header.height - uncle.height;
            if depth > self.cfg.max_uncle_depth {
                return Err(ValidationError::UncleTooOld);
            }

            if let Some(parent) = get_header_at_height(uncle.height.saturating_sub(1)) {
                if uncle.prev_hash != parent.hash() {
                    return Err(ValidationError::UncleHeightInvalid);
                }
            }
        }

        Ok(())
    }

    pub fn validate_tx_root(&self, block: &Block) -> Result<(), ValidationError> {
        let computed = block.compute_tx_root();
        if computed != block.header.tx_root {
            return Err(ValidationError::TxRootMismatch);
        }
        Ok(())
    }

    pub fn validate_uncle_root(&self, block: &Block) -> Result<(), ValidationError> {
        let computed = block.compute_uncle_root();
        if computed != block.header.uncle_root {
            return Err(ValidationError::UncleRootMismatch);
        }
        Ok(())
    }

    pub fn validate_transaction<F>(
        &self,
        tx: &Transaction,
        resolve_ring_member: F,
    ) -> Result<(), ValidationError>
    where
        F: Fn(u64) -> Result<(RistrettoPoint, RistrettoPoint, u64), ValidationError>,
    {
        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }

        if !tx.check_balance() {
            return Err(ValidationError::BalanceFailed);
        }

        let msg = tx.prefix_hash();
        for (i, (input, sig)) in tx
            .inputs
            .iter()
            .zip(tx.prunable.clsag_signatures.iter())
            .enumerate()
        {
            if input.ring.is_empty() {
                return Err(ValidationError::EmptyRing);
            }

            if input.ring.len() != self.cfg.ring_size {
                return Err(ValidationError::RingSizeMismatch {
                    expected: self.cfg.ring_size,
                    got: input.ring.len(),
                });
            }

            let mut ring_keys = Vec::with_capacity(input.ring.len());
            let mut ring_commits = Vec::with_capacity(input.ring.len());
            let mut ring_heights = Vec::with_capacity(input.ring.len());

            for oref in &input.ring {
                let (pk, cm, height) = resolve_ring_member(oref.global_index)?;
                ring_keys.push(pk);
                ring_commits.push(cm);
                ring_heights.push(height);
            }

            self.validate_ring_entropy(&ring_heights)?;

            let pseudo_out = input
                .pseudo_output
                .to_point()
                .map_err(|_| ValidationError::Decompression)?;

            clsag::clsag_verify(msg.as_bytes(), &ring_keys, &ring_commits, &pseudo_out, sig)
                .map_err(|e| ValidationError::ClsagFailed(i, e.to_string()))?;
        }

        let out_commitments: Result<Vec<RistrettoPoint>, _> = tx
            .outputs
            .iter()
            .map(|o| {
                o.commitment
                    .to_point()
                    .map_err(|_| ValidationError::Decompression)
            })
            .collect();
        let out_commitments = out_commitments?;

        tx.prunable
            .range_proof
            .verify(&out_commitments)
            .map_err(|e| ValidationError::RangeProofFailed(e.to_string()))?;

        Ok(())
    }

    fn validate_ring_entropy(&self, heights: &[u64]) -> Result<(), ValidationError> {
        let n = heights.len();
        if n < 2 {
            return Ok(());
        }

        let min_h = heights.iter().copied().min().unwrap_or(0);
        let max_h = heights.iter().copied().max().unwrap_or(0);
        let span = max_h - min_h;

        if span < self.cfg.min_ring_span {
            return Err(ValidationError::RingEntropyTooLow {
                span,
                min_span: self.cfg.min_ring_span,
            });
        }

        let mut unique = heights.to_vec();
        unique.sort_unstable();
        unique.dedup();
        let distinct = unique.len();
        let min_distinct = (n * 3).div_ceil(4);

        if distinct < min_distinct {
            return Err(ValidationError::RingDiversityTooLow {
                distinct,
                total: n,
            });
        }

        Ok(())
    }

    pub fn uncle_reward(&self, uncle_height: u64, nephew_height: u64, base_reward: u64) -> u64 {
        let depth = nephew_height.saturating_sub(uncle_height);
        let max_depth = self.cfg.max_uncle_depth;
        if depth > max_depth || depth == 0 {
            return 0;
        }
        let numerator = (max_depth + 1 - depth) * self.cfg.uncle_reward_numerator;
        let denominator = max_depth * self.cfg.uncle_reward_denominator;
        base_reward * numerator / denominator
    }

    pub fn nephew_reward(&self, base_reward: u64, uncle_count: usize) -> u64 {
        base_reward * self.cfg.nephew_reward_numerator * uncle_count as u64
            / self.cfg.nephew_reward_denominator
    }
}
