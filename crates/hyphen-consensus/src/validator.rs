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
    #[error("duplicate nullifier")]
    DuplicateNullifier,
    #[error("empty ring")]
    EmptyRing,
    #[error("decompression failed")]
    Decompression,
    #[error("no inputs")]
    NoInputs,
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
        now_secs: u64,
    ) -> Result<(), ValidationError> {
        // Height continuity
        if header.height != prev_height + 1 {
            return Err(CoreError::HeightMismatch {
                expected: prev_height + 1,
                got: header.height,
            }
            .into());
        }

        // Previous hash linkage
        if header.prev_hash != *prev_hash {
            return Err(CoreError::Validation("prev_hash mismatch".into()).into());
        }

        let max_future = now_secs + 2 * self.cfg.block_time.as_secs();
        if header.timestamp > max_future {
            return Err(ValidationError::TimestampFuture);
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

    pub fn validate_transaction<F>(
        &self,
        tx: &Transaction,
        resolve_ring_member: F,
    ) -> Result<(), ValidationError>
    where
        F: Fn(u64) -> Result<(RistrettoPoint, RistrettoPoint), ValidationError>,
    {
        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }

        // Balance check: Σ pseudo_outputs == Σ output_commits + fee·G
        if !tx.check_balance() {
            return Err(ValidationError::BalanceFailed);
        }

        // Verify each CLSAG
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

            let mut ring_keys = Vec::with_capacity(input.ring.len());
            let mut ring_commits = Vec::with_capacity(input.ring.len());

            for oref in &input.ring {
                let (pk, cm) = resolve_ring_member(oref.global_index)?;
                ring_keys.push(pk);
                ring_commits.push(cm);
            }

            let pseudo_out = input
                .pseudo_output
                .to_point()
                .map_err(|_| ValidationError::Decompression)?;

            clsag::clsag_verify(msg.as_bytes(), &ring_keys, &ring_commits, &pseudo_out, sig)
                .map_err(|e| ValidationError::ClsagFailed(i, e.to_string()))?;
        }

        // Verify aggregated range proof
        let out_commitments: Result<Vec<RistrettoPoint>, _> = tx
            .outputs
            .iter()
            .map(|o| o.commitment.to_point().map_err(|_| ValidationError::Decompression))
            .collect();
        let out_commitments = out_commitments?;

        tx.prunable
            .range_proof
            .verify(&out_commitments)
            .map_err(|e| ValidationError::RangeProofFailed(e.to_string()))?;

        Ok(())
    }
}
