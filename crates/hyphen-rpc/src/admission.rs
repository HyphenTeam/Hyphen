use hyphen_consensus::{BlockValidator, Blockchain, validator::ValidationError};
use hyphen_core::error::CoreError;
use hyphen_crypto::Hash256;
use hyphen_mempool::{Mempool, Validated, ValidatedProtocol};
use parking_lot::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("{0}")]
    Malformed(String),
    #[error("{0}")]
    Rejected(String),
    #[error("{0}")]
    State(String),
}

/// Common admission rules for transactions received from an RPC client or peer.
pub fn admit_transaction(
    chain: &Blockchain,
    pool: &RwLock<Mempool>,
    bytes: Vec<u8>,
    now_ms: u64,
) -> Result<Hash256, AdmissionError> {
    let height = chain
        .tip()
        .map_err(|e| AdmissionError::State(e.to_string()))?
        .height
        .checked_add(1)
        .ok_or_else(|| AdmissionError::State("chain height exhausted".into()))?;
    let protocol = hyphen_compute::ComputeTransaction::decode(&bytes)
        .map_err(|e| AdmissionError::Malformed(format!("bad AetherCompute transaction: {e}")))?
        .is_some()
        || hyphen_vm::VmTransaction::decode(&bytes)
            .map_err(|e| AdmissionError::Malformed(format!("bad WASM transaction: {e}")))?
            .is_some()
        || hyphen_state::WesTransaction::decode(&bytes)
            .map_err(|e| AdmissionError::Malformed(format!("bad H-WES transaction: {e}")))?
            .is_some();
    let inserted = if protocol {
        chain
            .validate_transaction_blobs_for_height(std::slice::from_ref(&bytes), height)
            .map_err(|e| AdmissionError::Rejected(format!("validation failed: {e}")))?;
        pool.write()
            .insert_protocol_at(bytes, ValidatedProtocol::new(), now_ms)
    } else {
        let validator = BlockValidator::new(&chain.cfg);
        let tx = validator
            .decode_payment(&bytes)
            .map_err(|e| AdmissionError::Malformed(format!("bad tx data: {e}")))?;
        for input in &tx.inputs {
            if chain
                .nullifiers
                .contains(&input.key_image)
                .map_err(|e| AdmissionError::State(e.to_string()))?
            {
                return Err(AdmissionError::Rejected(
                    "double-spend: key image already spent on chain".into(),
                ));
            }
        }
        let epochs = chain
            .build_valid_epoch_contexts(height)
            .map_err(|e| AdmissionError::State(e.to_string()))?;
        let store = chain.store();
        let count = chain.commitment_tree.read().count();
        let quality = validator
            .validate_transaction(
                &tx,
                |index| {
                    store
                        .resolve_ring_member(index)
                        .map_err(|e| ValidationError::Core(CoreError::Storage(e.to_string())))
                },
                &epochs,
                count,
                height,
            )
            .map_err(|e| AdmissionError::Rejected(format!("validation failed: {e}")))?;
        pool.write().insert_at(tx, Validated::new(quality), now_ms)
    };
    inserted.map_err(|e| AdmissionError::Rejected(e.to_string()))
}
