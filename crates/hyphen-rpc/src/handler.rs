use prost::Message;
use std::sync::Arc;
use thiserror::Error;

use hyphen_consensus::Blockchain;
use hyphen_mempool::Mempool;
use hyphen_tx::transaction::Transaction;

use crate::messages::*;

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
}

pub struct RpcHandler {
    pub chain: Arc<Blockchain>,
    pub mempool: Arc<parking_lot::RwLock<Mempool>>,
}

impl RpcHandler {
    pub fn new(
        chain: Arc<Blockchain>,
        mempool: Arc<parking_lot::RwLock<Mempool>>,
    ) -> Self {
        Self { chain, mempool }
    }

    pub fn handle_request(&self, request: &RpcRequest) -> RpcResponse {
        let result = match request.method {
            METHOD_GET_BLOCK => self.handle_get_block(&request.payload),
            METHOD_GET_BLOCK_BY_HEIGHT => self.handle_get_block_by_height(&request.payload),
            METHOD_GET_CHAIN_INFO => self.handle_get_chain_info(),
            METHOD_SUBMIT_TX => self.handle_submit_tx(&request.payload),
            METHOD_GET_MEMPOOL => self.handle_get_mempool(),
            METHOD_GET_TX_LOCATION => self.handle_get_tx_location(&request.payload),
            METHOD_GET_RANDOM_OUTPUTS => self.handle_get_random_outputs(&request.payload),
            METHOD_GET_OUTPUT_INFO => self.handle_get_output_info(&request.payload),
            _ => Err(HandlerError::InvalidRequest(format!(
                "unknown method: {}", request.method
            ))),
        };

        match result {
            Ok(payload) => RpcResponse {
                id: request.id,
                success: true,
                payload,
                error: String::new(),
            },
            Err(e) => RpcResponse {
                id: request.id,
                success: false,
                payload: vec![],
                error: e.to_string(),
            },
        }
    }

    fn handle_get_block(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetBlockRequest::decode(payload)?;
        if req.hash.len() != 32 {
            return Err(HandlerError::InvalidRequest("hash must be 32 bytes".into()));
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&req.hash);
        let hash = hyphen_crypto::Hash256::from_bytes(hash_arr);

        let block = self.chain.store().get_block_by_hash(&hash)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = bincode::serialize(&block.header)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let mut transactions = block.transactions;
        if let Ok(coinbase_blob) = self.chain.store().get_coinbase(block.header.height) {
            transactions.push(coinbase_blob);
        }

        let resp = BlockResponse {
            header_data,
            transactions,
            hash: hash.to_vec(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_block_by_height(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetBlockByHeightRequest::decode(payload)?;
        let block = self.chain.store().get_block_by_height(req.height)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = bincode::serialize(&block.header)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let mut transactions = block.transactions;
        // Append coinbase transaction if one was generated for this block
        if let Ok(coinbase_blob) = self.chain.store().get_coinbase(req.height) {
            transactions.push(coinbase_blob);
        }

        let resp = BlockResponse {
            header_data,
            transactions,
            hash: block.header.hash().to_vec(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_chain_info(&self) -> Result<Vec<u8>, HandlerError> {
        let tip = self.chain.tip().map_err(|e| HandlerError::Internal(e.to_string()))?;
        let next_height = tip.height + 1;
        let epoch_seed = self.chain.epoch_seed_for_height(next_height)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let resp = ChainInfoResponse {
            height: tip.height,
            tip_hash: tip.hash.to_vec(),
            difficulty: 0,
            cumulative_difficulty: tip.cumulative_difficulty.to_le_bytes().to_vec(),
            total_outputs: tip.total_outputs,
            network: self.chain.cfg.network_name.clone(),
            epoch_seed: epoch_seed.to_vec(),
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_tx_location(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetTxLocationRequest::decode(payload)?;
        if req.tx_hash.len() != 32 {
            return Err(HandlerError::InvalidRequest("tx_hash must be 32 bytes".into()));
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&req.tx_hash);
        let tx_hash = hyphen_crypto::Hash256::from_bytes(hash_arr);

        match self.chain.store().get_tx_location(&tx_hash) {
            Ok((block_hash, idx)) => {
                let resp = TxLocationResponse {
                    block_hash: block_hash.to_vec(),
                    tx_index: idx,
                    found: true,
                };
                Ok(resp.encode_to_vec())
            }
            Err(_) => {
                let resp = TxLocationResponse {
                    block_hash: vec![],
                    tx_index: 0,
                    found: false,
                };
                Ok(resp.encode_to_vec())
            }
        }
    }

    fn handle_submit_tx(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = SubmitTransactionRequest::decode(payload)?;
        let tx: Transaction = bincode::deserialize(&req.tx_data)
            .map_err(|e| HandlerError::InvalidRequest(format!("bad tx data: {e}")))?;

        // ── Pre-validation: check key images against blockchain nullifiers ──
        for inp in &tx.inputs {
            if self.chain.nullifiers.contains(&inp.key_image)
                .unwrap_or(false)
            {
                let resp = SubmitTransactionResponse {
                    accepted: false,
                    tx_hash: vec![],
                    error: "double-spend: key image already spent on chain".into(),
                };
                return Ok(resp.encode_to_vec());
            }
        }

        // ── Full transaction validation (balance, CLSAG, TERA, MD-VRE) ──
        let tip = self.chain.tip().map_err(|e| HandlerError::Internal(e.to_string()))?;
        let next_height = tip.height + 1;

        let valid_epoch_contexts = self.chain.build_valid_epoch_contexts(next_height)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let total_outputs = {
            let ct = self.chain.commitment_tree.read();
            ct.count()
        };

        let validator = hyphen_consensus::BlockValidator::new(&self.chain.cfg);
        let store = self.chain.store();
        let vre_quality = match validator.validate_transaction(
            &tx,
            |global_index| {
                store.resolve_ring_member(global_index).map_err(|e| {
                    hyphen_consensus::validator::ValidationError::Core(
                        hyphen_core::error::CoreError::Storage(e.to_string()),
                    )
                })
            },
            &valid_epoch_contexts,
            total_outputs,
            next_height,
        ) {
            Ok(q) => q,
            Err(e) => {
                let resp = SubmitTransactionResponse {
                    accepted: false,
                    tx_hash: vec![],
                    error: format!("validation failed: {e}"),
                };
                return Ok(resp.encode_to_vec());
            }
        };

        let mut pool = self.mempool.write();
        match pool.insert(tx, hyphen_mempool::Validated::new(vre_quality)) {
            Ok(tx_hash) => {
                let resp = SubmitTransactionResponse {
                    accepted: true,
                    tx_hash: tx_hash.to_vec(),
                    error: String::new(),
                };
                Ok(resp.encode_to_vec())
            }
            Err(e) => {
                let resp = SubmitTransactionResponse {
                    accepted: false,
                    tx_hash: vec![],
                    error: e.to_string(),
                };
                Ok(resp.encode_to_vec())
            }
        }
    }

    fn handle_get_mempool(&self) -> Result<Vec<u8>, HandlerError> {
        let pool = self.mempool.read();
        let tx_hashes: Vec<Vec<u8>> = pool.iter().map(|tx| tx.hash().to_vec()).collect();
        let resp = MempoolResponse {
            tx_count: pool.len() as u64,
            total_size: 0,
            tx_hashes,
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_random_outputs(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetRandomOutputsRequest::decode(payload)?;
        let count = (req.count as usize).min(128);
        let tip = self.chain.tip().map_err(|e| HandlerError::Internal(e.to_string()))?;
        let ceiling = if req.below_index > 0 {
            req.below_index.min(tip.total_outputs)
        } else {
            tip.total_outputs
        };
        let random_outs = self.chain
            .store()
            .get_random_outputs(count, ceiling)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let outputs = random_outs
            .into_iter()
            .map(|(pk, cm, idx, height)| OutputInfo {
                one_time_pubkey: pk.to_vec(),
                commitment: cm.to_vec(),
                global_index: idx,
                block_height: height,
            })
            .collect();
        let resp = RandomOutputsResponse { outputs };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_output_info(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetOutputInfoRequest::decode(payload)?;
        if req.global_indices.len() > 256 {
            return Err(HandlerError::InvalidRequest("too many indices (max 256)".into()));
        }
        let store = self.chain.store();
        let mut outputs = Vec::with_capacity(req.global_indices.len());
        for &gi in &req.global_indices {
            match store.get_output(gi) {
                Ok((pk, cm)) => {
                    let val = store
                        .resolve_ring_member(gi)
                        .map(|(_, _, h)| h)
                        .unwrap_or(0);
                    outputs.push(OutputInfo {
                        one_time_pubkey: pk.to_vec(),
                        commitment: cm.to_vec(),
                        global_index: gi,
                        block_height: val,
                    });
                }
                Err(_) => {
                    outputs.push(OutputInfo {
                        one_time_pubkey: vec![],
                        commitment: vec![],
                        global_index: gi,
                        block_height: 0,
                    });
                }
            }
        }
        let resp = GetOutputInfoResponse { outputs };
        Ok(resp.encode_to_vec())
    }
}
