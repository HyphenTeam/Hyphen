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
    pub chain: Arc<parking_lot::RwLock<Blockchain>>,
    pub mempool: Arc<parking_lot::RwLock<Mempool>>,
}

impl RpcHandler {
    pub fn new(
        chain: Arc<parking_lot::RwLock<Blockchain>>,
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

        let chain = self.chain.read();
        let block = chain.store().get_block_by_hash(&hash)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = bincode::serialize(&block.header)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let resp = BlockResponse {
            header_data,
            transactions: block.transactions,
            hash: hash.to_vec(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_block_by_height(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetBlockByHeightRequest::decode(payload)?;
        let chain = self.chain.read();
        let block = chain.store().get_block_by_height(req.height)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = bincode::serialize(&block.header)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let resp = BlockResponse {
            header_data,
            transactions: block.transactions,
            hash: block.header.hash().to_vec(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        Ok(resp.encode_to_vec())
    }

    fn handle_get_chain_info(&self) -> Result<Vec<u8>, HandlerError> {
        let chain = self.chain.read();
        let tip = chain.tip().map_err(|e| HandlerError::Internal(e.to_string()))?;
        let resp = ChainInfoResponse {
            height: tip.height,
            tip_hash: tip.hash.to_vec(),
            difficulty: 0,
            cumulative_difficulty: tip.cumulative_difficulty.to_le_bytes().to_vec(),
            total_outputs: tip.total_outputs,
            network: String::new(),
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

        let chain = self.chain.read();
        match chain.store().get_tx_location(&tx_hash) {
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

        let mut pool = self.mempool.write();
        match pool.insert(tx) {
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
}
