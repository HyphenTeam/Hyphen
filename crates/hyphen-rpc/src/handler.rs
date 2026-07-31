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
    pub fn new(chain: Arc<Blockchain>, mempool: Arc<parking_lot::RwLock<Mempool>>) -> Self {
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
            METHOD_GET_COMPUTE_TASK => self.handle_get_compute_task(&request.payload),
            METHOD_GET_VM_CONTRACT => self.handle_get_vm_contract(&request.payload),
            METHOD_GET_VM_STORAGE => self.handle_get_vm_storage(&request.payload),
            METHOD_GET_H_WES_ROOTS => self.handle_get_h_wes_roots(&request.payload),
            METHOD_LIST_COMPUTE_TASKS => self.handle_list_compute_tasks(&request.payload),
            _ => Err(HandlerError::InvalidRequest(format!(
                "unknown method: {}",
                request.method
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

        let block = self
            .chain
            .store()
            .get_block_by_hash(&hash)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&block.header)
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
        let block = self
            .chain
            .store()
            .get_block_by_height(req.height)
            .map_err(|e| HandlerError::NotFound(e.to_string()))?;

        let header_data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&block.header)
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
        let tip = self
            .chain
            .tip()
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let next_height = tip.height + 1;
        let epoch_seed = self
            .chain
            .epoch_seed_for_height(next_height)
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
            return Err(HandlerError::InvalidRequest(
                "tx_hash must be 32 bytes".into(),
            ));
        }
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&req.tx_hash);
        let tx_hash = hyphen_crypto::Hash256::from_bytes(hash_arr);

        match self.chain.store().get_tx_location(&tx_hash) {
            Ok((block_hash, idx)) => {
                let block_height = self
                    .chain
                    .store()
                    .get_block_by_hash(&block_hash)
                    .map_err(|error| HandlerError::Internal(error.to_string()))?
                    .header
                    .height;
                let resp = TxLocationResponse {
                    block_hash: block_hash.to_vec(),
                    tx_index: idx,
                    found: true,
                    block_height,
                };
                Ok(resp.encode_to_vec())
            }
            Err(_) => {
                let resp = TxLocationResponse {
                    block_hash: vec![],
                    tx_index: 0,
                    found: false,
                    block_height: 0,
                };
                Ok(resp.encode_to_vec())
            }
        }
    }

    fn handle_get_compute_task(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetComputeTaskRequest::decode(payload)?;
        let task_id = decode_hash("task_id", &req.task_id)?;
        let Some(record) = self.chain.compute_task(task_id) else {
            return Ok(ComputeTaskResponse {
                found: false,
                record_data: Vec::new(),
                status: 0,
                challenge_deadline: None,
                retain_until_height: None,
            }
            .encode_to_vec());
        };
        let (status, challenge_deadline, retain_until_height) = task_status_fields(&record.status);
        let record_data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&record)
            .map_err(|error| HandlerError::Internal(error.to_string()))?;
        Ok(ComputeTaskResponse {
            found: true,
            record_data,
            status,
            challenge_deadline,
            retain_until_height,
        }
        .encode_to_vec())
    }

    fn handle_list_compute_tasks(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        const MAX_TASK_PAGE: u32 = 100;
        let req = ListComputeTasksRequest::decode(payload)?;
        let limit = if req.limit == 0 {
            20
        } else {
            req.limit.min(MAX_TASK_PAGE)
        };
        let offset = usize::try_from(req.offset).map_err(|_| {
            HandlerError::InvalidRequest("task offset exceeds this platform".into())
        })?;
        let (records, total) = self.chain.compute_tasks(offset, limit as usize);
        let tasks = records
            .into_iter()
            .map(|(task_id, record)| {
                let (status, challenge_deadline, retain_until_height) =
                    task_status_fields(&record.status);
                let record_data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .serialize(&record)
                    .map_err(|error| HandlerError::Internal(error.to_string()))?;
                Ok(ComputeTaskItem {
                    task_id: task_id.to_vec(),
                    record_data,
                    status,
                    challenge_deadline,
                    retain_until_height,
                })
            })
            .collect::<Result<Vec<_>, HandlerError>>()?;
        Ok(ListComputeTasksResponse {
            tasks,
            total: total as u64,
            offset: req.offset,
            limit,
        }
        .encode_to_vec())
    }

    fn handle_get_vm_contract(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetVmContractRequest::decode(payload)?;
        let address = hyphen_vm::ContractAddress(*decode_hash("address", &req.address)?.as_bytes());
        let response = match self.chain.vm_contract(address) {
            Some(contract) => VmContractResponse {
                found: true,
                code_hash: contract.code_hash.to_vec(),
                code: contract.code,
                deployer: contract.deployer.to_vec(),
                deployed_height: contract.deployed_height,
            },
            None => VmContractResponse {
                found: false,
                code_hash: Vec::new(),
                code: Vec::new(),
                deployer: Vec::new(),
                deployed_height: 0,
            },
        };
        Ok(response.encode_to_vec())
    }

    fn handle_get_vm_storage(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = GetVmStorageRequest::decode(payload)?;
        if req.key.len() > hyphen_vm::host::MAX_STORAGE_KEY_SIZE {
            return Err(HandlerError::InvalidRequest(
                "storage key exceeds the protocol limit".into(),
            ));
        }
        let address = hyphen_vm::ContractAddress(*decode_hash("address", &req.address)?.as_bytes());
        let value = self.chain.vm_storage(address, &req.key);
        Ok(VmStorageResponse {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }
        .encode_to_vec())
    }

    fn handle_get_h_wes_roots(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        GetHWesRootsRequest::decode(payload)?;
        let (roots, consensus_root) = self.chain.h_wes_roots();
        Ok(HWesRootsResponse {
            live: roots.live.to_vec(),
            latest: roots.latest.to_vec(),
            nullifiers: roots.nullifiers.to_vec(),
            archive: roots.archive.to_vec(),
            availability: roots.availability.to_vec(),
            consensus_root: consensus_root.to_vec(),
        }
        .encode_to_vec())
    }

    fn handle_submit_tx(&self, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let req = SubmitTransactionRequest::decode(payload)?;
        match hyphen_compute::ComputeTransaction::decode(&req.tx_data) {
            Ok(Some(_)) => {
                let next_height = self
                    .chain
                    .tip()
                    .map_err(|error| HandlerError::Internal(error.to_string()))?
                    .height
                    .checked_add(1)
                    .ok_or_else(|| HandlerError::Internal("chain height exhausted".into()))?;
                if let Err(error) = self.chain.validate_transaction_blobs_for_height(
                    std::slice::from_ref(&req.tx_data),
                    next_height,
                ) {
                    return Ok(SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: format!("validation failed: {error}"),
                    }
                    .encode_to_vec());
                }
                let result = self
                    .mempool
                    .write()
                    .insert_protocol(req.tx_data, hyphen_mempool::ValidatedProtocol::new());
                return Ok(match result {
                    Ok(hash) => SubmitTransactionResponse {
                        accepted: true,
                        tx_hash: hash.to_vec(),
                        error: String::new(),
                    },
                    Err(error) => SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: error.to_string(),
                    },
                }
                .encode_to_vec());
            }
            Ok(None) => {}
            Err(error) => {
                return Err(HandlerError::InvalidRequest(format!(
                    "bad AetherCompute transaction: {error}"
                )));
            }
        }
        match hyphen_vm::VmTransaction::decode(&req.tx_data) {
            Ok(Some(_)) => {
                let next_height = self
                    .chain
                    .tip()
                    .map_err(|error| HandlerError::Internal(error.to_string()))?
                    .height
                    .checked_add(1)
                    .ok_or_else(|| HandlerError::Internal("chain height exhausted".into()))?;
                if let Err(error) = self.chain.validate_transaction_blobs_for_height(
                    std::slice::from_ref(&req.tx_data),
                    next_height,
                ) {
                    return Ok(SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: format!("validation failed: {error}"),
                    }
                    .encode_to_vec());
                }
                let result = self
                    .mempool
                    .write()
                    .insert_protocol(req.tx_data, hyphen_mempool::ValidatedProtocol::new());
                return Ok(match result {
                    Ok(hash) => SubmitTransactionResponse {
                        accepted: true,
                        tx_hash: hash.to_vec(),
                        error: String::new(),
                    },
                    Err(error) => SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: error.to_string(),
                    },
                }
                .encode_to_vec());
            }
            Ok(None) => {}
            Err(error) => {
                return Err(HandlerError::InvalidRequest(format!(
                    "bad WASM transaction: {error}"
                )));
            }
        }
        match hyphen_state::WesTransaction::decode(&req.tx_data) {
            Ok(Some(_)) => {
                let next_height = self
                    .chain
                    .tip()
                    .map_err(|error| HandlerError::Internal(error.to_string()))?
                    .height
                    .checked_add(1)
                    .ok_or_else(|| HandlerError::Internal("chain height exhausted".into()))?;
                if let Err(error) = self.chain.validate_transaction_blobs_for_height(
                    std::slice::from_ref(&req.tx_data),
                    next_height,
                ) {
                    return Ok(SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: format!("validation failed: {error}"),
                    }
                    .encode_to_vec());
                }
                let result = self
                    .mempool
                    .write()
                    .insert_protocol(req.tx_data, hyphen_mempool::ValidatedProtocol::new());
                return Ok(match result {
                    Ok(hash) => SubmitTransactionResponse {
                        accepted: true,
                        tx_hash: hash.to_vec(),
                        error: String::new(),
                    },
                    Err(error) => SubmitTransactionResponse {
                        accepted: false,
                        tx_hash: Vec::new(),
                        error: error.to_string(),
                    },
                }
                .encode_to_vec());
            }
            Ok(None) => {}
            Err(error) => {
                return Err(HandlerError::InvalidRequest(format!(
                    "bad H-WES transaction: {error}"
                )));
            }
        }
        let tx = Transaction::deserialise_limited(&req.tx_data)
            .map_err(|e| HandlerError::InvalidRequest(format!("bad tx data: {e}")))?;

        // ── Pre-validation: check key images against blockchain nullifiers ──
        for inp in &tx.inputs {
            if self
                .chain
                .nullifiers
                .contains(&inp.key_image)
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
        let tip = self
            .chain
            .tip()
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let next_height = tip.height + 1;

        let valid_epoch_contexts = self
            .chain
            .build_valid_epoch_contexts(next_height)
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
        let tx_hashes: Vec<Vec<u8>> = pool
            .hashes()
            .into_iter()
            .map(|hash| hash.to_vec())
            .collect();
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
        let tip = self
            .chain
            .tip()
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        let ceiling = if req.below_index > 0 {
            req.below_index.min(tip.total_outputs)
        } else {
            tip.total_outputs
        };
        let random_outs = self
            .chain
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
            return Err(HandlerError::InvalidRequest(
                "too many indices (max 256)".into(),
            ));
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

fn decode_hash(field: &str, bytes: &[u8]) -> Result<hyphen_crypto::Hash256, HandlerError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HandlerError::InvalidRequest(format!("{field} must be exactly 32 bytes")))?;
    Ok(hyphen_crypto::Hash256::from_bytes(value))
}

fn task_status_fields(status: &hyphen_compute::TaskStatus) -> (u32, Option<u64>, Option<u64>) {
    match status {
        hyphen_compute::TaskStatus::Open => (0, None, None),
        hyphen_compute::TaskStatus::Submitted {
            challenge_deadline, ..
        } => (1, Some(*challenge_deadline), None),
        hyphen_compute::TaskStatus::Rejected { .. } => (2, None, None),
        hyphen_compute::TaskStatus::Finalized {
            retain_until_height,
            ..
        } => (3, None, Some(*retain_until_height)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::{ChainConfig, FEATURE_H_WES};
    use hyphen_crypto::{Hash256, SecretKey};
    use hyphen_state::{
        wes_owner_policy, SignedStateCreate, StateClass, StateRecord, StateStatus, WesTransaction,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!("hyphen-rpc-{}-{sequence}", std::process::id())))
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn handler() -> (TestDb, RpcHandler) {
        let db = TestDb::new();
        let mut cfg = ChainConfig::devnet();
        cfg.consensus_features |= FEATURE_H_WES;
        let chain = Arc::new(Blockchain::open(db.0.to_str().unwrap(), cfg).unwrap());
        let mempool = Arc::new(parking_lot::RwLock::new(Mempool::new(16)));
        (db, RpcHandler::new(chain, mempool))
    }

    fn request<M: Message>(method: u32, payload: M) -> RpcRequest {
        RpcRequest {
            id: 7,
            method,
            payload: payload.encode_to_vec(),
        }
    }

    #[test]
    fn h_wes_submit_is_prevalidated_and_inserted_as_protocol_transaction() {
        let (_db, handler) = handler();
        let owner = SecretKey([51; 32]);
        let transaction = WesTransaction::Create(
            SignedStateCreate::sign(
                StateRecord {
                    chain_id: handler.chain.chain_id(),
                    class: StateClass::ContractStorage,
                    key: Hash256::from_bytes([52; 32]),
                    version: 0,
                    value_hash: Hash256::from_bytes([53; 32]),
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
        let response = handler.handle_request(&request(
            METHOD_SUBMIT_TX,
            SubmitTransactionRequest {
                tx_data: payload.clone(),
            },
        ));
        assert!(response.success, "{}", response.error);
        let submitted = SubmitTransactionResponse::decode(response.payload.as_slice()).unwrap();
        assert!(submitted.accepted, "{}", submitted.error);
        assert_eq!(
            handler
                .mempool
                .read()
                .get_block_candidate_blobs(payload.len()),
            vec![payload]
        );
    }

    #[test]
    fn protocol_state_queries_are_bounded_and_report_missing_values() {
        let (_db, handler) = handler();
        let missing = Hash256::from_bytes([61; 32]).to_vec();

        let response = handler.handle_request(&request(
            METHOD_GET_COMPUTE_TASK,
            GetComputeTaskRequest {
                task_id: missing.clone(),
            },
        ));
        assert!(response.success);
        assert!(
            !ComputeTaskResponse::decode(response.payload.as_slice())
                .unwrap()
                .found
        );

        let response = handler.handle_request(&request(
            METHOD_LIST_COMPUTE_TASKS,
            ListComputeTasksRequest {
                offset: 3,
                limit: 999,
            },
        ));
        assert!(response.success);
        let tasks = ListComputeTasksResponse::decode(response.payload.as_slice()).unwrap();
        assert!(tasks.tasks.is_empty());
        assert_eq!(tasks.total, 0);
        assert_eq!(tasks.offset, 3);
        assert_eq!(tasks.limit, 100);

        let response = handler.handle_request(&request(
            METHOD_GET_VM_CONTRACT,
            GetVmContractRequest {
                address: missing.clone(),
            },
        ));
        assert!(response.success);
        assert!(
            !VmContractResponse::decode(response.payload.as_slice())
                .unwrap()
                .found
        );

        let response = handler.handle_request(&request(
            METHOD_GET_VM_STORAGE,
            GetVmStorageRequest {
                address: missing,
                key: vec![0; hyphen_vm::host::MAX_STORAGE_KEY_SIZE + 1],
            },
        ));
        assert!(!response.success);
        assert!(response.error.contains("storage key"));

        let response =
            handler.handle_request(&request(METHOD_GET_H_WES_ROOTS, GetHWesRootsRequest {}));
        assert!(response.success);
        let roots = HWesRootsResponse::decode(response.payload.as_slice()).unwrap();
        assert_eq!(roots.live.len(), 32);
        assert_eq!(roots.latest.len(), 32);
        assert_eq!(roots.nullifiers.len(), 32);
        assert_eq!(roots.archive.len(), 32);
        assert_eq!(roots.availability.len(), 32);
        assert_eq!(roots.consensus_root, Hash256::ZERO.to_vec());
    }
}
