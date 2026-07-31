#[derive(Clone, prost::Message)]
pub struct GetBlockRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct GetBlockByHeightRequest {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}

#[derive(Clone, prost::Message)]
pub struct BlockResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub header_data: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub transactions: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub hash: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub height: u64,
    #[prost(uint64, tag = "5")]
    pub timestamp: u64,
}

#[derive(Clone, prost::Message)]
pub struct GetChainInfoRequest {}

#[derive(Clone, prost::Message)]
pub struct ChainInfoResponse {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub tip_hash: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub difficulty: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub cumulative_difficulty: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub total_outputs: u64,
    #[prost(string, tag = "6")]
    pub network: String,
    #[prost(bytes = "vec", tag = "7")]
    pub epoch_seed: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct SubmitTransactionRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub tx_data: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct SubmitTransactionResponse {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub tx_hash: Vec<u8>,
    #[prost(string, tag = "3")]
    pub error: String,
}

#[derive(Clone, prost::Message)]
pub struct GetMempoolRequest {}

#[derive(Clone, prost::Message)]
pub struct MempoolResponse {
    #[prost(uint64, tag = "1")]
    pub tx_count: u64,
    #[prost(uint64, tag = "2")]
    pub total_size: u64,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub tx_hashes: Vec<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct GetTxLocationRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub tx_hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct TxLocationResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub block_hash: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub tx_index: u32,
    #[prost(bool, tag = "3")]
    pub found: bool,
    #[prost(uint64, tag = "4")]
    pub block_height: u64,
}

#[derive(Clone, prost::Message)]
pub struct RpcRequest {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(uint32, tag = "2")]
    pub method: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct RpcResponse {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(bool, tag = "2")]
    pub success: bool,
    #[prost(bytes = "vec", tag = "3")]
    pub payload: Vec<u8>,
    #[prost(string, tag = "4")]
    pub error: String,
}

pub const METHOD_GET_BLOCK: u32 = 1;
pub const METHOD_GET_BLOCK_BY_HEIGHT: u32 = 2;
pub const METHOD_GET_CHAIN_INFO: u32 = 3;
pub const METHOD_SUBMIT_TX: u32 = 4;
pub const METHOD_GET_MEMPOOL: u32 = 5;
pub const METHOD_GET_TX_LOCATION: u32 = 6;
pub const METHOD_GET_RANDOM_OUTPUTS: u32 = 7;
pub const METHOD_GET_OUTPUT_INFO: u32 = 8;
pub const METHOD_GET_COMPUTE_TASK: u32 = 9;
pub const METHOD_GET_VM_CONTRACT: u32 = 10;
pub const METHOD_GET_VM_STORAGE: u32 = 11;
pub const METHOD_GET_H_WES_ROOTS: u32 = 12;
pub const METHOD_LIST_COMPUTE_TASKS: u32 = 13;

#[derive(Clone, prost::Message)]
pub struct GetComputeTaskRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub task_id: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ComputeTaskResponse {
    #[prost(bool, tag = "1")]
    pub found: bool,
    /// Canonical `hyphen_compute::TaskRecord` bytes for lossless clients.
    #[prost(bytes = "vec", tag = "2")]
    pub record_data: Vec<u8>,
    /// 0=open, 1=submitted, 2=rejected, 3=finalized.
    #[prost(uint32, tag = "3")]
    pub status: u32,
    #[prost(uint64, optional, tag = "4")]
    pub challenge_deadline: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub retain_until_height: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct ListComputeTasksRequest {
    #[prost(uint64, tag = "1")]
    pub offset: u64,
    #[prost(uint32, tag = "2")]
    pub limit: u32,
}

#[derive(Clone, prost::Message)]
pub struct ComputeTaskItem {
    #[prost(bytes = "vec", tag = "1")]
    pub task_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub record_data: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub status: u32,
    #[prost(uint64, optional, tag = "4")]
    pub challenge_deadline: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub retain_until_height: Option<u64>,
}

#[derive(Clone, prost::Message)]
pub struct ListComputeTasksResponse {
    #[prost(message, repeated, tag = "1")]
    pub tasks: Vec<ComputeTaskItem>,
    #[prost(uint64, tag = "2")]
    pub total: u64,
    #[prost(uint64, tag = "3")]
    pub offset: u64,
    #[prost(uint32, tag = "4")]
    pub limit: u32,
}

#[derive(Clone, prost::Message)]
pub struct GetVmContractRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct VmContractResponse {
    #[prost(bool, tag = "1")]
    pub found: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub code_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub code: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub deployer: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub deployed_height: u64,
}

#[derive(Clone, prost::Message)]
pub struct GetVmStorageRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub key: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct VmStorageResponse {
    #[prost(bool, tag = "1")]
    pub found: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct GetHWesRootsRequest {}

#[derive(Clone, prost::Message)]
pub struct HWesRootsResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub live: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub latest: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub nullifiers: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub archive: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub availability: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub consensus_root: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct GetOutputInfoRequest {
    #[prost(uint64, repeated, tag = "1")]
    pub global_indices: Vec<u64>,
}

#[derive(Clone, prost::Message)]
pub struct GetOutputInfoResponse {
    #[prost(message, repeated, tag = "1")]
    pub outputs: Vec<OutputInfo>,
}

#[derive(Clone, prost::Message)]
pub struct GetRandomOutputsRequest {
    #[prost(uint32, tag = "1")]
    pub count: u32,
    #[prost(uint64, tag = "2")]
    pub below_index: u64,
}

#[derive(Clone, prost::Message)]
pub struct OutputInfo {
    #[prost(bytes = "vec", tag = "1")]
    pub one_time_pubkey: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub commitment: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub global_index: u64,
    #[prost(uint64, tag = "4")]
    pub block_height: u64,
}

#[derive(Clone, prost::Message)]
pub struct RandomOutputsResponse {
    #[prost(message, repeated, tag = "1")]
    pub outputs: Vec<OutputInfo>,
}

#[cfg(test)]
mod adversarial_decode_tests {
    use super::*;
    use prost::Message;

    #[test]
    fn deterministic_malformed_rpc_corpus_never_panics() {
        let mut state = 0x3c6e_f372_fe94_f82bu64;
        for len in 0..=4096usize {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let result = std::panic::catch_unwind(|| RpcRequest::decode(bytes.as_slice()));
            assert!(
                result.is_ok(),
                "RPC decoder panicked for corpus length {len}"
            );
        }
    }

    #[test]
    fn rpc_request_roundtrip_preserves_untrusted_payload() {
        let request = RpcRequest {
            id: 7,
            method: METHOD_SUBMIT_TX,
            payload: vec![0xff; 1024],
        };
        let decoded = RpcRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.method, METHOD_SUBMIT_TX);
        assert_eq!(decoded.payload, vec![0xff; 1024]);
    }
}
