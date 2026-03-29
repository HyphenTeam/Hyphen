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
