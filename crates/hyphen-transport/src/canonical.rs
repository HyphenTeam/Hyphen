use prost::Message;

pub const TP_CANONICAL_HASHES: u32 = 121;
pub const TP_CANONICAL_HASHES_RESULT: u32 = 122;
pub const MAX_CANONICAL_HEIGHTS: usize = 128;

#[derive(Clone, Message)]
pub struct CanonicalHashesRequest {
    #[prost(message, optional, tag = "1")]
    pub chain: Option<super::TemplateRequest>,
    #[prost(uint64, repeated, tag = "2")]
    pub heights: Vec<u64>,
}

#[derive(Clone, Message)]
pub struct CanonicalHashesResult {
    #[prost(uint64, tag = "1")]
    pub request_nonce: u64,
    #[prost(uint64, tag = "2")]
    pub tip_height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub tip_hash: Vec<u8>,
    /// One hash per requested height, empty above the tip.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub hashes: Vec<Vec<u8>>,
}
