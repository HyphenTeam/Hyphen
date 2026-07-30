use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_GOSSIP_TRANSACTION_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GOSSIP_BLOCK_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GOSSIP_ENVELOPE_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetworkDecodeError {
    #[error("empty network message")]
    EmptyMessage,
    #[error("gossip envelope exceeds the size limit")]
    EnvelopeTooLarge,
    #[error("gossip transaction exceeds the size limit")]
    TransactionTooLarge,
    #[error("gossip block exceeds the size limit")]
    BlockTooLarge,
    #[error("unknown network message type {0}")]
    UnknownMessageType(u8),
    #[error("protobuf decode failed: {0}")]
    Protobuf(#[from] prost::DecodeError),
}

#[derive(Clone, prost::Message)]
pub struct ProtoTransaction {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ProtoBlock {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ProtoGetBlocks {
    #[prost(uint64, tag = "1")]
    pub start_height: u64,
    #[prost(uint32, tag = "2")]
    pub count: u32,
}

#[derive(Clone, prost::Message)]
pub struct ProtoGetBlock {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ProtoTip {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub cumulative_difficulty: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ProtoBlocks {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub blocks: Vec<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct ProtoError {
    #[prost(string, tag = "1")]
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    NewTransaction(Vec<u8>),
    NewBlock(Vec<u8>),
}

impl NetworkMessage {
    pub fn encode_proto(&self) -> Vec<u8> {
        use prost::Message;
        match self {
            NetworkMessage::NewTransaction(data) => {
                let mut buf = vec![0u8]; // tag byte: 0 = tx
                let proto = ProtoTransaction { data: data.clone() };
                let encoded = proto.encode_to_vec();
                buf.extend_from_slice(&encoded);
                buf
            }
            NetworkMessage::NewBlock(data) => {
                let mut buf = vec![1u8]; // tag byte: 1 = block
                let proto = ProtoBlock { data: data.clone() };
                let encoded = proto.encode_to_vec();
                buf.extend_from_slice(&encoded);
                buf
            }
        }
    }

    pub fn decode_proto(data: &[u8]) -> Result<Self, NetworkDecodeError> {
        use prost::Message;
        if data.is_empty() {
            return Err(NetworkDecodeError::EmptyMessage);
        }
        if data.len() > MAX_GOSSIP_ENVELOPE_SIZE {
            return Err(NetworkDecodeError::EnvelopeTooLarge);
        }
        match data[0] {
            0 => {
                let proto = ProtoTransaction::decode(&data[1..])?;
                if proto.data.len() > MAX_GOSSIP_TRANSACTION_SIZE {
                    return Err(NetworkDecodeError::TransactionTooLarge);
                }
                Ok(NetworkMessage::NewTransaction(proto.data))
            }
            1 => {
                let proto = ProtoBlock::decode(&data[1..])?;
                if proto.data.len() > MAX_GOSSIP_BLOCK_SIZE {
                    return Err(NetworkDecodeError::BlockTooLarge);
                }
                Ok(NetworkMessage::NewBlock(proto.data))
            }
            message_type => Err(NetworkDecodeError::UnknownMessageType(message_type)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlocks { start_height: u64, count: u32 },
    GetTip,
    GetBlock { hash: [u8; 32] },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    Blocks(Vec<Vec<u8>>),
    Tip {
        height: u64,
        hash: [u8; 32],
        cumulative_difficulty: u128,
    },
    Block(Vec<u8>),
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn proto_network_message_roundtrip_tx() {
        let msg = NetworkMessage::NewTransaction(vec![1, 2, 3, 4]);
        let encoded = msg.encode_proto();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::NewTransaction(data) => assert_eq!(data, vec![1, 2, 3, 4]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn proto_network_message_roundtrip_block() {
        let msg = NetworkMessage::NewBlock(vec![10, 20, 30]);
        let encoded = msg.encode_proto();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::NewBlock(data) => assert_eq!(data, vec![10, 20, 30]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn rejects_oversized_gossip_payloads() {
        let message = ProtoTransaction {
            data: vec![0u8; MAX_GOSSIP_TRANSACTION_SIZE + 1],
        };
        let mut encoded = vec![0u8];
        encoded.extend_from_slice(&message.encode_to_vec());
        assert!(NetworkMessage::decode_proto(&encoded).is_err());
        assert!(NetworkMessage::decode_proto(&vec![0u8; MAX_GOSSIP_ENVELOPE_SIZE + 1]).is_err());
    }

    #[test]
    fn deterministic_malformed_gossip_corpus_never_panics() {
        let mut state = 0xbb67_ae85_84ca_a73bu64;
        for len in 0..=4096usize {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let result = std::panic::catch_unwind(|| NetworkMessage::decode_proto(&bytes));
            assert!(
                result.is_ok(),
                "gossip decoder panicked for corpus length {len}"
            );
        }
    }
}
