use serde::{Deserialize, Serialize};

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

    pub fn decode_proto(data: &[u8]) -> Result<Self, prost::DecodeError> {
        use prost::Message;
        if data.is_empty() {
            return Err(prost::DecodeError::new("empty message"));
        }
        match data[0] {
            0 => {
                let proto = ProtoTransaction::decode(&data[1..])?;
                Ok(NetworkMessage::NewTransaction(proto.data))
            }
            1 => {
                let proto = ProtoBlock::decode(&data[1..])?;
                Ok(NetworkMessage::NewBlock(proto.data))
            }
            _ => Err(prost::DecodeError::new("unknown message type")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlocks {
        start_height: u64,
        count: u32,
    },
    GetTip,
    GetBlock {
        hash: [u8; 32],
    },
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
}
