use serde::{Deserialize, Serialize};
use thiserror::Error;

use hyphen_consensus::{InclusionReceiptVoteGossip, QuorumInclusionReceiptGossip};
use hyphen_state::{
    verify_blob_chunk_proof, verify_blob_metadata, BlobChunkProof, BlobMetadata, SparseMerkleProof,
};

pub const MAX_GOSSIP_TRANSACTION_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GOSSIP_BLOCK_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_GOSSIP_ENVELOPE_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_GOSSIP_RECEIPT_SIZE: usize = 512 * 1024;
pub const MAX_SYNC_BLOCK_COUNT: u32 = 500;
pub const MAX_SYNC_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NETWORK_ERROR_BYTES: usize = 512;

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
    #[error("fairness receipt exceeds the size limit")]
    ReceiptTooLarge,
    #[error("fairness receipt is structurally invalid")]
    InvalidReceipt,
    #[error("unknown network message type {0}")]
    UnknownMessageType(u8),
    #[error("invalid or unbounded sync request")]
    InvalidSyncRequest,
    #[error("invalid, unauthenticated or oversized sync response")]
    InvalidSyncResponse,
    #[error("protobuf decode failed: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("canonical payload decode failed: {0}")]
    Codec(#[from] rustbinary::Error),
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkMessage {
    NewTransaction(Vec<u8>),
    NewBlock(Vec<u8>),
    InclusionReceiptVote(InclusionReceiptVoteGossip),
    QuorumInclusionReceipt(QuorumInclusionReceiptGossip),
}

impl NetworkMessage {
    pub fn encode_proto(&self) -> Result<Vec<u8>, NetworkDecodeError> {
        use prost::Message;
        let encoded = match self {
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
            NetworkMessage::InclusionReceiptVote(receipt) => {
                receipt
                    .validate_shape()
                    .map_err(|_| NetworkDecodeError::InvalidReceipt)?;
                encode_receipt_payload(2, receipt)?
            }
            NetworkMessage::QuorumInclusionReceipt(receipt) => {
                receipt
                    .validate_shape()
                    .map_err(|_| NetworkDecodeError::InvalidReceipt)?;
                encode_receipt_payload(3, receipt)?
            }
        };
        if encoded.len() > MAX_GOSSIP_ENVELOPE_SIZE {
            return Err(NetworkDecodeError::EnvelopeTooLarge);
        }
        Ok(encoded)
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
            2 => {
                let payload = decode_receipt_payload(&data[1..])?;
                let receipt: InclusionReceiptVoteGossip =
                    crate::wire_config(MAX_GOSSIP_RECEIPT_SIZE).deserialize(&payload)?;
                receipt
                    .validate_shape()
                    .map_err(|_| NetworkDecodeError::InvalidReceipt)?;
                Ok(NetworkMessage::InclusionReceiptVote(receipt))
            }
            3 => {
                let payload = decode_receipt_payload(&data[1..])?;
                let receipt: QuorumInclusionReceiptGossip =
                    crate::wire_config(MAX_GOSSIP_RECEIPT_SIZE).deserialize(&payload)?;
                receipt
                    .validate_shape()
                    .map_err(|_| NetworkDecodeError::InvalidReceipt)?;
                Ok(NetworkMessage::QuorumInclusionReceipt(receipt))
            }
            message_type => Err(NetworkDecodeError::UnknownMessageType(message_type)),
        }
    }
}

fn encode_receipt_payload<T: Serialize>(tag: u8, value: &T) -> Result<Vec<u8>, NetworkDecodeError> {
    use prost::Message;
    let data = crate::wire_config(MAX_GOSSIP_RECEIPT_SIZE).serialize(value)?;
    let mut encoded = vec![tag];
    encoded.extend_from_slice(&ProtoTransaction { data }.encode_to_vec());
    Ok(encoded)
}

fn decode_receipt_payload(data: &[u8]) -> Result<Vec<u8>, NetworkDecodeError> {
    use prost::Message;
    let payload = ProtoTransaction::decode(data)?.data;
    if payload.len() > MAX_GOSSIP_RECEIPT_SIZE {
        return Err(NetworkDecodeError::ReceiptTooLarge);
    }
    Ok(payload)
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
    GetStateProof {
        namespace: [u8; 32],
        root: [u8; 32],
        key: [u8; 32],
    },
    GetBlobMetadata {
        object_hash: [u8; 32],
    },
    GetBlobChunk {
        object_hash: [u8; 32],
        index: u32,
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
    StateProof {
        root: [u8; 32],
        proof: SparseMerkleProof,
    },
    BlobMetadata(BlobMetadata),
    BlobChunk(BlobChunkProof),
    Error(String),
}

impl SyncRequest {
    pub fn validate(&self) -> Result<(), NetworkDecodeError> {
        if let Self::GetBlocks { count, .. } = self {
            if *count == 0 || *count > MAX_SYNC_BLOCK_COUNT {
                return Err(NetworkDecodeError::InvalidSyncRequest);
            }
        }
        Ok(())
    }
}

impl SyncResponse {
    pub fn validate(&self) -> Result<(), NetworkDecodeError> {
        match self {
            Self::Blocks(blocks) => {
                if blocks.len() > MAX_SYNC_BLOCK_COUNT as usize
                    || blocks
                        .iter()
                        .any(|block| block.len() > MAX_GOSSIP_BLOCK_SIZE)
                    || blocks
                        .iter()
                        .try_fold(0usize, |sum, block| sum.checked_add(block.len()))
                        .is_none_or(|sum| sum > MAX_SYNC_RESPONSE_BYTES)
                {
                    return Err(NetworkDecodeError::InvalidSyncResponse);
                }
            }
            Self::Block(block) if block.len() > MAX_GOSSIP_BLOCK_SIZE => {
                return Err(NetworkDecodeError::InvalidSyncResponse);
            }
            Self::StateProof { root, proof } => {
                let root = hyphen_crypto::Hash256::from_bytes(*root);
                if !hyphen_state::verify_sparse_merkle_proof(root, proof) {
                    return Err(NetworkDecodeError::InvalidSyncResponse);
                }
            }
            Self::BlobMetadata(metadata) if !verify_blob_metadata(metadata) => {
                return Err(NetworkDecodeError::InvalidSyncResponse);
            }
            Self::BlobChunk(proof) if !verify_blob_chunk_proof(proof) => {
                return Err(NetworkDecodeError::InvalidSyncResponse);
            }
            Self::Error(message) if message.len() > MAX_NETWORK_ERROR_BYTES => {
                return Err(NetworkDecodeError::InvalidSyncResponse);
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_consensus::{
        InclusionReceiptStatement, InclusionReceiptVote, InclusionReceiptVoteGossip,
    };
    use hyphen_crypto::{Hash256, SecretKey, Signature};
    use prost::Message;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn receipt_vote_gossip() -> InclusionReceiptVoteGossip {
        let metadata = hyphen_consensus::VisibleMetadata {
            transaction_id: hash(4),
            fee_class: 2,
            encoded_len: 512,
            conflict_tag: hash(5),
        };
        InclusionReceiptVoteGossip {
            statement: InclusionReceiptStatement {
                chain_id: hash(1),
                epoch: 9,
                committee_id: hash(2),
                slot: 7,
                cutoff: 100,
                transaction_id: metadata.transaction_id,
                metadata_hash: metadata.hash(),
            },
            metadata,
            vote: InclusionReceiptVote {
                seat: 3,
                observed_at: 90,
                signature: Signature([6; 64]),
            },
        }
    }

    #[test]
    fn proto_network_message_roundtrip_tx() {
        let msg = NetworkMessage::NewTransaction(vec![1, 2, 3, 4]);
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::NewTransaction(data) => assert_eq!(data, vec![1, 2, 3, 4]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn h_wes_envelope_round_trips_as_transaction_gossip() {
        let owner = SecretKey([31; 32]);
        let record = hyphen_state::StateRecord {
            chain_id: hash(1),
            class: hyphen_state::StateClass::ContractStorage,
            key: hash(2),
            version: 0,
            value_hash: hash(3),
            owner_policy: hyphen_state::wes_owner_policy(owner.public_key()),
            created_at: 7,
            lease_end: 20,
            status: hyphen_state::StateStatus::Live,
        };
        let transaction = hyphen_state::WesTransaction::Create(
            hyphen_state::SignedStateCreate::sign(record, &owner).unwrap(),
        );
        let payload = transaction.encode().unwrap();
        let encoded = NetworkMessage::NewTransaction(payload)
            .encode_proto()
            .unwrap();
        let NetworkMessage::NewTransaction(decoded) =
            NetworkMessage::decode_proto(&encoded).unwrap()
        else {
            panic!("wrong gossip variant");
        };
        assert_eq!(
            hyphen_state::WesTransaction::decode(&decoded).unwrap(),
            Some(transaction)
        );
    }

    #[test]
    fn proto_network_message_roundtrip_block() {
        let msg = NetworkMessage::NewBlock(vec![10, 20, 30]);
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::NewBlock(data) => assert_eq!(data, vec![10, 20, 30]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn receipt_vote_round_trip_preserves_the_signed_statement() {
        let receipt = receipt_vote_gossip();
        let encoded = NetworkMessage::InclusionReceiptVote(receipt.clone())
            .encode_proto()
            .unwrap();
        assert_eq!(
            NetworkMessage::decode_proto(&encoded).unwrap(),
            NetworkMessage::InclusionReceiptVote(receipt)
        );
    }

    #[test]
    fn receipt_gossip_rejects_post_cutoff_votes() {
        let mut receipt = receipt_vote_gossip();
        receipt.vote.observed_at = receipt.statement.cutoff + 1;
        assert!(matches!(
            NetworkMessage::InclusionReceiptVote(receipt).encode_proto(),
            Err(NetworkDecodeError::InvalidReceipt)
        ));
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

    #[test]
    fn sync_request_limits_reject_zero_excessive_and_overflow_prone_ranges() {
        assert!(SyncRequest::GetBlocks {
            start_height: 0,
            count: 0
        }
        .validate()
        .is_err());
        assert!(SyncRequest::GetBlocks {
            start_height: u64::MAX,
            count: MAX_SYNC_BLOCK_COUNT + 1
        }
        .validate()
        .is_err());
        assert!(SyncRequest::GetBlocks {
            start_height: 1,
            count: MAX_SYNC_BLOCK_COUNT
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn invalid_state_and_blob_proofs_fail_response_validation() {
        let response = SyncResponse::StateProof {
            root: [0; 32],
            proof: SparseMerkleProof {
                namespace: hyphen_crypto::Hash256::ZERO,
                key: hyphen_crypto::Hash256::ZERO,
                value: None,
                siblings: vec![],
            },
        };
        assert!(response.validate().is_err());

        let oversized = SyncResponse::Error("x".repeat(MAX_NETWORK_ERROR_BYTES + 1));
        assert!(oversized.validate().is_err());
    }
}
