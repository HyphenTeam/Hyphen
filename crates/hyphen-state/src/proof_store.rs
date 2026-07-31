//! Content-addressed, chunk-authenticated storage for proof and state blobs.

use hyphen_crypto::merkle::{MerkleProof, MerkleTree};
use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use thiserror::Error;

pub const MIN_BLOB_CHUNK_SIZE: u32 = 4 * 1024;
pub const MAX_BLOB_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_PROOF_BLOB_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_BLOB_CHUNKS: u32 = 4096;

const META_PREFIX: u8 = 0x20;
const CHUNK_PREFIX: u8 = 0x21;
const D_BLOB: &[u8] = b"HYPHEN_PROOF_BLOB_V1";
const D_CHUNK: &[u8] = b"HYPHEN_PROOF_BLOB_CHUNK_V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobMetadata {
    pub object_hash: Hash256,
    pub byte_len: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub chunk_root: Hash256,
}

impl BlobMetadata {
    pub fn canonical_bytes(&self) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[..32].copy_from_slice(self.object_hash.as_bytes());
        bytes[32..40].copy_from_slice(&self.byte_len.to_be_bytes());
        bytes[40..44].copy_from_slice(&self.chunk_size.to_be_bytes());
        bytes[44..48].copy_from_slice(&self.chunk_count.to_be_bytes());
        bytes[48..].copy_from_slice(self.chunk_root.as_bytes());
        bytes
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 80 {
            return None;
        }
        Some(Self {
            object_hash: hash_from_slice(&bytes[..32])?,
            byte_len: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            chunk_size: u32::from_be_bytes(bytes[40..44].try_into().ok()?),
            chunk_count: u32::from_be_bytes(bytes[44..48].try_into().ok()?),
            chunk_root: hash_from_slice(&bytes[48..80])?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobChunkProof {
    pub metadata: BlobMetadata,
    pub chunk_index: u32,
    pub chunk: Vec<u8>,
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Error)]
pub enum ProofStoreError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("blob is empty or exceeds the protocol size limit")]
    InvalidBlobSize,
    #[error("chunk size must be a power of two within the protocol bounds")]
    InvalidChunkSize,
    #[error("blob requires too many chunks")]
    TooManyChunks,
    #[error("blob metadata is malformed")]
    InvalidMetadata,
    #[error("content-addressed blob conflicts with existing data")]
    ContentConflict,
    #[error("blob was not found")]
    NotFound,
    #[error("chunk index is outside the committed blob")]
    InvalidChunkIndex,
    #[error("persisted blob failed its content hash")]
    CorruptBlob,
    #[error("blob storage transaction failed: {0}")]
    Transaction(String),
}

#[derive(Clone, Copy, Debug)]
enum BlobAbort {
    ContentConflict,
}

pub struct AuthenticatedBlobStore {
    tree: sled::Tree,
}

impl AuthenticatedBlobStore {
    pub fn open(db: &sled::Db) -> Result<Self, ProofStoreError> {
        Ok(Self {
            tree: db.open_tree("authenticated_proof_blobs_v1")?,
        })
    }

    pub fn put(&self, blob: &[u8], chunk_size: u32) -> Result<BlobMetadata, ProofStoreError> {
        let metadata = describe_blob(blob, chunk_size)?;
        let object_hash = metadata.object_hash;
        let chunks = blob.chunks(chunk_size as usize).collect::<Vec<_>>();
        let metadata_key = metadata_key(object_hash);
        let metadata_bytes = metadata.canonical_bytes();
        let result: Result<(), TransactionError<BlobAbort>> = self.tree.transaction(|tx| {
            if let Some(existing) = tx.get(&metadata_key)? {
                if existing.as_ref() != metadata_bytes {
                    return Err(ConflictableTransactionError::Abort(
                        BlobAbort::ContentConflict,
                    ));
                }
            }
            tx.insert(metadata_key.as_slice(), metadata_bytes.as_slice())?;
            for (index, chunk) in chunks.iter().enumerate() {
                let key = chunk_key(object_hash, index as u32);
                if let Some(existing) = tx.get(&key)? {
                    if existing.as_ref() != *chunk {
                        return Err(ConflictableTransactionError::Abort(
                            BlobAbort::ContentConflict,
                        ));
                    }
                }
                tx.insert(key.as_slice(), *chunk)?;
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.tree.flush()?;
                Ok(metadata)
            }
            Err(TransactionError::Abort(BlobAbort::ContentConflict)) => {
                Err(ProofStoreError::ContentConflict)
            }
            Err(TransactionError::Storage(error)) => {
                Err(ProofStoreError::Transaction(error.to_string()))
            }
        }
    }

    pub fn metadata(&self, object_hash: Hash256) -> Result<BlobMetadata, ProofStoreError> {
        let bytes = self
            .tree
            .get(metadata_key(object_hash))?
            .ok_or(ProofStoreError::NotFound)?;
        let metadata =
            BlobMetadata::from_canonical_bytes(&bytes).ok_or(ProofStoreError::InvalidMetadata)?;
        validate_metadata(&metadata)?;
        if metadata.object_hash != object_hash {
            return Err(ProofStoreError::InvalidMetadata);
        }
        Ok(metadata)
    }

    pub fn chunk_proof(
        &self,
        object_hash: Hash256,
        chunk_index: u32,
    ) -> Result<BlobChunkProof, ProofStoreError> {
        let metadata = self.metadata(object_hash)?;
        if chunk_index >= metadata.chunk_count {
            return Err(ProofStoreError::InvalidChunkIndex);
        }
        let mut merkle = MerkleTree::new();
        let mut requested = None;
        for index in 0..metadata.chunk_count {
            let chunk = self
                .tree
                .get(chunk_key(object_hash, index))?
                .ok_or(ProofStoreError::CorruptBlob)?
                .to_vec();
            if index == chunk_index {
                requested = Some(chunk.clone());
            }
            merkle.append(chunk_hash(object_hash, index, metadata.chunk_count, &chunk));
        }
        if merkle.root() != metadata.chunk_root {
            return Err(ProofStoreError::CorruptBlob);
        }
        Ok(BlobChunkProof {
            metadata,
            chunk_index,
            chunk: requested.ok_or(ProofStoreError::CorruptBlob)?,
            merkle_proof: merkle
                .prove(chunk_index as u64)
                .ok_or(ProofStoreError::CorruptBlob)?,
        })
    }

    pub fn get(&self, object_hash: Hash256) -> Result<Vec<u8>, ProofStoreError> {
        let metadata = self.metadata(object_hash)?;
        let capacity =
            usize::try_from(metadata.byte_len).map_err(|_| ProofStoreError::InvalidMetadata)?;
        let mut blob = Vec::with_capacity(capacity);
        for index in 0..metadata.chunk_count {
            let chunk = self
                .tree
                .get(chunk_key(object_hash, index))?
                .ok_or(ProofStoreError::CorruptBlob)?;
            blob.extend_from_slice(&chunk);
        }
        blob.truncate(capacity);
        if blob_hash(&blob) != object_hash {
            return Err(ProofStoreError::CorruptBlob);
        }
        Ok(blob)
    }

    pub fn flush(&self) -> Result<(), ProofStoreError> {
        self.tree.flush()?;
        Ok(())
    }
}

pub fn verify_blob_chunk_proof(proof: &BlobChunkProof) -> bool {
    if !verify_blob_metadata(&proof.metadata)
        || proof.chunk_index >= proof.metadata.chunk_count
        || proof.merkle_proof.leaf_index != proof.chunk_index as u64
    {
        return false;
    }
    let expected_len = if proof.chunk_index + 1 == proof.metadata.chunk_count {
        let consumed = proof.metadata.chunk_size as u64 * proof.chunk_index as u64;
        proof.metadata.byte_len.saturating_sub(consumed) as usize
    } else {
        proof.metadata.chunk_size as usize
    };
    if proof.chunk.len() != expected_len {
        return false;
    }
    let leaf = chunk_hash(
        proof.metadata.object_hash,
        proof.chunk_index,
        proof.metadata.chunk_count,
        &proof.chunk,
    );
    proof.merkle_proof.verify(&leaf, &proof.metadata.chunk_root)
}

pub fn verify_blob_metadata(metadata: &BlobMetadata) -> bool {
    validate_metadata(metadata).is_ok()
}

pub fn blob_hash(blob: &[u8]) -> Hash256 {
    hash_parts(D_BLOB, &[&(blob.len() as u64).to_be_bytes(), blob])
}

pub fn describe_blob(blob: &[u8], chunk_size: u32) -> Result<BlobMetadata, ProofStoreError> {
    validate_blob_parameters(blob.len(), chunk_size)?;
    let object_hash = blob_hash(blob);
    let chunks = blob.chunks(chunk_size as usize).collect::<Vec<_>>();
    let chunk_count = u32::try_from(chunks.len()).map_err(|_| ProofStoreError::TooManyChunks)?;
    if chunk_count > MAX_BLOB_CHUNKS {
        return Err(ProofStoreError::TooManyChunks);
    }
    let mut merkle = MerkleTree::new();
    for (index, chunk) in chunks.iter().enumerate() {
        merkle.append(chunk_hash(object_hash, index as u32, chunk_count, chunk));
    }
    Ok(BlobMetadata {
        object_hash,
        byte_len: blob.len() as u64,
        chunk_size,
        chunk_count,
        chunk_root: merkle.root(),
    })
}

fn chunk_hash(object_hash: Hash256, index: u32, count: u32, chunk: &[u8]) -> Hash256 {
    hash_parts(
        D_CHUNK,
        &[
            object_hash.as_bytes(),
            &index.to_be_bytes(),
            &count.to_be_bytes(),
            &(chunk.len() as u32).to_be_bytes(),
            chunk,
        ],
    )
}

fn validate_blob_parameters(len: usize, chunk_size: u32) -> Result<(), ProofStoreError> {
    if len == 0 || len > MAX_PROOF_BLOB_SIZE {
        return Err(ProofStoreError::InvalidBlobSize);
    }
    if !(MIN_BLOB_CHUNK_SIZE..=MAX_BLOB_CHUNK_SIZE).contains(&chunk_size)
        || !chunk_size.is_power_of_two()
    {
        return Err(ProofStoreError::InvalidChunkSize);
    }
    Ok(())
}

fn validate_metadata(metadata: &BlobMetadata) -> Result<(), ProofStoreError> {
    let byte_len =
        usize::try_from(metadata.byte_len).map_err(|_| ProofStoreError::InvalidMetadata)?;
    validate_blob_parameters(byte_len, metadata.chunk_size)?;
    let expected_count = metadata.byte_len.div_ceil(metadata.chunk_size as u64);
    if metadata.chunk_count == 0
        || metadata.chunk_count > MAX_BLOB_CHUNKS
        || expected_count != metadata.chunk_count as u64
    {
        return Err(ProofStoreError::InvalidMetadata);
    }
    Ok(())
}

fn metadata_key(object_hash: Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(META_PREFIX);
    key.extend_from_slice(object_hash.as_bytes());
    key
}

fn chunk_key(object_hash: Hash256, index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(37);
    key.push(CHUNK_PREFIX);
    key.extend_from_slice(object_hash.as_bytes());
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn hash_from_slice(bytes: &[u8]) -> Option<Hash256> {
    Some(Hash256::from_bytes(bytes.try_into().ok()?))
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    for part in parts {
        hasher.update(part);
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_chunk_has_a_verifiable_proof_and_blob_reopens() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let store = AuthenticatedBlobStore::open(&db).unwrap();
        let blob = (0..20_000u32)
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>();
        let metadata = store.put(&blob, MIN_BLOB_CHUNK_SIZE).unwrap();
        assert_eq!(metadata.chunk_count, 20);
        for index in 0..metadata.chunk_count {
            assert!(verify_blob_chunk_proof(
                &store.chunk_proof(metadata.object_hash, index).unwrap()
            ));
        }
        store.flush().unwrap();
        drop(store);
        let reopened = AuthenticatedBlobStore::open(&db).unwrap();
        assert_eq!(reopened.get(metadata.object_hash).unwrap(), blob);
    }

    #[test]
    fn malformed_parameters_and_proofs_fail_closed() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let store = AuthenticatedBlobStore::open(&db).unwrap();
        assert!(matches!(
            store.put(&[], MIN_BLOB_CHUNK_SIZE),
            Err(ProofStoreError::InvalidBlobSize)
        ));
        assert!(matches!(
            store.put(&[1], 5000),
            Err(ProofStoreError::InvalidChunkSize)
        ));
        let metadata = store.put(&vec![7; 9000], MIN_BLOB_CHUNK_SIZE).unwrap();
        let mut proof = store.chunk_proof(metadata.object_hash, 1).unwrap();
        proof.chunk[0] ^= 1;
        assert!(!verify_blob_chunk_proof(&proof));
        assert!(matches!(
            store.chunk_proof(metadata.object_hash, metadata.chunk_count),
            Err(ProofStoreError::InvalidChunkIndex)
        ));
    }
}
