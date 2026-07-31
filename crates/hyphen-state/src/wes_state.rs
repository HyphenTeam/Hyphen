use hyphen_crypto::{blake3_hash_many, Hash256, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compress::CompressedTree;
use crate::ReferenceExpiringState;
use crate::StateRecord;

pub const WES_STATE_KEY: &[u8] = b"h_wes_snapshot_v1";
pub const WES_ENVELOPE_MAGIC: &[u8; 8] = b"HYPHWES1";
pub const MAX_WES_TRANSACTION_BYTES: usize = 256 * 1024;
const D_WES_CREATE: &[u8] = b"HYPHEN_WES_CREATE_V1";
const D_WES_OWNER: &[u8] = b"HYPHEN_WES_OWNER_POLICY_V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedStateCreate {
    pub record: StateRecord,
    pub owner: PublicKey,
    pub signature: Signature,
}

impl SignedStateCreate {
    pub fn sign(record: StateRecord, secret: &SecretKey) -> Result<Self, WesTransactionError> {
        let owner = secret.public_key();
        if record.owner_policy != owner_policy(owner) {
            return Err(WesTransactionError::WrongOwnerPolicy);
        }
        let digest = create_digest(&record, owner);
        Ok(Self {
            record,
            owner,
            signature: secret.sign(digest.as_bytes()),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WesTransaction {
    Create(SignedStateCreate),
}

impl WesTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, WesTransactionError> {
        let payload = hyphen_codec::serialize_with_limit(self, MAX_WES_TRANSACTION_BYTES)
            .map_err(|error| WesTransactionError::Encoding(error.to_string()))?;
        let mut bytes = Vec::with_capacity(WES_ENVELOPE_MAGIC.len() + payload.len());
        bytes.extend_from_slice(WES_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, WesTransactionError> {
        if !bytes.starts_with(WES_ENVELOPE_MAGIC) {
            return Ok(None);
        }
        if bytes.len() > MAX_WES_TRANSACTION_BYTES {
            return Err(WesTransactionError::TransactionTooLarge);
        }
        hyphen_codec::deserialize_with_limit(
            &bytes[WES_ENVELOPE_MAGIC.len()..],
            MAX_WES_TRANSACTION_BYTES - WES_ENVELOPE_MAGIC.len(),
        )
        .map(Some)
        .map_err(|error| WesTransactionError::Encoding(error.to_string()))
    }

    pub fn apply(
        &self,
        state: &mut ReferenceExpiringState,
        chain_id: Hash256,
        at_height: u64,
    ) -> Result<(), WesTransactionError> {
        match self {
            Self::Create(signed) => {
                if signed.record.chain_id != chain_id
                    || signed.record.owner_policy != owner_policy(signed.owner)
                {
                    return Err(WesTransactionError::WrongOwnerPolicy);
                }
                signed
                    .owner
                    .verify(
                        create_digest(&signed.record, signed.owner).as_bytes(),
                        &signed.signature,
                    )
                    .map_err(|_| WesTransactionError::InvalidSignature)?;
                state
                    .insert_initial(signed.record.clone(), at_height)
                    .map_err(|error| WesTransactionError::Transition(error.to_string()))
            }
        }
    }
}

pub fn owner_policy(owner: PublicKey) -> Hash256 {
    blake3_hash_many(&[D_WES_OWNER, owner.as_bytes()])
}

fn create_digest(record: &StateRecord, owner: PublicKey) -> Hash256 {
    blake3_hash_many(&[D_WES_CREATE, record.hash().as_bytes(), owner.as_bytes()])
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WesTransactionError {
    #[error("H-WES transaction exceeds the protocol limit")]
    TransactionTooLarge,
    #[error("H-WES encoding error: {0}")]
    Encoding(String),
    #[error("owner policy does not bind the signing key")]
    WrongOwnerPolicy,
    #[error("owner signature is invalid")]
    InvalidSignature,
    #[error("H-WES transition rejected: {0}")]
    Transition(String),
}

#[derive(Debug, Error)]
pub enum WesStateStoreError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("encoding: {0}")]
    Encoding(String),
}

pub struct WesStateStore {
    pub(crate) tree: CompressedTree,
    committed: ReferenceExpiringState,
}

impl WesStateStore {
    pub fn open(db: &sled::Db, chain_id: Hash256) -> Result<Self, WesStateStoreError> {
        let tree = CompressedTree::new(
            db.open_tree("h_wes_state_v1")
                .map_err(|error| WesStateStoreError::Storage(error.to_string()))?,
        );
        let committed = match tree
            .get(WES_STATE_KEY)
            .map_err(|error| WesStateStoreError::Storage(error.to_string()))?
        {
            Some(bytes) => hyphen_codec::deserialize(&bytes)
                .map_err(|error| WesStateStoreError::Encoding(error.to_string()))?,
            None => ReferenceExpiringState::new(chain_id, Hash256::ZERO),
        };
        Ok(Self { tree, committed })
    }

    pub fn snapshot(&self) -> ReferenceExpiringState {
        self.committed.clone()
    }

    pub fn root(&self) -> Hash256 {
        if self.committed.is_empty() {
            Hash256::ZERO
        } else {
            self.committed.roots().combined()
        }
    }

    pub fn roots(&self) -> crate::StateRoots {
        self.committed.roots()
    }

    pub(crate) fn replace_committed(&mut self, state: ReferenceExpiringState) {
        self.committed = state;
    }
}
