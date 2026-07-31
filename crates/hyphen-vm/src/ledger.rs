use std::collections::{BTreeMap, HashMap};

use hyphen_crypto::{blake3_hash_many, Hash256, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract::Contract;
use crate::engine::VmEngine;
use crate::types::{ContractAddress, ContractCall, DeployParams};

pub const VM_ENVELOPE_MAGIC: &[u8; 8] = b"HYPWASM1";
pub const MAX_VM_TRANSACTION_BYTES: usize = 1024 * 1024;
const D_DEPLOY: &[u8] = b"HYPHEN_VM_DEPLOY_V1";
const D_CALL: &[u8] = b"HYPHEN_VM_CALL_V1";
const D_ROOT: &[u8] = b"HYPHEN_VM_STATE_ROOT_V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedDeploy {
    pub chain_id: Hash256,
    pub params: DeployParams,
    pub signature: Signature,
}

impl SignedDeploy {
    pub fn sign(
        chain_id: Hash256,
        params: DeployParams,
        secret: &SecretKey,
    ) -> Result<Self, VmLedgerError> {
        if params.deployer != *secret.public_key().as_bytes() {
            return Err(VmLedgerError::WrongSigner);
        }
        let signature = secret.sign(deploy_digest(chain_id, &params).as_bytes());
        Ok(Self {
            chain_id,
            params,
            signature,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCall {
    pub chain_id: Hash256,
    pub nonce: u64,
    pub call: ContractCall,
    pub signature: Signature,
}

impl SignedCall {
    pub fn sign(
        chain_id: Hash256,
        nonce: u64,
        call: ContractCall,
        secret: &SecretKey,
    ) -> Result<Self, VmLedgerError> {
        if call.caller != *secret.public_key().as_bytes() {
            return Err(VmLedgerError::WrongSigner);
        }
        let signature = secret.sign(call_digest(chain_id, nonce, &call).as_bytes());
        Ok(Self {
            chain_id,
            nonce,
            call,
            signature,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VmTransaction {
    Deploy(SignedDeploy),
    Call(SignedCall),
}

impl VmTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, VmLedgerError> {
        let payload = crate::wire_config(MAX_VM_TRANSACTION_BYTES)
            .serialize(self)
            .map_err(|error| VmLedgerError::Encoding(error.to_string()))?;
        let mut bytes = Vec::with_capacity(VM_ENVELOPE_MAGIC.len() + payload.len());
        bytes.extend_from_slice(VM_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, VmLedgerError> {
        if !bytes.starts_with(VM_ENVELOPE_MAGIC) {
            return Ok(None);
        }
        if bytes.len() > MAX_VM_TRANSACTION_BYTES {
            return Err(VmLedgerError::TransactionTooLarge);
        }
        crate::wire_config(MAX_VM_TRANSACTION_BYTES - VM_ENVELOPE_MAGIC.len())
            .deserialize(&bytes[VM_ENVELOPE_MAGIC.len()..])
            .map(Some)
            .map_err(|error| VmLedgerError::Encoding(error.to_string()))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmLedger {
    contracts: BTreeMap<ContractAddress, Contract>,
    storage: BTreeMap<(ContractAddress, Vec<u8>), Vec<u8>>,
    next_nonce: BTreeMap<PublicKey, u64>,
}

impl VmLedger {
    pub fn contract(&self, address: ContractAddress) -> Option<&Contract> {
        self.contracts.get(&address)
    }

    pub fn storage(&self, address: ContractAddress, key: &[u8]) -> Option<&[u8]> {
        self.storage
            .get(&(address, key.to_vec()))
            .map(Vec::as_slice)
    }

    pub fn root(&self) -> Hash256 {
        if self.contracts.is_empty() && self.storage.is_empty() && self.next_nonce.is_empty() {
            return Hash256::ZERO;
        }
        let encoded = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(self)
            .expect("VM ledger serialization is infallible");
        hash(D_ROOT, &encoded)
    }

    pub fn apply(
        &mut self,
        chain_id: Hash256,
        height: u64,
        transaction: &VmTransaction,
    ) -> Result<u64, VmLedgerError> {
        match transaction {
            VmTransaction::Deploy(signed) => self.deploy(chain_id, height, signed),
            VmTransaction::Call(signed) => self.call(chain_id, signed),
        }
    }

    fn deploy(
        &mut self,
        chain_id: Hash256,
        height: u64,
        signed: &SignedDeploy,
    ) -> Result<u64, VmLedgerError> {
        if signed.chain_id != chain_id {
            return Err(VmLedgerError::WrongChain);
        }
        let owner = PublicKey(signed.params.deployer);
        owner
            .verify(
                deploy_digest(chain_id, &signed.params).as_bytes(),
                &signed.signature,
            )
            .map_err(|_| VmLedgerError::InvalidSignature)?;
        self.consume_nonce(owner, signed.params.nonce)?;
        let expected_address =
            ContractAddress::from_deployer_and_nonce(&signed.params.deployer, signed.params.nonce);
        if self.contracts.contains_key(&expected_address) {
            return Err(VmLedgerError::ContractExists);
        }
        let mut engine = VmEngine::new();
        let (contract, result) = engine
            .deploy(&signed.params, height)
            .map_err(|error| VmLedgerError::Execution(error.to_string()))?;
        if !result.success || contract.address != expected_address {
            return Err(VmLedgerError::Execution("deployment failed".into()));
        }
        self.apply_changes(result.state_changes);
        self.contracts.insert(contract.address, contract);
        Ok(result.gas_used)
    }

    fn call(&mut self, chain_id: Hash256, signed: &SignedCall) -> Result<u64, VmLedgerError> {
        if signed.chain_id != chain_id || signed.call.value != 0 {
            return Err(VmLedgerError::WrongChain);
        }
        let caller = PublicKey(signed.call.caller);
        caller
            .verify(
                call_digest(chain_id, signed.nonce, &signed.call).as_bytes(),
                &signed.signature,
            )
            .map_err(|_| VmLedgerError::InvalidSignature)?;
        self.consume_nonce(caller, signed.nonce)?;
        let contract = self
            .contracts
            .get(&signed.call.contract)
            .cloned()
            .ok_or(VmLedgerError::UnknownContract)?;
        let contract_storage = self
            .storage
            .iter()
            .filter(|((address, _), _)| *address == contract.address)
            .map(|((_, key), value)| (key.clone(), value.clone()))
            .collect::<HashMap<_, _>>();
        let mut all_storage = HashMap::new();
        all_storage.insert(contract.address, contract_storage);
        let mut engine = VmEngine::with_storage(all_storage);
        let result = engine
            .call(&contract, &signed.call)
            .map_err(|error| VmLedgerError::Execution(error.to_string()))?;
        if !result.success {
            return Err(VmLedgerError::Execution(
                String::from_utf8_lossy(&result.return_data).into_owned(),
            ));
        }
        self.apply_changes(result.state_changes);
        Ok(result.gas_used)
    }

    fn consume_nonce(&mut self, owner: PublicKey, nonce: u64) -> Result<(), VmLedgerError> {
        let expected = self.next_nonce.get(&owner).copied().unwrap_or(0);
        if nonce != expected {
            return Err(VmLedgerError::InvalidNonce {
                expected,
                got: nonce,
            });
        }
        self.next_nonce.insert(
            owner,
            expected
                .checked_add(1)
                .ok_or(VmLedgerError::NonceExhausted)?,
        );
        Ok(())
    }

    fn apply_changes(&mut self, changes: Vec<crate::types::StateChange>) {
        for change in changes {
            let key = (change.contract, change.key);
            match change.new_value {
                Some(value) => {
                    self.storage.insert(key, value);
                }
                None => {
                    self.storage.remove(&key);
                }
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VmLedgerError {
    #[error("VM transaction exceeds the protocol limit")]
    TransactionTooLarge,
    #[error("VM encoding error: {0}")]
    Encoding(String),
    #[error("transaction belongs to another chain")]
    WrongChain,
    #[error("secret key does not own the declared account")]
    WrongSigner,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("account nonce is exhausted")]
    NonceExhausted,
    #[error("contract already exists")]
    ContractExists,
    #[error("unknown contract")]
    UnknownContract,
    #[error("VM execution failed: {0}")]
    Execution(String),
}

fn deploy_digest(chain_id: Hash256, params: &DeployParams) -> Hash256 {
    let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
        .serialize(params)
        .expect("deploy serialization is infallible");
    hash_many(D_DEPLOY, &[chain_id.as_bytes(), &bytes])
}

fn call_digest(chain_id: Hash256, nonce: u64, call: &ContractCall) -> Hash256 {
    let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
        .serialize(call)
        .expect("call serialization is infallible");
    hash_many(D_CALL, &[chain_id.as_bytes(), &nonce.to_be_bytes(), &bytes])
}

fn hash(domain: &[u8], bytes: &[u8]) -> Hash256 {
    hash_many(domain, &[bytes])
}

fn hash_many(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let mut framed = Vec::new();
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain);
    for part in parts {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part);
    }
    blake3_hash_many(&[&framed])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasm(source: &str) -> Vec<u8> {
        wasmer::wat2wasm(source.as_bytes()).unwrap().into_owned()
    }

    #[test]
    fn signed_deploy_and_call_change_the_consensus_root() {
        let chain_id = Hash256::from_bytes([9; 32]);
        let owner = SecretKey([7; 32]);
        let code = wasm(
            r#"(module
                (import "env" "h_storage_write" (func $write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1 1)
                (data (i32.const 0) "keyvalue")
                (func (export "set")
                    (drop (call $write (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 5))))
            )"#,
        );
        let params = DeployParams {
            deployer: *owner.public_key().as_bytes(),
            code,
            constructor_args: Vec::new(),
            gas_limit: 1_000_000,
            nonce: 0,
        };
        let deploy = VmTransaction::Deploy(SignedDeploy::sign(chain_id, params, &owner).unwrap());
        let encoded = deploy.encode().unwrap();
        assert_eq!(
            VmTransaction::decode(&encoded).unwrap(),
            Some(deploy.clone())
        );
        let mut ledger = VmLedger::default();
        ledger.apply(chain_id, 1, &deploy).unwrap();
        let address = ContractAddress::from_deployer_and_nonce(owner.public_key().as_bytes(), 0);
        let before = ledger.root();
        let call = ContractCall {
            caller: *owner.public_key().as_bytes(),
            contract: address,
            function: "set".into(),
            args: Vec::new(),
            gas_limit: 100_000,
            value: 0,
        };
        let call = VmTransaction::Call(SignedCall::sign(chain_id, 1, call, &owner).unwrap());
        ledger.apply(chain_id, 2, &call).unwrap();
        assert_ne!(ledger.root(), before);
        assert_eq!(ledger.storage(address, b"key"), Some(b"value".as_slice()));
    }
}
