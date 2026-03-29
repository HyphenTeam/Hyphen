use serde::{Deserialize, Serialize};
use hyphen_crypto::Hash256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractAddress(pub [u8; 32]);

impl ContractAddress {
    pub fn from_deployer_and_nonce(deployer: &[u8; 32], nonce: u64) -> Self {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(deployer);
        data.extend_from_slice(&nonce.to_le_bytes());
        let hash = hyphen_crypto::blake3_hash(&data);
        Self(*hash.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for ContractAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for ContractAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug)]
pub struct ContractResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub logs: Vec<ContractLog>,
    pub state_changes: Vec<StateChange>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractLog {
    pub contract: ContractAddress,
    pub topics: Vec<Hash256>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StateChange {
    pub contract: ContractAddress,
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCall {
    pub caller: [u8; 32],
    pub contract: ContractAddress,
    pub function: String,
    pub args: Vec<u8>,
    pub gas_limit: u64,
    pub value: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployParams {
    pub deployer: [u8; 32],
    pub code: Vec<u8>,
    pub constructor_args: Vec<u8>,
    pub gas_limit: u64,
    pub nonce: u64,
}
