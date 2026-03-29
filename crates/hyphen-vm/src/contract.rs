use serde::{Deserialize, Serialize};

use crate::types::ContractAddress;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
    pub address: ContractAddress,
    pub code_hash: hyphen_crypto::Hash256,
    pub code: Vec<u8>,
    pub deployer: [u8; 32],
    pub deployed_height: u64,
}

impl Contract {
    pub fn new(
        deployer: [u8; 32],
        code: Vec<u8>,
        nonce: u64,
        height: u64,
    ) -> Self {
        let address = ContractAddress::from_deployer_and_nonce(&deployer, nonce);
        let code_hash = hyphen_crypto::blake3_hash(&code);
        Self {
            address,
            code_hash,
            code,
            deployer,
            deployed_height: height,
        }
    }
}
