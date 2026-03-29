use std::sync::Arc;
use thiserror::Error;
use wasmer::{Instance, Module, Store, FunctionEnv};

use crate::contract::Contract;
use crate::gas::{GasError, GAS_DEPLOY_PER_BYTE};
use crate::host::{self, HostEnv};
use crate::types::{ContractCall, ContractResult, DeployParams};

#[derive(Debug, Error)]
pub enum VmError {
    #[error("compilation: {0}")]
    Compilation(String),
    #[error("instantiation: {0}")]
    Instantiation(String),
    #[error("execution: {0}")]
    Execution(String),
    #[error("gas: {0}")]
    Gas(#[from] GasError),
    #[error("missing export: {0}")]
    MissingExport(String),
}

pub struct VmEngine {
    store: Store,
}

impl VmEngine {
    pub fn new() -> Self {
        Self {
            store: Store::default(),
        }
    }

    pub fn deploy(&mut self, params: &DeployParams, height: u64) -> Result<(Contract, ContractResult), VmError> {
        let gas_needed = params.code.len() as u64 * GAS_DEPLOY_PER_BYTE;
        if gas_needed > params.gas_limit {
            return Err(GasError::OutOfGas {
                needed: gas_needed,
                remaining: params.gas_limit,
            }.into());
        }

        let module = Module::new(&self.store, &params.code)
            .map_err(|e| VmError::Compilation(e.to_string()))?;

        let contract = Contract::new(
            params.deployer,
            params.code.clone(),
            params.nonce,
            height,
        );

        let host_env = Arc::new(HostEnv::new(
            contract.address,
            params.deployer,
            params.gas_limit - gas_needed,
        ));

        let func_env = FunctionEnv::new(&mut self.store, host_env.clone());
        let import_object = host::build_imports(&mut self.store, &func_env);

        let instance = Instance::new(&mut self.store, &module, &import_object)
            .map_err(|e| VmError::Instantiation(e.to_string()))?;

        if let Ok(mem) = instance.exports.get_memory("memory") {
            host_env.set_memory(mem.clone());
        }

        if !params.constructor_args.is_empty() {
            if let Ok(init) = instance.exports.get_function("init") {
                init.call(&mut self.store, &[])
                    .map_err(|e| VmError::Execution(e.to_string()))?;
            }
        }

        let gas_used = gas_needed + host_env.gas.lock().unwrap().used();
        let logs = host_env.logs.lock().unwrap().clone();
        let return_data = host_env.return_data.lock().unwrap().clone();

        let result = ContractResult {
            success: true,
            return_data,
            gas_used,
            logs,
            state_changes: vec![],
        };

        Ok((contract, result))
    }

    pub fn call(&mut self, contract: &Contract, call: &ContractCall) -> Result<ContractResult, VmError> {
        let module = Module::new(&self.store, &contract.code)
            .map_err(|e| VmError::Compilation(e.to_string()))?;

        let host_env = Arc::new(HostEnv::new(
            contract.address,
            call.caller,
            call.gas_limit,
        ));

        let func_env = FunctionEnv::new(&mut self.store, host_env.clone());
        let import_object = host::build_imports(&mut self.store, &func_env);

        let instance = Instance::new(&mut self.store, &module, &import_object)
            .map_err(|e| VmError::Instantiation(e.to_string()))?;

        if let Ok(mem) = instance.exports.get_memory("memory") {
            host_env.set_memory(mem.clone());
        }

        let func = instance
            .exports
            .get_function(&call.function)
            .map_err(|_| VmError::MissingExport(call.function.clone()))?;

        let exec_result = func.call(&mut self.store, &[]);
        let gas_used = host_env.gas.lock().unwrap().used();
        let logs = host_env.logs.lock().unwrap().clone();
        let return_data = host_env.return_data.lock().unwrap().clone();

        match exec_result {
            Ok(_) => Ok(ContractResult {
                success: true,
                return_data,
                gas_used,
                logs,
                state_changes: vec![],
            }),
            Err(e) => Ok(ContractResult {
                success: false,
                return_data: e.to_string().into_bytes(),
                gas_used,
                logs,
                state_changes: vec![],
            }),
        }
    }
}

impl Default for VmEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_gas_check() {
        let mut engine = VmEngine::new();
        let params = DeployParams {
            deployer: [1u8; 32],
            code: vec![0u8; 100],
            constructor_args: vec![],
            gas_limit: 10,
            nonce: 0,
        };
        let result = engine.deploy(&params, 0);
        assert!(result.is_err());
    }
}
