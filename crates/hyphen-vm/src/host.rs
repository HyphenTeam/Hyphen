use std::sync::{Arc, Mutex};
use wasmer::{Function, FunctionEnv, FunctionEnvMut, Memory, Store, imports, Imports};

use crate::gas::{self, GasMeter, GasError};
use crate::types::{ContractAddress, ContractLog};

pub struct HostEnv {
    pub contract: ContractAddress,
    pub caller: [u8; 32],
    pub gas: Mutex<GasMeter>,
    pub storage: Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    pub logs: Mutex<Vec<ContractLog>>,
    pub return_data: Mutex<Vec<u8>>,
    pub memory: Mutex<Option<Memory>>,
}

impl HostEnv {
    pub fn new(contract: ContractAddress, caller: [u8; 32], gas_limit: u64) -> Self {
        Self {
            contract,
            caller,
            gas: Mutex::new(GasMeter::new(gas_limit)),
            storage: Mutex::new(std::collections::HashMap::new()),
            logs: Mutex::new(Vec::new()),
            return_data: Mutex::new(Vec::new()),
            memory: Mutex::new(None),
        }
    }

    pub fn set_memory(&self, mem: Memory) {
        *self.memory.lock().unwrap() = Some(mem);
    }
}

fn consume_gas(env: &HostEnv, amount: u64) -> Result<(), GasError> {
    env.gas.lock().unwrap().consume(amount)
}

fn get_memory(env: &FunctionEnvMut<Arc<HostEnv>>) -> Option<Memory> {
    env.data().memory.lock().unwrap().clone()
}

pub fn build_imports(store: &mut Store, env: &FunctionEnv<Arc<HostEnv>>) -> Imports {
    imports! {
        "env" => {
            "h_storage_read" => Function::new_typed_with_env(store, env, host_storage_read),
            "h_storage_write" => Function::new_typed_with_env(store, env, host_storage_write),
            "h_blake3" => Function::new_typed_with_env(store, env, host_blake3),
            "h_log" => Function::new_typed_with_env(store, env, host_log),
            "h_set_return" => Function::new_typed_with_env(store, env, host_set_return),
            "h_caller" => Function::new_typed_with_env(store, env, host_caller),
            "h_self_address" => Function::new_typed_with_env(store, env, host_self_address),
            "h_gas_remaining" => Function::new_typed_with_env(store, env, host_gas_remaining),
        }
    }
}

fn host_storage_read(env: FunctionEnvMut<Arc<HostEnv>>, key_ptr: u32, key_len: u32, val_ptr: u32) -> i32 {
    let data = env.data().clone();
    if consume_gas(&data, gas::GAS_STORAGE_READ).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut key = vec![0u8; key_len as usize];
    if view.read(key_ptr as u64, &mut key).is_err() {
        return -1;
    }

    let storage = data.storage.lock().unwrap();
    match storage.get(&key) {
        Some(val) => {
            let len = val.len() as i32;
            let val_copy = val.clone();
            drop(storage);
            if view.write(val_ptr as u64, &val_copy).is_err() {
                return -1;
            }
            len
        }
        None => 0,
    }
}

fn host_storage_write(env: FunctionEnvMut<Arc<HostEnv>>, key_ptr: u32, key_len: u32, val_ptr: u32, val_len: u32) -> i32 {
    let data = env.data().clone();
    if consume_gas(&data, gas::GAS_STORAGE_WRITE).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut key = vec![0u8; key_len as usize];
    let mut val = vec![0u8; val_len as usize];
    if view.read(key_ptr as u64, &mut key).is_err() {
        return -1;
    }
    if view.read(val_ptr as u64, &mut val).is_err() {
        return -1;
    }

    data.storage.lock().unwrap().insert(key, val);
    0
}

fn host_blake3(env: FunctionEnvMut<Arc<HostEnv>>, data_ptr: u32, data_len: u32, out_ptr: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_HASH).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut input = vec![0u8; data_len as usize];
    if view.read(data_ptr as u64, &mut input).is_err() {
        return -1;
    }
    let hash = hyphen_crypto::blake3_hash(&input);
    if view.write(out_ptr as u64, hash.as_bytes()).is_err() {
        return -1;
    }
    0
}

fn host_log(env: FunctionEnvMut<Arc<HostEnv>>, data_ptr: u32, data_len: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_LOG).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut log_data = vec![0u8; data_len as usize];
    if view.read(data_ptr as u64, &mut log_data).is_err() {
        return -1;
    }
    let log = ContractLog {
        contract: host.contract,
        topics: vec![],
        data: log_data,
    };
    host.logs.lock().unwrap().push(log);
    0
}

fn host_set_return(env: FunctionEnvMut<Arc<HostEnv>>, data_ptr: u32, data_len: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_BASE).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut ret = vec![0u8; data_len as usize];
    if view.read(data_ptr as u64, &mut ret).is_err() {
        return -1;
    }
    *host.return_data.lock().unwrap() = ret;
    0
}

fn host_caller(env: FunctionEnvMut<Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_BASE).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    if view.write(out_ptr as u64, &host.caller).is_err() {
        return -1;
    }
    0
}

fn host_self_address(env: FunctionEnvMut<Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_BASE).is_err() {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    if view.write(out_ptr as u64, host.contract.as_bytes()).is_err() {
        return -1;
    }
    0
}

fn host_gas_remaining(env: FunctionEnvMut<Arc<HostEnv>>) -> u64 {
    let remaining = env.data().gas.lock().unwrap().remaining();
    remaining
}

