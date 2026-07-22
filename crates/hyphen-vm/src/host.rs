use std::sync::{Arc, Mutex};
use wasmer::{imports, Function, FunctionEnv, FunctionEnvMut, Imports, Memory, Store};

use crate::gas::{self, GasError, GasMeter};
use crate::types::{ContractAddress, ContractLog};

pub const MAX_STORAGE_KEY_SIZE: usize = 1024;
pub const MAX_STORAGE_VALUE_SIZE: usize = 64 * 1024;
pub const MAX_IO_SIZE: usize = 64 * 1024;
pub const MAX_LOGS: usize = 64;

pub struct HostEnv {
    pub contract: ContractAddress,
    pub caller: [u8; 32],
    pub gas: Mutex<GasMeter>,
    pub storage: Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>,
    pub logs: Mutex<Vec<ContractLog>>,
    pub return_data: Mutex<Vec<u8>>,
    pub memory: Mutex<Option<Memory>>,
    pub input: Vec<u8>,
}

impl HostEnv {
    pub fn new(
        contract: ContractAddress,
        caller: [u8; 32],
        gas_limit: u64,
        input: Vec<u8>,
        storage: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    ) -> Self {
        Self {
            contract,
            caller,
            gas: Mutex::new(GasMeter::new(gas_limit)),
            storage: Mutex::new(storage),
            logs: Mutex::new(Vec::new()),
            return_data: Mutex::new(Vec::new()),
            memory: Mutex::new(None),
            input,
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
            "h_storage_delete" => Function::new_typed_with_env(store, env, host_storage_delete),
            "h_blake3" => Function::new_typed_with_env(store, env, host_blake3),
            "h_log" => Function::new_typed_with_env(store, env, host_log),
            "h_set_return" => Function::new_typed_with_env(store, env, host_set_return),
            "h_caller" => Function::new_typed_with_env(store, env, host_caller),
            "h_self_address" => Function::new_typed_with_env(store, env, host_self_address),
            "h_gas_remaining" => Function::new_typed_with_env(store, env, host_gas_remaining),
            "h_input_len" => Function::new_typed_with_env(store, env, host_input_len),
            "h_input_copy" => Function::new_typed_with_env(store, env, host_input_copy),
        }
    }
}

fn host_storage_read(
    env: FunctionEnvMut<Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
    val_ptr: u32,
) -> i32 {
    let data = env.data().clone();
    let key_len = key_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE
        || consume_gas(&data, gas::GAS_STORAGE_READ.saturating_add(key_len as u64)).is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut key = vec![0u8; key_len];
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

fn host_storage_write(
    env: FunctionEnvMut<Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
    val_ptr: u32,
    val_len: u32,
) -> i32 {
    let data = env.data().clone();
    let key_len = key_len as usize;
    let val_len = val_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE
        || val_len > MAX_STORAGE_VALUE_SIZE
        || consume_gas(
            &data,
            gas::GAS_STORAGE_WRITE.saturating_add((key_len + val_len) as u64),
        )
        .is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut key = vec![0u8; key_len];
    let mut val = vec![0u8; val_len];
    if view.read(key_ptr as u64, &mut key).is_err() {
        return -1;
    }
    if view.read(val_ptr as u64, &mut val).is_err() {
        return -1;
    }

    data.storage.lock().unwrap().insert(key, val);
    0
}

fn host_storage_delete(env: FunctionEnvMut<Arc<HostEnv>>, key_ptr: u32, key_len: u32) -> i32 {
    let data = env.data().clone();
    let key_len = key_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE
        || consume_gas(
            &data,
            gas::GAS_STORAGE_DELETE.saturating_add(key_len as u64),
        )
        .is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut key = vec![0u8; key_len];
    if mem.view(&env).read(key_ptr as u64, &mut key).is_err() {
        return -1;
    }
    data.storage.lock().unwrap().remove(&key);
    0
}

fn host_blake3(
    env: FunctionEnvMut<Arc<HostEnv>>,
    data_ptr: u32,
    data_len: u32,
    out_ptr: u32,
) -> i32 {
    let host = env.data().clone();
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE
        || consume_gas(
            &host,
            gas::GAS_HASH.saturating_add(data_len.div_ceil(32) as u64),
        )
        .is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut input = vec![0u8; data_len];
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
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE
        || host.logs.lock().unwrap().len() >= MAX_LOGS
        || consume_gas(&host, gas::GAS_LOG.saturating_add(data_len as u64)).is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut log_data = vec![0u8; data_len];
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
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE
        || consume_gas(&host, gas::GAS_BASE.saturating_add(data_len as u64)).is_err()
    {
        return -1;
    }
    let mem = match get_memory(&env) {
        Some(m) => m,
        None => return -1,
    };
    let view = mem.view(&env);
    let mut ret = vec![0u8; data_len];
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
    if view
        .write(out_ptr as u64, host.contract.as_bytes())
        .is_err()
    {
        return -1;
    }
    0
}

fn host_gas_remaining(env: FunctionEnvMut<Arc<HostEnv>>) -> u64 {
    let remaining = env.data().gas.lock().unwrap().remaining();
    remaining
}

fn host_input_len(env: FunctionEnvMut<Arc<HostEnv>>) -> u32 {
    env.data().input.len() as u32
}

fn host_input_copy(env: FunctionEnvMut<Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = env.data().clone();
    if consume_gas(&host, gas::GAS_BASE.saturating_add(host.input.len() as u64)).is_err() {
        return -1;
    }
    let memory = match get_memory(&env) {
        Some(memory) => memory,
        None => return -1,
    };
    if memory
        .view(&env)
        .write(out_ptr as u64, &host.input)
        .is_err()
    {
        return -1;
    }
    host.input.len() as i32
}
