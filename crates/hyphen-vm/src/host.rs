use std::sync::{Arc, Mutex};

use wasmi::{Caller, Engine, Linker, Memory};

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

    pub fn set_memory(&self, memory: Memory) {
        *self.memory.lock().unwrap() = Some(memory);
    }
}

fn consume_gas(env: &HostEnv, amount: u64) -> Result<(), GasError> {
    env.gas.lock().unwrap().consume(amount)
}

fn memory_of(caller: &Caller<'_, Arc<HostEnv>>) -> Option<Memory> {
    *caller.data().memory.lock().unwrap()
}

/// Registers the frozen host ABI under the `env` module.
///
/// Import names are compile-time constants, so registration can only fail for a
/// duplicate or malformed name; that is reported as a string instead of
/// panicking on the consensus path.
pub fn build_linker(engine: &Engine) -> Result<Linker<Arc<HostEnv>>, String> {
    let mut linker = Linker::new(engine);
    linker
        .func_wrap("env", "h_storage_read", host_storage_read)
        .and_then(|linker| linker.func_wrap("env", "h_storage_write", host_storage_write))
        .and_then(|linker| linker.func_wrap("env", "h_storage_delete", host_storage_delete))
        .and_then(|linker| linker.func_wrap("env", "h_blake3", host_blake3))
        .and_then(|linker| linker.func_wrap("env", "h_log", host_log))
        .and_then(|linker| linker.func_wrap("env", "h_set_return", host_set_return))
        .and_then(|linker| linker.func_wrap("env", "h_caller", host_caller))
        .and_then(|linker| linker.func_wrap("env", "h_self_address", host_self_address))
        .and_then(|linker| linker.func_wrap("env", "h_gas_remaining", host_gas_remaining))
        .and_then(|linker| linker.func_wrap("env", "h_input_len", host_input_len))
        .and_then(|linker| linker.func_wrap("env", "h_input_copy", host_input_copy))
        .map_err(|error| error.to_string())?;
    Ok(linker)
}

fn host_storage_read(
    mut caller: Caller<'_, Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
    val_ptr: u32,
) -> i32 {
    let data = caller.data().clone();
    let key_len = key_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE
        || consume_gas(&data, gas::GAS_STORAGE_READ.saturating_add(key_len as u64)).is_err()
    {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut key = vec![0u8; key_len];
    if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
        return -1;
    }

    let value = data.storage.lock().unwrap().get(&key).cloned();
    match value {
        Some(value) => {
            if memory.write(&mut caller, val_ptr as usize, &value).is_err() {
                return -1;
            }
            value.len() as i32
        }
        None => 0,
    }
}
fn host_storage_write(
    caller: Caller<'_, Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
    val_ptr: u32,
    val_len: u32,
) -> i32 {
    let data = caller.data().clone();
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
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut key = vec![0u8; key_len];
    let mut value = vec![0u8; val_len];
    if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
        return -1;
    }
    if memory.read(&caller, val_ptr as usize, &mut value).is_err() {
        return -1;
    }

    data.storage.lock().unwrap().insert(key, value);
    0
}

fn host_storage_delete(caller: Caller<'_, Arc<HostEnv>>, key_ptr: u32, key_len: u32) -> i32 {
    let data = caller.data().clone();
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
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut key = vec![0u8; key_len];
    if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
        return -1;
    }
    data.storage.lock().unwrap().remove(&key);
    0
}

fn host_blake3(
    mut caller: Caller<'_, Arc<HostEnv>>,
    data_ptr: u32,
    data_len: u32,
    out_ptr: u32,
) -> i32 {
    let host = caller.data().clone();
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
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut input = vec![0u8; data_len];
    if memory.read(&caller, data_ptr as usize, &mut input).is_err() {
        return -1;
    }
    let hash = hyphen_crypto::blake3_hash(&input);
    if memory
        .write(&mut caller, out_ptr as usize, hash.as_bytes())
        .is_err()
    {
        return -1;
    }
    0
}

fn host_log(caller: Caller<'_, Arc<HostEnv>>, data_ptr: u32, data_len: u32) -> i32 {
    let host = caller.data().clone();
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE
        || host.logs.lock().unwrap().len() >= MAX_LOGS
        || consume_gas(&host, gas::GAS_LOG.saturating_add(data_len as u64)).is_err()
    {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut data = vec![0u8; data_len];
    if memory.read(&caller, data_ptr as usize, &mut data).is_err() {
        return -1;
    }
    host.logs.lock().unwrap().push(ContractLog {
        contract: host.contract,
        topics: vec![],
        data,
    });
    0
}

fn host_set_return(caller: Caller<'_, Arc<HostEnv>>, data_ptr: u32, data_len: u32) -> i32 {
    let host = caller.data().clone();
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE
        || consume_gas(&host, gas::GAS_BASE.saturating_add(data_len as u64)).is_err()
    {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    let mut value = vec![0u8; data_len];
    if memory.read(&caller, data_ptr as usize, &mut value).is_err() {
        return -1;
    }
    *host.return_data.lock().unwrap() = value;
    0
}

fn host_caller(mut caller: Caller<'_, Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = caller.data().clone();
    if consume_gas(&host, gas::GAS_BASE).is_err() {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    if memory
        .write(&mut caller, out_ptr as usize, &host.caller)
        .is_err()
    {
        return -1;
    }
    0
}

fn host_self_address(mut caller: Caller<'_, Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = caller.data().clone();
    if consume_gas(&host, gas::GAS_BASE).is_err() {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    if memory
        .write(&mut caller, out_ptr as usize, host.contract.as_bytes())
        .is_err()
    {
        return -1;
    }
    0
}

fn host_gas_remaining(caller: Caller<'_, Arc<HostEnv>>) -> u64 {
    caller.data().gas.lock().unwrap().remaining()
}

fn host_input_len(caller: Caller<'_, Arc<HostEnv>>) -> u32 {
    caller.data().input.len() as u32
}

fn host_input_copy(mut caller: Caller<'_, Arc<HostEnv>>, out_ptr: u32) -> i32 {
    let host = caller.data().clone();
    if consume_gas(&host, gas::GAS_BASE.saturating_add(host.input.len() as u64)).is_err() {
        return -1;
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return -1,
    };
    if memory
        .write(&mut caller, out_ptr as usize, &host.input)
        .is_err()
    {
        return -1;
    }
    host.input.len() as i32
}
