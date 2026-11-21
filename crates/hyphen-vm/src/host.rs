use std::sync::{Arc, Mutex};

use wasmi::{Caller, Engine, Linker, Memory};

use crate::gas;
use crate::types::{ContractAddress, ContractLog};
use std::collections::HashMap;

pub const MAX_STORAGE_KEY_SIZE: usize = 1024;
pub const MAX_STORAGE_VALUE_SIZE: usize = 64 * 1024;
pub const MAX_IO_SIZE: usize = 64 * 1024;
pub const MAX_LOGS: usize = 64;
pub const MAX_CONTRACT_STORAGE_BYTES: usize = 256 * 1024;
const ENTRY_CHARGE: usize = 64;

pub struct ContractStorage {
    pub(crate) entries: HashMap<Vec<u8>, Vec<u8>>,
    bytes: usize,
    bounded: bool,
}

impl ContractStorage {
    fn new(entries: HashMap<Vec<u8>, Vec<u8>>, bounded: bool) -> Result<Self, String> {
        let mut bytes = 0;
        for (key, value) in &entries {
            bytes += ENTRY_CHARGE + key.len() + value.len();
            if bounded && bytes > MAX_CONTRACT_STORAGE_BYTES {
                return Err("contract storage budget exceeded".into());
            }
        }
        Ok(Self {
            entries,
            bytes,
            bounded,
        })
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), wasmi::Error> {
        let old = self
            .entries
            .get(&key)
            .map_or(0, |v| ENTRY_CHARGE + key.len() + v.len());
        let next = self.bytes - old + ENTRY_CHARGE + key.len() + value.len();
        if self.bounded && next > MAX_CONTRACT_STORAGE_BYTES {
            return Err(wasmi::Error::new("contract storage budget exceeded"));
        }
        self.entries.insert(key, value);
        self.bytes = next;
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) {
        if let Some(value) = self.entries.remove(key) {
            self.bytes -= ENTRY_CHARGE + key.len() + value.len();
        }
    }
}

pub struct HostEnv {
    pub(crate) legacy_gas: Option<Mutex<gas::GasMeter>>,
    pub contract: ContractAddress,
    pub caller: [u8; 32],
    pub storage: Mutex<ContractStorage>,
    pub logs: Mutex<Vec<ContractLog>>,
    pub return_data: Mutex<Vec<u8>>,
    pub memory: Mutex<Option<Memory>>,
    pub input: Vec<u8>,
}

impl HostEnv {
    pub fn new(
        contract: ContractAddress,
        caller: [u8; 32],
        input: Vec<u8>,
        storage: std::collections::HashMap<Vec<u8>, Vec<u8>>,
        legacy_limit: Option<u64>,
    ) -> Result<Self, String> {
        Ok(Self {
            contract,
            caller,
            storage: Mutex::new(ContractStorage::new(storage, legacy_limit.is_none())?),
            legacy_gas: legacy_limit.map(|limit| Mutex::new(gas::GasMeter::new(limit))),
            logs: Mutex::new(Vec::new()),
            return_data: Mutex::new(Vec::new()),
            memory: Mutex::new(None),
            input,
        })
    }

    pub fn set_memory(&self, memory: Memory) {
        *self.memory.lock().unwrap() = Some(memory);
    }
}

fn consume_gas(caller: &mut Caller<'_, Arc<HostEnv>>, amount: u64) -> Result<bool, wasmi::Error> {
    if let Some(meter) = &caller.data().legacy_gas {
        return Ok(meter.lock().unwrap().consume(amount).is_ok());
    }
    let remaining = caller
        .get_fuel()?
        .checked_sub(amount)
        .ok_or(wasmi::TrapCode::OutOfFuel)?;
    caller.set_fuel(remaining)?;
    Ok(true)
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
) -> Result<i32, wasmi::Error> {
    let data = caller.data().clone();
    let key_len = key_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE {
        return Ok(-1);
    }
    if !consume_gas(&mut caller, gas::GAS_STORAGE_READ + key_len as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let start = key_ptr as usize;
    let Some(key) = memory
        .data(&caller)
        .get(start..start.saturating_add(key_len))
    else {
        return Ok(-1);
    };

    let storage = data.storage.lock().unwrap();
    match storage.entries.get(key) {
        Some(value) if value.len() > MAX_STORAGE_VALUE_SIZE => Ok(-1),
        Some(value) => {
            if data.legacy_gas.is_none() {
                consume_gas(&mut caller, value.len() as u64)?;
            }
            if memory.write(&mut caller, val_ptr as usize, value).is_err() {
                return Ok(-1);
            }
            Ok(value.len() as i32)
        }
        None => Ok(0),
    }
}
fn host_storage_write(
    mut caller: Caller<'_, Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
    val_ptr: u32,
    val_len: u32,
) -> Result<i32, wasmi::Error> {
    let data = caller.data().clone();
    let key_len = key_len as usize;
    let val_len = val_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE || val_len > MAX_STORAGE_VALUE_SIZE {
        return Ok(-1);
    }
    if !consume_gas(
        &mut caller,
        gas::GAS_STORAGE_WRITE + (key_len + val_len) as u64,
    )? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let mut key = vec![0u8; key_len];
    let mut value = vec![0u8; val_len];
    if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
        return Ok(-1);
    }
    if memory.read(&caller, val_ptr as usize, &mut value).is_err() {
        return Ok(-1);
    }

    data.storage.lock().unwrap().put(key, value)?;
    Ok(0)
}

fn host_storage_delete(
    mut caller: Caller<'_, Arc<HostEnv>>,
    key_ptr: u32,
    key_len: u32,
) -> Result<i32, wasmi::Error> {
    let data = caller.data().clone();
    let key_len = key_len as usize;
    if key_len > MAX_STORAGE_KEY_SIZE {
        return Ok(-1);
    }
    if !consume_gas(&mut caller, gas::GAS_STORAGE_DELETE + key_len as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let mut key = vec![0u8; key_len];
    if memory.read(&caller, key_ptr as usize, &mut key).is_err() {
        return Ok(-1);
    }
    data.storage.lock().unwrap().remove(&key);
    Ok(0)
}

fn host_blake3(
    mut caller: Caller<'_, Arc<HostEnv>>,
    data_ptr: u32,
    data_len: u32,
    out_ptr: u32,
) -> Result<i32, wasmi::Error> {
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE {
        return Ok(-1);
    }
    if !consume_gas(&mut caller, gas::GAS_HASH + data_len.div_ceil(32) as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let start = data_ptr as usize;
    let Some(input) = memory
        .data(&caller)
        .get(start..start.saturating_add(data_len))
    else {
        return Ok(-1);
    };
    let hash = hyphen_crypto::blake3_hash(input);
    if memory
        .write(&mut caller, out_ptr as usize, hash.as_bytes())
        .is_err()
    {
        return Ok(-1);
    }
    Ok(0)
}

fn host_log(
    mut caller: Caller<'_, Arc<HostEnv>>,
    data_ptr: u32,
    data_len: u32,
) -> Result<i32, wasmi::Error> {
    let host = caller.data().clone();
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE || host.logs.lock().unwrap().len() >= MAX_LOGS {
        return Ok(-1);
    }
    if !consume_gas(&mut caller, gas::GAS_LOG + data_len as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let mut data = vec![0u8; data_len];
    if memory.read(&caller, data_ptr as usize, &mut data).is_err() {
        return Ok(-1);
    }
    host.logs.lock().unwrap().push(ContractLog {
        contract: host.contract,
        topics: vec![],
        data,
    });
    Ok(0)
}

fn host_set_return(
    mut caller: Caller<'_, Arc<HostEnv>>,
    data_ptr: u32,
    data_len: u32,
) -> Result<i32, wasmi::Error> {
    let host = caller.data().clone();
    let data_len = data_len as usize;
    if data_len > MAX_IO_SIZE {
        return Ok(-1);
    }
    if !consume_gas(&mut caller, gas::GAS_BASE + data_len as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    let mut value = vec![0u8; data_len];
    if memory.read(&caller, data_ptr as usize, &mut value).is_err() {
        return Ok(-1);
    }
    *host.return_data.lock().unwrap() = value;
    Ok(0)
}

fn host_caller(mut caller: Caller<'_, Arc<HostEnv>>, out_ptr: u32) -> Result<i32, wasmi::Error> {
    let host = caller.data().clone();
    if !consume_gas(&mut caller, gas::GAS_BASE)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    if memory
        .write(&mut caller, out_ptr as usize, &host.caller)
        .is_err()
    {
        return Ok(-1);
    }
    Ok(0)
}

fn host_self_address(
    mut caller: Caller<'_, Arc<HostEnv>>,
    out_ptr: u32,
) -> Result<i32, wasmi::Error> {
    let host = caller.data().clone();
    if !consume_gas(&mut caller, gas::GAS_BASE)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    if memory
        .write(&mut caller, out_ptr as usize, host.contract.as_bytes())
        .is_err()
    {
        return Ok(-1);
    }
    Ok(0)
}

fn host_gas_remaining(caller: Caller<'_, Arc<HostEnv>>) -> u64 {
    caller.data().legacy_gas.as_ref().map_or_else(
        || caller.get_fuel().unwrap_or(0),
        |meter| meter.lock().unwrap().remaining(),
    )
}

fn host_input_len(caller: Caller<'_, Arc<HostEnv>>) -> u32 {
    caller.data().input.len() as u32
}

fn host_input_copy(
    mut caller: Caller<'_, Arc<HostEnv>>,
    out_ptr: u32,
) -> Result<i32, wasmi::Error> {
    let host = caller.data().clone();
    if !consume_gas(&mut caller, gas::GAS_BASE + host.input.len() as u64)? {
        return Ok(-1);
    }
    let memory = match memory_of(&caller) {
        Some(memory) => memory,
        None => return Ok(-1),
    };
    if memory
        .write(&mut caller, out_ptr as usize, &host.input)
        .is_err()
    {
        return Ok(-1);
    }
    Ok(host.input.len() as i32)
}
