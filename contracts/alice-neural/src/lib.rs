//! Alice: the on-chain half of the neural challenge.
//!
//! The contract stores one 56-byte descriptor per epoch, verifies a submitted
//! preimage with exactly one forward pass, and records the first accepted
//! solution. It never trains, never allocates and never uses floating point:
//! weights, activation and acceptance are the same Q32.32 code the miners run.
//!
//! # Operations
//!
//! `hyphen_execute` accepts three request bodies:
//!
//! ```text
//! Open   0x01 || descriptor(56)
//! Submit 0x02 || epoch(8) || width(2) || Q32.32 values(width * 8)
//! Status 0x03 || epoch(8)                            (also accepted as query)
//! ```
//!
//! `hyphen_query` additionally accepts `Status` and performs no write, which is
//! what the VM's read-only rule requires.
//!
//! # Responses
//!
//! ```text
//! byte 0      status code (0 rejected, 1 accepted, 2 already solved, else NeuralError::code)
//! bytes 1..9  worst per-component error in Q32.32 ulps
//! bytes 9..17 mean squared error, saturated to u64
//! ```
//!
//! # Trust model
//!
//! Opening an epoch is permissionless and first-writer-wins. Two calls with the
//! same descriptor are idempotent; a second, different descriptor for an epoch
//! that is already open is rejected, so an epoch's shape cannot be rewritten
//! after miners start searching. The descriptor must carry a real chain seed;
//! the contract cannot check the seed's provenance, only bind it to the epoch.

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use core::panic::PanicInfo;

use hyphen_neural::mlp::{MAX_HIDDEN_DIM, MAX_INPUT_DIM, MAX_OUTPUT_DIM, MAX_WEIGHTS};
use hyphen_neural::{
    decode_descriptor, decode_open, decode_status, decode_submit, decode_values_into,
    encode_descriptor, ChallengeDescriptor, NeuralError, DESCRIPTOR_BYTES, SUBMISSION_HEADER_BYTES,
};

/// Largest request the contract accepts. Descriptor and solution bodies are far
/// smaller; the bound only stops a caller from forcing a large copy.
const MAX_REQUEST_BYTES: usize = 1024;

/// Status code for a rejected solution.
const STATUS_REJECTED: u8 = 0;
/// Status code for an accepted, newly recorded solution.
const STATUS_ACCEPTED: u8 = 1;
/// Status code for a solution submitted after the epoch was already settled.
const STATUS_ALREADY_SOLVED: u8 = 2;
/// Status code returned by `Status` when the epoch is open and unsettled.
const STATUS_OPEN: u8 = 3;
/// Status code returned by `Status` when the epoch was never opened.
const STATUS_MISSING: u8 = 4;

const CHALLENGE_PREFIX: &[u8] = b"hyphen:chal:v1:";
const SOLUTION_PREFIX: &[u8] = b"hyphen:sol:v1:";
const KEY_BYTES: usize = 23;

#[link(wasm_import_module = "env")]
extern "C" {
    fn h_input_len() -> u32;
    fn h_input_copy(ptr: u32) -> i32;
    fn h_set_return(ptr: u32, len: u32) -> i32;
    fn h_storage_read(key_ptr: u32, key_len: u32, value_ptr: u32) -> i32;
    fn h_storage_write(key_ptr: u32, key_len: u32, value_ptr: u32, value_len: u32) -> i32;
    fn h_caller(ptr: u32) -> i32;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(target_arch = "wasm32")]
    core::arch::wasm32::unreachable();
    #[cfg(not(target_arch = "wasm32"))]
    loop {
        core::hint::spin_loop();
    }
}

/// Verifying entry point.
///
/// `no_mangle` is an unsafe attribute by definition: two definitions of the same
/// symbol would be undefined at link time. There is exactly one here.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn hyphen_execute() {
    let mut request = [0u8; MAX_REQUEST_BYTES];
    let length = match read_request(&mut request) {
        Ok(length) => length,
        Err(error) => {
            respond(error.code(), 0, 0);
            return;
        }
    };
    match execute(&request[..length]) {
        Ok((status, max_error, mean_squared_error)) => {
            respond(status, max_error, mean_squared_error)
        }
        Err(error) => respond(error.code(), 0, 0),
    }
}

/// Read-only entry point. `Status` is answered here and on `hyphen_execute`.
///
/// The VM rejects a query that writes, and this entry point performs no
/// `h_storage_write`, so a `hyphen_query` call cannot mutate consensus state.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn hyphen_query() {
    let mut request = [0u8; MAX_REQUEST_BYTES];
    let length = match read_request(&mut request) {
        Ok(length) => length,
        Err(error) => {
            respond(error.code(), 0, 0);
            return;
        }
    };
    if length == 0 || request[0] != 3 {
        respond(NeuralError::UnknownOperation.code(), 0, 0);
        return;
    }
    match status_request(&request[..length]) {
        Ok((status, max_error, mean_squared_error)) => {
            respond(status, max_error, mean_squared_error)
        }
        Err(error) => respond(error.code(), 0, 0),
    }
}

type Execution = Result<(u8, u64, u64), NeuralError>;

fn execute(request: &[u8]) -> Execution {
    if request.is_empty() {
        return Err(NeuralError::InvalidEncoding);
    }
    match request[0] {
        1 => open(request),
        2 => submit(request),
        3 => status_request(request),
        _ => Err(NeuralError::UnknownOperation),
    }
}

fn open(request: &[u8]) -> Execution {
    let descriptor = decode_open(request)?;
    let key = storage_key(CHALLENGE_PREFIX, descriptor.epoch);
    let mut existing = [0u8; DESCRIPTOR_BYTES];
    let found = read_storage(&key, &mut existing)?;
    if found > 0 {
        if found == DESCRIPTOR_BYTES && existing == encode(descriptor)? {
            // Idempotent re-open: the descriptor is already canonical.
            return Ok((STATUS_ACCEPTED, 0, 0));
        }
        return Err(NeuralError::EpochConflict);
    }
    write_storage(&key, &encode(descriptor)?)?;
    Ok((STATUS_ACCEPTED, 0, 0))
}

fn submit(request: &[u8]) -> Execution {
    if request.len() < SUBMISSION_HEADER_BYTES {
        return Err(NeuralError::InvalidEncoding);
    }
    let epoch = u64::from_le_bytes(
        request[1..9]
            .try_into()
            .map_err(|_| NeuralError::InvalidEncoding)?,
    );
    let key = storage_key(CHALLENGE_PREFIX, epoch);
    let mut descriptor_bytes = [0u8; DESCRIPTOR_BYTES];
    let found = read_storage(&key, &mut descriptor_bytes)?;
    if found != DESCRIPTOR_BYTES {
        return Err(NeuralError::InvalidDescriptor);
    }
    let descriptor = decode_descriptor(&descriptor_bytes)?;
    let width = descriptor.spec.input_dim as usize;
    let (_, values) = decode_submit(request, width)?;

    let mut solution = [0i64; MAX_INPUT_DIM];
    decode_values_into(values, &mut solution[..width])?;

    let mut weights = [0i64; MAX_WEIGHTS];
    let mut preimage = [0i64; MAX_INPUT_DIM];
    let mut target = [0i64; MAX_OUTPUT_DIM];
    let mut hidden = [0i64; MAX_HIDDEN_DIM];
    let mut output = [0i64; MAX_OUTPUT_DIM];
    let verification = descriptor.evaluate(
        &solution[..width],
        &mut weights,
        &mut preimage,
        &mut target,
        &mut hidden,
        &mut output,
    )?;
    let mean_squared_error = u64::try_from(verification.mean_squared_error).unwrap_or(u64::MAX);
    if !verification.accepted {
        return Ok((STATUS_REJECTED, verification.max_error, mean_squared_error));
    }

    let solution_key = storage_key(SOLUTION_PREFIX, epoch);
    let mut existing = [0u8; 32 + MAX_INPUT_DIM * 8 + 8];
    let found = read_storage(&solution_key, &mut existing)?;
    if found > 0 {
        return Ok((
            STATUS_ALREADY_SOLVED,
            verification.max_error,
            mean_squared_error,
        ));
    }

    let mut record = [0u8; 32 + MAX_INPUT_DIM * 8 + 8];
    let mut caller = [0u8; 32];
    if host_caller(&mut caller) != 0 {
        return Err(NeuralError::HostFailure);
    }
    record[..32].copy_from_slice(&caller);
    for (index, value) in solution[..width].iter().enumerate() {
        let offset = 32 + index * 8;
        record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    record[32 + width * 8..32 + width * 8 + 8]
        .copy_from_slice(&verification.max_error.to_le_bytes());
    let record_length = 32 + width * 8 + 8;
    write_storage(&solution_key, &record[..record_length])?;
    Ok((STATUS_ACCEPTED, verification.max_error, mean_squared_error))
}

fn status_request(request: &[u8]) -> Execution {
    let epoch = decode_status(request)?;
    let key = storage_key(CHALLENGE_PREFIX, epoch);
    let mut descriptor_bytes = [0u8; DESCRIPTOR_BYTES];
    if read_storage(&key, &mut descriptor_bytes)? != DESCRIPTOR_BYTES {
        return Ok((STATUS_MISSING, 0, 0));
    }
    let solution_key = storage_key(SOLUTION_PREFIX, epoch);
    let mut record = [0u8; 32 + MAX_INPUT_DIM * 8 + 8];
    let length = read_storage(&solution_key, &mut record)?;
    if length == 0 {
        return Ok((STATUS_OPEN, 0, 0));
    }
    if length < 8 {
        return Err(NeuralError::InvalidEncoding);
    }
    let max_error = u64::from_le_bytes(
        record[length - 8..length]
            .try_into()
            .map_err(|_| NeuralError::InvalidEncoding)?,
    );
    Ok((STATUS_ALREADY_SOLVED, max_error, 0))
}

fn encode(descriptor: ChallengeDescriptor) -> Result<[u8; DESCRIPTOR_BYTES], NeuralError> {
    let mut bytes = [0u8; DESCRIPTOR_BYTES];
    encode_descriptor(&descriptor, &mut bytes)?;
    Ok(bytes)
}

fn storage_key(prefix: &[u8], epoch: u64) -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    let prefix_length = prefix.len().min(KEY_BYTES - 8);
    key[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    key[KEY_BYTES - 8..].copy_from_slice(&epoch.to_le_bytes());
    key
}

fn read_request(buffer: &mut [u8]) -> Result<usize, NeuralError> {
    let length = host_input_len() as usize;
    if length > buffer.len() {
        return Err(NeuralError::InvalidEncoding);
    }
    let copied = host_input_copy(buffer);
    if copied < 0 || copied as usize != length {
        return Err(NeuralError::HostFailure);
    }
    Ok(length)
}

/// Reads a stored value into `buffer` and returns its length, or zero when the
/// key is absent.
fn read_storage(key: &[u8; KEY_BYTES], buffer: &mut [u8]) -> Result<usize, NeuralError> {
    let length = host_storage_read(key, buffer);
    if length < 0 {
        return Err(NeuralError::HostFailure);
    }
    Ok(length as usize)
}

fn write_storage(key: &[u8; KEY_BYTES], value: &[u8]) -> Result<(), NeuralError> {
    if host_storage_write(key, value) != 0 {
        return Err(NeuralError::HostFailure);
    }
    Ok(())
}

fn respond(status: u8, max_error: u64, mean_squared_error: u64) {
    let mut response = [0u8; 17];
    response[0] = status;
    response[1..9].copy_from_slice(&max_error.to_le_bytes());
    response[9..17].copy_from_slice(&mean_squared_error.to_le_bytes());
    host_set_return(&response);
}

// Host wrappers. Each one passes a pointer to a live stack buffer and its exact
// length to the frozen `env` ABI. The host either copies exactly that range or
// fails, so the raw pointers never outlive the call and never describe memory
// the contract does not own.
#[allow(unsafe_code)]
fn host_input_len() -> u32 {
    unsafe { h_input_len() }
}

#[allow(unsafe_code)]
fn host_input_copy(buffer: &mut [u8]) -> i32 {
    unsafe { h_input_copy(buffer.as_mut_ptr() as u32) }
}

#[allow(unsafe_code)]
fn host_caller(buffer: &mut [u8; 32]) -> i32 {
    unsafe { h_caller(buffer.as_mut_ptr() as u32) }
}

#[allow(unsafe_code)]
fn host_set_return(buffer: &[u8]) -> i32 {
    unsafe { h_set_return(buffer.as_ptr() as u32, buffer.len() as u32) }
}

#[allow(unsafe_code)]
fn host_storage_read(key: &[u8; KEY_BYTES], buffer: &mut [u8]) -> i32 {
    unsafe {
        h_storage_read(
            key.as_ptr() as u32,
            key.len() as u32,
            buffer.as_mut_ptr() as u32,
        )
    }
}

#[allow(unsafe_code)]
fn host_storage_write(key: &[u8; KEY_BYTES], value: &[u8]) -> i32 {
    unsafe {
        h_storage_write(
            key.as_ptr() as u32,
            key.len() as u32,
            value.as_ptr() as u32,
            value.len() as u32,
        )
    }
}
