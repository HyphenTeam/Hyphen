use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use thiserror::Error;
use wasmi::{Config, Engine, Instance, Module, Store, TrapCode};
use wasmparser::{ExternalKind, Parser, Payload, TypeRef, Validator, WasmFeatures};

use crate::contract::Contract;
use crate::gas::{GAS_DEPLOY_PER_BYTE, GasError};
use crate::host::{self, HostEnv, MAX_IO_SIZE};
use crate::types::{ContractAddress, ContractCall, ContractResult, DeployParams, StateChange};

pub const VM_ABI_VERSION: u32 = 1;
pub const MAX_CONTRACT_CODE_SIZE: usize = 512 * 1024;
pub const MAX_MEMORY_PAGES: u64 = 64;
pub const MAX_TABLE_ELEMENTS: u64 = 4096;

/// Maximum nested wasm calls inside one invocation.
///
/// Wasmi executes a wasm call by descending into the callee, so the host stack it
/// consumes is proportional to call depth. The limit is explicit, small, and far
/// below what the thread stack of any supported host can serve.
pub const MAX_CONTRACT_RECURSION_DEPTH: usize = 128;

const ALLOWED_IMPORTS: &[&str] = &[
    "h_storage_read",
    "h_storage_write",
    "h_storage_delete",
    "h_blake3",
    "h_log",
    "h_set_return",
    "h_caller",
    "h_self_address",
    "h_gas_remaining",
    "h_input_len",
    "h_input_copy",
];

#[derive(Debug, Error)]
pub enum VmError {
    #[error("validation: {0}")]
    Validation(String),
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
    #[error("contract address mismatch")]
    ContractMismatch,
    #[error("contract code hash mismatch")]
    CodeIntegrity,
}

/// Deterministic WASM executor with fuel metering and transactional in-memory
/// state. Chain integration must persist the returned state changes atomically
/// with the containing block.
///
/// Execution is interpreted, not JIT compiled: identical input produces
/// identical fuel consumption and identical results on every host, and no
/// native code generator sits in the consensus path.
pub struct VmEngine {
    pub(crate) asset_rules: bool,
    storage: HashMap<ContractAddress, HashMap<Vec<u8>, Vec<u8>>>,
}

impl VmEngine {
    pub fn new() -> Self {
        Self {
            asset_rules: true,
            storage: HashMap::new(),
        }
    }

    pub fn with_storage(storage: HashMap<ContractAddress, HashMap<Vec<u8>, Vec<u8>>>) -> Self {
        Self {
            storage,
            asset_rules: true,
        }
    }

    pub fn deploy(
        &mut self,
        params: &DeployParams,
        height: u64,
    ) -> Result<(Contract, ContractResult), VmError> {
        if params.constructor_args.len() > MAX_IO_SIZE {
            return Err(VmError::Validation(
                "constructor input exceeds 64 KiB".into(),
            ));
        }

        let deploy_cost = (params.code.len() as u64).saturating_mul(GAS_DEPLOY_PER_BYTE);
        if deploy_cost > params.gas_limit {
            return Err(GasError::OutOfGas {
                needed: deploy_cost,
                remaining: params.gas_limit,
            }
            .into());
        }

        validate_contract(&params.code, self.asset_rules)?;
        let contract = Contract::new(params.deployer, params.code.clone(), params.nonce, height);
        let execution_limit = params.gas_limit - deploy_cost;
        let empty = HashMap::new();
        let base_storage = self.storage.get(&contract.address).unwrap_or(&empty);
        let (mut store, instance, host_env) = create_instance(
            &contract.code,
            contract.address,
            params.deployer,
            execution_limit,
            params.constructor_args.clone(),
            base_storage.clone(),
            self.asset_rules,
        )?;

        let execution = match instance.get_func(&store, "init") {
            Some(function) => match function.typed::<(), ()>(&store) {
                Ok(typed) => typed.call(&mut store, ()),
                Err(error) => Err(error),
            },
            None => Ok(()),
        };
        let instruction_used = instruction_gas_used(&store, execution_limit);
        let execution_used = instruction_used.saturating_add(legacy_host_gas(&host_env));

        if out_of_fuel(&execution) || execution_used > execution_limit {
            return Err(GasError::OutOfGas {
                needed: execution_used,
                remaining: execution_limit,
            }
            .into());
        }
        execution.map_err(|error| VmError::Execution(error.to_string()))?;

        let updated_storage = std::mem::take(&mut host_env.storage.lock().unwrap().entries);
        let state_changes = state_changes(contract.address, base_storage, &updated_storage);
        self.storage.insert(contract.address, updated_storage);
        let return_data = host_env.return_data.lock().unwrap().clone();
        let logs = host_env.logs.lock().unwrap().clone();

        Ok((
            contract,
            ContractResult {
                success: true,
                return_data,
                gas_used: deploy_cost.saturating_add(execution_used),
                logs,
                state_changes,
            },
        ))
    }

    pub fn call(
        &mut self,
        contract: &Contract,
        call: &ContractCall,
    ) -> Result<ContractResult, VmError> {
        if call.contract != contract.address {
            return Err(VmError::ContractMismatch);
        }
        if hyphen_crypto::blake3_hash(&contract.code) != contract.code_hash {
            return Err(VmError::CodeIntegrity);
        }
        if !valid_export_name(&call.function) {
            return Err(VmError::Validation("invalid exported function name".into()));
        }
        if call.args.len() > MAX_IO_SIZE {
            return Err(VmError::Validation("call input exceeds 64 KiB".into()));
        }
        validate_contract(&contract.code, self.asset_rules)?;

        let empty = HashMap::new();
        let base_storage = self.storage.get(&contract.address).unwrap_or(&empty);
        let (mut store, instance, host_env) = create_instance(
            &contract.code,
            contract.address,
            call.caller,
            call.gas_limit,
            call.args.clone(),
            base_storage.clone(),
            self.asset_rules,
        )?;
        let function = instance
            .get_func(&store, &call.function)
            .ok_or_else(|| VmError::MissingExport(call.function.clone()))?;
        let execution = match function.typed::<(), ()>(&store) {
            Ok(typed) => typed.call(&mut store, ()),
            Err(error) => Err(error),
        };
        let exhausted = out_of_fuel(&execution);
        let instruction_used = instruction_gas_used(&store, call.gas_limit);
        let combined_used = instruction_used.saturating_add(legacy_host_gas(&host_env));
        let out_of_gas = exhausted || combined_used > call.gas_limit;
        let mut success = execution.is_ok() && !out_of_gas;
        let mut read_only_violation = false;

        let (state_changes, logs) = if success {
            let updated_storage = std::mem::take(&mut host_env.storage.lock().unwrap().entries);
            let changes = state_changes(contract.address, base_storage, &updated_storage);
            if call.function == crate::application::APP_QUERY_EXPORT && !changes.is_empty() {
                success = false;
                read_only_violation = true;
                (Vec::new(), Vec::new())
            } else {
                self.storage.insert(contract.address, updated_storage);
                (changes, host_env.logs.lock().unwrap().clone())
            }
        } else {
            (Vec::new(), Vec::new())
        };

        let return_data = if read_only_violation {
            b"hyphen_query is read-only".to_vec()
        } else if out_of_gas {
            b"out of gas".to_vec()
        } else if let Err(error) = execution {
            error.to_string().into_bytes()
        } else {
            host_env.return_data.lock().unwrap().clone()
        };

        Ok(ContractResult {
            success,
            return_data,
            gas_used: if exhausted && self.asset_rules {
                call.gas_limit
            } else {
                combined_used.min(call.gas_limit)
            },
            logs,
            state_changes,
        })
    }
}

impl Default for VmEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Live instance handles for one contract invocation.
type VmInstance = (Store<Arc<HostEnv>>, Instance, Arc<HostEnv>);

fn legacy_host_gas(env: &HostEnv) -> u64 {
    env.legacy_gas
        .as_ref()
        .map_or(0, |meter| meter.lock().unwrap().used())
}

fn create_instance(
    code: &[u8],
    contract: ContractAddress,
    caller: [u8; 32],
    gas_limit: u64,
    input: Vec<u8>,
    storage: HashMap<Vec<u8>, Vec<u8>>,
    asset_rules: bool,
) -> Result<VmInstance, VmError> {
    let engine = engine();
    let module = Module::new(engine, code).map_err(|e| VmError::Compilation(e.to_string()))?;
    let host_env = Arc::new(
        HostEnv::new(
            contract,
            caller,
            input,
            storage,
            (!asset_rules).then_some(gas_limit),
        )
        .map_err(VmError::Validation)?,
    );
    let mut store = Store::new(engine, host_env.clone());
    store
        .set_fuel(gas_limit)
        .map_err(|e| VmError::Instantiation(e.to_string()))?;
    let linker = host::build_linker(engine).map_err(VmError::Instantiation)?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| VmError::Instantiation(e.to_string()))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| VmError::Validation("contract must export memory as 'memory'".into()))?;
    host_env.set_memory(memory);
    Ok((store, instance, host_env))
}

/// Process-wide interpreter engine. Fuel metering is enabled once here, so every
/// store created from it charges for metered instructions.
fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = Config::default();
        config.consume_fuel(true);
        config.set_max_recursion_depth(MAX_CONTRACT_RECURSION_DEPTH);
        Engine::new(&config)
    })
}

/// Fuel consumed by metered instructions, capped at the limit.
fn instruction_gas_used(store: &Store<Arc<HostEnv>>, limit: u64) -> u64 {
    let remaining = store.get_fuel().unwrap_or(0);
    limit.saturating_sub(remaining)
}

fn out_of_fuel(execution: &Result<(), wasmi::Error>) -> bool {
    execution
        .as_ref()
        .err()
        .and_then(wasmi::Error::as_trap_code)
        .is_some_and(|code| code == TrapCode::OutOfFuel)
}

fn state_changes(
    contract: ContractAddress,
    before: &HashMap<Vec<u8>, Vec<u8>>,
    after: &HashMap<Vec<u8>, Vec<u8>>,
) -> Vec<StateChange> {
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let old_value = before.get(key);
            let new_value = after.get(key);
            (old_value != new_value).then(|| StateChange {
                contract,
                key: key.clone(),
                old_value: old_value.cloned(),
                new_value: new_value.cloned(),
            })
        })
        .collect()
}

fn valid_export_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
        && name.len() <= 64
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn validate_contract(code: &[u8], asset_rules: bool) -> Result<(), VmError> {
    if code.len() > MAX_CONTRACT_CODE_SIZE {
        return Err(VmError::Validation(format!(
            "contract code exceeds {} bytes",
            MAX_CONTRACT_CODE_SIZE
        )));
    }

    let mut features = WasmFeatures::default();
    features.remove(
        WasmFeatures::FLOATS
            | WasmFeatures::SIMD
            | WasmFeatures::RELAXED_SIMD
            | WasmFeatures::THREADS
            | WasmFeatures::SHARED_EVERYTHING_THREADS
            | WasmFeatures::MEMORY64
            | WasmFeatures::MULTI_MEMORY
            | WasmFeatures::COMPONENT_MODEL
            | WasmFeatures::EXCEPTIONS
            | WasmFeatures::LEGACY_EXCEPTIONS,
    );
    Validator::new_with_features(features)
        .validate_all(code)
        .map_err(|e| VmError::Validation(e.to_string()))?;
    crate::application::application_manifest(code)
        .map_err(|error| VmError::Validation(error.to_string()))?;

    let mut memory_count = 0usize;
    let mut exports_memory = false;
    for payload in Parser::new(0).parse_all(code) {
        match payload.map_err(|e| VmError::Validation(e.to_string()))? {
            Payload::ImportSection(imports) => {
                for import in imports.into_imports() {
                    let import = import.map_err(|e| VmError::Validation(e.to_string()))?;
                    if import.module != "env"
                        || !matches!(import.ty, TypeRef::Func(_))
                        || !ALLOWED_IMPORTS.contains(&import.name)
                    {
                        return Err(VmError::Validation(format!(
                            "unsupported import {}::{}",
                            import.module, import.name
                        )));
                    }
                }
            }
            Payload::TableSection(tables) if asset_rules => {
                if tables.count() > 1 {
                    return Err(VmError::Validation(
                        "at most one function table is allowed".into(),
                    ));
                }
                for table in tables {
                    let ty = table.map_err(|e| VmError::Validation(e.to_string()))?.ty;
                    if ty.table64
                        || ty.shared
                        || ty.element_type != wasmparser::RefType::FUNCREF
                        || !ty.maximum.is_some_and(|max| max <= MAX_TABLE_ELEMENTS)
                    {
                        return Err(VmError::Validation(
                            "table must be wasm32 funcref with maximum at most 4096".into(),
                        ));
                    }
                }
            }
            Payload::MemorySection(memories) => {
                for memory in memories {
                    let memory = memory.map_err(|e| VmError::Validation(e.to_string()))?;
                    memory_count += 1;
                    if memory.memory64
                        || memory.shared
                        || (asset_rules && memory.page_size_log2.is_some())
                        || memory.initial > MAX_MEMORY_PAGES
                        || memory.maximum.is_none()
                        || memory.maximum > Some(MAX_MEMORY_PAGES)
                    {
                        return Err(VmError::Validation(format!(
                            "memory must be wasm32, unshared, and bounded to {MAX_MEMORY_PAGES} pages"
                        )));
                    }
                }
            }
            Payload::ExportSection(exports) => {
                for export in exports {
                    let export = export.map_err(|e| VmError::Validation(e.to_string()))?;
                    if export.name == "memory" && export.kind == ExternalKind::Memory {
                        exports_memory = true;
                    }
                }
            }
            Payload::StartSection { .. } => {
                return Err(VmError::Validation(
                    "start sections are forbidden; export init instead".into(),
                ));
            }
            _ => {}
        }
    }
    if memory_count != 1 || !exports_memory {
        return Err(VmError::Validation(
            "contract must define and export exactly one bounded memory".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wasm(source: &str) -> Vec<u8> {
        wat::parse_bytes(source.as_bytes()).unwrap().into_owned()
    }

    fn deploy(engine: &mut VmEngine, code: Vec<u8>) -> Contract {
        engine
            .deploy(
                &DeployParams {
                    deployer: [1u8; 32],
                    code,
                    constructor_args: Vec::new(),
                    gas_limit: 10_000_000,
                    nonce: 0,
                },
                1,
            )
            .unwrap()
            .0
    }

    #[test]
    fn deploy_gas_check_precedes_compilation() {
        let mut engine = VmEngine::new();
        let params = DeployParams {
            deployer: [1u8; 32],
            code: vec![0u8; 100],
            constructor_args: vec![],
            gas_limit: 10,
            nonce: 0,
        };
        assert!(engine.deploy(&params, 0).is_err());
    }

    #[test]
    fn rejects_floating_point_and_unbounded_memory() {
        let float = wasm(
            "(module (memory (export \"memory\") 1 1) (func (export \"run\") (drop (f32.const 1))))",
        );
        assert!(matches!(
            validate_contract(&float, true),
            Err(VmError::Validation(_))
        ));

        let unbounded = wasm("(module (memory (export \"memory\") 1) (func (export \"run\")))");
        assert!(matches!(
            validate_contract(&unbounded, true),
            Err(VmError::Validation(_))
        ));
    }

    #[test]
    fn table_bounds_and_host_fuel_follow_the_active_rules() {
        let unbounded = wasm("(module (memory (export \"memory\") 1 1) (table 0 funcref))");
        assert!(validate_contract(&unbounded, true).is_err());
        assert!(validate_contract(&unbounded, false).is_ok());
        let code = wasm(
            r#"(module (import "env" "h_storage_write" (func $w (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1 1) (func (export "run") i32.const 0 i32.const 1 i32.const 0 i32.const 1 call $w drop))"#,
        );
        for asset_rules in [true, false] {
            let mut engine = VmEngine {
                asset_rules,
                ..VmEngine::new()
            };
            let contract = deploy(&mut engine, code.clone());
            let call = ContractCall {
                caller: [0; 32],
                contract: contract.address,
                function: "run".into(),
                args: vec![],
                gas_limit: 100,
                value: 0,
            };
            let result = engine.call(&contract, &call).unwrap();
            assert_eq!(result.success, !asset_rules);
            assert!(result.state_changes.is_empty());
            if asset_rules {
                assert_eq!(result.return_data, b"out of gas");
                assert_eq!(result.gas_used, 100);
            }
        }
    }

    #[test]
    fn infinite_loop_is_stopped_by_instruction_gas() {
        let mut engine = VmEngine::new();
        let contract = deploy(
            &mut engine,
            wasm("(module (memory (export \"memory\") 1 1) (func (export \"run\") (loop br 0)))"),
        );
        let result = engine
            .call(
                &contract,
                &ContractCall {
                    caller: [2u8; 32],
                    contract: contract.address,
                    function: "run".into(),
                    args: Vec::new(),
                    gas_limit: 100,
                    value: 0,
                },
            )
            .unwrap();
        assert!(!result.success);
        assert_eq!(result.return_data, b"out of gas");
    }

    #[test]
    fn storage_commits_on_success_and_rolls_back_on_trap() {
        let mut engine = VmEngine::new();
        let contract = deploy(
            &mut engine,
            wasm(
                r#"(module
                    (import "env" "h_storage_read" (func $read (param i32 i32 i32) (result i32)))
                    (import "env" "h_storage_write" (func $write (param i32 i32 i32 i32) (result i32)))
                    (import "env" "h_set_return" (func $ret (param i32 i32) (result i32)))
                    (memory (export "memory") 1 1)
                    (data (i32.const 0) "keyvalue")
                    (func (export "set") (drop (call $write (i32.const 0) (i32.const 3) (i32.const 3) (i32.const 5))))
                    (func (export "set_then_fail")
                        (drop (call $write (i32.const 0) (i32.const 3) (i32.const 8) (i32.const 1)))
                        unreachable)
                    (func (export "get")
                        (drop (call $read (i32.const 0) (i32.const 3) (i32.const 32)))
                        (drop (call $ret (i32.const 32) (i32.const 5))))
                )"#,
            ),
        );
        let call = |name: &str| ContractCall {
            caller: [2u8; 32],
            contract: contract.address,
            function: name.into(),
            args: Vec::new(),
            gas_limit: 100_000,
            value: 0,
        };

        assert!(engine.call(&contract, &call("set")).unwrap().success);
        assert!(
            !engine
                .call(&contract, &call("set_then_fail"))
                .unwrap()
                .success
        );
        let get = engine.call(&contract, &call("get")).unwrap();
        assert!(get.success);
        assert_eq!(get.return_data, b"value");
    }
}
