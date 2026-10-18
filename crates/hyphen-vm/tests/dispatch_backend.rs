//! Regression tests for the interpreter's dispatch backend.
//!
//! Wasmi selects a tail-call backend unless `auto-dispatch` is enabled. On stable
//! targets at `opt-level` 0/1 LLVM cannot turn those dispatches into sibling
//! calls, so every executed instruction grows the host stack and a long-running
//! contract aborts the process instead of trapping. These tests execute more
//! instructions than a default stack can hold and must simply succeed.

use hyphen_vm::types::{ContractCall, DeployParams};
use hyphen_vm::VmEngine;

const GAS: u64 = 200_000_000;

fn deploy(engine: &mut VmEngine, source: &str) -> hyphen_vm::Contract {
    let wasm = wat::parse_str(source).expect("WAT must parse");
    let (contract, result) = engine
        .deploy(
            &DeployParams {
                deployer: [5u8; 32],
                code: wasm,
                constructor_args: Vec::new(),
                gas_limit: GAS,
                nonce: 0,
            },
            1,
        )
        .expect("the module must validate and instantiate");
    assert!(result.success);
    contract
}

fn call(engine: &mut VmEngine, contract: &hyphen_vm::Contract, function: &str) -> bool {
    let result = engine
        .call(
            contract,
            &ContractCall {
                caller: [6u8; 32],
                contract: contract.address,
                function: function.into(),
                args: Vec::new(),
                gas_limit: GAS,
                value: 0,
            },
        )
        .expect("execution must not fail at the VM level");
    result.success
}

#[test]
fn a_long_run_of_wasm_calls_does_not_exhaust_the_host_stack() {
    let mut engine = VmEngine::new();
    let contract = deploy(
        &mut engine,
        r#"
        (module
          (memory (export "memory") 1 1)
          (func $callee (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.add)
          (func $run
            (local $i i32)
            (local $acc i32)
            (block $done
              (loop $again
                local.get $i
                i32.const 20000
                i32.ge_u
                br_if $done
                local.get $acc
                local.get $i
                call $callee
                i32.add
                local.set $acc
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                br $again)))
          (func (export "hyphen_execute") call $run)
          (func (export "hyphen_query") call $run))
        "#,
    );
    assert!(call(&mut engine, &contract, "hyphen_execute"));
}

#[test]
fn a_long_instruction_stream_does_not_exhaust_the_host_stack() {
    let mut engine = VmEngine::new();
    let contract = deploy(
        &mut engine,
        r#"
        (module
          (memory (export "memory") 1 1)
          (func $run
            (local $i i32)
            (block $done
              (loop $again
                local.get $i
                i32.const 500000
                i32.ge_u
                br_if $done
                local.get $i
                i32.const 1
                i32.add
                local.set $i
                br $again)))
          (func (export "hyphen_execute") call $run)
          (func (export "hyphen_query") call $run))
        "#,
    );
    assert!(call(&mut engine, &contract, "hyphen_execute"));
}

#[test]
fn deep_recursion_traps_instead_of_overflowing_the_host() {
    let mut engine = VmEngine::new();
    // The contract recurses until its own depth counter stops it; the VM's
    // recursion limit must produce a failed result rather than a process abort.
    let contract = deploy(
        &mut engine,
        r#"
        (module
          (memory (export "memory") 1 1)
          (func $run (param i32)
            local.get 0
            i32.eqz
            if
              return
            end
            local.get 0
            i32.const 1
            i32.sub
            call $run)
          (func (export "hyphen_execute") i32.const 100000 call $run)
          (func (export "hyphen_query") i32.const 100000 call $run))
        "#,
    );
    // The VM's own recursion limit must trip before the host stack does, so the
    // call reports a failed execution instead of aborting the process.
    assert!(
        !call(&mut engine, &contract, "hyphen_execute"),
        "unbounded recursion must trap inside the VM"
    );
}
