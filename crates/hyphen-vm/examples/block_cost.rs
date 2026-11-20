use std::error::Error;
use std::time::Instant;

use hyphen_crypto::{Hash256, SecretKey};
use hyphen_vm::gas::{MAX_BLOCK_GAS, MAX_TRANSACTION_GAS, MIN_TRANSACTION_GAS};
use hyphen_vm::ledger::{MAX_LEDGER_BYTES, SignedCall, SignedDeploy, VmBlockBudget, VmLedgerError};
use hyphen_vm::types::{ContractCall, DeployParams};
use hyphen_vm::{ContractAddress, VmLedger, VmTransaction};

const MODULE: &str = r#"(module
  (import "env" "h_input_copy" (func $input (param i32) (result i32)))
  (import "env" "h_storage_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 64 64)
  (table 4096 4096 funcref)
  (data (i32.const 0) "abcd")
  (func (export "init") (local $key i32)
    (loop $row
      (if (call $write (local.get $key) (i32.const 1) (i32.const 16) (i32.const 65470)) (then unreachable))
      (local.set $key (i32.add (local.get $key) (i32.const 1)))
      (br_if $row (i32.lt_u (local.get $key) (i32.const 4)))))
  (func (export "compute") (local $n i32)
    (drop (call $input (i32.const 0)))
    (local.set $n (i32.load (i32.const 0)))
    (loop $count
      (local.tee $n (i32.sub (local.get $n) (i32.const 1)))
      (br_if $count)))
  (@custom "size_fixture" "PADDING"))"#;

fn deploy(
    ledger: &mut VmLedger,
    key: &SecretKey,
    nonce: u64,
    padding: usize,
) -> Result<(), Box<dyn Error>> {
    let params = DeployParams {
        deployer: *key.public_key().as_bytes(),
        nonce,
        code: wat::parse_str(MODULE.replace("PADDING", &"x".repeat(padding)))?,
        constructor_args: Vec::new(),
        gas_limit: MAX_TRANSACTION_GAS,
    };
    let signed = SignedDeploy::sign(Hash256::ZERO, params, key)?;
    ledger.apply(Hash256::ZERO, nonce + 1, &VmTransaction::Deploy(signed))?;
    Ok(())
}

fn call(
    key: &SecretKey,
    nonce: u64,
    iterations: u32,
    gas_limit: u64,
) -> Result<VmTransaction, VmLedgerError> {
    let caller = *key.public_key().as_bytes();
    let call = ContractCall {
        caller,
        contract: ContractAddress::from_deployer_and_nonce(&caller, 0),
        function: "compute".into(),
        args: iterations.to_le_bytes().to_vec(),
        value: 0,
        gas_limit,
    };
    Ok(VmTransaction::Call(SignedCall::sign(
        Hash256::ZERO,
        nonce,
        call,
        key,
    )?))
}

fn main() -> Result<(), Box<dyn Error>> {
    let key = SecretKey([18; 32]);
    let mut ledger = VmLedger::default();
    for nonce in 0..10 {
        deploy(&mut ledger, &key, nonce, 523_000)?;
    }
    let mut estimate = ledger.clone();
    deploy(&mut estimate, &key, 10, 0)?;
    let padding = MAX_LEDGER_BYTES - estimate.accounted_bytes() - 32;
    drop(estimate);
    deploy(&mut ledger, &key, 10, padding)?;
    let measure = |n| {
        ledger
            .clone()
            .apply(Hash256::ZERO, 12, &call(&key, 11, n, MAX_TRANSACTION_GAS)?)
    };
    let overhead = measure(1)?;
    let per_iteration = measure(2)? - overhead;
    let iterations = 1 + u32::try_from((MAX_TRANSACTION_GAS - overhead) / per_iteration)?;
    println!("profile,state_bytes,transactions,declared_gas,used_gas,apply_ms,root_ms,root");
    for (profile, count, gas) in [
        ("instructions", iterations, MAX_TRANSACTION_GAS),
        ("short_calls", 1, MIN_TRANSACTION_GAS),
    ] {
        let mut candidate = ledger.clone();
        let calls = (0..MAX_BLOCK_GAS / gas)
            .map(|offset| call(&key, 11 + offset, count, gas))
            .collect::<Result<Vec<_>, _>>()?;
        let start = Instant::now();
        let mut budget = VmBlockBudget::new(&candidate, true);
        let mut used = 0;
        for tx in &calls {
            used += candidate.apply_in_block(Hash256::ZERO, 12, tx, &mut budget)?;
        }
        let apply = start.elapsed();
        let start = Instant::now();
        let root = candidate.root()?;
        let root_time = start.elapsed();
        println!(
            "{profile},{},{},{MAX_BLOCK_GAS},{used},{:.3},{:.3},{root}",
            candidate.accounted_bytes(),
            calls.len(),
            apply.as_secs_f64() * 1000.,
            root_time.as_secs_f64() * 1000.
        );
    }
    Ok(())
}
