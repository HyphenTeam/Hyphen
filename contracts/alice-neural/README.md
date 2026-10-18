# Alice: on-chain neural challenge

`alice-neural-contract` is the contract half of the [neural-cryptography
challenge](../../docs/research/neural-cryptography.md). It stores one challenge
descriptor per epoch, verifies a submitted preimage with a single forward pass,
and records the first accepted solution. It performs no floating-point
arithmetic, allocates nothing, and compiles the same fixed-point code the miners
run.

## Build

```powershell
.\scripts\build-alice-contract.ps1
```

The script installs the `wasm32-unknown-unknown` target if needed, builds
`--release --locked`, and prints the artifact size and SHA-256. The build uses the
repository-pinned toolchain from `rust-toolchain.toml`.

The module is intentionally small (about 11 KiB). `.cargo/config.toml` sets the
two linker properties the chain requires:

- `--max-memory=4194304` — the VM rejects a memory without a declared maximum and
  caps it at 64 pages;
- `-zstack-size=2097152` — the largest accepted profile keeps a 132 KiB weight
  buffer on the stack, so the default 1 MiB stack is too tight for comfort.

## Test

```powershell
cargo test -p hyphen-vm --test alice_contract
```

The test deploys this module into `hyphen-vm`, opens an epoch, rejects a wrong
answer, accepts the correct one, verifies that a repeat submission is refused, and
runs the widest profiled width inside the gas limit. Set
`HYPHEN_REQUIRE_ALICE_WASM=1` to make a missing artifact a hard failure instead of
a skip.

## Interface

`hyphen_execute` accepts `Open`, `Submit` and `Status`; `hyphen_query` accepts
`Status` only and performs no write. The exact request and response encoding,
storage keys and status codes are specified in the
[research note](../../docs/research/neural-cryptography.md#contract-abi).

## Deploying

Deployment uses the ordinary `hyphen-vm` ledger path: a signed `VmTransaction`
carrying the module bytes, `constructor_args` empty, and enough gas for
`GAS_DEPLOY_PER_BYTE * code_len` (about 2.3 million gas for the current module).
Opening an epoch is a signed call with the encoded descriptor as `args`.

The contract does not choose `chain_seed`. The calling application must derive it
from a value the operator cannot pick, such as the parent block hash, and the same
seed must be reachable by every miner. See the trust model in the research note.
