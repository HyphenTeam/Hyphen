# Build and verification

[Network acceptance procedure](Operations-Peer-Network.md) · [节点互联验收](Operations-Peer-Network-CN.md)

## Maintaining the project wikis

Edit shared protocol pages in `Hyphen/wiki/`. Each client repository maintains its own `wiki/Home.md` and `wiki/Operations.md`. Merging documentation into `main` triggers publication to that repository’s GitHub Wiki. The three client repositories also check the shared pages hourly. To publish between scheduled runs, open **Actions → Publish wiki → Run workflow** on the client’s `main` branch. Publication preserves wiki pages maintained outside the synchronized set.

协议文档统一在主仓库的 `wiki/` 目录维护。矿工、矿池和钱包的首页与操作指南由各自仓库维护。文档合入 `main` 后，GitHub Actions 会更新该项目的 Wiki。三个客户端每小时还会检查一次共享文档。如需提前同步，可在对应项目的 **Actions → Publish wiki → Run workflow** 中选择 `main` 并运行。

## Node checks

The November HYN3 review compares a separate Rust work evaluator with full node replay, checks identical nonce windows on CPU and CUDA, and records the assumptions behind canonical offline settlement. [Algorithm audit and measurements](HYN3-Algorithm-Audit.md)

Run from the root with the pinned Rust toolchain, a C/C++ toolchain and the WebAssembly target. Build the Alice contract from its own directory configuration before running the VM integration tests. The PowerShell command works on hosts with `pwsh`.

```powershell
./scripts/build-alice-contract.ps1
$env:HYPHEN_REQUIRE_ALICE_WASM = '1'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --all-targets --locked
```

The identity vectors live in `test-vectors/chain-identity-neural-v3.json`. The explorer's client bundle can be rebuilt with `./scripts/build-explorer-wasm.ps1`. Nightly fuzzing exercises transaction, RPC, P2P and canonical decoding. Dependency audit commands and release conditions are versioned with the source. [CI](../.github/workflows/ci.yml) · [Fuzzing](../.github/workflows/nightly-fuzz.yml) · [Release](../.github/workflows/release.yml)

## Cross-repository checks

On Windows, `./scripts/devnet-smoke.ps1 -VerifyPeerSync` builds the node, pool and miner, mines a SOLO reward, synchronizes a peer and checks the wallet scan.

With `-VerifyPeerSync`, the smoke script forcibly stops the synchronized peer and reopens its database without a boot node. It checks the restored height and hash before reporting success. For a multi-peer test, compare every running node again after the restart and after payment confirmation.

### Third-party contract commands

Build the node and client with `cargo build --locked -p hyphen-node --bins`. The acceptance script also uses `cargo build --locked -p hyphen-neural --bin bob-miner` to build the Rust contract's challenge input tool. Point `--rpc` at a neural-devnet node. Supply a raw 32-byte Ed25519 seed file for signed operations and the signer's next nonce starting at zero. Wait for deployment to appear on chain before calling the returned address. Input files contain ABI bytes.

```sh
hyphen-contract --rpc 127.0.0.1:48333 deploy app.wasm --key-file signer.seed --nonce 0
hyphen-contract --rpc 127.0.0.1:48333 call "$ADDRESS" hyphen_execute --input call.bin --key-file signer.seed --nonce 1
hyphen-contract --rpc 127.0.0.1:48333 storage "$ADDRESS" 6b
hyphen-contract --rpc 127.0.0.1:48333 query "$ADDRESS" --input query.bin
```

`storage` prints the value for one hex key. `query` fetches the contract code and storage at one tip from the selected node and executes `hyphen_query` locally with a zero caller, zero value and bounded fuel. Use `--function NAME` to select another read-only export. The client rejects executions that return storage changes. It prints the snapshot block hash and hex result. The snapshot relies on the node's view of canonical state.

For a local chain check, run `hyphen-contract query ADDRESS --data-dir STOPPED_NODE_DB --expect-tip HASH`. The client checks the stored tip header and its committed state root before executing the query. Supply a hash obtained independently of the queried database. HYN3 enables the same Wasm asset rules for signed calls and query execution. Both verify the BLAKE3 code digest before execution. [Contract client](../crates/hyphen-node/src/bin/hyphen-contract.rs) · [VM engine](../crates/hyphen-vm/src/engine.rs)

Run `scripts/build-alice-contract.ps1` and `scripts/test-contract-toolchains.ps1` to compile Rust, C, C++ and Wasm assembly contracts. With the node, pool and miner binaries built, run `python scripts/test-contract-rpc.py`. The test signs deployments and calls, verifies their inclusion, then checks storage and query results after restart. Two accounts also exercise escrow, fill and cancellation with fixed-supply assets. [Market contract and ABI](../contracts/limit-orders/README.md)

HYN3 acceptance uses `test-contract-rpc.py` for four toolchains and limit orders, `test-compute-rpc.py` for task publication and finalization, and `test-offline-payments.py` for competing settlements and archive replay.

## Local HYN3 acceptance

The signed contract run reached height 14. Rust, C, C++ and Wasm assembly modules each completed deploy, execute, storage read and query. The limit-order contract executed six accepted transactions including deployment, rejected an unfunded fill and a stale order identifier, and preserved balances after restart. A second node synchronized the tip and admitted a subsequently gossiped transaction. [RPC test](../scripts/test-contract-rpc.py) · [Limit-order contract](../contracts/limit-orders/README.md)

The release smoke test mined to height 6, checked the first direct reward of 99,999,994,075,298 atomic units against the wallet, and reopened both the pool ledger and the synchronized peer. The fixed-cost benchmark covered 16,384 nonces in 16 ranges, with 1,016 scratchpad evaluations and 60 accepted nonces. On an RTX A4000 Laptop GPU all 1,024 MLP scores in the first-height window matched Rust and four nonces passed both gates. The first was 125. [Independent Python evaluator](../scripts/check-neural-work.py) · [HYN3 vector](../test-vectors/neural-block-work-v3.json)

The compute RPC run included publication, submission and finalization at heights 3, 5 and 23. The offline test rejected 32 unfunded wallets, changed the winning receipt after peer reorganization and spent the winning output with a standard private transaction. After a funding relocation to global index 11, the recipient verified 9,000,000 atomic units and the archive replayed through height 14. [Acceptance scripts](../scripts/test-offline-payments.py)

Across the 16 fixed windows, aggregate release search throughput was 2,450 nonces/s and independent verification averaged 7.07 ms per accepted nonce. Before restart in the four-project smoke run, peak Windows working sets were 37,953,536 bytes for the node, 10,842,112 for the pool and 7,180,288 for the miner. These process-wide peaks include runtime and I/O allocations. [Live CPU and CUDA measurements](Operations-Mining-Acceleration.md)

Chromium displayed 14 canonical blocks, two validated fork blocks and 15 visible parent edges after reopening the offline settlement database. The old tip at `(11, 2, 9)` opened its original full-hash detail with the fork label. A separate two-block fixture exercised selection at identical coordinates with `z = 18446744073709551615`. [Coordinate and status rules](HYN3-Identity-and-Recovery.md)

### HYN3 collection, branch and rendering checks

Build the Wasm modules with `scripts/test-contract-toolchains.ps1` and run `python scripts/test-contract-rpc.py --collection`. The collection constructor takes one positive little-endian `u64` lifetime issuance cap. The issuer mints a sequential ID with `01 || owner[32] || metadata_digest[32]`. Owners transfer, approve or burn using `opcode || id_le64 || revision_le64` followed by a 32-byte recipient for transfer (`02`) or delegate for approval (`03`). A zero approval revokes the delegate. Burn (`04`) preserves the metadata and ID. Every successful ownership or approval change increments the revision and a transfer clears approval. Query `00` returns issuer, cap and issued count. Query `01 || id_le64` returns owner, delegate, metadata digest and revision, or empty bytes for an unissued ID. Use `(genesis, contract address, token ID)` and record the observed block hash when tracking ownership across branches. [Collection source](../contracts/collection/lib.rs) · [Signed-node test](../scripts/test-contract-rpc.py)

`python scripts/test-application-reorg.py LIGHT_DB HEAVY_DB` starts independent nodes from copies of two stopped HYN3 databases with different application state. It checks that the lighter node adopts the heavier branch over P2P, then compares the contracts, tasks, state root and tip against the seed after adoption, restart and fresh archive replay. In the NFT-to-market run, the same deployer and nonce gave the two contracts the same address on competing histories. The application code hash and canonical state root distinguished them. [Reorganization check](../scripts/test-application-reorg.py)

`node scripts/measure-explorer.mjs CHROME BASELINE_URL UPDATED_URL` compares two local explorers at the same tip. Use a chain with a validated fork and a Chromium build supporting View Transitions. A batch of 120 slider events over 14 canonical and two detached blocks took one canvas draw and zero bitmap dimension assignments after the change, compared with 120 draws and 240 assignments in the previous build. Both builds recorded zero idle draws in 500 ms. The test also changes tabs during a delayed response, returns to a selected fork, enables reduced motion, backgrounds the tab and resumes it. These figures count canvas work during a synthetic input burst. They do not estimate whole-system energy or interactive frame rate. [Browser measurement](../scripts/measure-explorer.mjs)

## Historical HYN2 acceptance

All runs below used genesis `b38330f989bf614fb1e7c1afa55af2adb0d7e6c94c638a6f77f01c7dea405707`, separate fresh databases, Rust release builds and the same shared protocol revision `acb8b9b273b609d2fc1c4fb08ece628266de878b`. Build all three clients against that revision. For release RPC tests set `HYPHEN_NODE_BIN_DIR` to `target/release`. [Chain identity](../test-vectors/chain-identity-neural-v2.json)

| Reproduction | Observed result |
|---|---|
| `./scripts/devnet-smoke.ps1 -Release -VerifyPeerSync` | First SOLO reward of 99,999,994,075,298 atomic units matched the wallet scan. The peer and restarted pool recovered their state. |
| `python scripts/test-contract-rpc.py` | Rust, C, C++ and Wasm assembly deployments, signed calls and queries survived restart. Six market transactions covered issuance, escrow, funding, fill, a second offer and cancellation. The peer synchronized to height 36. |
| `python scripts/test-compute-rpc.py` | The node included the task publication at height 2, solution at 6 and finalization at 24. The client verified the stored result after restart. |
| `python scripts/test-offline-payments.py` | A 10,000,000-unit reserve settled for 9,000,000. A heavier branch changed the recipient and the wallet spent the canonical proceeds. Relocation to output index 12 also settled and replayed through height 16. |
| `python scripts/measure-mining.py --seconds 30 --accelerator-dir DIRECTORY` | On an i7-11850H and RTX A4000 Laptop GPU, CPU and CUDA each reached height 21 with 21 valid submissions and zero invalid ones. CUDA score windows matched the Rust reference in the miner’s device test. |

The 16 fixed benchmark windows contained 16,384 nonces, 1,007 neural finalists and 66 accepted nonces. All 66 passed recomputation by the Rust verifier. The first-height vector includes nonce 76, both scores, the block commitment and a 32-byte Argon2id v19 digest cross-checked with libargon2. On the RTX A4000 Laptop GPU, `hyphen-miner accelerator-check --offset 76 --batch 1` accepted that nonce. The check starting at nonce 0 matched all 1,024 Rust scores and accepted seven nonces. Set `HYPHEN_ACCELERATOR_DIR` to the CUDA plugin directory before running either check. [Benchmark](../crates/hyphen-consensus/examples/work_cost.rs) · [Block work vector](../test-vectors/neural-block-work-v2.json)

## VM memory measurements

Run `cargo run --locked --release -p hyphen-vm --example block_cost` to measure signed calls with 8,388,578 accounted state bytes. On the local i7-11850H, two calls consumed 255,999,992 fuel in 119.261 ms, plus 8.616 ms to compute the root. A block of 2,560 short calls reserved the same 256,000,000 fuel and consumed 547,840 in 1,080.916 ms, plus 9.971 ms for the root. The measurements cover ledger application and root calculation. Full-node block verification, disk commit and peer latency incur additional cost. [Workload source](../crates/hyphen-vm/examples/block_cost.rs)

On Windows, build `block_cost` with `cargo build --locked --release -p hyphen-vm --example block_cost` in each checkout. Pass both executable paths to `python scripts/measure-vm-memory.py BASELINE UPDATED`. The script alternates execution order over six paired trials, reads the process peak working set every 5 ms and checks the state root, gas, transaction count and accounted state size for each workload. Against `95d87e5`, streaming the compact ledger into BLAKE3 and reducing temporary allocations brought the median process peak from 43.594 to 28.129 MiB. For 2,560 short calls, median root time fell from 15.18 to 2.59 ms. Median call application time in those trials rose from 2,065 to 2,335 ms. The raw measurements and executable hashes are in `target/vm-memory-936904bb/result.json`. [Measurement script](../scripts/measure-vm-memory.py)

## Neural work verification

`cargo run --release --locked -p hyphen-consensus --example work_cost` scores reproducible nonce ranges and rechecks each winner. [Hardware measurement](Operations-Mining-Acceleration.md)

## 范围证明验证成本

Windows x64，Intel i7-11850H，Rust release，11 次取中位数。批量入口依次验证四份不同证明，遇第一处错误即返回。错误样本替换第一个输出承诺。其他错误的失败位置与成本会不同。表中长度为紧凑序列化的聚合证明，时间单位 ms。

| 每份证明的输出数 | 字节 | 单份 | 四份全部通过 | 首份失败 | 末份失败 |
|---:|---:|---:|---:|---:|---:|
| 1 | 675 | 12.47 | 46.78 | 0.27 | 38.71 |
| 2 | 739 | 18.83 | 81.17 | 0.41 | 65.57 |
| 4 | 803 | 38.15 | 172.58 | 0.53 | 149.75 |
| 8 | 867 | 74.84 | 387.13 | 0.83 | 289.10 |
| 16 | 931 | 177.14 | 720.68 | 1.46 | 578.09 |

在同一台 i7-11850H 上重新构建 `95d87e5` 和本轮验证器，按基线、修改版、修改版、基线的顺序运行。下表给出各版本两轮中位数的平均值，单位为毫秒。两版证明编码长度相同。修改版复用各轮的公开系数，将生成元项合并到一次多标量乘法，仍分别检查多项式等式和内积等式。原始数据与二进制 SHA-256 见 `target/range-paired-5lwy79fg/result.json`。

| 每份输出数 | 单份基线 | 单份修改版 | 四份基线 | 四份修改版 |
|---:|---:|---:|---:|---:|
| 1 | 6.62 | 1.82 | 26.75 | 7.87 |
| 2 | 15.97 | 2.60 | 53.19 | 9.31 |
| 4 | 29.46 | 3.83 | 115.61 | 16.09 |
| 8 | 57.64 | 7.46 | 230.25 | 27.00 |
| 16 | 109.08 | 12.21 | 456.10 | 55.79 |


`cargo run --release --locked -p hyphen-consensus --example range_verify_cost` reproduces the payment verification workload.
