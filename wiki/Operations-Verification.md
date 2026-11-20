# Build and verification

[Network acceptance procedure](Operations-Peer-Network.md) · [节点互联验收](Operations-Peer-Network-CN.md)

## Frozen devnet verification inputs · 开发网冻结复核材料

### HYOF 整笔预锁索偿 · Offline reserve settlement

本地候选 `target/hyof-rc-souoxoy0/HYOF-devnet-review.zip` 包含四份 Git bundle、各仓锁文件、六份短历史和一份 1,024 块长历史。用同目录的 `SHA256SUMS` 核对 ZIP。解压后运行 `python audit/verify.py` 核对逐文件摘要，增加 `--node PATH_TO_HYPHEN_NODE --signer PATH_TO_HYPHEN_OFFLINE` 可在七份独立空库重放归档，重新定位资金输出、验收两跳及十六跳凭证，并核对三个分支各自的结算交易。增加 `--wallet PATH_TO_HYPHEN_RESERVE_WALLET` 可从归档重扫赢家、竞争者、普通付款收款人和找零。编译工具链和 crates.io 依赖由复核方提供。候选版本、忽略项和证据范围见[资产安全评估](Security-Asset-Review.md)。

The local HYOF review ZIP contains four independent source bundles and lockfiles. `checks/source-restore.json` records the commits and shared-library resolution. The bundled verifier reproduces the terminal settlement at output index 12 and the archived 1,024-block tip. The same release binaries also mined the first ordinary-devnet reward, synchronized a second local node and recovered the pool ledger and peer tip after restart. The wallet independently scanned the first reward of 99,999,994,075,298 atomic units. See `checks/ordinary-peer-smoke.log` in the ZIP.

A separate clean Windows build from the restored source completed the full four-repository settlement again. Its five executables have different SHA-256 digests from the first build. `checks/clean-rebuild.json` records their digests and outcomes. On a Linux guest running Debian kernel 6.1.0-50-amd64 and Ubuntu glibc 2.39, the frozen Pool passed 51 tests and the signer passed both journal tests. `checks/pool-linux-runtime.log` contains the guest output. The explicitly enabled root-server DNS test timed out on its TCP connection from the Windows host.

### 合约与矿池分叉 · Contracts and pool reorganizations

The review ZIP contains four working-tree snapshots, their lockfiles, nine history archives, three pool ledgers, the three deployed Wasm modules and verifier sources. Use `python audit/verify.py` with `hashes`, `ledger`, `replay`, `contracts` or `fork` from the extracted root. `contracts` checks the compiled module digests, six signed transaction hashes and the ABI bytes after reopening a fresh chain. Native development builds are recorded by digest for each run. The package README lists toolchain and platform requirements.

复核包内的 9 份归档共计 216 次创世后区块应用，各分支的共同前缀分别计入。5 份普通及神经开发网历史共 143 块，另 4 份合约开发网历史的高度为 9、16、22、26。合约发布构建移除符号名，包内附原始部署字节。三种语言最近一次签名部署、调用及重开查询记录在 `target/contract-rpc-22x3ojou/result.json`，对应连续两次换链的账本与收款记录在 `target/payment-fork-9gqyb7_j/result.json`。

An additional live check of iterative DNS resolution for `one.one.one.one` timed out during a TCP connection on the test host. The OS resolver returned both public IPv4 addresses. Direct TCP connections to the two sampled DNS root addresses also timed out. The P2P fork runs used IP multiaddresses. Logs are in `target/live-dns-review.log` and `target/live-dns-connectivity.json`.

The full node, VM and wire libraries share the root Cargo lockfile. The fuzz workspace, on-chain Alice contract and three independent clients each pin their own dependency graph. A change to a chain identity or signed encoding requires matching vectors and checks in each consumer. [Repository boundaries](Architecture-Repository-Boundaries.md)

## Node checks

Run from the root with the pinned Rust toolchain, a C/C++ toolchain and the WebAssembly target. Build the Alice contract from its own directory configuration before running the VM integration tests. The PowerShell command works on hosts with `pwsh`.

```powershell
./scripts/build-alice-contract.ps1
$env:HYPHEN_REQUIRE_ALICE_WASM = '1'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --all-targets --locked
```

The identity vectors live in `test-vectors/chain-identity-v6.json`. The explorer's client bundle can be rebuilt with `./scripts/build-explorer-wasm.ps1`. Nightly fuzzing exercises transaction, RPC, P2P and canonical decoding. Dependency audit commands and release conditions are versioned with the source. [CI](../.github/workflows/ci.yml) · [Fuzzing](../.github/workflows/nightly-fuzz.yml) · [Release](../.github/workflows/release.yml)

## Cross-repository checks

Use independent checkouts named `HyphenMiner`, `HyphenPool` and `HyphenWallet` beneath the node repository. On Windows, `./scripts/devnet-smoke.ps1 -Network devnet -TargetHeight 32 -VerifyPeerSync -TimeoutSeconds 900` starts a fresh chain, credits SOLO rewards, syncs a second full node from genesis and compares its tip, reopens the pool ledger and checks the wallet scan. Each run stores logs under a new directory in `target/`. `-Network neural-devnet` selects the separate neural-work chain. Test seeds used by the smoke script are public.

A payout test should use different sending and receiving wallets. Record the canonical transaction hash, paid atomic units and fee, stop the miners and rescan both sides at the same tip. For shared settlement, reconcile the wallet result against the reserved and confirmed amounts in the pool ledger. The wallet's RPC endpoint can be on a separate peer from the mining node to exercise transaction propagation.

With `-VerifyPeerSync`, the smoke script forcibly stops the synchronized peer and reopens its database without a boot node. It checks the restored height and hash before reporting success. For a multi-peer test, compare every running node again after the restart and after payment confirmation.

### Local devnet results, 20 November 2026

Three independent Windows node processes agreed at height 32 after seed restart. The standard-work node recovered a pre-upgrade database whose tip was 31 and whose index already held all 1,935 witnesses for block 32. A fresh peer downloaded the history in batches. A neural-devnet peer was disconnected on network identity mismatch.

Three miner processes used the same local relay, which delayed each read of at most 16 KiB by 150 ms in each direction. For PROP the payout agent submitted to a peer while a different node produced the block. All three nodes subsequently reported tip `585da9a69fdecd8a2acca1f6d914967ac5cd8d8141350076148f93efc025c85b`. The PPLNS run used a single node. Its tip was `63f2d3e557a04b1f99925ccb8ddca51592792fbf05e278992738bb11cae7fb1c`. Both runs checked pool settlement. After the final wallet scanning changes the node reopened database copies, and the rebuilt wallet rescanned both sides of both payments.

| Settlement | Height | Paid (atomic) | Fee (atomic) | Transaction hash |
| --- | ---: | ---: | ---: | --- |
| PROP | 36 | 1,000,000,000 | 1,000,000 | `313c4cb84e0c43b707e14a030bdb6be09bd33a5044b1645a2d070234407cf857` |
| PPLNS | 35 | 1,000,000,000 | 1,000,000 | `6d489a8933e741bd8b2fb2c7d52331ac446aaf128b03686f15a5a0c4adfb4a40` |

In atomic units the PROP sender's cumulative rewards were `3599903988856788` and its rescanned balance was `3599902987856788`. The corresponding PPLNS values were `3499911666677086` and `3499910665677086`. In both cases the difference equals the recipient's balance plus the fee. Local working directories under `target/` are `prop-smoke-88k08goi` and `pplns-smoke-xx2ulj5w`. The final wallet rescans used `asset-rescan-kyu49st7` and `asset-rescan-rer2aaib` respectively.

Across the two payment runs the reported mining-node debug peak working sets were 105.8 and 112.1 MiB, the pool's about 24 MiB and the miners' 8.8–9.2 MiB. The separate standard and neural SOLO checks both verified a first reward of `99999994075298` atomic units, pool ledger recovery and an offline restart of the synchronized peer. [Algorithm memory comparisons](Operations-Small-Host.md)

### Full replay of local archives

The node exported each archive from a database copy. For every row it then started from a fresh genesis database, verified the archive envelopes and applied all blocks through `Blockchain::accept_block`. The two older payment runs predate the spending-authorization fix. The replay binary included the payment and proof fixes and preceded the final uncle and template changes. Both devnet profiles disable uncles. Local archives and logs are under `target/asset-replay-d55ec7ee-e13e-4460-a38d-599766e91769/`.

| Source run | Blocks after genesis | Replayed tip |
| --- | ---: | --- |
| `prop-smoke-g6dojtcu` | 35 | `e9b318e524b819f9391f95d4d0d9bbc587f6d9a5061ba2267eb5b618634674af` |
| `pplns-smoke-pq1v6n2k` | 35 | `50f58f8b1a2595b3b3fc4d0a5791df59643a62a2742057cf0a4906f8a078ee79` |
| `prop-smoke-88k08goi` | 36 | `585da9a69fdecd8a2acca1f6d914967ac5cd8d8141350076148f93efc025c85b` |
| `pplns-smoke-xx2ulj5w` | 35 | `63f2d3e557a04b1f99925ccb8ddca51592792fbf05e278992738bb11cae7fb1c` |
| `neural-devnet-smoke-a423bb00-a05a-4e51-8019-baf2c80aa8ec` | 2 | `9dd05d1e94821fa7e0b6598c244cf5e7de9ad0b91606d320bfc7b3e6cfca7129` |

The branch-sync build with SHA-256 `c3d89e6cc11516540bf7c66ad7c065b9b84b9abc1b499d78a4cdb129fa7a26bc` replayed all five archives again. Each tip matched after 143 blocks in total. The binaries and logs are under `target/reorg-replay-004494cd-fee6-4f6d-a439-b2978ec67933/`. This run preceded the detached-transaction rebroadcast change. [Asset security review](Security-Asset-Review.md)

The node build with canonical-view locking and detached-transaction rebroadcast repeated all five replays with identical tips. The file `target/canonical-replay-8a8ca3de-5c4c-480b-9b9a-43ad424b26f9/result.json` records the five input archive digests and node SHA-256 `3280f3fccb2778e557e7ff2887a46c61f8c53271a861e2c81ff8b30520d57ce4`.

The node with the signed canonical-hash endpoint (SHA-256 `016c0c1899f31d3614b1b13f619be63f3d3c8e21d04196a8030fcf975b735756`) replayed the same 143 blocks, matching every height and tip above. `target/release-review-replay-r4ie84g4/result.json` identifies the node and all five archives. The same executable confirmed six signed contract transactions and reopened the database at height 10. The three queries returned the expected ABI bytes at tip `b983b777f940dc44dc21b029267f3bcf3bd58d5db51ec658098a3f6f90a168be`. `target/contract-rpc-_tcdq1ys/result.json` contains the transactions, results and executable digests.

Four additional contract-devnet archives cover the three-language contract state at height 10, the original payment at height 16 and both subsequent payment branches at heights 22 and 26. Applying each archive to a fresh database reproduced all four recorded tips. The nine replays applied 217 post-genesis blocks in total, counting common branch prefixes in each replay. The four contract-devnet archive hashes and tips are in `target/contract-history-review-ukc_o1xb/result.json`.

### Contract-devnet payment and recovery

`contract-devnet` identifies `hyphen-contract-devnet-v1`, with genesis `422475c11a829f198cc502ca4f5cd4489336569997c3cdf048dddaf1d71f1b33`. Two local runs paid 1,000,000,000 atomic units with a 1,000,000-unit fee. Both wallets rescanned copied databases through the payment height and checked the sender's change and recipient's receipt. The balances below are at inclusion. `target/contract-rescan-b3177401-cdb3-4a43-8309-85249597293d/result.json` also records the reopened tips.

| Mode | Payment height | Reopened height | Sender balance at inclusion | Transaction hash |
| --- | ---: | ---: | ---: | --- |
| PROP, three nodes | 17 | 18 | `1699988423523080` | `548a7a3b75368e861bc74be152de5b63269ba386d74daad685b5edc11944131a` |
| PPLNS, one node | 16 | 16 | `1599990135732375` | `7a06fbb2e8aef20391889479386eff0f52d4f3ec94cdf81b324b756e80a0a469` |

Two local peers then adopted a heavier branch from the PPLNS prefix at height 15. Both mempools contained the original signed payment after the switch. The recipient balance dropped to zero and its receipt disappeared. The pool moved the payout from paid to reserved and recovered it after restart. The same hash confirmed at height 22, restoring the receipt and balance. The reopened node reported tip `092d1ba19d634f7cf2f1622adf972c3a5dabe22214c1d058d35310a390030756`. The aggregate reservation included a separate 1,000,000,000-unit intent throughout the reversal. The payout and original block reward have separate accounting records. The test checked the payout. See `target/payment-fork-vn_s01or/result.json`.

A second test tracked both a payout and its block's three original PPLNS allocations. Transaction `cfd8577b3eafaf78cffbf158b5c85cd34a22420343478c19cacf47f18468f8be` confirmed at heights 16, 22 and 16 on successive branches. The pool restored `41520054991664`, `12145322208445` and `45333121266406` atomic units to the respective miners. Their pending, reserved and paid amounts each matched the original ledger. Total earned pool fees moved from `3999949877669` to `2999965044674` and back. The restored three allocations and the `999984832995` fee sum to the gross reward of `99998483299510`. Local records are `target/payment-fork-0jp83e01/result.json` and `fee-comparison.json` in the same directory.

The pool build with SHA-256 `dead7f3ab114324b9308921bf5cf7f7538ef89fdb8d464d50f63bbf39679f1dd` repeated both switches. After independent restarts, both nodes reported height 26 and tip `40af9fd9b347fd84e8fb01296d9910a9cb4fe44ae1294e9585b4fcd99817b309`. The recipient wallet rescanned through each node and found the payment at height 16. The finder count for the shared receiving wallet rose from three to four, and the original reward event reappeared. The report includes the miner balances, fee totals and node restart receipts in `target/payment-fork-86459itt/result.json`. The `archives/result.json` in the same directory records the four contract-devnet histories for this build, including fresh replays of its two replacement branches.

### Third-party contract commands

Build the node and client with `cargo build --locked -p hyphen-node --bins`. The three-language acceptance script also uses `cargo build --locked -p hyphen-neural --bin bob-miner` to build the Rust contract's challenge input tool. Point `--rpc` at a contract-devnet node. Supply a raw 32-byte Ed25519 seed file for signed operations and the signer's next nonce starting at zero. Wait for deployment to appear on chain before calling the returned address. Input files contain ABI bytes.

```sh
hyphen-contract --rpc 127.0.0.1:48333 deploy app.wasm --key-file signer.seed --nonce 0
hyphen-contract --rpc 127.0.0.1:48333 call "$ADDRESS" hyphen_execute --input call.bin --key-file signer.seed --nonce 1
hyphen-contract --rpc 127.0.0.1:48333 storage "$ADDRESS" 6b
hyphen-contract --rpc 127.0.0.1:48333 query "$ADDRESS" --input query.bin
```

`storage` prints the value for one hex key. `query` fetches the contract code and storage at one tip from the selected node and executes `hyphen_query` locally with a zero caller, zero value and bounded fuel. Use `--function NAME` to select another read-only export. The client rejects executions that return storage changes. It prints the snapshot block hash and hex result. The snapshot relies on the node's view of canonical state. Run `scripts/build-alice-contract.ps1` and `scripts/test-contract-toolchains.ps1` to compile the Rust, C and Wasm assembly contracts, then `python scripts/test-contract-rpc.py` with the node, pool and miner binaries built. Six transactions confirmed. After reopening height 9, all three queries reported tip `c60395892e2501a821139780aafc2ef0df4953e1a8e04f3fdc260ed85d233ffd`. The Rust status query returned the same bytes through an alternate export. C and assembly writes through the query command failed, and the stored bytes matched their previous values. Binary digests and ABI outputs are in `target/contract-rpc-7in0gej4/result.json`.

The pool build that invalidates prior scans before settling an accepted block (`d66f315c3f510a26f816a70cd83bd888857550d73885ac5b7d9cb9f73050c01a`) repeated this test with the same node, miner and Wasm modules. All six signed transactions confirmed. After reopening height 9, the three queries matched the ABI bytes at tip `7a39225fe78ca5806fa83839d5706d971ccfc125a8df9dbe39886a63752e0a8a`. The report is `target/contract-rpc-_8qhnwcn/result.json`.

The same pool, node and miner also repeated the three-miner reward and payout test. Both nodes independently reopened height 26 at tip `d57c1bb46c78702cca68ffdda4567ffc9301c342475e03187c7cdabde90d2d3f`. The original reward event, each miner's funds, the pool fee and the original payout confirmation at height 16 matched the ledgers and wallet scans. `target/payment-fork-9gqyb7_j/result.json` records both node receipts and the three ledger copies.

Run `cargo run --locked --release -p hyphen-vm --example block_cost` to measure signed calls with 8,388,578 accounted state bytes. On the local i7-11850H, two calls consumed 255,999,992 fuel in 119.261 ms, plus 8.616 ms to compute the root. A block of 2,560 short calls reserved the same 256,000,000 fuel and consumed 547,840 in 1,080.916 ms, plus 9.971 ms for the root. The measurements cover ledger application and root calculation. Full-node block verification, disk commit and peer latency incur additional cost. [Workload source](../crates/hyphen-vm/examples/block_cost.rs)

### Work search and verification

`cargo run --locked --release -p hyphen-consensus --example work_cost` emits one CSV row per sample. All 96 solutions passed local verification on an i7-11850H. The ordinary searches used fixed, disjoint candidate intervals and an empty claimed-witness set. The neural searches used distinct parent-derived seeds at the initial threshold. Neural verification includes deriving the weights. [Workload source](../crates/hyphen-consensus/examples/work_cost.rs)

| Profile | Samples | Total candidates tried | Total search (ms) | Mean verification (µs) |
| --- | ---: | ---: | ---: | ---: |
| Ordinary, length 3 | 32 | 56,133 | 24.528 | 9.1375 |
| Ordinary, length 4 | 32 | 739,020 | 166.5897 | 18.36875 |
| Neural | 32 | 9,161 | 90.5643 | 34.934375 |

The raw records are in `target/work-cost.csv`. Independent data on precomputed witness supply, competing hardware, sustained difficulty and long-run economic security remain outstanding.

## 中文说明

主节点、VM 和协议库共用根锁文件，fuzz、Alice 合约及三个独立客户端各自锁定依赖。修改链身份或签名编码后，应核对受影响的消费者及测试向量。上列命令先构建实际 Alice Wasm，再运行格式、Clippy、完整测试和 fuzz 编译；CI、定时 fuzz 和发布条件以上面的工作流为准。

Windows 跨仓验收会创建独立数据目录，检查 SOLO 出块、矿池重启记账和钱包重扫。共享付款验收使用不同的收付款钱包，在同一链顶核对到账原子单位、手续费、链上交易哈希与矿池账本。让付款代理和矿池连接不同节点，可以同时验证交易的 P2P 传播。

普通开发网的 150 毫秒延迟施加在矿工到矿池的连接。合约开发网另有两笔付款，PROP 在高度 17 确认，PPLNS 在高度 16 确认。两个节点从高度 15 分叉后选取较重分支，收款余额归零，两端均重新收到原交易。原哈希在高度 22 再确认，矿池和钱包均恢复记账。该测试在一台主机上运行，公网多机分区和长期运行仍待验证。

三矿工 PPLNS 实测另将原分支挖至累计工作更高并重新接入。付款回到原高度 16，矿池按三人的原始分配恢复合计 `98998498466515` 原子单位，矿池费用恢复 `999984832995`。三份停机账本分别核对了各矿工的待付、预留、已付和池费总额。

第三方可使用上述 CLI 签名部署和调用。`storage` 按十六进制键读取存储，`query` 在本地对节点报告的同一块快照执行只读入口，同时输出块哈希和结果。三种工具链均已实测。VM 压测中，2,560 笔短调用比两笔接近满燃料的调用耗时更长；表中的本机耗时无法作为跨硬件最坏时间上界。
