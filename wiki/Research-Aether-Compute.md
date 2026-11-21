# AetherCompute protocol boundary

## Inline Alice tasks on neural-devnet

`hyphen-neural-devnet-v3` (`HYN3`) activates an inline Alice verifier at genesis. The `hyphen-compute` client signs publications and solutions, reads task records, and requests finalization through the node RPC. The node recomputes the descriptor commitment, target, candidate output, hidden activations and operation count. Finalization requires a block height strictly greater than the challenge deadline. The finalized record retains the descriptor and solution. A branch change can replace or remove that record.

The profile accepts up to 32 compute transitions per block, 4,096 bytes per envelope and 2,048 task records over the lifetime of the chain. The publisher declares `reward` in the signed specification. Native payment requires a separately funded reserve and publisher authorization.

`hyphen-compute reward TASK --data-dir DB` reads the locally validated HYN3 task. Use `reserve FEE` to derive the gross funding amount and address. After finalization the worker signs `invoice DESTINATION --key-file WORKER --out INVOICE`. The publisher uses `pay INVOICE INDEX FEE --key-file PUBLISHER --journal JOURNAL --out CLAIM`. Relay with `hyphen-offline submit CLAIM --rpc RPC`. The worker uses `confirm INVOICE RESERVE_SPEND --min-confirmations N` to check the canonical payout and retained invoice. Confirmation binds the finalized task, actual reserve, destination, net amount and depth on the selected branch. A heavier history can revoke it. [CLI implementation](../crates/hyphen-node/src/bin/hyphen-compute/reward.rs) · [Payment and reorg test](../crates/hyphen-node/tests/compute_reward.rs)

`hyphen-compute show TASK_ID` checks the publisher and worker signatures and recomputes submitted or finalized solutions. The RPC node supplies the chain status. To check against your own validated chain, stop your neural-devnet node and run `hyphen-compute show TASK_ID --data-dir PATH`. The client checks the locally stored protocol state against the tip header and writes the tip height, hash and state root to stderr. The signed record is written to stdout.

Add `--expect-tip HASH` to the local command to bind the read to an independently selected block. A mismatch fails before result export. The same tip can be used for `hyphen-contract query` and offline payment confirmation. [Local state check](../crates/hyphen-node/src/bin/common/mod.rs)

Build `hyphen-node`, `hyphen-compute`, `bob-miner`, the independent miner and the pool server in their default debug directories. Run `python scripts/test-compute-rpc.py` from the workspace to submit a task to a fresh network and compare its finalized record before and after a node restart. The script prints the directory containing its transactions, heights and signed record. [RPC test](../scripts/test-compute-rpc.py)

## Consensus-enforced behavior

`hyphen-compute show TASK_ID --output solution.bin` verifies the signed record and writes the finalized solution as little-endian signed Q32.32 words to a new file. Add `--data-dir PATH` to read a stopped local node. Both paths check the BLAKE3 digest of the bytes against the worker's signed output commitment. In a fresh run the task was published at height 1, submitted at 2 and finalized at 19. The client rejected an early export. After restart the RPC and local database exports both matched the original 128 solution bytes. [Client](../crates/hyphen-node/src/bin/hyphen-compute.rs) · [End-to-end check](../scripts/test-compute-rpc.py)

`hyphen-compute` defines bounded, domain-separated transactions for publishing
scientific tasks, submitting state updates, filing fraud proofs, renewing
proof-of-custody attestations and finalizing after a challenge period. Publishers, workers, challengers and custody providers sign their statements. Anyone may request finalization. Task identity binds the chain, scientist nonce,
domain, deterministic arithmetic profile, program and circuit hashes, input
commitment, operation ceiling, challenge window, retention term and deadline.

The validator executes transitions in transaction order and checks the
post-state against `BlockHeader.state_root`. AetherCompute, WASM and all five
H-WES roots are persisted in the same sled transaction as the block, tip,
commitment tree, nullifiers, indexes and undo journal. Reorg rollback restores
the preceding snapshots.

The external custody path requires attestations from three distinct signing keys covering the retention term. The count establishes key diversity. Operator independence requires separate evidence. The bundled neural backends reject external custody attestations.

WASM deployment and calls use signed, chain-bound envelopes and monotonic
account nonces. The executor forbids floating point, SIMD, threads, unbounded
memory, start sections and unapproved imports. Execution and host calls are
metered; failed execution does not mutate committed state.

H-WES public creation binds the owner policy to the signer. Each block performs
at most 1024 expirations in canonical `(lease_end, key)` order and commits the
live, latest, nullifier, archive and availability roots. Shielded recovery and
consume remain disabled until their owner/nullifier and DA relations exist.

## Read-only RPC

The protobuf RPC surface exposes bounded canonical state queries:

| Method | ID | Result |
| --- | ---: | --- |
| `GET_COMPUTE_TASK` | 9 | Task status, challenge/retention heights and canonical task record |
| `GET_VM_CONTRACT` | 10 | Contract code hash, code, deployer and deployment height |
| `GET_VM_STORAGE` | 11 | One bounded contract storage value |
| `GET_H_WES_ROOTS` | 12 | Five H-WES roots and their consensus contribution |
| `LIST_COMPUTE_TASKS` | 13 | Canonical task page, total count and status heights |

Each query takes the chain transition lock while copying its snapshot, so a
response cannot mix in-memory state from two block heights.

The Explorer exposes `/api/science/tasks` and `/api/science/task/{id}` and a
corresponding `#/science` UI. It shows the scientific domain, arithmetic
profile, task state, deadlines, reward, operation ceiling, program/circuit
commitments, input/output data commitments, trace/checkpoint roots, worker,
proof-system ID and current retention-provider count. Search accepts a task ID.

## Native execution host

The CUDA plugin batches neural evaluations. The host checks the winning neural score and applies the memory gate. [Mining measurements](Operations-Mining-Acceleration.md)

## Non-claims

- A checkpoint or random slice is not proof of an entire computation.
- A signature is not proof of execution or storage.
- IEEE-754 GPU results are not cross-device deterministic by default.
- Bulletproofs do not automatically prove an arbitrary Rust/C job.
- A small SNARK exists only after complete arithmetization and activation of a
  versioned verifier key.

Other profiles that enable compute use `NeuralWorkVerifier`. It verifies the solution against the threshold in the committed work descriptor. This verifier does not reconstruct all output and accounting fields. Finalization on its external custody path requires a custody verifier.

`NeuralChallengeVerifier` remains available for the inverse Alice circuit, whose
target is `A(x*)` with `x*` derived from the public `chain_seed`. It is
deterministic but not worked for, so it must not settle anything that gates
block validity. A production profile must install an audited `ProofVerifier` and
bind `circuit_id` plus `proof_system` in consensus.

## External infrastructure

These are integration targets, not permissionless blockchain job endpoints:

| Official platform | Role | Connector boundary |
| --- | --- | --- |
| [BOINC](https://boinc.berkeley.edu/) | Volunteer-computing middleware | Deterministic CPU work units; BOINC validation is not a SNARK |
| [OSPool](https://osg-htc.org/services/open_science_pool.html) | Open HTC for eligible research | HTCondor submission with project authorization and immutable hashes |
| [EGI HTC](https://www.egi.eu/service/high-throughput-compute/) | Federated European HTC | EGI identity/site policy and recorded job provenance |
| [USQCD](https://www.usqcd.org/) | Lattice-QCD software and computing program | Approved formats and allocations; not public mining |
| [ILDG](https://hpc.lqcd.org/ildg/) | Lattice-gauge data federation | Dataset provenance, not arbitrary scheduling |
| [EBRAINS](https://www.ebrains.eu/) | Neuroscience data and simulation | Authorized datasets/jobs with license enforcement |
| [Human Connectome Project](https://www.humanconnectome.org/) | Connectomics datasets | Inputs remain subject to access and data-use terms |

Connectors keep credentials off-chain, map a task to an authorized platform
job, verify downloaded content, upload encrypted output and submit only the
commitment and proof. Patient-derived data additionally requires consent,
purpose limitation and jurisdiction-specific compliance.

## Remaining gates

The epoch seed remains PoW-grindable. H-FOC' stays inactive: a raw seed is not
an unbiasable beacon, and the repository does not yet contain a reviewed
threshold-VRF/unique-threshold-signature DKG, finalized committee provider and
live pacemaker wired into block execution.

The v1 AetherCompute execution statement also lacks an unbiasable post-funding
challenge. It must not be used for anti-precomputation or proof-theft claims
until a versioned statement binds such a beacon, the task and the worker.

---

<!-- hyphen-bilingual-chinese -->

# AetherCompute 协议边界

## 神经开发网的内联 Alice 任务

`hyphen-neural-devnet-v3`（`HYN3`）从创世启用内联 Alice 验证器。`hyphen-compute` 客户端签署任务和解，通过节点 RPC 提交、查询并请求最终化。节点复算描述符承诺、目标、候选输出、隐藏层激活值和操作数。最终化区块的高度必须严格超过挑战截止高度。规范链记录保留描述符与解，重组可以替换或移除记录。

每块最多接受 32 次计算状态转换，每个交易封装最多 4,096 字节，整条链累计可容纳 2,048 条任务记录。`reward` 是发布者签署的报价。发布者可以按报价和手续费单独准备原生资产储备。工作者在任务最终化后签署收款地址，发布者用 `hyphen-compute reward … pay` 核对发票并生成兑付交易，任意中继可广播。工作者用 `confirm` 核对当前规范链上的储备、收款地址、净额和确认深度。重组后须重新核实到账。[CLI 与完整命令示例](#inline-alice-tasks-on-neural-devnet) · [兑付及重组测试](../crates/hyphen-node/tests/compute_reward.rs)

`hyphen-compute show TASK_ID` 校验发布者和工作者签名，复算已提交或已最终化的解。任务的上链状态由 RPC 节点提供。要核对自己验证过的链，停止本地神经开发网节点，运行 `hyphen-compute show TASK_ID --data-dir PATH`。客户端对照链顶区块头核验本地协议状态，将链顶高度、哈希和状态根写入标准错误，将签名记录写入标准输出。

在各仓库默认 debug 目录构建 `hyphen-node`、`hyphen-compute`、`bob-miner`、独立矿工和矿池服务端后，在主仓运行 `python scripts/test-compute-rpc.py`。脚本在新网络提交任务，比较节点重启前后的最终化记录，并打印含交易哈希、高度和签名记录的目录。[RPC 联调脚本](../scripts/test-compute-rpc.py)

## 共识强制行为

`hyphen-compute` 定义有界、域分离的交易，用于发布科学任务、提交状态更新、提出欺诈证明、续期保管证明和请求最终化。发布者、工作者、挑战者和保管方签署各自的声明，任何人均可请求最终化。任务身份绑定链、发布者 nonce、领域、确定性算术规则、程序和电路哈希、输入承诺、操作上限、挑战窗口、保存期限和截止高度。

Validator 按交易顺序执行转换，并用 `BlockHeader.state_root` 检查后状态。AetherCompute、WASM 和全部五个 H-WES 根与区块、tip、commitment tree、nullifier、索引和 undo journal 在同一个 sled 事务中持久化。Reorg 回滚恢复此前快照。

外部保管路径要求三个不同签名公钥的有效证明共同覆盖保存期限。三个公钥是否属于独立运营者需要另外验证。内置神经验证器均拒绝外部保管证明。

WASM 部署和调用使用签名、链绑定 envelope 和单调账户 nonce。执行器禁用浮点、SIMD、线程、无界内存、start section 和未批准 import。执行与 host call 均计量；执行失败不改变已提交状态。

H-WES 公开创建把 owner policy 绑定到 signer。每个区块按规范 `(lease_end, key)` 顺序最多处理 1024 个过期项，并承诺 live、latest、nullifier、archive 和 availability 根。Shielded recovery 与 consume 在 owner/nullifier 和 DA 关系具备前保持禁用。

## 只读 RPC

Protobuf RPC 暴露有界规范状态查询：

| 方法 | ID | 结果 |
| --- | ---: | --- |
| `GET_COMPUTE_TASK` | 9 | 任务状态、challenge/retention 高度和规范任务记录 |
| `GET_VM_CONTRACT` | 10 | 合约 code hash、代码、deployer 和部署高度 |
| `GET_VM_STORAGE` | 11 | 一个有界合约存储值 |
| `GET_H_WES_ROOTS` | 12 | 五个 H-WES 根及其共识贡献 |
| `LIST_COMPUTE_TASKS` | 13 | 规范任务页、总数和状态高度 |

每个查询复制快照时持有链转换锁，因此响应不会混合两个区块高度的内存状态。

Explorer 提供 `/api/science/tasks`、`/api/science/task/{id}` 以及对应 `#/science` UI。它展示科学领域、算术 profile、任务状态、deadline、奖励、操作上限、程序/电路 commitment、输入/输出数据 commitment、trace/checkpoint 根、worker、proof-system ID 和当前 retention-provider 数量。搜索支持 task ID。

## 原生执行宿主

CUDA 插件计算神经评分，主机执行 BLAKE3 scratchpad。参见[设备验收](Operations-Mining-Acceleration.md)。

## 非声明事项

- Checkpoint 或随机切片不是完整计算证明。
- 签名不是执行或存储证明。
- IEEE-754 GPU 结果默认不具跨设备确定性。
- Bulletproofs 不会自动证明任意 Rust/C job。
- 只有完整算术化并激活版本化 verifier key 后，才存在小型 SNARK。

其他启用计算交易的配置使用 `NeuralWorkVerifier`，按已承诺工作描述符中的阈值核对解。该验证器尚未逐项复算输出和计量字段，其外部保管路径仍需保管验证器才能最终化。

`NeuralChallengeVerifier` 仍保留给 Alice 逆问题电路：它的目标是 `A(x*)`，而 `x*` 由公开的 `chain_seed` 推出。它具备确定性但不代表工作量，因此不能用于决定区块有效性的结算。生产 profile 必须安装已审计 `ProofVerifier`，并在共识中绑定 `circuit_id` 和 `proof_system`。

## 外部基础设施

以下是集成目标，不是无许可区块链 job endpoint：

| 官方平台 | 作用 | Connector 边界 |
| --- | --- | --- |
| [BOINC](https://boinc.berkeley.edu/) | 志愿计算中间件 | 确定性 CPU work unit；BOINC validation 不是 SNARK |
| [OSPool](https://osg-htc.org/services/open_science_pool.html) | 面向合格研究的开放 HTC | 需项目授权并记录不可变哈希的 HTCondor 提交 |
| [EGI HTC](https://www.egi.eu/service/high-throughput-compute/) | 欧洲联合 HTC | EGI 身份/站点政策和已记录 job 来源 |
| [USQCD](https://www.usqcd.org/) | 晶格 QCD 软件与计算计划 | 需批准格式和配额；不是公开挖矿 |
| [ILDG](https://hpc.lqcd.org/ildg/) | 晶格规范场数据联合体 | 数据集来源，不是任意调度 |
| [EBRAINS](https://www.ebrains.eu/) | 神经科学数据与模拟 | 经授权数据集/job，并强制许可 |
| [Human Connectome Project](https://www.humanconnectome.org/) | 连接组学数据集 | 输入仍受访问和数据使用条款约束 |

Connector 将 credential 留在链下，把任务映射到获授权平台 job，验证下载内容，上传加密输出，并只提交 commitment 与 proof。患者来源数据还要求同意、目的限制和具体司法辖区合规。

## 剩余门槛

Epoch seed 仍可被 PoW grinding。H-FOC' 保持未激活：裸 seed 不是不可偏置信标，仓库中还没有经过审查的 threshold-VRF/unique-threshold-signature DKG、最终委员会 provider 和接入区块执行的在线 pacemaker。

AetherCompute v1 execution statement 也缺少出资后不可偏置 challenge。在版本化 statement 绑定该信标、任务和 worker 前，不得用于反预计算或防证明盗取声明。
