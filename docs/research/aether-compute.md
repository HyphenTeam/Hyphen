# AetherCompute protocol boundary

Status: implemented consensus lifecycle; proof backends remain activation-gated.

## Consensus-enforced behavior

`hyphen-compute` defines bounded, domain-separated transactions for publishing
scientific tasks, submitting state updates, filing fraud proofs, renewing
proof-of-custody attestations and finalizing after a challenge period. Every
mutating object is signed. Task identity binds the chain, scientist nonce,
domain, deterministic arithmetic profile, program and circuit hashes, input
commitment, operation ceiling, challenge window, retention term and deadline.

The validator executes transitions in transaction order and checks the
post-state against `BlockHeader.state_root`. AetherCompute, WASM and all five
H-WES roots are persisted in the same sled transaction as the block, tip,
commitment tree, nullifiers, indexes and undo journal. Reorg rollback restores
the preceding snapshots.

Long-term DA is renewable. Finalization needs three independent providers whose
verified custody responses cover the retention term. Later responses extend
the committed height only when three providers jointly cover it. This does not
claim permanent storage; expired obligations remain observable.

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

The independent `HyphenMiner` repository contains a versioned C ABI for native
CUDA, HIP, Intel OpenVINO NPU/GPU and Qualcomm QNN plugins. ABI loading,
capability checks, bounded result ownership and error isolation stay in Rust.
ABI v2 implements the consensus 64x64 Q12 periodic diffusion/PDE step with
bounded non-negative `i32` cells. CUDA, HIP and OpenVINO use the same
four-neighbour relation and seven-operation accounting as PoUW v1. Old ABI v1
plugins are rejected. Every accepted device output is recomputed by the
independent Rust implementation, checked byte-for-byte and committed with
domain-separated BLAKE3 input/output hashes.

The CUDA source compiles with CUDA 13.2 on the current development host. No
compatible device execution was performed in this verification run, and HIP,
OpenVINO and QNN were not built because their SDK/runtime and target hardware
were unavailable. QNN advertises no kernel capability until a target-specific
deterministic graph implements ABI v2. Provider discovery is not treated as
useful computation.

The ABI v2 execution path is connected to block mining: verified devices run
the exact header-derived consensus grid, while the default path falls back to
Rust CPU execution. `--require-accelerator` makes device availability and
successful execution mandatory. This boundary does not replace the consensus
`ProofVerifier` and does not settle user-published AetherCompute tasks.

## Non-claims

- A checkpoint or random slice is not proof of an entire computation.
- A signature is not proof of execution or storage.
- IEEE-754 GPU results are not cross-device deterministic by default.
- Bulletproofs do not automatically prove an arbitrary Rust/C job.
- A small SNARK exists only after complete arithmetization and activation of a
  versioned verifier key.

The default node uses `RejectingVerifier`: task publication is possible, but
result settlement, fraud and custody proofs fail closed. A production profile
must install an audited `ProofVerifier` and bind `circuit_id` plus
`proof_system` in consensus.

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

状态：共识生命周期已实现；证明后端仍受激活门槛限制。

## 共识强制行为

`hyphen-compute` 定义有界、域分离的交易，用于发布科学任务、提交状态更新、提出欺诈证明、续期 proof-of-custody attestation，以及在挑战期后完成结算。每个改变状态的对象都带签名。任务身份绑定链、scientist nonce、领域、确定性算术 profile、程序和电路哈希、输入 commitment、操作上限、挑战窗口、保存期限和 deadline。

Validator 按交易顺序执行转换，并用 `BlockHeader.state_root` 检查后状态。AetherCompute、WASM 和全部五个 H-WES 根与区块、tip、commitment tree、nullifier、索引和 undo journal 在同一个 sled 事务中持久化。Reorg 回滚恢复此前快照。

长期 DA 可续期。完成结算需要三个独立 provider，其已验证 custody response 覆盖保存期限。只有三个 provider 共同覆盖更高高度时，后续 response 才扩展已承诺高度。这不声称永久存储；已过期义务仍可观察。

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

独立 `HyphenMiner` 仓库包含版本化 C ABI，用于原生 CUDA、HIP、Intel OpenVINO NPU/GPU 和 Qualcomm QNN plugin。ABI 加载、能力检查、有界结果所有权和错误隔离由 Rust 负责。v1 确定性 kernel 是 Q12 周期 diffusion/PDE step，使用有界非负 `i32` cell。每个设备输出都由独立 Rust 实现重新计算，逐字节检查，并以域分离 BLAKE3 输入/输出哈希承诺。

在当前开发主机上，CUDA plugin 使用 CUDA 13.2 编译，并在 NVIDIA RTX A4000 Laptop GPU 上通过设备执行。由于缺少 SDK/runtime 与目标硬件，HIP 和 OpenVINO 仍不可用。已安装的 x86_64 Qualcomm SDK 可以初始化 HTP provider，但在没有目标 SoC 确定性 graph package 时，QNN plugin 不公布 kernel 能力。发现 provider 不等于完成有用计算。

该执行 ABI 尚未连接 Pool Protocol 科学 job transport 或结果 envelope 提交。它提供经过复算验证的原生执行边界，但不能替代共识 `ProofVerifier`。

## 非声明事项

- Checkpoint 或随机切片不是完整计算证明。
- 签名不是执行或存储证明。
- IEEE-754 GPU 结果默认不具跨设备确定性。
- Bulletproofs 不会自动证明任意 Rust/C job。
- 只有完整算术化并激活版本化 verifier key 后，才存在小型 SNARK。

默认节点使用 `RejectingVerifier`：任务可发布，但结果结算、欺诈证明和 custody proof 均 fail-closed。生产 profile 必须安装已审计 `ProofVerifier`，并在共识中绑定 `circuit_id` 和 `proof_system`。

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
