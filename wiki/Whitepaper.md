# Hyphen neural proof of work and private settlement

Status: research base chain. No mainnet has been launched, no independent
consensus, cryptographic or circuit audit has been performed, and nothing in
this document should be read as a safety claim about real value. Every mechanism
below is labelled with what the code actually establishes today.

---

## 0. Summary

Hyphen is a Rust research blockchain for private payments and Wasm applications. On `neural-devnet`, miners evaluate a fixed-point neural network for each nonce. When the BLAKE3 gate passes, they compute the final digest using a 1 MiB scratchpad. Nodes independently verify both thresholds.

Everything else in this document is engineering: how the state transitions
atomically, how difficulty is controlled without floating point, how keys and
addresses are derived, and what remains unproven.

## 1. Design philosophy

**Determinism beats performance, always.** Consensus values must be identical on
every host, so no `libm` call, no floating point and no JIT sits on that path.
The difficulty controller is integer-only; the contract VM was moved from a
Cranelift JIT to a pure-Rust interpreter with built-in fuel metering — a
deliberate acceptance of lower throughput in exchange for reproducible fuel
accounting and the removal of a code generator from consensus.

**Every dependency must justify itself against a hand-written alternative.** The
hex codec, the base58 codec, the SNTP client and the NTP-adjusted clock live in
the workspace, because a consensus crate should not import a supply chain for
forty lines of byte shuffling. The dependency graph is 267 crates; it dropped by
101 crates in one step when the Wasm runtime changed, and the whole Cranelift,
`bindgen`, CMake and `libclang` surface disappeared with it.

Unsupported proof systems are rejected according to the active [profile rules](Consensus-Profiles.md).
Section 11 records the implementation status and open validation requirements for each research mechanism.

Application compute tasks carry their own signed descriptions and results. The block work score determines mining eligibility.

## 2. System overview

| Layer | Implementation | Status |
| --- | --- | --- |
| Consensus | Neural score, BLAKE3 scratchpad and threshold-based fork weight | [Consensus](Consensus-Neural-Work.md) |
| State | Atomic multi-root transition with undo journal, reorg coordinator, H-WES expiry | Active |
| Privacy | Stealth addresses, CLSAG rings, Pedersen commitments, Bulletproof-style range proofs | Active |
| Disclosure | H-SAC one-output opening with scoped Schnorr ownership proof | Research, inactive |
| Execution | Wasmi 2.0 interpreter, fuel metering, bounded host ABI | Active |
| Settlement | AetherCompute | [Profile rules](Consensus-Profiles.md) |
| Network | libp2p (gossipsub, Kademlia, identify, relay, DCUtR), template protocol TP v4 | Active |
| Pool | NCAP miner authorization, share receipts, Pool Protocol v6 | Active, spec in `Research-Non-Custodial-Pool` |
| Wallet | Flutter client over a Rust core: derivation, encrypted storage, isolated signer | Active |

## 3. Consensus

### 3.1 Block validation

Full nodes derive the nonce challenge from the parent, height and miner key. They verify the two gates, timestamp, branch-specific threshold, miner authorization and state transition. Branch adoption requires strictly greater validated cumulative weight. [Consensus rules](Consensus-Neural-Work.md)

## 4. State model

The canonical state is a small number of roots combined into the header's state
root: the AetherCompute snapshot, the WASM ledger, and the H-WES reference
expiring state. Block application is atomic across all of them plus the
commitment tree, nullifier set, chain tip and the branches. A serialised undo
record per block carries the previous snapshots, the transaction hashes, output
indices and nullifiers needed for exact rollback, so a reorg is a deterministic
inverse operation rather than a re-derivation.

H-WES (recoverable state expiry) keeps a five-root atomic state: signed public
creation, bounded deterministic expiry and reorg rollback are implemented and
integrated on research profiles; a shielded recovery circuit, incentives and
benchmarks are not.

## 5. Privacy layer

Ordinary transfers use one-time output keys, linkable ring signatures and range proofs. The amount and the public fee have different visibility. The precise balance relation, signer scope and cross-network limitation are specified in the [payment rules](Consensus-Profiles.md). H-SAC selective disclosure remains a separate research protocol.

## 6. Execution and scientific settlement

Contracts are WASM modules executed by a pure-Rust interpreter. The validator
forbids floating point, SIMD, threads, shared memory, memory64, multi-memory,
component model and exception handling; exactly one bounded exported memory is
required; a start section is rejected; imports are restricted to the frozen host
ABI. Fuel is charged by the interpreter itself, so out-of-gas is a deterministic
consensus outcome rather than a wall-clock accident, and host calls add their own
explicit charges for storage, hashing and logging.

Enabled verifiers, public inputs, limits and activation are fixed by the [consensus profile](Consensus-Profiles.md).

## 7. Economics

Block reward follows a logistic decay:

```text
R_lcd(h) = R_tail + (R_0 − R_tail) · c² / (h² + c²)
R(h)     = R_lcd(h) · μ(h)
```

with `R_0` the initial reward, `R_tail` the asymptotic floor, `c` the decay
constant, and `μ(h)` an optional multiplier bounded by the MSE floor and ceiling
in basis points. The deviation from a hard cap is intentional: a chain with
perpetual tail emission has a predictable long-run security budget, whereas a
capped chain converts into a fee-only regime whose security depends on fee
demand. Fees are partly burned (`fee_burn_bps`), which offsets tail issuance at
the margin without pretending to make supply deflationary.

Uncle blocks are supported on research profiles with an explicit reward split
(7/8 to the uncle miner, 1/32 to the nephew) so that orphaned work is partially
compensated and the incentive to withhold blocks is reduced.

## 8. Network and pool protocol

Peers run libp2p with Noise, Yamux, gossipsub, Kademlia, identify, ping,
request-response, relay and DCUtR, all with DNS and mDNS excluded from the
runtime graph. Node-to-pool communication is the Template Provider protocol
(TP v4); pool-to-miner is Pool Protocol v6. A template is bound to network
magic, the consensus parameters hash and the genesis hash, and the miner
recomputes the transaction root and rejects any mismatch in chain identity,
header, difficulty, depth, miner key or reward key.

Block authorization is miner-signed: the pool may relay an authorised block but
cannot change the header or the reward recipient, and the signature covers the
full solved header, the chain identity and the reward keys. Share accounting uses
pool-signed envelopes with a hash-chain receipt, so a miner can prove what it
submitted even if the pool disappears.

## 9. Wallet

The wallet derives account and sub-address keys from a seed and encodes an `hy1…` address with a version, public view and spend keys, and a checksum. Storage supports plaintext and password-encrypted save/load. Recovery from a seed requires scanning chain history. A wallet with saved scan state can resume from its checkpoint. Its displayed receipts depend on the canonical history supplied by the selected node.

The signer is a separate protocol boundary: a request carries the network
binding, the key locator, the ring signing inputs and a reviewable output set,
and a response is verified against the network binding before use. This is what
allows a hardware or remote signer to be dropped in without changing the wallet
core.

## 10. Engineering standards

- Rust 1.97.0, pinned in CI, with `--locked` everywhere.
- Gates that must all pass before anything is called done: workspace build,
  `clippy --all-targets -- -D warnings`, `rustfmt --check`,
  `cargo test --workspace --all-targets`, `cargo doc --no-deps` with
  `RUSTDOCFLAGS=-D warnings`, the fuzz workspace build, a RustSec audit, a
  regression check that `bincode` cannot re-enter the dependency graph, and a
  check that the excluded DNS resolver is absent from the build graph.
- No dependency mirror and no `[patch.crates-io]` override: every dependency is
  a crates.io release pinned by the committed lockfile.
- Determinism review as a category: floating point, `libm`, hash-map iteration
  order and platform-dependent integer widths are treated as consensus bugs
  rather than style issues.

## 11. Limitations and roadmap

Stated plainly, because a reader who discovers these later has been misled:

1. **No audit, no mainnet.** `mainnet` here is a research profile.
2. Independent measurements of optimized solvers, dedicated hardware, memory–time tradeoffs and energy per verified block are pending.
3. **Research mechanisms outside HYN3.** H-WES shielded recovery,
   H-BFM DAG set agreement, H-FOC' live pacemaker and beacon, and the H-SAC
   compliance circuit are unimplemented beyond the reference models.
4. See the profile table for the active settlement verifier. [HYN3 profile](Consensus-Profiles.md)
5. **Cross-repository coordination is mandatory.** Miner, Pool and Wallet pin
   chain identity and block version; a consensus change requires updating all
   three before any joint test can pass.

The release priority is a quantified fork-security model, reproducible consensus and monetary-soundness vectors, crash recovery and independent review.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen 神经工作量证明与隐私结算

状态：研究型主链。尚未启动主网，也没有经过独立的共识、密码学或电路审计；本文任何内容都不构成对真实资产安全的声明。下面每个机制都标注了代码今天真正建立的东西。

## 0. 摘要

Hyphen 是以 Rust 实现的隐私支付与 Wasm 应用研究链。`neural-devnet` 的矿工搜索由 nonce 派生的定点神经网络输入，初筛通过后执行 BLAKE3 scratchpad，节点独立复算两个门槛。

其余内容都是工程：状态如何原子迁移、难度如何在不使用浮点的前提下控制、密钥与地址如何派生，以及还有什么尚未证明。

## 1. 设计哲学

**确定性永远优先于性能。** 共识值必须在所有主机上完全一致，因此该路径上不允许出现 `libm`、浮点和 JIT。难度控制器全程整数；合约 VM 从 Cranelift JIT 换成纯 Rust 解释器并内建 fuel 计量——这是刻意用吞吐换可复现的 fuel 计费，并把代码生成器逐出共识路径。

**每个依赖都必须与手写替代方案竞争上岗。** hex 编解码、base58 编解码、SNTP 客户端和 NTP 校正时钟都实现在本仓库内，因为共识 crate 不该为几十行字节处理引入一条供应链。依赖图共 267 个 crate；仅更换 Wasm 运行时一步就砍掉 101 个，Cranelift、`bindgen`、CMake、`libclang` 整套原生面随之消失。

**Fail closed，并且让失败可见。** 拒绝型验证器、拒绝打开的数据库、不可信时钟和关闭的研究功能都是系统明确报告的状态。静默回退被视为缺陷：解析失败后"再试别的方式"的编码路径正是共识分裂的成因。

第 11 节列出各项研究机制的实现状态和仍需完成的验证。

应用计算任务单独签名和结算；区块的神经评分用于判定出块资格。

## 2. 系统总览

| 层 | 实现 | 状态 |
| --- | --- | --- |
| 共识 | 定点神经评分、内存门槛和累计权重 | [规范](Consensus-Neural-Work.md) |
| 状态 | 带 undo journal 的多根原子迁移、reorg 协调器、H-WES 过期 | 生效 |
| 隐私 | 隐身地址、CLSAG 环签名、Pedersen 承诺、Bulletproof 型范围证明 | 生效 |
| 披露 | H-SAC 单输出 opening + 受限 Schnorr 所有权证明 | 研究，未激活 |
| 执行 | Wasmi 2.0 解释器、fuel 计量、受限主机 ABI | 生效 |
| 结算 | AetherCompute | [按 profile 查看](Consensus-Profiles.md) |
| 网络 | libp2p（gossipsub、Kademlia、identify、relay、DCUtR）、TP v4 模板协议 | 生效 |
| 矿池 | NCAP 矿工授权、share receipt、Pool Protocol v6 | 生效，规范见 `Research-Non-Custodial-Pool` |
| 钱包 | Flutter 客户端 + Rust 核心：派生、加密存储、隔离签名器 | 生效 |

## 3. 共识

### 3.1 区块与 epoch

全节点重算神经分数、BLAKE3 scratchpad、阈值、时间与状态转移，并检查奖励授权。重组时仅接纳验证通过且累计权重严格更大的分支。[计算与选链规则](Consensus-Neural-Work.md)

## 4. 状态模型

规范状态是少量根的组合，汇总进区块头的状态根：AetherCompute 快照、WASM ledger、H-WES 引用过期状态。区块应用在它们以及承诺树、nullifier 集、链尖和分支归档上原子完成。每个区块序列化一条 undo 记录，携带先前快照以及精确回滚所需的交易哈希、输出索引与 nullifier，因此重组是确定性的逆操作，而不是重新推导。

H-WES（可恢复状态过期）维护五根原子状态：签名公开创建、有界确定性过期与重组回滚已实现并接入研究 profile；屏蔽恢复电路、激励与基准尚未完成。

## 5. 隐私层

普通付款使用一次性输出公钥、可链接环签名及范围证明。手续费公开，金额承诺与输出顺序共同参与验证。签名关联、余额等式及跨网络边界见[共识规范](Consensus-Profiles.md)。H-SAC 选择性披露属于独立研究。

## 6. 执行与科学结算

合约是纯 Rust 解释器执行的 WASM 模块。校验器禁止浮点、SIMD、线程、共享内存、memory64、多内存、组件模型与异常；要求恰好一个受限导出内存；拒绝 start section；导入被限制在冻结的主机 ABI 内。fuel 由解释器自身计费，因此 out-of-gas 是确定性的共识结果而不是墙钟意外；主机调用对存储、哈希和日志另行显式计费。

各 profile 允许的电路、公开输入、资源上限与生效条件以[共识规则表](Consensus-Profiles.md)为准。

## 7. 经济模型

出块奖励遵循 logistic 衰减：

```text
R_lcd(h) = R_tail + (R_0 − R_tail) · c² / (h² + c²)
R(h)     = R_lcd(h) · μ(h)
```

其中 `R_0` 为初始奖励，`R_tail` 为渐近下限，`c` 为衰减常数，`μ(h)` 为可选的、受 MSE 上下限（基点）约束的乘子。偏离硬顶是刻意的：永续尾部排放的链拥有可预测的长期安全预算，而硬顶链会转入依赖手续费需求的安全模型。手续费按 `fee_burn_bps` 部分销毁，在边际上抵消尾部发行，但不会假装让供给变成通缩。

研究 profile 支持叔块并带显式奖励分配（叔叔矿工 7/8，侄块 1/32），以部分补偿被孤立的算力并降低扣块激励。

## 8. 网络与矿池协议

节点使用 libp2p，包含 Noise、Yamux、gossipsub、Kademlia、identify、ping、request-response、relay 与 DCUtR，且 DNS 与 mDNS 已被排除出运行图。节点到矿池通信是 Template Provider 协议（TP v4），矿池到矿工是 Pool Protocol v6。模板绑定 network magic、共识参数哈希与创世哈希；矿工重算交易根，并拒绝链身份、区块头、难度、深度、矿工密钥或奖励密钥的任何不匹配。

区块授权由矿工签名：矿池可以转发被授权的区块，但不能改动区块头或收款方；签名覆盖完整已求解区块头、链身份与奖励密钥。Share 记账使用矿池签名信封加哈希链 receipt，因此即使矿池消失，矿工也能证明自己提交过什么。

## 9. 钱包

钱包由种子派生账户与子地址密钥，并用版本字节、view/spend 公钥和校验和构造 `hy1…` 地址。存储支持明文和口令加密。只用种子恢复需要扫描历史；持有已有扫描状态的钱包可以从检查点续扫。收款记录取决于所选节点提供的规范链历史。

签名器是独立的协议边界：请求携带网络绑定、密钥定位符、环签名输入与可审阅输出集合，响应在使用前必须对照网络绑定校验。这正是硬件或远程签名器可以即插即用、而无需改动钱包核心的原因。

## 10. 工程标准

- Rust 1.97.0，CI 固定版本，所有命令带 `--locked`。
- 称之为"完成"前必须全绿的门禁：工作区构建、`clippy --all-targets -- -D warnings`、`rustfmt --check`、`cargo test --workspace --all-targets`、`cargo doc --no-deps` 且 `RUSTDOCFLAGS=-D warnings`、fuzz 工作区构建、RustSec 审计、`bincode` 不得重回依赖图的回归检查，以及被排除的 DNS 解析器不得出现在构建图中的检查。
- 没有依赖镜像、没有 `[patch.crates-io]` 覆盖：每个依赖都是由提交的锁文件固定的 crates.io 正式发布版本。
- 把确定性当作一个审查类别：浮点、`libm`、哈希表迭代顺序与平台相关整型宽度被当作共识缺陷，而不是风格问题。

## 11. 局限与路线

直说，因为读者若在之后才发现这些，就是被误导了：

1. **没有审计，没有主网。** 这里的 `mainnet` 是研究 profile。
2. 专用硬件优势、替代求解器成本及每焦耳评分需要独立测量。
3. H-WES 屏蔽恢复、H-BFM DAG 集合一致性、H-FOC' 在线 pacemaker 与 beacon、H-SAC 合规电路仍处于研究阶段。
4. HYN3 从创世启用内联 Alice 任务验证器。[共识规则表](Consensus-Profiles.md)
5. 矿工、矿池和钱包分别核对链身份与区块版本，共识变更需要跨仓库联测。

发布前优先验证分叉权重的安全模型、共识与金额守恒向量、故障恢复，并接受独立审查。
