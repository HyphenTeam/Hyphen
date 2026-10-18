# Hyphen 主链

[English](README.md)

Hyphen 是一条使用 Rust 实现的实验性隐私主链。区块版本 5 启用 PoUW v3：工作量来自对一次性 Cunningham 链见证的可验证搜索，验证方只做确定性的整数素性检验，而不是重复矿工的全部尝试。AetherCompute 的任务状态机已接入区块执行，默认验证器只结算 Alice 神经挑战电路，其余电路仍拒绝；因此这里只能准确称为科学计算工作证明，不能宣称已经实现任务支撑的生产级有用工作证明。

本仓库不包含 HyphenMiner、HyphenPool、HyphenWallet 三个产品。它们是独立的 Git 仓库，拥有各自的锁文件、CI、发布流程和安全边界；本签出可能在同目录并列放置 `HyphenMiner/`、`HyphenPool/` 与 `HyphenWallet/`，`.gitignore` 保证它们不进入本仓库历史。三者存在时，`scripts/devnet-smoke.ps1` 会构建并运行它们；不存在时会给出明确错误而不是静默跳过。协议变更可能需要三端协同升级，但这不会让它们成为本仓库的一部分。

## 当前边界

项目尚未经过独立密码学、共识或电路审计，也没有已发布的生产主网。命令行中的 mainnet 仍是研究配置，不应承载真实资产。

设计理念、威胁模型、机制状态与已知局限全部写在[白皮书](docs/whitepaper.md)里。引用本仓库任何主张之前请先读它。

- H-BFM 已实现固定 DAG 的规范排序、缺父块拒绝、DA 集合检查和原子冲突处理；DAG 集合一致性、激励和活性仍未完成。
- H-FOC 已实现持久锁、timeout/view-change、双委员会 handoff 和 receipt obligation；不可偏置 beacon、在线 pacemaker/leader、最终委员会来源、区块执行接线和 WAN 基准仍未完成。
- H-SAC 已实现单输出 opening 和绑定 auditor/scope 的所有权证明；冻结的合规关系、provenance ZK 电路、证明器/验证器接线和独立审计仍未完成。
- AetherCompute 的任务状态机已接入区块执行、RPC/P2P、mempool、状态根和重组回滚。默认验证器结算 Alice 神经挑战电路的任务，每次提交都在本地重做一次确定性前向传播；其余电路仍由拒绝验证器挡住，没有真实且审计过的电路/VK 时不会结算。
- WASM 支持签名部署和调用，失败执行原子回滚。hyphen.app ABI 支持 defi、game、utility 分类，并强制 hyphen_query 只读。
- Explorer 的核心渲染器由 Rust 编译为 WASM；浏览器 API 不返回科学对象 locator、凭证或私有交易 payload。页面、脚本、模块和所有 `/api/…` 路由都由 Courierust 自带的 HTTP/1.1 + HTTP/2 服务端提供，状态与 socket 之间没有 Web 框架，且每个响应都带同一套 media type、`nosniff`、`no-referrer` 与 CSP。

## 科学计算 PoUW v3

共识工作量是对可验证数学见证的搜索。区块必须认领 `difficulty` 个互异的 Cunningham 链见证，链长 `pouw_chain_length` 是 epoch 不变的共识参数：

```text
见证 n  <=>  n, 2n+1, 4n+3, …（长度 L）全为素数且全部 < 2^64
```

素性判定不是"假定正确"，而是**可证明正确**：Miller-Rabin 使用 Jaeschke、Sorenson 与 Webster 证明对全 `n < 2^64` 无假阳性的七基集合。共识路径不存在概率误差上界，也不需要大整数依赖。验证者付 `L` 次素性检验（微秒级），求解者在密度按 `A_L · (ln n)^-L` 下降的候选空间中搜索（秒到分钟级）；每个被接受的见证都是可独立核验的数论数据，而不是烧掉的摘要。

**绑定方式与直觉相反，这一点必须写清楚。** 用 header 派生过滤器（`H(header ‖ n) < T`）绑定见证是**不成立**的：构造 `m / p` 条链的求解者可以满足之后**每一个** header——过滤器按 header 逐次求值而池子持久，于是每多一个区块的边际成本塌缩成几次哈希。宽度为 `b` 的剩余类绑定同样失效：覆盖全部剩余类的代价 `2^b · m / density` 恰好等于一个诚实区块的代价 `m · 2^b / density`。因此见证必须**单次使用**：`hyphen-state::WitnessSet` 用稀疏 Merkle 集合记录已认领见证，预计算池只能花掉一次，总工作量守恒，预计算退化为"提前挖矿"、零优势。

工作量承诺按父区块链式构造：`pow_commitment = BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)`。承诺刻意做成父区块相对而非集合根——集合根依赖整条已认领集合，竞争者为自己分支挖块时必须知道该分支的集合状态，这是不可维护的耦合。单次使用仍然是节点对自身分支已认领集合的本地判定，重组时释放被拆下区块的见证，使回退的分支可原样重新接入。

诚实定位：这是可验证数学搜索。验证成本与求解成本结构性不对称（`L` 次素性检验 vs 完整搜索），见证集是可发布的数据集。它不是关于人工智能、量子计算或外部科研资助的声明——那些属于 AetherCompute 结算层，目前只激活了神经挑战电路，且该验证器只证明确定性、不度量搜索量。
## 链身份迁移

PoUW v3 改变了区块版本、共识参数和创世哈希；序列化切换到 RustBinary 0.1.8 的 schema 驱动紧凑档后，创世哈希再次改变。规范向量位于 test-vectors/chain-identity-v6.json（v1 与 v5 保留为已被取代身份的历史记录）。旧数据库会在任何状态变更前因 params_hash 不匹配而拒绝打开；Miner、Pool 和 Wallet 也必须同步升级，否则会因协议版本或链身份不匹配而拒绝服务。链身份与创世块只有一份实现，位于 hyphen-core，由 ChainConfig 单独推导（ChainIdentity::of、build_genesis_block），区块版本常量同样来源于此。Miner 与 Pool 通过各自的锁文件钉定同一份公开 revision，不在本地链接主链路径，因此可以从干净克隆构建；Wallet 是独立发布的应用，同样钉住该 revision，并用单元测试与规范向量比对，一旦漂移立即失败。没有这类测试的复制常量会把客户端钉死在一条已不存在的链上，握手在第一个字节就会失败。区块头里不再存在 arena/page/pouw_depth 等失效参数，共识参数哈希只承诺真正生效的字段。

当前 devnet 标识：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=521f6cdc47f4424c1ea7b9f4d6770cf114f620cdff62958060f8c6953cb69de8
genesis_hash=5f7c144f0ef27880259b2429e46ef175685da679916fcc6b80c45f457465e32d
block_version=5
pouw_protocol_version=3
```

## 构建与运行

要求 Rust 1.97.0 和主机 C/C++ 工具链：

```powershell
cargo build --release --locked -p hyphen-node
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
.\target\release\hyphen-node.exe --network devnet --print-chain-identity
```

启动本地节点：

```powershell
.\target\release\hyphen-node.exe `
  --network devnet `
  --data-dir .\data\devnet-pouw-v1 `
  --listen /ip4/127.0.0.1/tcp/48334 `
  --rpc-bind 127.0.0.1:48333 `
  --template-bind 127.0.0.1:3350 `
  --explorer-bind 127.0.0.1:8080
```

要在服务器上长期运行（systemd 单元、防火墙、备份、升级与健康检查），按 [docs/operations/deploy-linux.md](docs/operations/deploy-linux.md) 操作。

Explorer 使用 HTTP；RPC、P2P 和模板端口是二进制协议。修改 Explorer Rust 渲染器后运行：

```powershell
.\scripts\build-explorer-wasm.ps1
```

共识和持久化编码使用 RustBinary 0.1.8 的 schema 驱动紧凑档：字段按声明顺序、无字段名、无类型标签，规范的 little-endian varint，容器长度前缀，并拒绝尾随字节。每次调用都设置字节与集合上限，一个值只有唯一被接受的编码。格式迁移必须显式失败，禁止在共识哈希、签名或授权路径中自动回退。

### 依赖策略

本仓库不保留依赖镜像，也没有任何 `[patch.crates-io]` 覆盖：每个依赖都是 crates.io 正式发布版本，由提交的锁文件固定。对"这个 crate 要不要引"的默认答案是不引——hex 编解码、base58 编解码、SNTP 客户端和 NTP 校正时钟都实现在 `hyphen-crypto` 与 `hyphen-core` 内部，因为共识 crate 不该为几十行字节处理引入一条供应链。真正引入的外部 crate 只回答本仓库不该自己回答的问题：有界二进制编解码（`rustbinary`，在 `hyphen-wire` 中冻结）、种子名字的 DNSSEC 校验解析（`recurse-x`）、面向运营者的时间戳日历（`tzcraft`）、服务 Explorer、矿池结算 API 与付款链路两端的 HTTP/1.1 + HTTP/2 栈（`courierust`——它自身零依赖，替换掉了本工作区里的 axum、tower 与 hyper），以及执行封禁策略的 peer 黑名单（`libp2p-allow-block-list`——umbrella `libp2p` crate 没有把它导出为 feature）。

Miner 不携带任何代理引擎：`--via-proxy` 自己完成 SOCKS5 或 HTTP `CONNECT` 握手，所以运营者运行的任何代理——包括带 `socks5` 或 `http` inbound 的 `corduit` 服务——都是 Miner 去拨号的外部进程，而不是它链接进来的库。

合约 VM 使用 Wasmi 2.0（纯 Rust 解释器，内建 fuel 计量），不再是 JIT 运行时。这是刻意的取舍：

- 执行在所有主机上确定性一致，合约 fuel 消耗是可复现的共识值，共识路径里没有代码生成器；
- 依赖图从 368 个 crate 降到 267 个，同时移除整个 Cranelift、`bindgen`、CMake、`libclang` 和原生工具链面；
- Wasmi 已通过两次独立审计，其中包括 Stellar Development Foundation 委托 Runtime Verification 的审计。

Wasmer 间接引入的 `proc-macro-error2` 2.0.1 已彻底离开依赖图。上游从未发布修复其 `pub extern crate proc_macro;` 可见性问题的版本，因此移除需要它的运行时是唯一正确的解法。

合约 gas 单位随运行时改变：指令 fuel 现在按 Wasmi 模型计费，而不是 Wasmer 的每操作一点。主机侧计费（`GAS_STORAGE_READ`、`GAS_HASH`、`GAS_LOG` 等）保持不变。任何按 PoUW v1 的 gas 数值调过的合约预算都必须重新测量。

workspace 显式启用了 Wasmi 的 `auto-dispatch` 特性。缺少它时引擎总是选择 tail-call 后端；在 `opt-level` 0/1 下 LLVM 无法把分派优化成尾调用，于是每执行一条指令都会推高宿主栈，长时间运行的合约会直接把进程打崩。`auto-dispatch` 正是为「LLVM 无法做尾调用优化」这一情况选择循环后端；`MAX_CONTRACT_RECURSION_DEPTH` 则给剩下的调用深度封顶。两点都由 `crates/hyphen-vm/tests` 中的合约测试钉住。

## 神经密码学挑战（研究合约）

仓库同时提供 Alice/Bob 神经挑战：链上合约公布一个随机两层感知机 `A` 与目标 `y* = A(x*)`，Rust 求解器搜索原像 `x`。验证是一次定点前向传播；求解是 Q32.32 整数上的 Levenberg–Marquardt。设计、为什么判定必须是求逆而不是「学习 Alice 权重」、实测成本边界、合约 ABI 与待办事项都在 [docs/research/neural-cryptography.md](docs/research/neural-cryptography.md)。

需要讲清楚的三点：

- 它不是区块工作量证明，也不增加链权重；
- 它不是十分钟出块时钟——链上验证必须重新生成权重，宽度轴在到达十分钟之前就会饱和；实测边界如实公布，不做承诺；
- 它不是「AI 有用性」主张。它是一个确定性逆问题，配一个便宜且精确的验证器。

求解器是普通 Rust 二进制，不需要跑节点：

```bash
cargo run --release -p hyphen-neural --bin bob-miner -- solve \
  --seed <64-hex> --epoch 1 --hidden 512
```

## 从 Kaspa 借鉴什么，不借鉴什么

Kaspa 是高吞吐 PoW 链的成熟参照。Hyphen 借鉴的是工程流程，而不是共识：

- **模板提供者分离**：节点产出区块模板，矿池把模板转成分片工作，矿工只负责搜索。`hyphen-transport` 的模板协议遵循同样的分层，区块头与交易集合只有一个真源——节点。
- **明确的分片记账**：solo、prop、pplns、pps、pps+、fpps 模式具名，费率以基点显式表示，结算先落盘再对外报告；矿池不猜余额。
- **按网络钉定身份**：network magic、共识参数哈希、创世哈希都是公开向量；节点、矿工、矿池各自派生，钱包钉住并用漂移测试兜底。
- **发布纪律**：可复现构建、带校验和的产物、钉定工具链、夜间 fuzz 与严格的依赖策略。

不借鉴 Kaspa 的共识。Kaspa 用 GHOSTDAG 的 blue set 给区块 DAG 排序；Hyphen 的 H-BFM 在固定 braid 上按全序 rank 融合，明确不是 GHOSTDAG 或 PHANTOM 实现。Kaspa 的 kHeavyHash 是摘要研磨的 ASIC 工作量；Hyphen 的 PoUW v3 是一次性 Cunningham 见证搜索，神经挑战是叠加其上的研究合约，而不是二者的替代品。照抄 Kaspa 的哈希或 DAG 排序，只会得到一条已有链的更差副本。

针对 `rusty-kaspa` 已报告过的几类问题，逐条对照本仓库（不是靠类比，而是查代码）：

| Kaspa 的问题类型 | 本仓库的状态 |
| --- | --- |
| 构造区块头时硬编码升级前的 block version | 不适用。`FROZEN_BLOCK_VERSION = 5` 是编译期常量，并被哈希进 `consensus_params_hash`；创世、校验器、授权、重放与节点都走同一常量，没有可以写错的运行期开关，改动它等于换一条链的身份。 |
| 难度加权错算父块，或随深度衰减 | 累计难度是 `header.difficulty` 的 `u128` 精确求和；该值必须等于纯整数 LWMA 控制器对当前窗口的期望值（`chain.rs` 的 `expected_difficulty`），不等即拒。共识路径没有浮点，也没有按轮次的加权项；窗口取自当前 tip 下的规范高度索引，父集合或高度不一致的区块在计分前就被拒绝。 |
| 排序不是全序，或并列时没有唯一解 | `rank(b) = (logical_round, lane, block_hash)`，作用在已认证的区块标识上；就绪集是 `BTreeSet<Rank>`，最小值唯一。 |
| 导入 UTXO／剪枝点快照却不先校验 | 不存在快照导入面。同步只有区块（`GetBlocks`／`GetBlock`），状态一律由执行重建。 |
| 恶意 peer 拖垮节点却没有任何代价 | 信封、载荷无法解码，或同步响应超出结构预算，都计分；十分钟内三次封禁一小时并断开现有连接。依赖上下文才能判定的失败**不**计分。见 [docs/security/peer-policy.md](docs/security/peer-policy.md)。 |

## 对等节点策略与版本一致性

入站 peer 只在节点能够本地证明的过错上计分：信封或载荷无法解码，或同步响应超出结构预算。十分钟内三次即封禁一小时；封禁会立即断开现有连接并拒绝重连。一个格式正确但未通过上下文校验的区块**不**计分——节点是相对当前 tip 校验的，追块同步若据此计分，会把诚实的转发者也封掉。策略细节（包括仅内存保存的局限、以及当前不存在快照导入面）见 [docs/security/peer-policy.md](docs/security/peer-policy.md)。

这里不存在可切换的区块版本：`FROZEN_BLOCK_VERSION` 是构建中唯一的版本，它被写入共识参数身份哈希，创世构造、区块头校验、授权与重放读取的都是同一个常量。profile 变更意味着新的构建和新的身份向量，而不是一个区块头构造器可能悄悄忽略的运行时开关。

## 许可证

所有 Hyphen 自有代码，包括 HyphenMiner、HyphenPool 和 HyphenWallet，均使用 PolyForm Strict License 1.0.0。第三方依赖遵循各自许可证。完整条款见 [LICENSE](LICENSE)。
