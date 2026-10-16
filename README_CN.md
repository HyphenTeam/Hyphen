# Hyphen 主链

[English](README.md)

Hyphen 是一条使用 Rust 实现的实验性隐私主链。区块版本 4 启用 AetherCompute PoUW v2：工作量来自确定性的科学计算加一次精确的 claim 搜索，验证方只复算一次场，而不是重复矿工的全部尝试。当前区块内核没有消费用户科研任务，因此只能准确称为科学计算工作证明，不能宣称已经实现任务支撑的生产级有用工作证明。

本仓库包含节点、共识、状态转换、P2P、RPC、密码学库、WASM 执行和共识测试向量。HyphenMiner、HyphenPool、HyphenWallet 是独立仓库，拥有各自的锁文件、CI 和发布边界，但必须使用同一套链身份和 PoUW 测试向量。

## 当前边界

项目尚未经过独立密码学、共识或电路审计，也没有已发布的生产主网。命令行中的 mainnet 仍是研究配置，不应承载真实资产。

设计理念、威胁模型、机制状态与已知局限全部写在[白皮书](docs/whitepaper.md)里。引用本仓库任何主张之前请先读它。

- H-BFM 已实现固定 DAG 的规范排序、缺父块拒绝、DA 集合检查和原子冲突处理；DAG 集合一致性、激励和活性仍未完成。
- H-FOC 已实现持久锁、timeout/view-change、双委员会 handoff 和 receipt obligation；不可偏置 beacon、在线 pacemaker/leader、最终委员会来源、区块执行接线和 WAN 基准仍未完成。
- H-SAC 已实现单输出 opening 和绑定 auditor/scope 的所有权证明；冻结的合规关系、provenance ZK 电路、证明器/验证器接线和独立审计仍未完成。
- AetherCompute 的任务状态机已接入区块执行、RPC/P2P、mempool、状态根和重组回滚。用户任务结算默认使用拒绝验证器；没有真实且审计过的电路/VK 时不会结算。
- WASM 支持签名部署和调用，失败执行原子回滚。hyphen.app ABI 支持 defi、game、utility 分类，并强制 hyphen_query 只读。
- Explorer 的核心渲染器由 Rust 编译为 WASM；浏览器 API 不返回科学对象 locator、凭证或私有交易 payload。

## 科学计算 PoUW v3

共识工作量是对可验证数学见证的搜索。区块必须认领 `difficulty` 个互异的 Cunningham 链见证，链长 `pouw_chain_length` 是 epoch 不变的共识参数：

```text
见证 n  <=>  n, 2n+1, 4n+3, …（长度 L）全为素数且全部 < 2^64
```

素性判定不是"假定正确"，而是**可证明正确**：Miller-Rabin 使用 Jaeschke、Sorenson 与 Webster 证明对全 `n < 2^64` 无假阳性的七基集合。共识路径不存在概率误差上界，也不需要大整数依赖。验证者付 `L` 次素性检验（微秒级），求解者在密度按 `A_L · (ln n)^-L` 下降的候选空间中搜索（秒到分钟级）；每个被接受的见证都是可独立核验的数论数据，而不是烧掉的摘要。

**绑定方式与直觉相反，这一点必须写清楚。** 用 header 派生过滤器（`H(header ‖ n) < T`）绑定见证是**不成立**的：构造 `m / p` 条链的求解者可以满足之后**每一个** header——过滤器按 header 逐次求值而池子持久，于是每多一个区块的边际成本塌缩成几次哈希。宽度为 `b` 的剩余类绑定同样失效：覆盖全部剩余类的代价 `2^b · m / density` 恰好等于一个诚实区块的代价 `m · 2^b / density`。因此见证必须**单次使用**：`hyphen-state::WitnessSet` 用稀疏 Merkle 集合记录已认领见证，预计算池只能花掉一次，总工作量守恒，预计算退化为"提前挖矿"、零优势。

工作量承诺按父区块链式构造：`pow_commitment = BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)`。承诺刻意做成父区块相对而非集合根——集合根依赖整条已认领集合，竞争者为自己分支挖块时必须知道该分支的集合状态，这是不可维护的耦合。单次使用仍然是节点对自身分支已认领集合的本地判定，重组时释放被拆下区块的见证，使回退的分支可原样重新接入。

诚实定位：这是可验证数学搜索。验证成本与求解成本结构性不对称（`L` 次素性检验 vs 完整搜索），见证集是可发布的数据集。它不是关于人工智能、量子计算或外部科研资助的声明——那些属于 AetherCompute 结算层，且默认 fail-closed。
## 链身份迁移

PoUW v3 改变了区块版本、共识参数和创世哈希；序列化切换到 RustBinary 0.1.8 的 schema 驱动紧凑档后，创世哈希再次改变。规范向量位于 test-vectors/chain-identity-v6.json（v1 与 v5 保留为已被取代身份的历史记录）。旧数据库会在任何状态变更前因 params_hash 不匹配而拒绝打开；Miner、Pool 和 Wallet 也必须同步升级，否则会因协议版本或链身份不匹配而拒绝服务。链身份与创世块只有一份实现，位于 hyphen-core，由 ChainConfig 单独推导（ChainIdentity::of、build_genesis_block），区块版本常量同样来源于此。Miner 与 Pool 以路径依赖链接并在运行时派生身份；Wallet 是独立发布的应用，因此钉住同样的取值，并用单元测试与规范向量比对，一旦漂移立即失败。没有这类测试的复制常量会把客户端钉死在一条已不存在的链上，握手在第一个字节就会失败。区块头里不再存在 arena/page/pouw_depth 等失效参数，共识参数哈希只承诺真正生效的字段。

当前 devnet 标识：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=521f6cdc47f4424c1ea7b9f4d6770cf114f620cdff62958060f8c6953cb69de8
genesis_hash=4c24528fa76c896299d5bfa6d7fee28bf39b21c0efd1684d4b8bafa9819bde55
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

Explorer 使用 HTTP；RPC、P2P 和模板端口是二进制协议。修改 Explorer Rust 渲染器后运行：

```powershell
.\scripts\build-explorer-wasm.ps1
```

共识和持久化编码使用 RustBinary 0.1.2 的固定宽度、小端、限制字节/集合长度并拒绝尾随字节的配置。格式迁移必须显式失败，禁止在共识哈希、签名或授权路径中自动回退。

### 依赖策略

本仓库不保留依赖镜像，也没有任何 `[patch.crates-io]` 覆盖：每个依赖都是 crates.io 正式发布版本，由提交的锁文件固定。对"这个 crate 要不要引"的默认答案是不引——hex 编解码、base58 编解码、SNTP 客户端和 NTP 校正时钟都实现在 `hyphen-crypto` 与 `hyphen-core` 内部，因为共识 crate 不该为几十行字节处理引入一条供应链。

合约 VM 使用 Wasmi 2.0（纯 Rust 解释器，内建 fuel 计量），不再是 JIT 运行时。这是刻意的取舍：

- 执行在所有主机上确定性一致，合约 fuel 消耗是可复现的共识值，共识路径里没有代码生成器；
- 依赖图从 368 个 crate 降到 267 个，同时移除整个 Cranelift、`bindgen`、CMake、`libclang` 和原生工具链面；
- Wasmi 已通过两次独立审计，其中包括 Stellar Development Foundation 委托 Runtime Verification 的审计。

Wasmer 间接引入的 `proc-macro-error2` 2.0.1 已彻底离开依赖图。上游从未发布修复其 `pub extern crate proc_macro;` 可见性问题的版本，因此移除需要它的运行时是唯一正确的解法。

合约 gas 单位随运行时改变：指令 fuel 现在按 Wasmi 模型计费，而不是 Wasmer 的每操作一点。主机侧计费（`GAS_STORAGE_READ`、`GAS_HASH`、`GAS_LOG` 等）保持不变。任何按 PoUW v1 的 gas 数值调过的合约预算都必须重新测量。

## 许可证

所有 Hyphen 自有代码，包括 HyphenMiner、HyphenPool 和 HyphenWallet，均使用 PolyForm Strict License 1.0.0。第三方依赖遵循各自许可证。完整条款见 [LICENSE](LICENSE)。
