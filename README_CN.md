# Hyphen 主链

[English](README.md)

Hyphen 是一条使用 Rust 实现的实验性隐私主链。区块版本 3 启用名为 AetherCompute PoUW v1 的协议：区块工作量来自确定性的科学计算，不是寻找低于目标值的哈希。当前区块内核没有消费用户科研任务，因此只能准确称为科学计算工作证明，不能宣称已经实现任务支撑的生产级有用工作证明。

本仓库包含节点、共识、状态转换、P2P、RPC、密码学库、WASM 执行和共识测试向量。HyphenMiner、HyphenPool、HyphenWallet 是独立仓库，拥有各自的锁文件、CI 和发布边界，但必须使用同一套链身份和 PoUW 测试向量。

## 当前边界

项目尚未经过独立密码学、共识或电路审计，也没有已发布的生产主网。命令行中的 mainnet 仍是研究配置，不应承载真实资产。

- H-BFM 已实现固定 DAG 的规范排序、缺父块拒绝、DA 集合检查和原子冲突处理；DAG 集合一致性、激励和活性仍未完成。
- H-FOC 已实现持久锁、timeout/view-change、双委员会 handoff 和 receipt obligation；不可偏置 beacon、在线 pacemaker/leader、最终委员会来源、区块执行接线和 WAN 基准仍未完成。
- H-SAC 已实现单输出 opening 和绑定 auditor/scope 的所有权证明；冻结的合规关系、provenance ZK 电路、证明器/验证器接线和独立审计仍未完成。
- AetherCompute 的任务状态机已接入区块执行、RPC/P2P、mempool、状态根和重组回滚。用户任务结算默认使用拒绝验证器；没有真实且审计过的电路/VK 时不会结算。
- WASM 支持签名部署和调用，失败执行原子回滚。hyphen.app ABI 支持 defi、game、utility 分类，并强制 hyphen_query 只读。
- Explorer 的核心渲染器由 Rust 编译为 WASM；浏览器 API 不返回科学对象 locator、凭证或私有交易 payload。

## 科学计算 PoUW v1

共识输入绑定区块版本、高度、时间戳、父块、交易/状态根、epoch seed、难度、nonce、矿工公钥、费用和奖励。矿工据此生成 64x64 的 Q12 整数字段，执行二维扩散 PDE：

```text
u_next[x,y] =
  ((4096 - 4a) * u[x,y]
   + a * (u[north] + u[south] + u[west] + u[east])) / 4096

a = 512
iterations = difficulty
```

边界采用周期索引，所有运算均为确定性整数运算。pow_commitment 承诺完整最终字段以及协议版本、网格、系数、迭代数和输入承诺。节点和 Pool 独立复算后比较承诺；不存在 difficulty_to_target 或 hash < target 判定。BLAKE3 仅用于确定性输入派生和完整性承诺。

迭代数必须在 1..=4096，节点在复算前先检查期望难度，避免攻击者用任意大迭代数制造验证 DoS。Pool Protocol v5 可用较低迭代数的科学计算检查点计量贡献，再验证完整区块迭代结果。v5 将计算速率固定为每单元更新 7 次算术操作，并拒绝使用旧 9 次计量的 v4 客户端。三端固定向量为：

```text
25078c250c5b44211bbf0fea60e90ac7024df6ff94d154161852fdd72684e524
```

每个网格单元更新的规范计量是 7 次算术操作：3 次邻居加法、2 次乘法、1 次最终加法和 1 次整数除法。遥测按该模型计数，不代表 CPU/GPU 指令数或硬件无关的能耗。

固定向量证明四端实现的一致性，不等于外部审计、SNARK/STARK，也不代表用户提供的外部科学数据已经进入区块 PoUW。当前验证者会完整复算 PDE，且每个完成计算的候选都具备资格；确定性竞速的中心化、分叉率、验证成本和对抗调度尚无公开安全分析。因此这是可执行的研究计算工作协议，不是已经完成的生产级 PoUW。

## 链身份迁移

PoUW v1 改变了区块版本、共识参数和创世哈希。规范向量位于 test-vectors/chain-identity-v3.json。旧数据库会在任何状态变更前因 params_hash 不匹配而拒绝打开；Miner、Pool 和 Wallet 也会拒绝旧协议或旧链身份。

当前 devnet 标识：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=54bf97e4e28d4fcf963d884a555a8425bbfe7c84d2753001bcabbaf116232fda
genesis_hash=47d530160cfef9141fe3b37b886e09b9f96ec4dc93d6c05005b9c6dbf35b1972
block_version=3
pouw_protocol_version=1
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

`vendor/proc-macro-error2` 是当前构建依赖，不是普通依赖镜像。Wasmer 7.2.1 选择的 `proc-macro-error2` 2.0.1 在 Rust 1.97 上存在 `proc_macro` 可见性编译错误；本地副本应用上游兼容修复并保留 MIT/Apache-2.0 许可证。在 `[patch.crates-io]` 存在时不能删除。只有升级到包含修复的 Wasmer/传递依赖、重新生成 `Cargo.lock`，并通过全部 locked 构建和测试后才能移除。

## 许可证

所有 Hyphen 自有代码，包括 HyphenMiner、HyphenPool 和 HyphenWallet，均使用 PolyForm Strict License 1.0.0。第三方依赖遵循各自许可证。完整条款见 [LICENSE](LICENSE)。
