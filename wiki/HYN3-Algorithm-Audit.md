# HYN3 算法审计与测量 · 2026-11-21

本次验证对象是 `hyphen-neural-devnet-v3`。单线程 Rust 与 CUDA 评分加主机内存计算在相同的 131,072 个 nonce 上得出相同的 507 个有效解。8 份已有归档和 1 份本轮生成的 16 跳兑付归档，分别通过独立工作量验算和节点全状态重放。离线储备在一条规范历史中至多兑付一次，收款人的到账取决于广播、入块和此后的分叉选择。直接使用过主仓 Rust 子地址 API 的集成需要迁移旧子地址资产。[钱包迁移说明](Security-Asset-Review.md) · [网络参数](../crates/hyphen-core/src/config.rs) · [归档验证入口](../crates/hyphen-consensus/src/replay.rs)

## 工作量、吞吐与内存

Core i7-11850H、RTX A4000 Laptop GPU、Windows x64、驱动 596.71、Rust 1.97.0 release。挑战来自创世块的第一个子块，矿工公钥为 32 个 `0x13`。连续 16 窗口，每窗 8,192 个 nonce，每个窗口先运行 CUDA，再运行单线程 Rust。CUDA 只计算神经评分，两条完整路径都在主机计算两道 BLAKE3 门槛。计时排除插件加载、权重生成、签名、网络和出块。主机另有编译与测试负载，两个后端的先后顺序固定。[挖矿流程](Operations-Mining-Acceleration.md)

| 同一批 131,072 次尝试 | 总时间 | 合计吞吐 | 每窗最短至最长 |
| --- | ---: | ---: | ---: |
| 单线程 Rust 完整搜索 | 52.350 s | 2,504 nonce/s | 2.400–4.171 s |
| CUDA 评分和主机完整判定 | 43.008 s | 3,048 nonce/s | 2.041–3.277 s |
| 上一行中的 CUDA 评分调用 | 1.422 s | 92,162 score/s | 0.075–0.104 s |

同窗完整搜索吞吐比为 **1.22 倍**。每个评分都与 Rust 比较，每个获胜 nonce 及其顺序也逐个比较。另用主仓 `work_cost` 跑 16 个不同种子各 1,024 次，1,016 次进入内存阶段，60 个获胜。搜索共 18.991 s，逐个重新生成权重并验证 60 个解共 0.974 s。这一组种子、二进制和同期主机负载与上表不同。[Rust 基准](../crates/hyphen-consensus/examples/work_cost.rs)

另以真实本地节点、SOLO 矿池和矿工各连续运行约 180 秒。CPU 和 CUDA 各接受 22 份、拒绝 0 份，均达到高度 22。逐高度核对了后端记录，CUDA 未发生回退。每组各采集 179 个 GPU 板卡功率样本。两条链分别调难，板卡传感器只覆盖 GPU 用电。稳定性记录覆盖每个后端实际运行的三分钟。[逐组计时、温度和功耗](Operations-Mining-Acceleration.md)

固定向量 `nonce=125` 的第二阶段有 32,768 个顺序填充单元和 32,768 次状态依赖读取。下表对每种间隔实际重算并比对完整 32 字节摘要。调用数计入内存初始化与最终摘要，第一道筛选另算。[Rust 独立实现](../crates/hyphen-consensus/examples/hyn3_work_audit.rs) · [固定向量](../test-vectors/neural-block-work-v3.json)

| 每隔多少个单元保存一次 | 保留的摘要字节 | BLAKE3 调用 |
| ---: | ---: | ---: |
| 1 | 1,048,576 | 65,538 |
| 2 | 524,288 | 81,818 |
| 3 | 349,536 | 98,258 |
| 4 | 262,144 | 114,664 |
| 8 | 131,072 | 179,772 |
| 16 | 65,536 | 308,540 |
| 32 | 32,768 | 571,068 |

设单元数为 `N`、间隔为 `k`。保留 `32 ceil(N/k)` 字节，每次读取下标 `j` 多做 `j mod k` 次哈希；顺序填充、每步读取的结果及最后摘要均可用归纳法证明相同。这给出了上述实现的时间与空间成本。片上 SRAM、并行 nonce 和专用 BLAKE3 电路均可能改变最优方案。BRAM36 的容量折算只说明容纳这些字节至少需要多少总位数。芯片速度、能耗和成本上界仍缺 FPGA 综合与板测、ASIC 布局布线和同任务整机电表读数。[门槛定义和概率假设](Consensus-Neural-Work.md)

## 资产安全的条件与证明

**离线储备。** 假设哈希抗碰撞、签名不可伪造、Ristretto 离散对数困难，收款人从自己的验证节点安装检查点，节点按协议验证并原子提交区块。资金输出绑定网络、金额、费用和初始所有者。逐跳验签时，收款请求绑定前一凭证摘要，当前持有人再对该请求签名。对跳数归纳，末端公钥的权限来自同一资金凭证。兑付验证器从规范位置读取一次性公钥与承诺，检查整条授权链、末端签名及范围证明，重新生成唯一目的输出。因此对被接受的兑付有 `兑付净额 + 固定费用 = 储备金额`。[授权和兑付验证](../crates/hyphen-tx/src/offline.rs)

**同一历史的唯一性。** 每种分支授权都从链标识、真实输出公钥和承诺推导同一个花费标识，重定位索引也不改变它。设同一历史有两笔成功兑付。同块重复由区块内去重拒绝；跨块时，第一笔原子提交同时写入标识和付款，第二笔需要该标识不存在，产生矛盾。重组共同回滚付款和标识。证明的范围是一条给定的规范历史，持有人仍须按自己的确认深度复核。对两个互不通信的离线收款人，另一份授权的存在不会改变任一方本地看到的字节；付款状态可复制时，无法同时保证两人都能到账。[原子写入及撤销](../crates/hyphen-state/src/atomic.rs) · [分叉集成测试](../crates/hyphen-consensus/src/chain.rs)

| 交付情形 | 收款人当时可以核实 | 到账条件 |
| --- | --- | --- |
| 付款人离线、收款人在线 | 核验预留资金与当前链上的花费状态，保留自己的请求，签收和提交兑付 | 自己的节点确认匹配请求、地址和约定净额的付款 |
| 收款人离线、付款人或中继在线 | 收款人用预装检查点和请求核验，末端持有人可离线签署兑付，在线方代为广播 | 收款人恢复联网后独立核对规范兑付与深度 |
| 双方离线、连续转付 | 每一跳核验同一储备和双方签名，每一位收款人保留自己的请求和完整授权链。每笔最多 16 跳 | 末端持有人联网后提交或经中继提交，按规范历史处理冲突 |

钱包会在 `accept`、`transfer` 和 `redeem` 核对回流凭证中本机记录过的转出决定，包括初始出资人的首笔转付。签名文件在决定持久化后发布。用同一请求重试时须指定新的输出文件名。合法回流可继续转付，本机日志的保护取决于设备保留完整签名历史。付款人与收款人基于同一储备进行多次整额转付，独立支付不同金额需分别准备储备。[钱包入口](../crates/hyphen-node/src/bin/hyphen-offline.rs) · [操作步骤](Offline-Payments.md)

本机用三个独立签名日志作 16 跳循环转付，全程签名只用本地检查点和文件。偶数跳调用 `accept` 两次，奇数跳由下次转付直接检查历史。末端凭证 4,240 字节，兑付交易 4,319 字节，两次签署的文件 SHA-256 相同。节点在高度 9 收录 `226e9f510e5de8c3783c841aa9f78fe4bf12a1c4b91653cbf7054c1134197fd6`，净额 9,000,000 原子单位。在线查询时已有 2 次确认，停止节点后查到 5 次确认，独立工作验算与全状态重放得到同一高度 13 链顶。详细结果在 `target/audit-local/payments-80a8e3c0-bf76-4298-b783-c0c5a7501173/result.json`。

**Rust 钱包子地址。** 旧子地址派生对公开材料的依赖使其支出密钥面临暴露。修正后用主种子作为 BLAKE3 密钥，按域、账户、索引及用途派生两个子密钥，并以固定公钥向量验证恢复结果。普通主地址使用独立的原有入口。已用旧 API 收款的外部集成需单独处理既有资产。扫描普通输出时，钱包现在只派生一次主密钥对，每个输出只计算一次接收方 ECDH，共享结果用于归属判断、解密和承诺核对。[派生与迁移说明](Security-Asset-Review.md) · [钱包扫描](../crates/hyphen-wallet/src/wallet.rs)

**普通交易与应用。** 普通隐私支付的条件还包括 CLSAG 的可链接性、Pedersen 承诺的绑定性、范围证明的可靠性、规范编码，以及钱包秘密和验证节点的完整性。验签绑定真实规范环成员，范围和承诺平衡约束共同限制凭空增加面值。挖矿授权另行绑定奖励键。DeFi 示例在两种合约内资产上遵守 `账户余额之和 + 挂单锁定量 = 初始化供应量`，逐条检查转账、挂单、成交和撤单可得；算术失败或 Wasm trap 不提交部分变更。NFT 每次铸造检查发行人和上限，每次转移或销毁检查权限和版本，更新后清除旧批准。两种合约管理各自状态，原生 HPN 的兑付另走原生交易。[交易验证](../crates/hyphen-consensus/src/validator.rs) · [限价单](../contracts/limit-orders/lib.rs) · [NFT](../contracts/collection/lib.rs)

**AetherCompute。** HYN3 节点重新执行 Alice 描述符和候选解，核对输出、隐藏激活、操作数与签名，超过挑战截止高度才能最终化。该描述符公开导出一个有效参考输入，最终化证明的是接受关系成立，无法证明求解者耗费了特定时间或完成任意外部科学任务。`reward` 是发布者签署的报价。`hyphen-compute reward` 可用一笔独立的原生储备把报价实际付给工作者；发布者仍须出资并签署，最终化本身不划款。测试覆盖不同发票、重试、深度、重组撤销、重新入块、工作者钱包余额及归档重放。[执行验证](../crates/hyphen-compute/src/inline.rs) · [付款测试](../crates/hyphen-node/tests/compute_reward.rs)

**叔块与发行。** 历史以太坊 Ethash 每块最多引用两个叔块，验证祖先关系、近期已引用集合与叔块头，叔块作者得到 `(8 − 深度) / 8` 倍补贴，收录矿工每个得到 `1/32` 倍补贴。HYN3 的最大收录数和这两项奖励均为零，浏览器展示的近期兄弟块不参与分叉权重。研究配置的奖励辅助函数现在以宽整数计算比例，对零分母返回零，超出 `u64` 的估值饱和。启用可支付叔块仍需完整工作见证、矿工授权、分支内跨块去重及版本化发行规则。[历史 Geth 实现](https://github.com/ethereum/go-ethereum/blob/v1.10.26/consensus/ethash/consensus.go) · [Hyphen 验证和奖励计算](../crates/hyphen-consensus/src/validator.rs)

## 主要算法的成本与覆盖范围

时间按实现的操作数估计。额外内存与持久存储分别列出。数据库查找、椭圆曲线群运算和签名验证的耗时因后端和机器而异。

本轮还修正了 Q32.32 极值附近的取整和神经提交宽度转换，取消了基准对首道门槛的重复计算。LWMA 在历史长度不匹配时退回初始难度，V2 自相关统计单遍累计。基准发行量估算保留原有分段舍入规则，直接累计已进入尾部的区间，避免遍历极端高度或在边界回绕。[定点算术](../crates/hyphen-neural/src/fixed.rs) · [难度](../crates/hyphen-pow/src/difficulty.rs) · [发行估算](../crates/hyphen-economics/src/emission.rs)

| 模块或操作 | 时间与空间 | 验证与边界 |
| --- | --- | --- |
| `neural` 正向计算与 HYN3 PoW | 输入、隐藏、输出宽度 `i,h,o`；评分用 `ih+ho` 次乘加，权重占 `ih+h+ho+o` 个 64 位字。每个首门通过者另用 `Θ(N)` 次哈希与 `32N` 字节全表 | HYN3 为 16/64/16，即 2,048 次乘加。单个合法块须重算评分与两道门槛 |
| `neural` 研究求解器 | 每轮雅可比 `O(iho)`、正规方程 `O(oi²)`、每次线性求解 `O(i³)`。额外数组含 `io`、`i²` 和权重。迭代和重启由参数限制 | 链上验解走前向计算。LM 求解可提前退出，也可能耗尽预算 |
| `pow` 历史工作量，`consensus` 难度 | Cunningham 对每个候选筛小素数，对留下的链元素做 64 位确定性 Miller–Rabin，至多 7 个底数。LWMA 窗口长 `w`，用 `O(w)` 时间；V2 保留 `O(w)` 解时数组，自相关额外空间 `O(1)` | V2 保留旧窗口根取值以维持历史兼容。HYN3 单独从 16 个间隔重定门槛 |
| `core`、`wire`、`transport`、`crypto` | 编码与哈希随总字节数线性增长。输出树的 Merkle 路径固定 32 层；验证用 32 次合并哈希与常量工作空间。环签名每输入随环宽 `r` 线性增长 | 固定网络和工作向量、严格签名验证、编码元素与字节预算；实验 WOTS 需要一次性密钥状态 |
| `tx`、`proof`、`wallet` 与离线工具 | `m` 个输出的聚合范围证明使用 `64m` 个比特坐标，验证的群项与临时向量为 `O(64m)`，内积证明轮数为 `log₂(64m)`。`t` 跳授权链需 `2t` 次签名验证和 `O(t)` 凭证；本地检查点对已花储备作 `O(log s)` 次认证读取 | 批接口逐证明验证。添加每一跳都重验前缀，走满 `t` 次转付累计 `O(t²)`。持久签名日志依赖不可回滚的本机历史 |
| `compute`、`vm` 与合约 | Alice 前向验解与权重大小同阶。`p` 个保留签名的第三高期限单遍 `O(p)`、额外 `O(1)`，最终化找到三个合格项即停止。Wasm 账本根随编码状态字节数增长 | HYN3 每块最多 32 个计算转换，任务上限 2,048。VM 每交易最多 128,000,000 gas，每块最多 256,000,000 gas，账本最多 8 MiB。外部托管的三个签名键不能证明三个独立运营方 |
| `state`、`consensus` 与历史重放 | 规范 nullifier 根流式扫描 `s` 条记录，`O(s)` 时间、常量哈希空间。持久化完整承诺树快照要编码并压缩整个快照。分叉计划与分歧路径长度成正比，再逐块执行验证；归档阅读器将有上限的归档读入内存 | 重放对照块头与状态根。研究稀疏 Merkle 树深度 256；历史恢复另有数据可用性条件 |
| `economics`、`token`、`mempool` | 单块补贴、费用和固定宽度发行策略为常量次算术；供应量展示按 1,024 块分段积分，最坏 `O(1+高度/1024)`、额外 `O(1)`，同奖励区间可跳过。内存池 B 树索引单次操作 `O(log n)`，候选选择或清理可扫描 `n` 项 | 展示供应是近似基准发行，精确到账由规范交易决定。代币库的承诺、发行策略检查和合约内的发行权限各有自己的调用入口 |
| `network`、`rpc`、`node`、`explorer`、`explorer-web` | 接收、解码和传输至少与实际消息字节数成正比；请求的总成本还包括相应的索引查找、证明、状态复制或历史扫描。RPC 计算任务分页最多 100 条 | 本地回放和集成测试覆盖被调用的路径。公网上的传播尾延迟、浏览器负载、磁盘放大、独立钱包或矿池全平台性能均未做本轮逐函数测量 |

研究模块有各自的验收条件。公平排序对 `v` 个合格条目和 `q` 个观察者最多比较 `qv(v−1)` 次，预算为 8,000,000；每次观察者位置查询使用 B 树，关系图最多有 `v(v−1)` 条边。可用性证明对整份数据计算分块承诺，证书另按席位去重并逐票验签。两阶段终局性模块检验锁和双委员会交接，实际运行需要网络和超时调度。Fusion 先求父块可达闭包，再按确定的拓扑顺序处理冲突；该模块要求调用者预先验证区块及其可用性。上述研究模型的单元测试覆盖票据冲突、交接、缺失父块和顺序一致性，HYN3 的规范分支仍由累计工作选择。[公平排序](../crates/hyphen-consensus/src/private_fair_ordering.rs) · [数据可用性](../crates/hyphen-consensus/src/availability.rs) · [终局性](../crates/hyphen-consensus/src/fair_finality.rs) · [Fusion](../crates/hyphen-consensus/src/fusion.rs)

本轮实测的范围证明中，1/2/4/8/16 个输出的证明依次为 675/739/803/867/931 字节，单证明验证中位数为 2.799/5.190/5.607/6.675/10.715 ms，各取 11 次。接近 8 MiB 账本时，两笔指令密集调用使用 255,999,992 gas，执行 125.552 ms、算根 2.501 ms；2,560 笔短调用共使用 547,840 gas，执行 2,070.509 ms、算根 1.805 ms。这是本机两种构造负载，可见每次调用本身的开销。它们没有覆盖所有合法程序的最坏执行时间。[范围证明基准](../crates/hyphen-consensus/examples/range_verify_cost.rs) · [VM 基准](../crates/hyphen-vm/examples/block_cost.rs)

## 复核方法

在有锁定依赖缓存的工作区运行下列命令。`hyn3_work_audit` 不带参数时核对固定向量与七种内存间隔，附加归档路径时逐块重建头哈希、门槛、见证和累计权重。它和节点共享归档解码与基础密码库，两者的工作量计算分别实现。节点的 `--verify-history` 另外执行交易与完整状态转换。

```powershell
$archive = 'target/audit-local/payments-80a8e3c0-bf76-4298-b783-c0c5a7501173/final.archive'
$cudaDir = 'target/hyn3-audit-nov/fresh-cuda'
cargo run --release --locked --offline -p hyphen-consensus --example hyn3_work_audit -- $archive
cargo run --release --locked --offline -p hyphen-node --bin hyphen-node -- --network neural-devnet --verify-history $archive
cargo run --release --locked --offline -p hyphen-consensus --example work_cost
cargo run --release --locked --offline -p hyphen-consensus --example range_verify_cost
cargo run --release --locked --offline -p hyphen-vm --example block_cost
0..15 | ForEach-Object {
    & ./HyphenMiner/target/release/hyphen-miner.exe --accelerator-dir $cudaDir accelerator-check --batch 8192 --offset ($_ * 8192) --timings
    if ($LASTEXITCODE) { throw "window $_ failed" }
}
```

8 份已有归档高度分别为 14、23、7、19、31、15、11、10。加上高度 13 的新兑付归档，九份归档共重放 143 条创世后记录，含共享祖先的重复记录。已有归档的 SHA-256、链顶和累计工作见本机 `target/audit-local/replayed.csv` 与 `reference.jsonl`。新归档的 SHA-256 为 `8080aecd4b168a1fe0c530d29bbe41e7e0b087db849fd0d8b7e2e380ce75de0e`，其目录内的 `reference.jsonl` 记录独立验算结果。原始测量见 `target/audit-local/` 中的 `accelerator-windows.txt`、`cpu-windows.csv`、`range.csv` 和 `vm.csv`。矿工可执行文件 SHA-256 为 `6da2db9703dd57a38fb8f28d504fa4729157a60963f8e7658bfb38efe8dea919`，CUDA DLL 为 `197e188e9eb70b21654dc6938a2ff15bde72b77bb4d7fa3920053fe816d9d728`。独立矿工的锁文件指向共享库提交 `8bb9f0f4c43f1fba8a20bbcb1a0e93b907ccccb7`，主仓测试使用当前工作区源码。

最终源码的 `cargo test --release --locked --offline --workspace --all-targets` 共 447 项通过、2 项默认忽略。另行运行两项忽略测试时，五个实际编译的合约样本通过部署、执行及节点重开检查，公共根 DNS 递归解析测试因 TCP 连接超时失败。合约工具链集成使用 `archived_contract_devnet_v1()`，HYN3 的验证另见上面的开发网归档。Alice 通过项目脚本重建，产物为 10,637 字节，BLAKE3 为 `3f9d8305f8203c28402bc2a4f07b4fae3f85758ed63d16195c965edf2e390187`，四项 VM 集成测试通过。复核 Alice 时使用项目脚本或从合约目录构建，以载入 VM 要求的内存链接配置。独立矿工默认 25 项通过，另行运行的原生 CUDA 测试通过。工作区和矿工格式检查、release Clippy `-D warnings` 均通过。[Alice 构建](../scripts/build-alice-contract.ps1) · [合约工具链验收](../scripts/test-contract-toolchains.ps1)

最终重放所用节点的 SHA-256 为 `a03387e7459cec69fc980a8dcae1b306aca99693bbdd461a7f555f8112713ccd`。三分钟挖矿使用的节点早于最终钱包修正，该次节点 SHA-256 为 `6527dea3bae5abd35f995bbf4654eb61eda5b2ce572a3f53be6be898e23fadd5`。独立 Rust 验算与最终节点对九份归档逐一得出相同的链顶。

独立 fuzz 工作区的四个解码目标通过 `cargo check --release --locked --offline --manifest-path crates/hyphen-fuzz/Cargo.toml --all-targets`。本次记录的是编译检查。`cargo-audit 0.23.0` 使用本地 RustSec 库 `074ea9a7` 和 `--no-fetch --no-yanked`，扫描主仓、fuzz、Alice、独立矿工、矿池和钱包的六份锁文件，报告已知漏洞数均为零。主仓有 `fxhash`、`instant` 和 `paste` 停止维护提示。逐算法的形式化验证、第三方密码学评审和真实资产生产验收仍待完成。
