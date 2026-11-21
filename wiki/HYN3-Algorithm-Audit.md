# HYN3 算法审计与测量 · 2026-11-21

本次验证对象是 `hyphen-neural-devnet-v3`。单线程 Rust 与 CUDA 评分加主机内存计算在相同的 131,072 个 nonce 上得出相同的 507 个有效解。8 份已有归档和 1 份本轮生成的 16 跳兑付归档，分别通过独立工作量验算和节点全状态重放。离线储备在一条规范历史中至多兑付一次，收款人的到账取决于广播、入块和此后的分叉选择。直接使用过主仓 Rust 子地址 API 的集成需要迁移旧子地址资产。[钱包迁移说明](Security-Asset-Review.md) · [网络参数](../crates/hyphen-core/src/config.rs) · [归档验证入口](../crates/hyphen-consensus/src/replay.rs)

最终节点与集成矿工另生成五份实矿归档，四份高度 21，一份高度 22。连同上述九份，十四份归档共核对 249 条创世后记录，计数包含共享历史。当前发布判断为继续 HYN3 开发网验证。主网放行仍缺专用硬件测量、长期多机稳定性、独立密码学与共识评审，以及真实资产验收。

## 满块转账与 Parent Chain 复核

HYN3 对完整编码区块设置 2,097,152 字节上限。模板选择原先只累计交易正文，临界负载会漏算区块头、工作量见证、矿工授权和交易长度前缀。节点现在按实际线格式收取每笔前缀，给 v5 区块结构和见证预留空间。矿池自定义模板使用同一预算。RPC 和对等节点共用的准入入口也检查区块中单个交易字节向量的 1,000,000 元素上限。[节点模板](../crates/hyphen-node/src/main.rs) · [交易准入](../crates/hyphen-rpc/src/admission.rs)

在临时磁盘库中挖出 HYN3 奖励，链上拆分得到 4,096 个可独立花费的输出，每个输出签发一笔普通 CLSAG 转账。测试使用节点默认手续费、容量和过期策略，调用 RPC 与 P2P 共用的准入函数、矿池模板及区块提交处理函数。每次提交后逐笔检查剩余交易仍在内存池，数据库重开后逐笔匹配区块哈希与交易序号。接收钱包解密并核对全部输出承诺，净收 99,995,625,075,298 原子单位。结果来自单节点进程内调用。[容量回归测试](../crates/hyphen-node/src/payment_capacity.rs)

| 高度 | 收录转账 | 完整编码字节 | 池中待确认 |
|---:|---:|---:|---:|
| 8 | 1,733 | 2,095,723 | 2,363 |
| 9 | 1,733 | 2,095,725 | 630 |
| 10 | 630 | 762,198 | 0 |

复测命令为 `cargo test --release --locked --offline -p hyphen-node --bin hyphen-node payments_roll_over -- --ignored --nocapture`。1,733 是本次单输入、单输出支付的装载量。费用优先级、交易大小、协议交易、过期及内存池驱逐都会影响实际确认高度。

Parent Chain 按高度横向排列可选区块卡片，分支单独占行。Chrome 核对了高度 13 的 14 个规范块、2 个旁支及 15 条连线，逐条比对完整父哈希与卡片边界。390 和 1,280 像素视口分别验证了选择窗口内任一区块后卡片完整可见。哈希坐标视图单独按需绘制。[渲染实现](../crates/hyphen-explorer/src/stack.js) · [浏览器验收](../scripts/measure-explorer.mjs)

## Pascal 构建与调难开销

GTX 1060 对应 Pascal `sm_61`。本轮用 CUDA 12.9.86 编译 `sm_61`、`sm_75`、`sm_86` 及 `compute_61` PTX，静态链接 CUDA 运行时。Release 插件 SHA-256 为 `cdd720dee3ba6cde9512a43c701745b95dcf84853969dff12df704e0d7c9a66a`。在 RTX A4000 Laptop 上原生运行 32,768 个 nonce，另强制驱动从 PTX 编译并运行后续 8,192 个 nonce，分别得到与 Rust 一致的 119 和 33 个解。GTX 1060 的实际吞吐、功耗及温度尚缺板测。[构建说明](../HyphenMiner/wiki/Operations.md)

HYN3 调难沿用 16 个间隔、30 秒目标及逐块四倍调整界限。节点按链顶哈希复用最近的区块头，正常延长只需读取新增块；重组时沿新父哈希回溯，重开后从持久化链重建。高度 21 同一静止链顶交替执行两条读取路径，每种 8 轮、每轮 500 次。逐次读取并解码 17 个块体与缓存命中的单次平均耗时取各轮中位数，分别为 80.504 和 7.259 微秒，两者均算出门槛 `1125899906842624`。这是热链顶查询耗时。[窗口实现](../crates/hyphen-consensus/src/chain.rs) · [调难规则](../crates/hyphen-consensus/src/neural_work.rs)

对应节点 SHA-256 为 `e6bcebe11f88b3b26bde40c493a6c8471a48e7b12bc37f0852022ac091bc3045`。节点重放既有 14 份归档均匹配原链顶。新 CUDA 插件另实矿 45.44 秒，接受 21 份，拒绝 0 份。新增归档的高度 21 和累计工作 5,691 经节点重放和独立 Rust 实现复核。本轮工作区 release 测试 449 项通过、3 项默认忽略，上述转账压力测试单独执行通过。Clippy 使用 `-D warnings`。RustSec 数据库 `f291af9b1cc0d21dfcea1709d6b037963cef262b` 扫描工作区及独立矿工锁文件，匹配漏洞数均为 0；工作区依赖有 `fxhash`、`instant`、`paste` 三项停止维护提示。本轮原始记录在 `target/parent-chain-audit/`。

其余两个默认忽略项也已单独执行。五种已编译合约在两种配置下的部署、执行和重开测试通过。公共根 DNS 递归解析测试连续两次在 TCP 建连时超时，本轮记录为失败。

## 工作量、吞吐与内存

Core i7-11850H、RTX A4000 Laptop GPU、Windows x64、驱动 596.71、Rust 1.97.0 release。挑战来自创世块的第一个子块，矿工公钥为 32 个 `0x13`。连续 16 窗口，每窗 8,192 个 nonce，每个窗口先运行 CUDA，再运行单线程 Rust。CUDA 只计算神经评分，两条完整路径都在主机计算两道 BLAKE3 门槛。计时排除插件加载、权重生成、签名、网络和出块。主机另有编译与测试负载，两个后端的先后顺序固定。[挖矿流程](Operations-Mining-Acceleration.md)

| 同一批 131,072 次尝试 | 总时间 | 合计吞吐 | 每窗最短至最长 |
| --- | ---: | ---: | ---: |
| 单线程 Rust 完整搜索 | 52.350 s | 2,504 nonce/s | 2.400–4.171 s |
| CUDA 评分和主机完整判定 | 43.008 s | 3,048 nonce/s | 2.041–3.277 s |
| 上一行中的 CUDA 评分调用 | 1.422 s | 92,162 score/s | 0.075–0.104 s |

同窗完整搜索吞吐比为 **1.22 倍**。每个评分都与 Rust 比较，每个获胜 nonce 及其顺序也逐个比较。另用主仓 `work_cost` 跑 16 个不同种子各 1,024 次，1,016 次进入内存阶段，60 个获胜。搜索共 18.991 s，逐个重新生成权重并验证 60 个解共 0.974 s。这一组种子、二进制和同期主机负载与上表不同。[Rust 基准](../crates/hyphen-consensus/examples/work_cost.rs)

另以真实本地节点、SOLO 矿池和矿工各连续运行约 180 秒。CPU 和 CUDA 各接受 22 份、拒绝 0 份，均达到高度 22。逐高度核对了后端记录，CUDA 未发生回退。每组各采集 179 个 GPU 板卡功率样本。两条链分别调难，板卡传感器只覆盖 GPU 用电。稳定性记录覆盖每个后端实际运行的三分钟。[逐组计时、温度和功耗](Operations-Mining-Acceleration.md)

新 CUDA 内核以规格化除数的高位估计商，再用完整整数乘积校正。旧、新 DLL 按窗口交替先后，在同一挑战下各搜索 8 × 8,192 个 nonce，每个版本的 65,536 个评分和 245 个获胜 nonce 均与 Rust 相符。旧、新版本的评分调用合计分别为 0.6853、0.6546 秒，含主机判定的完整搜索分别为 18.5856、19.1782 秒。评分用时下降 4.5%，该批完整搜索用时上升 3.2%。新 DLL 的 SHA-256 为 `48cb91e97f196232b4394dcdef9ff2c37d0ba80b4773a4d7c97232f051716ba2`。在使用原锁定共享库的矿工上另从创世启动 CPU 和新 CUDA 两组 SOLO 实矿，分别运行 70.37 和 70.47 秒，均在高度 21 累计接受 21 份、拒绝 0 份，逐高度日志确认后端。

主机挖矿线程在首次进入第二道门槛时分配 1 MiB，此后在该线程复用；验块按次分配和释放。1,024 个输入逐个比对完整摘要一致。独立矿工的一份隔离构建通过 Cargo 本地覆盖使用工作区 `hyphen-neural`，SHA-256 为 `14fdf9b075fd836360715e4e00d0fee8bdc2708e8136c83e9bc18c8cdd6a3062`。在相同新版 CUDA DLL 上，原锁定矿工与该构建交替搜索同样的八个窗口。单线程 CPU 完整搜索合计从 32.122 秒降至 28.457 秒，CUDA 加主机判定从 31.373 秒降至 28.890 秒，两种构建各找到相同的 245 个解。测量期间本机并行运行其他验证任务。生产集成需将独立矿工的共享库版本指向发布该变更的提交。[主机工作实现](../crates/hyphen-neural/src/block_work.rs)

为单独测量缓冲区复用，又在同一源码目录、同一锁文件和原 CUDA 插件下各编译一次，只替换 `block_work.rs` 的分配实现。每种构建先预热，再交替完成相同的 8 × 8,192 个 nonce。逐次分配与线程内复用的 CPU 完整搜索分别用时 18.0042、15.2265 秒，CUDA 加主机分别为 17.4670、15.1321 秒，两者各得到 245 个解。本轮累计用时分别减少 15.4% 和 13.4%。据此保留主机复用。逐窗原始数据见 `host-control/windows.csv`。

最终节点与上述集成矿工的 CPU 和 CUDA 实矿分别运行 70.15 和 70.46 秒，各接受 21 份、拒绝 0 份。两条独立链均在高度 18 开始调整，至高度 21 门槛为 `2^52`、累计工作为 5,691。对两份导出归档又分别运行节点全状态重放和独立 Rust 工作量验算。CPU 归档 SHA-256 为 `c92bf86ada2a6f0f5a6dca8685b1988d4eef87154466e0a39a5fc86b88375a92`，CUDA 归档为 `6a3c69c8b0fb70daa6d49cacb079ec8191cb197d8ebf6f188f0e33c95976a605`。两次短测各覆盖四个调整高度。较长时间内能否稳定贴近 30 秒目标，还需随算力变化实测。

集成矿工预热后，再对同样 8 个窗口交替加载原 CUDA 内核和候选内核。两者各核对 65,536 个评分、245 个解。评分合计分别为 0.5828、0.5908 秒，完整搜索为 14.6370、14.5465 秒。候选内核在两轮完整搜索中的耗时变化方向相反，矿工源码选用原来的整数内核。逐窗计时保存在 `integrated-plugin-windows.csv`。

选用的原 CUDA 内核与集成矿工在新数据目录中实矿 70.50 秒，接受 22 份、拒绝 0 份，逐高度核对了 CUDA 后端。其高度 22 链顶为 `99536a4007ee197973424f95f24b365c498841e366de1f2098829e5235ee711e`，累计工作 22,074。导出归档的 SHA-256 为 `37e95f90eb92e243ca3229cc00f0cd837e45135877586dd5772039f4b8f515a3`，由节点重放和独立 Rust 实现再次核对。记录位于 `selected-cuda/result.json` 及 `selected-cuda/replay.json`。

从相同配置和锁文件重新链接后，可执行文件的 SHA-256 变为 `58993ed58396bcda0a7504d428686e635f174ad8cb9bf3a32e83fe6fe58e9a6e`。本机保留此副本为 `integrated-miner.exe`。独立数据目录内的 CPU 和原 CUDA 插件分别实矿 30.27、30.19 秒，各接受 21 份、拒绝 0 份。两份归档均经节点和独立 Rust 实现复核至高度 21、累计工作 5,691。二进制清单及逐组链顶保存在 `integrated-miner.json`。两次链接的字节级可重复性尚未建立。

调难回归测试以确定性的平均解题时间驱动实际 `expected_threshold`，四段算力依次为基线的 1、8、1 和 1/8 倍，每段 32 个块。逐块核对四倍变化界限和门槛上限。前三段的末次间隔距 30 秒均在 2 毫秒以内，末段达到最易门槛 `2^62` 后，模型的平均间隔为 60 秒。该模型省略随机出块和传播延迟。[调难回归测试](../crates/hyphen-consensus/src/neural_work.rs)

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

**近期兄弟块与发行。** HYN3 浏览器要求本节点曾验证该块、与同一正高度的规范块同父、工作承诺不同，并且距当前链顶少于 16 个高度。高度 13 的保留历史有两个旁支块，其中一个符合条件。规范分支按已验证累计工作选择。HYN3 的叔块最大收录数、收录奖励和旁支奖励均为零。研究配置的奖励辅助函数以宽整数计算比例，对零分母返回零，超出 `u64` 的估值饱和。启用可支付叔块需完整工作见证、矿工授权、分支内跨块去重及版本化发行规则。[兄弟块定义及与 Ethash 的差异](Consensus-Neural-Work.md) · [验证和奖励计算](../crates/hyphen-consensus/src/validator.rs)

## 浏览器、钱包与同高重组

同一 HYN3 创世下，归档 `combined.archive` 的 SHA-256 为 `ce09405eae9a71947315ee57647c95e44d4642bcf734b3d717ff11c6e6fa9cc0`。其高度 31 链顶为 `e8cb8e56edf747b9e67642beb63cb2c3bd6d31465cba2dbd79ad092d795a0813`。任务 `c4a57b6ce563a8f86bb771810fc57e2cb91cfc48b11b423d01117c868152f0db` 在高度 12 发布、14 提交、31 最终化，公开报价为 1 个原子单位。应用页列出六份合约，包括 DeFi、NFT、C、C++、Wasm 汇编和一个 Rust 合约。另一个高度 13 的节点在两页均返回零条。Block Stack 的 14 个规范块含创世，另有 2 个旁支块；逐条比对的 15 条画布连线均匹配完整父哈希。[浏览器 API](../crates/hyphen-explorer/src/lib.rs) · [归档重放](../crates/hyphen-consensus/src/replay.rs)

将 `combined.archive` 的前 19 块重放到空目录，保持该节点的应用页打开，再接入重放 `market-to-compute.archive` 的节点。两链同为高度 19，累计工作分别为 263 和 573。节点实际撤下并接纳各 19 块；应用页自动从六份合约更新为空。两类列表携带旧链顶均得到 HTTP 200，携带当前链顶均得到 204。另在高度 13 和 31 的静止历史上，浏览器测量脚本恢复一个过期页码，以实际 HTTP 请求核对回退后的内容。四组列表均回到第一页，同链顶的刷新保留原 DOM 元素。[列表路由](../crates/hyphen-explorer/src/app.js) · [Chrome 验收脚本](../scripts/measure-explorer.mjs)

在最终二进制上再次触发同一重组，保持打开的 AetherCompute 页自动将同一任务从 `submitted` 更新为 `finalized`。另一浏览器仅将客户端分页大小从 20 调为 2，以六份实际部署进入第三页。重组后通过正常刷新回到第一页并显示空状态。HTTP 内容、链顶与节点分叉选择均来自真实节点。另逐个打开高度 31 的六个合约详情，并与原归档记录核对六个部署地址、部署高度及全部 19 笔交易的位置。

高度 31 浏览器展示的 DeFi 和 NFT 合约代码分别为 5,638 和 6,246 字节。工具链重建及重开测试使用当前源码的 5,898 和 6,509 字节产物。C、C++、Wasm 汇编在两组记录中的大小分别为 706、708、451 字节。

Chrome 157.0.8103.79 在同一高度 13 上收到 120 次角度输入，旧版绘制 120 次并赋值 240 次画布尺寸，新版绘制 1 次、尺寸赋值 0 次。新版在 500 ms 空闲和隐藏窗口内均绘制 0 次，恢复后重新绘制。启用和禁用动效、详情往返、快速导航以及宽度 390 和 1280 的布局均通过。禁用往返缓存后，GC 后使用的 JS 堆从 702,208 变为 691,388 字节，单份画布像素估算均为 1,283,508 字节。另以全新配置启动 headless Chrome 各三次，初始 Block Stack 静置四秒后采样，均计入 11 个 Chrome 进程。进程树私有字节中位数从 351,088,640 变为 353,533,952，工作集总和中位数从 633,335,808 变为 636,952,576 字节。工作集总和包含跨进程共享页。浏览器整体的内存下降尚无实测依据。[浏览器测量](../scripts/measure-explorer.mjs)

Windows 钱包使用 Flutter 3.50.0 release、相同原生 runner 和空的测试凭据存储。以 `bacc4436c680b8ceb0b5a43471a27f5cd19b541a` 为基线，与本地修改各启动三个新进程；路由稳定后每页计数五秒。欢迎页及节点模式页原各产生 300–301 帧，新版六个采样窗口均为 0 帧。设备像素比为 1 时，Flutter 已解码图片缓存从 11,614,464 降至 57,600 字节。欢迎页 RSS 中位数从 141,271,040 变为 141,848,576 字节，节点模式页从 144,969,728 变为 142,581,760 字节。两页的进程内存变化方向不同。11 项 Flutter 测试全部通过，含原生 FFI、交互后空闲和列表数据对象重建后奖励金额的双向 Hero 过渡。原始逐次记录见同目录 `wallet-final-rss.log`。

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

集成构建在独立矿工的源码副本上只覆盖 `hyphen-neural` 的来源，保留其余 Git 依赖的提交。本机该副本的 `Cargo.lock` 的 SHA-256 为 `c437caeaf427b0c233b343c929bed652308415041a7f1bd7d463fb3dec938ddf`。从主仓根目录可用本轮保存的配置和锁文件重建并检查集成矿工。

```powershell
$run = (Resolve-Path 'target/explorer-hyn3-eee7ddc8-bfc4-4bfd-90f8-e947316ed8c0').Path
$cudaDir = (Resolve-Path 'target/hyn3-audit-nov/fresh-cuda').Path
cargo build --release --locked --offline --config "$run/miner-local.toml" --manifest-path "$run/miner-source/Cargo.toml" --target-dir "$run/miner-build"
if ($LASTEXITCODE) { throw 'Miner build failed' }
& "$run/miner-build/release/hyphen-miner.exe" --accelerator-dir $cudaDir accelerator-check --batch 8192 --offset 0 --timings
```

设置 `HYPHEN_REQUIRE_ALICE_WASM=1` 后，`cargo test --release --locked --offline --workspace --all-targets` 共 448 项通过、2 项默认忽略。单独运行合约工具链脚本，在 `ChainConfig::neural_devnet()` 和 `archived_contract_devnet_v1()` 分别部署并执行 DeFi、NFT、C、C++ 和 Wasm 汇编，重开磁盘库后核对链顶、状态根、存储及查询结果。另一个默认忽略项是公共根 DNS 递归解析，前次遇到 TCP 超时，本轮单跑通过。Alice 通过项目脚本重建，产物为 10,637 字节，BLAKE3 为 `3f9d8305f8203c28402bc2a4f07b4fae3f85758ed63d16195c965edf2e390187`，四项 VM 集成测试通过。独立矿工默认 25 项通过，新 CUDA DLL 的原生评分窗口测试通过。工作区和矿工通过 release Clippy `-D warnings`。[Alice 构建](../scripts/build-alice-contract.ps1) · [合约工具链验收](../scripts/test-contract-toolchains.ps1)

最终重放所用节点的 SHA-256 为 `73ebea9c1a0f5942f9f7eb4977534823800b397f5b7644de8bc020d79d2076ed`。三分钟挖矿所用节点的 SHA-256 为 `6527dea3bae5abd35f995bbf4654eb61eda5b2ce572a3f53be6be898e23fadd5`，首次 70 秒新 CUDA 实矿使用 `5fa9820ff8ff2338de08b0599bb86aa633feab4e04bfab583237cd70e6d81449`。独立 Rust 验算与最终节点对九份归档逐一得出相同的链顶。当前工作区本机原始记录位于 `target/explorer-hyn3-eee7ddc8-bfc4-4bfd-90f8-e947316ed8c0/`，含 `candidate-archives.json`、`candidate-apps.json`、`candidate-render.json`、`candidate-memory.json`、`host-windows.csv`、`before-19.json` 和 `after-19.json`。

独立 fuzz 工作区的四个解码目标通过 `cargo check --release --locked --offline --manifest-path crates/hyphen-fuzz/Cargo.toml --all-targets`。本次记录的是编译检查。`cargo-audit 0.23.0` 使用本地 RustSec 库 `074ea9a7` 和 `--no-fetch --no-yanked`，扫描主仓、fuzz、Alice、独立矿工、矿池和钱包的六份锁文件，报告已知漏洞数均为零。主仓有 `fxhash`、`instant` 和 `paste` 停止维护提示。逐算法的形式化验证、第三方密码学评审和真实资产生产验收仍待完成。
