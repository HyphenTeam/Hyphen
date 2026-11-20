# 钱包资产与共识安全审查 · 2026-11-20

**发布判断仍限于无价值开发网。** `hyphen-contract-devnet-v1` 已从创世启用奖励收款键绑定、父支付状态承诺、手续费核对及合约资源预算。本地节点完成了签名付款、共享矿池奖励脱链和原分配恢复，以及 Rust、C、Wasm 汇编合约的签名部署、调用和查询。主网激活、发布网络历史重放、跨主机分区恢复和独立密码学与共识审计仍是上线条件。[开发网验收](Operations-Verification.md)

## 收款核验候选 · Receipt verification candidate

本地四仓候选 `target/hyof-receipt-rc2/` 的提交与默认 Windows Rust 测试结果如下。三份客户端清单与独立锁文件均引用同一主仓提交。各仓通过格式检查、严格 Clippy 和 Windows release 构建。

| 仓库 | 冻结提交 | 通过 / 忽略 |
| --- | --- | ---: |
| Node | `f78878eb53e2966ac10aaf51a272e57cf1e757b9` | 414 / 2 |
| Miner | `d8cda0273b935190611b2bf6cf7c3d7e83e9a863` | 23 / 1 |
| Pool | `73fc3a1ff08d7fa15d1daf5be8744fe89247fa27` | 51 / 0 |
| Wallet | `ba84c48231e57243ce5b583e4fe2a392163eaa34` | 44 / 2 |

四仓实跑中，资金交易 `0680b9b722a62669ea306c37319615c402b4b87d20eaa5608a89a78f92cb1fec` 预锁 10,000,000 原子单位。首次赢家收到 9,000,000，竞争方收到 0。换链后两人的余额互换。资金交易另一次重定位后，原末端收款人凭留存请求核对高度 14 的兑付 `fe86f6ac5d3aec40a7b10a146f1ab6505029b0737cf2ab50657e8f1446b76957`。三个分支使用同一个预锁花费标识。32 个零余额钱包均无法准备预锁付款。首页 8 项 Flutter 测试通过，另用实际 Windows release 动态库连接本机节点，核对赢家余额、竞争方余额、收款交易、扫描高度及链顶哈希。[收款操作](Offline-Payments.md)

同一签名器通过 20 对并发转付和 26 次中断试验，其中实际终止 22 次。全部可见凭证均有持久化签名决定，原请求可逐字节重试。QEMU Linux 客体执行了 51 项矿池测试和 3 项签名器测试。候选 CUDA 插件在 RTX A4000 Laptop GPU 上逐项核对了 40,962 个神经评分。真机密钥保护、跨物理主机的恢复、第三方密码学与共识审查仍待验收。累计 499,989 个输出时，当前整树快照超过解码集合限制。[状态规模与测量](Operations-Small-Host.md)

完整包 `HYOF-receipt-devnet.zip` 为 134,290,569 字节，SHA-256 为 `061ebd4473426a814b525704b9d2a35e584e2ca6b343f1009dccc14b475d2a4a`。解压程序核对了 116 个文件的摘要，并从七份归档分别重建数据库。另从最终 ZIP 中的四份 bundle 和四个锁文件，在空构建目录中重建五个命令行程序。重建程序重新完成四仓结算，换索引兑付的重放链顶为 `21c2c0b62e5e64292b671d37186d8dc8099374fad8c8efcaf49c7aad5b4b52e5`。重建程序也验证了包内原始七份归档。默认 Cargo release 设置下，两组程序的五个 SHA-256 均有差异。逐个摘要见 `target/hyof-receipt-rc2/clean-rebuild.json`。

The four receipt-verification commits above were exercised together on a local HYOF network. The recipient's retained invoice was checked against the canonical payout on each branch, including after the funding output moved from index 6 to 12. A separate test used the packaged desktop wallet's release bridge against the packaged node. All five ordinary release executables rebuilt from the ZIP completed a fresh payment and replayed all seven histories. Their digests differed from the original ordinary builds. Independent certification and physical-device acceptance remain open.

同一台 Windows 主机使用 Rust 1.97.0、MSVC、固定绝对路径、Rust 路径映射及 `/Brepro` 链接选项，从最终 ZIP 的四份 bundle 再做两次干净构建。五个命令行程序逐个 SHA-256 相同。第二组程序完整执行四仓付款并重放全部七份归档。补充包 `HYOF-reproducible-cli.zip` 为 16,331,919 字节，SHA-256 为 `d465b37d681a43509ad1d8495abc5f7c5b90d7a9a66187a4239beaa500a99ed4`。包内附两轮摘要、重建脚本和实测日志。

桌面和 Android 钱包另从最终 ZIP 中的钱包 bundle 重建。对照 26 个桌面文件和 1 个 APK，17 个摘要相同，10 个不同。重建桌面钱包的 Rust 动态库从实际节点核对了高度 14 的赢家交易、余额与扫描链顶。重建 ARM64 APK 通过调试证书 v2 验签。真机运行和硬件签名尚待验收。

Two fixed-path builds on the same Windows host produced identical SHA-256 values for all five console executables. The second build replayed all seven histories and completed another four-repository payment. A separate desktop and Android rebuild matched 17 of 27 distributed files. The rebuilt desktop bridge verified the canonical receipt and scan tip. The ARM64 APK passed v2 verification with the local Android Debug certificate.

## 上一版 HYOF 候选 · Previous HYOF candidate

早期检查使用四份含未提交改动的 Windows 工作树，起始提交分别为 Hyphen `951ea01`、HyphenWallet `aac6300`、HyphenMiner `90895d6` 和 HyphenPool `f101835`。上一版 HYOF 验收使用以下四份独立冻结的本地提交。原客户端工作树引用公开提交 `951ea013f0b61115632f463cea22850cd972df83`。

| 本地 HYOF 候选 | Git 提交 | Windows 默认 Rust 测试通过 / 忽略 |
| --- | --- | ---: |
| Node | `c5719981a79fe4c5bb5704f2529a62f2922c0c42` | 413 / 2 |
| Miner | `412a951ce6c88535ba35d035c0fe8ac2eacce857` | 23 / 1 |
| Pool | `f4bbc0c7263f4479fea0db67d461b6baf831207f` | 51 / 0 |
| Wallet | `3b0ded749a9097d0f587ae82d41734206dcabfb0` | 43 / 2 |

四仓均通过格式、严格 Clippy 和 Windows release 构建。钱包另行通过七网身份向量和 7 项 Flutter 测试。冻结版 Node 从空库重放 1,024 个创世后区块，到达 `5500d899aa27b71d9702217f5448876e62d468f717cebd292034dec3dd285db8`。四仓结算的资金交易在高度 13 改至索引 12，末端以原始两跳授权在高度 14 再获 9,000,000 原子单位。该分支重放链顶为 `b4c618eca4e3f66792c3234a52bec7d71d04fe3ade3d6352f334e56180c315f0`。复核材料位于 `target/hyof-rc-souoxoy0/`。

另从包内四份 bundle 克隆，在空的构建目录、独立 Cargo Git 缓存和相同的本地 crates.io 依赖上重建五个 Windows release 程序。四个锁文件摘要保持一致。重建程序完整走通四仓付款，换索引后兑付 9,000,000，重放本轮高度 14 链顶为 `50e731e69d130e6cf83c62fa2f81a9e84fc7602539d22027cae3dd50eaf89362`。五个重建程序的 SHA-256 均与首批构建不同，逐个摘要见 `checks/clean-rebuild.json`。目前已验证源码可重建与行为复现，逐字节构建复现仍未达成。

## 密码学与钱包

收款方核验修订使用本地四仓开发网实测。32 个独立零余额钱包分别创建预锁条款，全部在资金交易准备阶段失败，也都无法用另一笔真实预锁的索引签发凭证。另一组检查将合法签署的转付交给持有独立检查点的收款方，32 份缺少规范预锁的凭证全部被拒。在两条竞争历史中，`confirm` 仅接受收款方留存的请求、实际赢家及预期兑付地址和净额。原赢家在重组后失去确认，同笔资金重定位后可用原请求和旧索引凭证核对新兑付。开发工作树的记录在 `target/offline-settlement-orqhho2w/result.json`。本段修订晚于上表四个冻结提交。旧复核包使用旧的 `status` 语义。操作说明见[离线付款](Offline-Payments.md)。

The receipt revision binds the canonical payout to the recipient's retained request, expected address and net amount. The local four-repository run rejected all 32 unfunded wallets and revoked the previous winner's confirmation after a chain reorganization. The original review package predates these changes.

| 风险及状态 | 检查结果 | 受影响路径 |
| --- | --- | --- |
| 严重，已在本地修复 | 旧验证器按两个列表中较短的长度遍历输入和 CLSAG 签名，可能漏掉输入的授权校验。共用验证器现在先要求两者数量完全相等，再对每个输入验签并核对声明的 key image。 | RPC 准入、P2P 准入、区块验证与历史重放。[验证器](../crates/hyphen-consensus/src/validator.rs) |
| 高，已在本地收紧 | CLSAG 拒绝单位元 key image 和非规范响应标量。范围证明核对响应标量、聚合维度及内积证明轮数。生成器要求盲因子数量与金额数量一致，聚合数量限于 1、2、4、8、16。Ed25519 签名采用严格验证。 | 这些变化收紧共识接受集合，跨版本部署需要明确生效边界和历史兼容结果。[CLSAG](../crates/hyphen-crypto/src/clsag.rs) · [范围证明](../crates/hyphen-proof/src/range_proof.rs) · [内积证明](../crates/hyphen-proof/src/inner_product.rs) |
| 高，钱包本地修复 | 旧输出缓存含一次性支出私钥和承诺盲因子。新版缓存仅保留金额、索引、点编码及派生材料。钱包在解锁后重新推导支出密钥，签名前复核公钥和金额承诺。升级清理旧活动缓存，既有备份、系统快照和底层介质中的副本不在这次清理的验证范围内。 | Flutter 应用缓存、Rust 签名器与付款代理。扫描按 key image 去重，同一 key image 对应多个输出时只计一次可花费金额。 |
| 高，恢复语义已核对 | 旧版 Flutter 地址同时依赖助记词和原密码。原密码先经历史 WOTS 公钥变换，派生过程保留原始 UTF-8 字节。恢复界面接受 12 或 24 个英文词。不同内部空白和不同 Unicode 形式可能产生不同地址。 | 英文 BIP39 `TREZOR` 向量通过。用 `aac6300` 的源码及其原始锁文件独立生成地址，与当前实现的公开 `public-fixture` 向量相同。 |
| 高，用户入口已停用 | 修正两份实验性 WOTS 的三位十六进制校验和。原无状态消息签名接口无法保证一次性使用，现保留 FFI 签名并返回错误。旧实验性签名有兼容性损失。底层原语仍依赖调用者管理密钥生命周期。 | 付款使用 CLSAG。历史密码变换使用 WOTS 公钥，与消息校验和无关。[实验性原语](../crates/hyphen-crypto/src/pq.rs) |
| 付款金额及隐私，本地修复且仍有边界 | 发送界面将最多 12 位小数直接解析为整数，确认和签名使用同一金额。金额、手续费及输入选择执行溢出检查。钱包把真实输出与本地抽样候选置于一次批量查询，检查响应索引、数量、点编码和真实输出内容。节点仍可观察访问时序、候选集及交易广播，缺少真实分布上的匿名性测量。 | 解析器测试覆盖一个原子单位、超过 `2^53` 的金额、`u64` 上界及越界输入。签名开始前会复核发起付款的钱包会话。 |

Flutter 新钱包容器采用 Argon2id（64 MiB、3 次迭代、1 路）和 XChaCha20-Poly1305，测试覆盖认证、随机盐与 nonce 及旧格式解密。主仓 `hyphen-wallet` 是另一套容器，其 v2 使用迭代 BLAKE3、分离的流密钥与 MAC 密钥。两套格式需要分别评估。Flutter 的生物识别凭据按钱包隔离，删除钱包及禁用生物识别会清理相关凭据。对安全存储升级的检查使用了 mock，真机安全存储、系统级认证、内存中密钥生命周期仍需设备验证。[主仓密钥库](../crates/hyphen-wallet/src/keystore.rs)

## 仍阻止真实资产上线的协议问题

| 优先级 | 实现和影响 | 关闭条件 |
| --- | --- | --- |
| 历史配置的奖励归属 | v5 历史配置仅在矿工授权中记录两把收款公钥。合约开发网要求 `extra_nonce` 承诺该公钥对，随后由块哈希派生奖励输出。替换收款键的验块回归覆盖两种规则，钱包也检查新网承诺。 | 冻结真实资产网络的激活规则，并独立复核奖励向量。[签名域](../crates/hyphen-core/src/authorization.rs) |
| 支付状态及手续费 | 合约开发网模板在同一过渡锁下获取规范父块、父承诺树与 nullifier 集合根。验块核对这两个根、交易根、交易费用之和及协议后状态根。新网及旧网均检查支出授权和重复 key image。 | 独立实现复核历史重放、回滚和切换后的状态。[状态过渡](../crates/hyphen-consensus/src/chain.rs) |
| 竞争分支与结算 | 本地三矿工 PPLNS 原块在高度 16 脱链，两个节点重新准入原付款，收款余额归零，已付款退回预留。同笔付款在高度 22 再确认。原分支重新胜出后，付款恢复为高度 16 确认。三名矿工的待付、预留、已付余额及矿池累计费用均恢复到原值。 | 公网多机分区、深分叉及旧账本缺少原始分配的情形仍需单独验收。迁移前已裁剪的记录需要外部账目。[分叉验收](Operations-Verification.md) |
| Wasm 资源与存储 | 合约开发网每笔声明燃料 `100000` 至 `128000000`，整块预留至多 `256000000`。宿主和指令共享燃料，最多一张 4096 元素的有界表。单合约存储上限 256 KiB，账本上限 8 MiB，均计条目开销。调用复制目标存储，计算根仍需编码账本。研究配置沿用旧计量。 | 复核多机最坏合法负载、持续占用及状态增长的经济成本。[执行器](../crates/hyphen-vm/src/engine.rs) · [账本](../crates/hyphen-vm/src/ledger.rs) |
| 高：叔块有效性 | 研究配置校验叔块根、个数、块内去重、深度和父块关系。本地已修复规范祖先缺失时继续通过的问题，并排除将同高度规范块自身列为叔块。区块仅携带叔块头，未见完整见证、矿工授权及跨块重复引用校验。普通开发网关闭叔块。 | 冻结叔块是否计入奖励或权重的规则，以及所需的授权、工作量和唯一性证据。在研究配置进行独立历史验证。[叔块验证](../crates/hyphen-consensus/src/validator.rs) |

钱包 RPC 需要先升级节点。有奖励块的响应必须带 `block_authorization`（protobuf 字段 6）。钱包会验证严格签名，并依据收款密钥和 `header.reward` 重算奖励输出。普通付款查询核对块哈希、块内位置与交易根。扫描器使用所连节点提供的规范历史，确认数使用该节点报告的链顶。

`HYOF` 开发网采用预锁整额转付和有条件索偿。两笔竞争索偿分别在两个节点确认。两个节点通过本机 TCP 重连后，原收款人的扫描余额从 9,000,000 降至 0，另一收款人收到 9,000,000，并成功通过普通钱包再次支付。另一轮分叉使同一资金交易的输出索引由 6 移至 12，末端持有人保留全部离线签名，独立刷新证明并在高度 14 重新结算。各次规范兑付加上 1,000,000 的手续费等于 10,000,000 的整笔预锁。旧持有人仍能竞争兑付。Flutter NFC 当前传递地址，真机双离线、密钥防回滚和独立认证仍待验收。[规则、哈希与内存实测](Offline-Payments.md)

## 科学工作量和研究功能

本地候选矿工在 RTX A4000 Laptop GPU 上把三个窗口共 40,962 个神经评分逐项与 Rust 核对，包含计数器回绕。GPU 插件 SHA-256 为 `f5bfcded5f365450ecf153ac0d50e3260df1875ec21f990bf09c48e7c1bc2c37`。该次检查验证计算结果。先前两轮各四组的 70 秒实验记录了独立链的增长、份额与显卡板载传感器读数；整机耗电、长期电费和同条件 ASIC/FPGA 效率仍缺测量。[配置和测量数据](Research-Aether-Compute.md)

普通工作量逐项检查 `u64` 范围内的第一类 Cunningham 素数链，要求见证严格递增、数量正确且在当前链上首次使用。父承诺、高度和见证列表共同进入工作承诺。该规则验证数学结果和链上单次使用。见证可以预计算，库存集中、专用硬件优势、见证供给与长期难度稳定性仍缺少公开对抗性数据。[数学谓词](../crates/hyphen-pow/src/vms.rs)

神经开发网 `hyphen-neural-devnet-v1` 使用由父块、块高和矿工公钥派生的挑战、定点计算、阈值和整数调难。SOLO 结算一份完整有效解。本次验收验证了出块和奖励归属。验证者复算分数，可以确认候选解达标。寻找解的最优算法成本、分数分布、对专用硬件的敏感性和科研任务价值仍需独立证据。[神经工作量](../crates/hyphen-consensus/src/neural_work.rs)

`mainnet()` 和 `testnet()` 启用包含叔块、TERA、VRE、Wasm、AetherCompute 及 H-WES 在内的研究配置。两次开发网付款没有覆盖该组规则。AetherCompute 实现有界任务和结果状态机，正常节点使用 `NeuralWorkVerifier`。新增科学领域仍需具体可验证程序、输入输出和验证后端。H-WES 的公开状态转换已接入对应配置，隐私恢复仍缺电路。H-BFM、H-FOC、H-SAC 没有进入本次开发网验块判定。基于上一个 epoch 末块哈希的抽样种子存在发布选择偏差，委员会安全概率依赖的独立随机性尚未成立。[配置](../crates/hyphen-core/src/config.rs) · [科学任务](Research-Aether-Compute.md) · [密码学激活条件](Security-Cryptographic-Activation-Gates.md)

## 发布与证据

冻结版 Pool 的 51 项 Linux 测试和签名日志的 2 项 Linux 测试已在本机 QEMU 11.1.0 虚拟机中执行并通过。测试程序在 Windows 上交叉链接至 `x86_64-unknown-linux-gnu`，然后在 Debian 6.1.0-50-amd64 内核和 Ubuntu glibc 2.39 中运行。覆盖项包括矿池账本重开、分叉恢复、Linux 密钥轮换及钱包文件锁。原始输出和测试程序摘要位于 `checks/pool-linux-runtime.log`、`checks/pool-linux-runtime.json`。公开候选的托管 CI 和跨物理主机网络验证仍待完成。

冻结候选另行通过了 C 与 Wasm 汇编编译产物的共识测试，以及普通开发网首奖扫描、矿池账本重开和本机 P2P 节点同步重启。默认忽略的公网递归 DNS 测试在该候选上单独运行失败，根服务器解析路径报告 TCP 连接超时。四仓结算及同机 peer 测试使用 IP 地址。日志分别在复核包 `checks/compiled-contracts.log`、`checks/ordinary-peer-smoke.log` 和 `checks/public-dns.log`。

在日志升级前的一次四仓验收中，主仓通过 411 项测试，默认忽略 2 项。四仓闭环的第三条历史把预锁由索引 6 移到 12，末端索偿 `955c316242cca3b44ce7e7c63b02b2670145d8c949b3a340294d780b546009c3` 在高度 14 确认，创世重放得到链顶 `ae522de70f8ff136f69d8da888542e98edc217b76b7c200feb8eea06cb3628be`。记录在 `target/offline-settlement-q50muksp/result.json`。redb 5.0 候选签名器保留此轮旧钱包的签名决定与收款记录。20 对竞争转付各仅发布一份凭证；5 份截断日志与 12 份截断导入均被拒绝。另有 26 次进程终止试验，实际终止的 18 次中，11 次未提交也未发布、4 次已提交未发布、3 次已提交并发布。全部 26 次原请求重试字节相同，竞争请求均拒绝。样本见复核包内 `checks/journal-upgrade.json` 和 `checks/interrupted-transfers.json`。[检查点与钱包内存测量](Offline-Payments.md)

开发网复核包冻结了四仓源码、锁文件、9 份归档、三份矿池账本与三种语言的部署字节。收款和区块奖励的连续两次换链实测使用同一组节点、矿工及矿池程序。另行运行的公网递归 DNS 测试因 TCP 连接超时失败。P2P 实测使用 IP 多地址。真实资产发布仍需独立机构或操作者在不同主机上重建并审查候选版本。[复核入口及运行记录](Operations-Verification.md)

合约开发网验收时，主仓工作区 402 项测试通过，2 项忽略。运行包含真实 Rust Alice Wasm，C/ASM 工具链另行实测。跨交易 key image 回归在两种排序下分别检查严格拒绝和模板筛选。独立 fuzz 工作区通过所有目标的编译检查。钱包 Rust 默认通过 43 项，指定环境的链身份和首奖扫描另通过 2 项。引入 `HYOF` 后用 Flutter 3.50.0 复跑的 7 项测试全部通过；矿工通过 23 项，矿池通过 51 项。矿池回归覆盖同高度替换中途失败、数据库重开后重试、SOLO 恢复、旧共享账本缺明细、扫描期间发生结算及旧节点回复。

五份开发网历史使用含分支同步和模板修改的节点从创世再验，五个独立数据库共应用 143 块，与原高度及链顶逐一吻合。该节点 SHA-256 为 `c3d89e6cc11516540bf7c66ad7c065b9b84b9abc1b499d78a4cdb129fa7a26bc`，记录目录为 `target/reorg-replay-004494cd-fee6-4f6d-a439-b2978ec67933/`。两种历史开发网均关闭叔块。[逐份高度与完整链顶](Operations-Verification.md)

带有规范哈希查询接口的节点 `016c0c1899f31d3614b1b13f619be63f3d3c8e21d04196a8030fcf975b735756` 再次从创世重放这 143 块，五个历史链顶全部吻合。同一二进制在合约开发网上确认三种语言的六笔签名交易，重开数据库后在高度 10 核对了三个查询输出。逐个二进制和输入归档的哈希见验收记录。下表是包含收款界面的本地钱包构建。[运行记录](Operations-Verification.md)

| 本地产物 | SHA-256 |
| --- | --- |
| Windows release `hyphen_wallet.exe` | `9c9a8838ff7f280448b8eecb1f99d3a093e4c905a235fb398f866fc43330c2cb` |
| 同一目录的 `rust_lib_hyphen_wallet.dll` | `45372bcdc0bd08301546233f4de945361c109814b92410ea9339a2a34a874918` |
| Windows `data/app.so` | `7a9b16eae01de43332e41233a4d5b8aecb41991fae0825c60f90e6cf3f646b0e` |
| Android ARM64 release APK | `8c87b844c1c8a9445da7c245b50264b8fa377c92269f118b420e4dfe3170c9da` |

付款、恢复和运行资源的证据覆盖一台 Windows 主机上的独立进程、本机中继和开发网测试资产。两种工作量均通过 SOLO 首奖扫描。共享付款中，PROP 使用三节点、三矿工并跨节点广播，PPLNS 使用单节点、三矿工。两次付款各支付 `1000000000` 原子单位，手续费均为 `1000000`，重开数据库后双方重扫对账一致。大规模钱包 key image 和矿工见证去重使用临时磁盘，额外磁盘 I/O 和空间是内存降低的代价。[付款哈希、链顶及余额](Operations-Verification.md) · [内存实测条件](Operations-Small-Host.md)

主网发布需要一份可重建的冻结提交和独立审计。共识收紧需要选定新网络身份或明确激活高度，验证升级前后的历史与分叉边界。随后发布共享库，让三个客户端更新 revision 与各自锁文件，在同一发布候选版本重复付款、恢复和多主机分区重组验收。当前 Windows 钱包和 Android ARM64 release 均已构建，Android APK 使用 `Android Debug` 证书。iOS、macOS、Linux、真机 NFC、生物识别和安全存储迁移仍缺验证，三个 HarmonyOS Sans SC 字体文件的再分发授权仍待确认。

## English release assessment

Real-asset launch remains blocked. Contract-devnet binds the reward keys and validates parent payment roots and fees. Its VM enforces transaction, block and storage limits from genesis. Two local branch changes reversed and restored three miners' PPLNS allocations, the pool fee and the original payment. Signed Rust, C and Wasm assembly deployments and calls survived a node restart and returned the expected query bytes. On offline-devnet, local peers adopted a heavier history that switched the canonical payout to the competing holder. In a separate branch change the original funding transaction moved to another index. Its terminal holder refreshed the proof and settled the same two-hop voucher independently. The four local HYOF candidate bundles restore the exact commits listed above. Each reconstructed client's lockfile resolves the same shared-library commit. Public release, mainnet activation, uncle rules, multi-host partition recovery, independent economic and cryptographic review, hardware-backed signing and mobile offline acceptance remain open.
