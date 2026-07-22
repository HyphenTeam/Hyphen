# Hyphen

[English](README.md) | 中文

Hyphen 是一个用 Rust 编写的实验性、隐私导向、CPU-first PoW 区块链研究项目。仓库包含全节点、共识与密码学库、CPU 矿工、矿池、Flutter 钱包、独立 WASM 执行库，以及节点到矿池和矿池到矿工的带签名协议。

> **安全状态，2026-07-23：** 本仓库的 devnet 节点、Template Provider、Pool v3 矿池和 CPU 矿工已经完成本机端到端运行验证，但项目还没有外部密码学/共识审计、完整 reorg、长期公开测试网、自动共享矿池付款或正式 bug bounty。不要发送真实资产，不要把钱包或矿池宣传成可承载大额价值的生产系统。

## 这份文档怎么读

如果你第一次接触区块链，不要一上来运行 mainnet：

1. 先读“先看结论”和“系统如何工作”，知道哪些功能尚未完成。
2. 按“5 分钟跑起来”完成一次自动 devnet 验证。
3. 按“手动启动”分别运行节点、SOLO 矿池和矿工，并学会看日志/API。
4. 再阅读钱包、历史 replay 和攻击性测试；这些步骤教你验证系统，而不是只会启动程序。
5. 最后阅读非托管矿池、Useful-Work、创新验收和外部审计门槛。它们是研究路线，不是生产承诺。

本文中的 `mainnet` 始终表示“mainnet-research 参数档”，不是已经上线或可承载资产的生产主网。命令行的最终依据是当前二进制的 `--help`，共识的最终依据是版本化规范和测试向量，而不是 README 的宣传文字。

### 先选择你的路线

| 你的目标 | 从哪里开始 | 做到什么才算完成 |
| --- | --- | --- |
| 我只想确认项目能运行 | “5 分钟跑起来” | smoke 输出 `status: passed`，并保存 commit 与日志目录 |
| 我想学会节点、矿池和挖矿 | “手动启动” | 能解释各接口用途、看到 accepted share，并知道 share 不是链上奖励 |
| 我想开发或提交 PR | “测试与攻击性验证” | workspace、矿池、矿工、钱包后端和 fuzz target 编译全部退出码为 0 |
| 我想研究抗矿池控制 | “Hyphen Non-Custodial Pool Protocol” | 能逐项说明六类攻击的已实现防线和开放问题，不能只说“有签名” |
| 我想研究 Useful-Work | “Useful-Work 的边界” | 保持基础 PoW 独立安全下界，外部任务不增加发行量或 chain weight |
| 我想组织测试网或审计 | “激励测试网”和“外部验证” | 所有 launch blocker 关闭，并公开精确 revision、原始数据、报告和复测 |

相关文档各有唯一职责：[devnet-v1.md](docs/consensus/devnet-v1.md) 定义冻结共识；[non-custodial-pool.md](docs/research/non-custodial-pool.md) 定义矿池威胁模型；[useful-work-augmented-pow.md](docs/research/useful-work-augmented-pow.md) 定义 Useful-Work 准入边界；[incentivized-testnet.md](docs/operations/incentivized-testnet.md) 定义测试网上线和监控；[SECURITY.md](SECURITY.md) 定义漏洞报告与发布阻断条件。README 教你使用，但不能替代这些规范。

## 先看结论

| 能力 | 当前状态 | 你应如何理解 |
| --- | --- | --- |
| 冻结 devnet v1 | 已实现 | 研究特性关闭，链身份、数据库身份和测试向量固定 |
| 节点启动与本地挖矿 | 已验证 | 一键脚本实测节点、矿池、矿工连通并产生有效 share |
| 历史导出、验证、replay | 已实现 | archive 绑定链身份，完整 replay 必须写入新数据库 |
| Pool v3 矿工出块授权 | 实验实现 | 池方不能在矿工授权后替换区块头、交易根、收益密钥或链身份 |
| 共享矿池付款 | 未完成 | PROP/PPS/PPLNS/PPS+/FPPS 余额只是矿池内部账本，不是钱包到账资产 |
| Fork choice 与 reorg | 未完成 | 当前链管理器只追加活动 tip，激励测试网上线前必须补齐竞争分支和状态回滚 |
| 隐私交易与 ZKP | 库实现 | CLSAG、承诺、range proof 等需要独立密码学审查 |
| WASM 合约 | 独立库 | 尚未接入交易、区块执行、状态根、回执或 RPC，链上不能部署合约 |
| Flutter 钱包 | 实验软件 | 只适合无价值测试；硬件钱包只有协议模型，没有厂商 App 和物理设备适配 |
| Useful-Work | 仅研究规范 | 不在共识中，不能称为 AI 挖矿，也不能替代基础 PoW 安全预算 |

## 系统如何工作

先记住一条数据流：

```text
钱包 --提交/查询--> 节点 RPC --验证交易--> mempool
                                |
                                +--> P2P 同步其他节点
                                +--> Explorer HTTP 展示只读链状态
                                +--> TP v2 下发候选区块给矿池
                                           |
                                           v
矿工 <--Pool v3 job/share/签名回执--> 矿池 --完整区块--> 节点
  |                                        |
  +--重算交易根和 PoW----------------------+--记录 share/待结算余额
  +--只对自己认可的最终 solved header 签名
```

| 术语 | 小白解释 |
| --- | --- |
| 节点 | 保存并验证区块链的程序；它决定一个区块是否符合当前共识规则 |
| 矿工 | 搜索满足难度目标的 nonce；Pool v3 下还必须检查模板并授权最终区块 |
| 矿池 | 汇总 share、降低收益方差并转发区块；它不是共识真相，也不应获得矿工完整出块权 |
| share | 达到矿池较低难度的工作证明，用于统计贡献；普通 share 不是有效区块或链上收入 |
| 模板 | 父块、交易集、奖励、难度和 epoch 参数组成的候选区块工作 |
| coinbase | 区块奖励输出；SOLO 模式直接绑定矿工钱包，shared 模式当前进入池收益地址后仍需外部付款 |
| chain identity | 网络 magic、共识参数哈希和创世哈希的组合；任一不同都表示不是同一条链 |
| replay | 将历史区块重新走一遍权威验证路径，检查新实现是否得到同一结果 |
| reorg | 更重竞争分支替换当前 tip；Hyphen 目前缺少完整实现，所以不能进入有价值测试网 |

密钥也不要混淆：钱包的 24 词助记词控制资产；`devnet-miner.key` 授权矿工找到的区块；`devnet-pool.key` 标识并签署矿池消息；节点的 `p2p_identity.key` 标识网络节点。后三者都不能恢复钱包资产。

### 为什么同一台节点有多个端口

这些端口使用的协议不同，不能互换：

| 接口 | 谁使用 | 能否用浏览器/`Invoke-RestMethod` | 当前用途 |
| --- | --- | --- | --- |
| P2P | 节点之间 | 不能 | libp2p 发现、gossip 和同步 |
| Protobuf RPC | 钱包/客户端 | 不能直接用 HTTP 工具 | 长度分帧的 protobuf 请求，不是 JSON-RPC/HTTP |
| Explorer HTTP | 人和监控脚本 | 可以 | `/api/info` 等只读 HTTP 接口 |
| TP v2 | 节点与矿池 | 不能 | 签名模板、job declaration 和完整区块提交 |
| Pool v3 | 矿池与矿工 | 不能 | 登录、job、share、矿工授权和回执 |
| Pool accounting HTTP | 矿工/运营者 | 可以 | 查询健康、share 与内部结算账本；不是链上余额证明 |

因此，浏览器访问 RPC/TP/Pool v3 端口看到空白或连接关闭不表示服务损坏。新手只应在 Explorer 和矿池 HTTP API 上使用 `Invoke-RestMethod`。

## 5 分钟跑起来，Windows 推荐方式

### 第 0 步：获取源码并准备环境

安装 Git、当前稳定版 Rust。Windows 还需要 Visual Studio Build Tools 的“使用 C++ 的桌面开发”组件。第一次获取源码：

```powershell
git clone https://github.com/HyphenTeam/Hyphen.git
Set-Location .\Hyphen
git rev-parse HEAD
git status --short --branch
```

`git rev-parse HEAD` 输出的是你正在测试的精确 commit，报告问题时必须附上它。已经有仓库时，进入你自己的实际路径即可；不要照抄下面这台开发机的绝对路径，也不要在有未保存改动时盲目执行 `git pull`。

确认工具链：

```powershell
Set-Location D:\RustProject\Hyphen
rustc --version
cargo --version
```

建议至少预留 10 GiB 磁盘给源码、依赖和 debug 构建。devnet/testnet 挖矿 arena 为 64 MiB；研究 mainnet 配置会为每个矿工进程使用约 2 GiB arena。第一次构建需要联网下载依赖，依赖已经缓存时才可以在后续命令加 `--offline`。

Linux 需要 Rust、`build-essential`、`pkg-config`、OpenSSL/Clang 等本机依赖；macOS 需要 Xcode Command Line Tools。各发行版包名不同，缺少系统库时以 Cargo 报错的库名为准。GUI 钱包还需要 Flutter 和对应平台 SDK，节点/矿池/矿工本身不需要 Flutter。

### 新手先看懂命令格式

- 每条命令默认在仓库根目录执行；看到 `Set-Location` 后，后续相对路径都以新目录为准。
- PowerShell 行尾的反引号 `` ` `` 表示下一行仍属于同一条命令，反引号后不能有空格。Linux/macOS shell 应改用反斜杠 `\`，Windows `.exe` 路径则去掉 `.exe`。
- `<你的地址>`、`<peer-id>` 这类尖括号内容是占位符，必须替换，不要连尖括号一起输入。
- `#` 开头是说明，不是需要输入的程序参数。
- Cargo 第一次运行可能花很久下载和编译；只要进程仍在工作就不要重复启动第二份构建。
- 命令完成后执行 `$LASTEXITCODE`；`0` 表示该程序正常退出，非 `0` 必须查看本次命令上方的第一条错误，不能只截最后一行。

### 第 1 步：运行一键 devnet 烟雾测试

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1
```

已有编译结果并希望完全离线复测时：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1 `
  -SkipBuild -Offline -TimeoutSeconds 120
```

脚本会完成以下工作：

1. 构建节点、独立矿池和独立矿工。
2. 用全新数据目录启动 `hyphen-devnet-v1` 节点。
3. 启动连接节点 TP v2 的 SOLO 矿池。
4. 启动单线程 Pool v3 矿工。
5. 等到矿池账本 API 看到 `valid_shares > 0`。
6. 输出网络、tip、share 计数和日志目录。
7. 无论成功还是失败都停止三个进程。

成功输出类似：

```json
{
  "status": "passed",
  "network": "hyphen-devnet-v1",
  "pool_health": "ok",
  "valid_shares": 3,
  "invalid_shares": 0,
  "direct_coinbase_mode": true
}
```

日志保存在 `target/devnet-smoke-日期时间/`。如果端口 `49633`、`49634`、`49640`、`49650`、`49680` 或 `49681` 已被占用，先停止占用程序再重试。

通过的含义只限于：三个进程能启动、协议身份匹配、矿工收到工作并产生至少一个有效 share。它不证明找到了完整区块，不证明共享余额已经链上付款，也不证明 P2P、reorg、隐私密码学或长期稳定性安全。

### 保存一次可复核的运行证据

“我这里能跑”不够。至少保存 revision、工具链、测试输出和 smoke 目录：

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$revision = (git rev-parse --short=12 HEAD).Trim()
$evidence = ".\evidence\$stamp-$revision"
New-Item -ItemType Directory -Force $evidence | Out-Null

git status --short --branch | Tee-Object "$evidence\git-status.txt"
rustc --version | Tee-Object "$evidence\toolchain.txt"
cargo --version | Tee-Object -Append "$evidence\toolchain.txt"

powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1 *>&1 |
  Tee-Object "$evidence\devnet-smoke.log"
$smokeExit = $LASTEXITCODE
if ($smokeExit -ne 0) { throw "devnet smoke failed: exit $smokeExit" }

Get-FileHash .\test-vectors\chain-identity-v1.json |
  Format-List | Out-File "$evidence\chain-vector.sha256.txt"
```

不要把钱包助记词、钱包密码、`*.key` 或私有漏洞细节放入 evidence、issue 或公开日志。smoke JSON 中的 `run_dir` 指向三个进程的完整日志；报告故障时附上无秘密的日志、精确 commit、OS、CPU、内存和复现命令。

`devnet-smoke.ps1` 为保证测试结束后不遗留后台进程，会强制停止子进程。因此 `run_dir` 是诊断证据，不是经过一致性快照的节点备份；即使 JSON 曾显示高度 1，重新打开其中的数据库也可能只有最后一次已刷盘高度。要验证“非空历史”的 export/verify/replay，请使用后面的手动流程，先在节点窗口按 `Ctrl+C` 并等待 `Shutdown complete.`，再对那个已停止的数据目录导出。不要把 smoke 目录的短暂内存 tip 当作持久化证明。

## 手动启动，理解每个组件

手动流程需要三个 PowerShell 窗口。以下地址来自公开固定测试种子，只能用于本地 devnet，任何人都知道对应种子，绝不能接收真实价值。

先在窗口 1 构建并生成测试地址：

```powershell
cargo build --locked -p hyphen-node
cargo build --locked --manifest-path HyphenPool/Cargo.toml
cargo build --locked --manifest-path HyphenMiner/Cargo.toml
cargo run -p hyphen-wallet --example dev_address --locked
```

固定 devnet 地址是：

```text
hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD
```

### 窗口 1：启动节点

```powershell
.\target\debug\hyphen-node.exe `
  --network devnet `
  --data-dir .\data\devnet-node `
  --listen /ip4/127.0.0.1/tcp/48334 `
  --rpc-bind 127.0.0.1:48333 `
  --template-bind 127.0.0.1:3350 `
  --explorer-bind 127.0.0.1:8080
```

浏览器访问 `http://127.0.0.1:8080`。也可以在新 PowerShell 中检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/api/info | ConvertTo-Json
```

应看到 `network` 为 `hyphen-devnet-v1`，初始 `height` 为 `0`，`tip_hash` 为本文链身份表中的 devnet 创世哈希。

### 窗口 2：生成矿池身份并启动 SOLO 矿池

第一次运行先生成身份密钥：

```powershell
New-Item -ItemType Directory -Force .\keys | Out-Null
.\HyphenPool\target\debug\hyphen-pool-server.exe keygen `
  --output .\keys\devnet-pool.key
```

然后启动矿池：

```powershell
.\HyphenPool\target\debug\hyphen-pool-server.exe `
  --network devnet `
  --node 127.0.0.1:3350 `
  --key-file .\keys\devnet-pool.key `
  --bind 127.0.0.1:3340 `
  --api-bind 127.0.0.1:8081 `
  --share-difficulty 1 `
  --payout-mode solo `
  --pool-state-dir .\data\devnet-pool
```

`--share-difficulty 1` 只适合快速本机测试。真实网络必须根据算力和观测数据设置。检查矿池健康：

```powershell
Invoke-RestMethod http://127.0.0.1:8081/healthz
```

### 窗口 3：生成矿工身份并启动矿工

```powershell
.\HyphenMiner\target\debug\hyphen-miner.exe keygen `
  --output .\keys\devnet-miner.key

.\HyphenMiner\target\debug\hyphen-miner.exe `
  --network devnet `
  --pool 127.0.0.1:3340 `
  --key-file .\keys\devnet-miner.key `
  --wallet-address hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD `
  --threads 1 `
  --batch-size 1000
```

`--threads 0` 表示使用所有可用逻辑 CPU。一个矿工进程的线程共享一个 epoch arena。devnet/testnet arena 为 64 MiB，研究 mainnet 配置为每个挖矿进程 2 GiB，另加正常程序开销。

查询这个测试地址的矿池账本：

```powershell
$address = 'hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD'
Invoke-RestMethod "http://127.0.0.1:8081/api/pool/wallet/$address/balance" |
  ConvertTo-Json -Depth 6
```

完成后在每个窗口按 `Ctrl+C`。不要让 mainnet、testnet 和 devnet 共用同一个数据目录。

### 如何判断三个组件正常

| 观察位置 | 正常信号 | 常见异常 |
| --- | --- | --- |
| 节点日志 | 显示 `hyphen-devnet-v1`、tip、P2P peer ID、TP/RPC/Explorer 监听地址 | genesis mismatch 表示用了旧或其他网络的数据目录 |
| Explorer `/api/info` | `network` 正确，`height` 和 `tip_hash` 可读 | 连接拒绝通常是节点未启动或 bind 地址错误 |
| 矿池 `/healthz` | 返回健康状态 | TP 连接错误通常是 `--node` 与节点 `--template-bind` 不一致 |
| 矿工日志 | login accepted、收到 job、hash/share 计数增长 | network、协议版本、链身份、钱包地址任一不匹配都会拒绝 |
| 钱包账本 API | `valid_shares` 增长，`invalid_shares` 没有持续快速增长 | pending 只是池账本；只有完整区块和后续付款才可能形成链上余额 |

### 共享矿池模式仅用于研究

SOLO 是当前最容易验证的模式。要实验 PPLNS，可将池启动参数改为：

```powershell
--payout-mode pplns `
--pool-wallet <与当前网络匹配的池钱包hy1地址> `
--pool-fee-bps 100 `
--pplns-window-factor 2
```

矿工还必须显式加入：

```powershell
--allow-shared-reward-recipient
```

这项显式授权只允许当前 job 使用池公布的共享收益密钥，不允许池修改已经签名的 header 或任意替换收益地址。当前 PPLNS/PPS/FPPS 等模式只会形成持久化内部账本，没有自动构造、签名、广播链上付款交易；因此不能把 API 的 pending/confirmed 字段当作钱包到账，也不要运营真实价值共享池。

mainnet-research 下的非 SOLO 模式还必须向矿池传入 `--acknowledge-manual-payouts`，否则程序拒绝启动。这个参数只表示运营者承认“必须使用外部付款流程”，不会创建资金、证明偿付能力或使付款自动化。

## 构建 release 程序

```powershell
cargo build --release --locked -p hyphen-node
cargo build --release --locked --manifest-path HyphenPool/Cargo.toml
cargo build --release --locked --manifest-path HyphenMiner/Cargo.toml
```

输出位置：

| 程序 | Windows 路径 |
| --- | --- |
| 节点 | `target/release/hyphen-node.exe` |
| 矿池 | `HyphenPool/target/release/hyphen-pool-server.exe` |
| 矿工 | `HyphenMiner/target/release/hyphen-miner.exe` |

每个程序的最终参数依据是 `--help`：

```powershell
.\target\release\hyphen-node.exe --help
.\HyphenPool\target\release\hyphen-pool-server.exe --help
.\HyphenMiner\target\release\hyphen-miner.exe --help
```

## 停机、备份和重新开始

节点、矿池和矿工都用 `Ctrl+C` 正常停止。先确认三个进程都退出，再移动数据目录；节点写入数据库时复制或移动目录可能产生不一致快照。需要重新开始实验时，优先保留旧数据而不是直接删除：

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force .\data\backups | Out-Null
if (Test-Path .\data\devnet-node) {
  Move-Item .\data\devnet-node ".\data\backups\devnet-node-$stamp"
}
```

下一次启动会创建新的 `devnet-node`。不要把 devnet、testnet、mainnet-research 的数据库或 replay 目标目录混用；不要删除唯一的钱包、助记词或审计证据。源码更新后先运行链身份命令，如果身份改变，则必须使用新数据目录并调查对应的规范/profile 变更。

## 冻结 devnet 共识与链身份

devnet v1 使用固定创世时间、固定参数承诺、固定创世块和区块版本 2。研究性的 uncles、TERA、VRE 共识强制、MSE 与 MDAD-SPR 均关闭，难度固定使用整数 LWMA v1。

| Profile | Magic | 共识参数哈希 | 创世哈希 |
| --- | --- | --- | --- |
| `devnet-v1` | `48594456` | `e9591468e6b53e922b67f6dbecd0dccec4217e95f0f09a21bce7244fbe8e8322` | `4ee146f63ec54ded2ed743e88ee4ff0981598afc0412d4261e17e43a731a1b92` |
| `testnet-research` | `48595453` | `9b5a781f5ee647bcef6b1481b684bbd3df277118d7887e9ae49db18d507c2bda` | `d51438cdc8364e9d0a139f731296d3a33845c1bb5f4b0a7cd1fa13ebce2ae78f` |
| `mainnet-research` | `4859504e` | `eb77360a33bd560945196590b9fe4d9aef8889724d9a6a9475e0bc4db520f957` | `fcc91f7a7537b84f8ef1757d56bac75d1fc0d18aa1540726c61db49ac8991c9e` |

请用程序重新核对，不要只相信 README：

```powershell
cargo run -p hyphen-node --locked -- --network devnet --print-chain-identity
cargo run -p hyphen-node --locked -- --network testnet --print-chain-identity
cargo run -p hyphen-node --locked -- --network mainnet --print-chain-identity
```

机器可读向量在 `test-vectors/chain-identity-v1.json`，完整规范在 [docs/consensus/devnet-v1.md](docs/consensus/devnet-v1.md)。任何共识参数改变都必须产生新 profile、测试向量和链身份，不能静默修改 devnet v1。

## 历史导出、reference verifier 与 replay

先停止正在写源数据库的节点，或使用一致的数据库副本。

```powershell
# 导出高度 1 到 tip 的区块及链身份
cargo run -p hyphen-node --locked -- `
  --network devnet `
  --data-dir .\data\devnet-node `
  --export-history .\data\devnet-history-v1.bin

# 轻量验证：身份、连续高度、父哈希、时间戳、roots 和矿工授权
cargo run -p hyphen-node --locked -- `
  --network devnet `
  --verify-history .\data\devnet-history-v1.bin

# 完整 replay：目标目录必须是新的空目录
cargo run -p hyphen-node --locked -- `
  --network devnet `
  --data-dir .\data\devnet-replay `
  --replay-history .\data\devnet-history-v1.bin
```

轻量 verifier 不执行完整 PoW、交易和状态转换；完整 replay 会通过权威 `accept_block` 路径。archive 当前是 Rust/bincode v1 格式且 CLI 限制为 512 MiB。生产共识仍需要语言无关的规范编码和跨实现测试向量。

## 测试与攻击性验证

### 日常回归

```powershell
cargo test --workspace --all-targets --locked
cargo test --manifest-path HyphenPool/Cargo.toml --locked
cargo test --manifest-path HyphenMiner/Cargo.toml --locked
cargo test --manifest-path HyphenWallet/rust/Cargo.toml --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
```

缓存完整时可加 `--offline`。2026-07-23 本机验证基线：workspace 共 105 passed、1 ignored；矿池 11 passed；矿工 2 passed；Flutter Rust backend 21 passed；三个 fuzz target 编译通过；一键端到端 smoke 通过。workspace 中最大聚合 range-proof 测试在本机约需 60 秒，短超时不等于失败。

### 怎样判断测试真的通过

| 级别 | 通过条件 | 失败时先做什么 | 它不能证明什么 |
| --- | --- | --- | --- |
| 编译/check | 退出码 0；没有 `error:` | 从第一条编译错误开始，确认 Rust 版本和 lockfile 未被私自改写 | 运行路径、协议互操作或安全性 |
| 单元/集成测试 | 所有预期测试 `ok`；只有登记过的 ignored；退出码 0 | 记录失败测试全名，用精确 filter 单独重跑，保留完整 backtrace | 未编码进测试的攻击和长期网络行为 |
| devnet smoke | JSON 为 `passed`，网络身份正确，accepted share 大于 0 | 打开 `run_dir` 内 node/pool/miner stderr，先找最早异常 | 完整出块、付款、reorg、外审和生产稳定性 |
| 持续 fuzz | 预算结束时无 crash/hang/OOM；corpus 和覆盖率可复用 | 保存并最小化 crashing input，在修复前加入回归 corpus | 没跑到的路径、状态化网络攻击或形式化安全 |
| 多节点故障演练 | 预定义 invariant 全部满足，原始时间序列完整 | 停止激励、保留磁盘/日志快照并复盘 | 密码学正确性和独立审计 |

本轮出现 warning 也要记录。warning 不会自动把退出码变成失败，但 deprecated API、unused 安全检查或 future-incompatibility 都应进入 issue/技术债；“测试通过”不能写成“零问题”。如需保留回归日志，可在上面的 evidence 目录中使用 `*>&1 | Tee-Object <文件>`，并在每条原生命令后立即保存 `$LASTEXITCODE`。

### 七项要求与证据追踪

这张表是发布检查表，不是路线图宣传。命令必须在仓库根目录运行，退出码为 0；“人工/外部”项不能用单元测试伪造完成。

| 要求 | 现在怎样验证 | 当前结论与阻断项 |
| --- | --- | --- |
| 冻结 devnet 共识 | `cargo test -p hyphen-core frozen_devnet_disables_research_consensus_features --locked`；`cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked`；执行 history verify/replay | profile、链身份和向量已固定；仍缺语言无关编码与第二个 reference verifier |
| Transaction/RPC/P2P 与攻击实验 | 下文三个 fuzz target、LWMA、匿名集、池账本和钱包恢复命令 | 有单元/属性样本和 fuzz 入口；状态化网络序列、长期统计、真实支付故障仍缺 |
| 独立审查与 bounty | 核对 [SECURITY.md](SECURITY.md) 中精确 commit、范围、报告、修复和 retest | 尚未发生，任何真实价值宣传被阻断 |
| 小规模激励测试网 | 先通过 devnet smoke，再按 [incentivized-testnet.md](docs/operations/incentivized-testnet.md) 演练和采集指标 | 完整 fork choice/reorg 未实现，因此目前不得启动有价值激励测试网 |
| 独立而非拼装式创新 | 为每个 claim 提供 prior-art claim chart、形式化性质、ablation、原始数据、复现实验和独立实现 | 现阶段只能称候选贡献，不能保证新颖性或专利自由 |
| 矿工不可委托最终出块权 | `cargo test -p hyphen-core authorization --locked`；`cargo test --manifest-path HyphenMiner/Cargo.toml miner_recomputes_and_chains --locked` | solved-header/链/收益绑定已有原型；矿工自主模板和直接提交仍缺 |
| 抗池控制与可审计结算 | `cargo test --manifest-path HyphenPool/Cargo.toml protocol::tests --locked`；`cargo test --manifest-path HyphenPool/Cargo.toml accounting::tests --locked` | 可检测部分篡改、漏记与崩溃；不能强制付款或消除审查、withholding、clandestine pool |

### 已覆盖的攻击面

| 领域 | 自动检查 |
| --- | --- |
| Transaction | 有界反序列化、超大/尾随数据拒绝、确定性畸形 corpus、libFuzzer target |
| RPC | protobuf 畸形 corpus 不 panic、payload roundtrip、libFuzzer target |
| P2P | gossip 包和 tx/block 大小上限、未知类型、畸形 corpus、libFuzzer target |
| 时间戳/难度 | 倒退时间戳样本、LWMA solve-time clamp、每步 3 倍上下限、哈希率变化实验 |
| 匿名集偏差 | 近期/索引聚集 decoy 与跨年龄/索引分层 decoy 的质量分数实验 |
| 非托管矿池 | sender 身份替换、payload 篡改、share receipt 提交/结果/顺序绑定 |
| 矿池账本 | 主文件截断恢复、重复结算幂等、PPLNS 尾部工作窗口和钱包聚合结算 |
| 钱包恢复 | 同 seed 恢复相同地址、扫描高度归零、加密文件单字节损坏拒绝 |
| 历史 replay | 链身份错配、高度缺口、交易根篡改、矿工授权篡改 |

只运行关键演练：

```powershell
cargo test -p hyphen-pow frozen_lwma_clamps_timestamp_reversal_attack --locked
cargo test -p hyphen-consensus anonymity_set_bias_experiment --locked
cargo test -p hyphen-consensus reference_verifier_rejects --locked
cargo test -p hyphen-wallet seed_recovery_restores_keys_but_requires_rescan --locked
cargo test --manifest-path HyphenPool/Cargo.toml recovers_last_committed_ledger --locked
cargo test --manifest-path HyphenMiner/Cargo.toml miner_recomputes_and_chains --locked
```

按攻击面分别运行并理解结果：

```powershell
# 不可信 transaction 字节：超大、尾随、畸形输入不得越界或 panic
cargo test -p hyphen-tx adversarial_decode_tests --locked

# 不可信 RPC protobuf payload
cargo test -p hyphen-rpc adversarial_decode_tests --locked

# 不可信 P2P gossip：总包、交易和区块大小上限
cargo test -p hyphen-network protocol::tests --locked

# 时间戳倒退与冻结 LWMA clamp
cargo test -p hyphen-pow frozen_lwma_clamps_timestamp_reversal_attack --locked

# 聚集诱饵相对分层诱饵的匿名集偏差实验
cargo test -p hyphen-consensus anonymity_set_bias_experiment --locked

# 池消息身份替换/篡改、回执链和账本损坏恢复
cargo test --manifest-path HyphenPool/Cargo.toml protocol::tests --locked
cargo test --manifest-path HyphenPool/Cargo.toml recovers_last_committed_ledger --locked

# seed 恢复和加密钱包单字节损坏
cargo test -p hyphen-wallet seed_recovery_restores_keys_but_requires_rescan --locked
cargo test -p hyphen-wallet encrypted_wallet_rejects_single_byte_corruption --locked
```

测试通过表示代码满足该测试写下的有限性质，不表示攻击面已经审计完成。当前还缺少状态化 RPC/P2P 序列 fuzz、多个真实节点的 eclipse/partition/reorg 仿真、不同 CPU/OS 的 PoW 向量、长期匿名集统计、池支付交易故障注入和移动端进程被杀后的恢复自动化。

### 真正运行 fuzz

Windows 本机先用上面的 `cargo check` 验证 target。持续 fuzz 推荐 Ubuntu 或 WSL；CI 的 `Nightly fuzz smoke` 每天分别运行 transaction、RPC、P2P target。

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cd crates/hyphen-fuzz
cargo +nightly fuzz run transaction_decode -- -max_total_time=300
cargo +nightly fuzz run rpc_decode -- -max_total_time=300
cargo +nightly fuzz run p2p_decode -- -max_total_time=300
```

5 分钟 smoke 不是充分 fuzz。公开测试网前应保存 corpus、崩溃样本、最小化输入、覆盖率趋势，并对 Pool v3、TP v2 和钱包文件格式增加专用 target。

## Flutter 钱包：构建、创建、收款与恢复

钱包位于 `HyphenWallet/`，不是 `crates/hyphen-wallet`。前者是 Flutter GUI 和它自己的 Rust backend，后者是 workspace 内的核心钱包库。当前 GUI 只提供 testnet/mainnet 选择，没有 devnet 选项，因此不能直接连接上文的 devnet 烟雾网络。

### 1. 准备并运行

先安装 Flutter，并运行 `flutter doctor` 安装 Windows/Android/Linux/macOS 对应工具链。当前 `pubspec.yaml` 要求 Dart `^3.12.0-210.2.beta`，如果稳定版 Flutter 尚不满足，需要使用兼容的 Flutter channel/version，不能跳过 SDK 约束。

```powershell
Set-Location D:\RustProject\Hyphen\HyphenWallet
flutter doctor
flutter pub get

# 只在修改 rust/src/api 后重新生成绑定
flutter_rust_bridge_codegen generate

flutter analyze
flutter run -d windows
```

Android 可用 `flutter run -d android`，Linux 用 `flutter run -d linux`，macOS 用 `flutter run -d macos`。iOS/macOS 签名必须在 macOS 完成，Android release 需要你自己的 keystore，Linux 需要 GTK3 开发包。仓库目前没有经过审计和签名发布的安装包。

### 2. 第一次创建测试钱包

1. 在欢迎页选择创建钱包和节点模式。
2. 设置仅用于测试的钱包密码。
3. 离线抄写 24 个助记词并核对顺序，不要截图、上传网盘或发给任何人。
4. 进入设置，确认选择的是 testnet；mainnet-research 不能承载真实资产。
5. 在接收页复制完整 `hy1...` 地址。相同前缀不代表相同网络，程序还会检查版本字节和 checksum。
6. 要将它用于挖矿，把地址原样传给矿工的 `--wallet-address`；共享池自身的奖励地址才使用池的 `--pool-wallet`。

发送流程会从 RPC 扫描输出、选择输入/诱饵、构造并自验证隐私交易后提交。只有当节点可达、钱包已有可花费测试输出、匿名集数据足够且费用满足规则时才可能成功。当前没有可信公共测试网清单，也没有完成外审，因此 README 不提供任何“购买/充值真实币”步骤。

### 3. 连接你自己的 testnet 节点

GUI 没有 devnet 开关；如需本机 RPC，启动隔离的无价值 testnet 节点，并在钱包设置中填 `127.0.0.1` 和 `38333`：

```powershell
Set-Location D:\RustProject\Hyphen
.\target\debug\hyphen-node.exe `
  --network testnet `
  --data-dir .\data\wallet-testnet-node `
  --listen /ip4/127.0.0.1/tcp/38334 `
  --rpc-bind 127.0.0.1:38333 `
  --template-bind 127.0.0.1:3350 `
  --explorer-bind 127.0.0.1:8080
```

单节点 genesis 网络没有来自其他节点的历史、资金或足够诱饵，只能验证连接与基础 UI。完整收发测试需要受控的多节点测试环境和测试资产。

### 4. 做一次恢复演练

1. 在原钱包记录地址和扫描高度，并确认 24 词备份可读。
2. 使用另一台测试设备、虚拟机或独立测试用户，避免破坏唯一副本。
3. 选择恢复钱包，按原顺序输入 24 词和相同 passphrase/password 规则。
4. 核对恢复地址完全一致。
5. 从高度 0 重扫并核对交易历史与余额；刚恢复时缓存余额为 0 是正确行为。
6. 分别演练错误密码、错一个助记词、损坏备份和扫描中断，记录结果。

不要用删除唯一钱包数据的方式做第一次演练。自动单元测试只证明确定性派生、清零重扫和损坏拒绝，不能替代真实设备全链恢复。

## Hyphen Non-Custodial Pool Protocol

TP v2 是节点到矿池协议，Pool v3 是矿池到矿工协议，不要混淆版本。核心目标是：

```text
收益可以共享 AND 最终出块授权仍由矿工掌握
```

当前实现中：

- 每个 job 的 header 包含矿工公钥。
- 矿工重算交易根并检查 chain identity、epoch seed、难度、arena、page 和收益 view/spend key。
- 完整区块需要矿工对完整 solved header、链身份和收益密钥签名。
- 池方不能在矿工授权后替换交易根、nonce、收益地址或链。
- 每个接受 share 都有提交 hash、结果 hash 和前序 receipt hash 组成的池签名回执链，矿工自己重算。
- SOLO 模式 coinbase 直接使用矿工授权地址。

当前没有解决：

- 池方仍选择它下发的交易集，因此还不能宣称消除交易审查或 MEV 控制。
- 池方仍可不转发矿工找到的完整区块。
- 矿工可以 block withholding。
- 无法阻止有意链下出售工作的 clandestine pool。
- 共享模式没有自动链上付款、reserve proof 或偿付能力保证。
- receipt 能发现漏记/调序/替换，不能强迫池方付款。

六类核心攻击必须分别验收，不能用“消息有签名”一项测试代替全部性质：

| 攻击/控制面 | 当前防线 | 自动证据 | 仍然缺少 |
| --- | --- | --- | --- |
| share stealing | share envelope 绑定发送者公钥、精确 submission 和回执位置 | `signed_envelope_rejects_share_stealing_identity_substitution`、矿工回执重算 | 网络截获、重放、并发换序和多连接身份测试 |
| block withholding | 节点只接受矿工授权的完整区块 | 只覆盖授权有效性 | 池拒绝转发时的矿工直提路径、双方 withholding 的协议/经济惩罚 |
| template hijacking | 矿工重算交易根并把完整 solved header、链身份和收益密钥签入授权 | `authorization_binds_header_chain_and_reward_keys`、`pool_cannot_redirect_reward_after_authorization` | 矿工自主构造/协商模板；当前池仍能先行审查交易、影响 MEV/软分叉信号 |
| clandestine pool | 无充分协议防线 | 无 | 对链下工作出售给中心运营者的可执行威胁模型和负面结果；不能虚假声称可彻底阻止自愿串通 |
| payout griefing | 签名回执链、持久账本、截断恢复和幂等结算 | `recovers_last_committed_ledger_after_primary_corruption`、`duplicate_block_settlement_is_idempotent` | 公共数据可用性、偿付证明、超时规则和自动链上付款 |
| pool hopping | PPLNS 使用按目标工作量截取的尾部窗口 | `pplns_excludes_old_work_after_trailing_target_is_met` | 多策略仿真、跨池切换成本、不同结算模式长期公平性 |

VarDiff、节点服务和模板广播可以由池提供，但它们不能成为池接管最终授权的理由。当前协议也没有阻止池调度矿工连接或只给部分矿工发送某些模板；这些控制面必须在 Pool v4 设计和真实测试网指标中单独处理。

详细威胁模型和 Pool v4 研究方向见 [docs/research/non-custodial-pool.md](docs/research/non-custodial-pool.md)。Legacy Stratum V1 只能用 `--enable-legacy-stratum` 开启本地 share 测试，无法提交冻结版本区块，mainnet 模式会拒绝它。

### 不可委托出块权的验收定义

“矿工有签名”还不够。最终协议必须同时满足：

| 性质 | 可验证验收条件 | 当前状态 |
| --- | --- | --- |
| 模板完整性 | 池修改交易根、父块、难度、epoch、nonce 或链身份后，原授权必定失效 | header 授权已覆盖；仍需跨实现向量 |
| 收益不可重定向 | 池修改 view/spend 收益密钥后，节点拒绝区块 | 已有单元测试 |
| 矿工自主模板 | 矿工能从自己的节点构造/协商交易集，池不能以协议优势强制审查 | 未实现 |
| 完整区块可达性 | 池拒绝转发时，矿工能直接向 P2P/节点提交 | 未实现 |
| Share 不可盗用 | 截获者不能把别人的 share 绑定到自己的身份或收益 | 消息身份绑定已实现；需网络重放/并发审计 |
| 账本可验证 | 矿工能验证漏记、调序、替换和结算规则 | 签名回执链可检测部分问题；不能强制付款 |
| 偿付/付款 | 奖励储备和链上批量付款可公开核对、崩溃恢复且幂等 | 未实现 |
| 抗 withholding/clandestine pool | 协议或经济机制限制双方隐瞒和链下出售完整工作 | 开放研究问题，不能声称解决 |

因此，Pool v3 更准确的说法是“减少已授权区块被池篡改/重定向的能力”，不是已经实现完全去中心化矿池，也不是对矿工不可串通的数学证明。

## Useful-Work 的边界

Hyphen 不做“AI 挖矿”。Useful-Work 当前完全不参与共识。任何研究原型都必须保持：

```text
chain_weight = 经过验证的基础 HyphenPoW
矿工收入 = 基础区块奖励 + 手续费 + 请求方预存的任务赏金
```

外部任务为零时，基础 PoW 难度和安全成本不能下降。任务必须确定性、公开、结果唯一、验证远低于计算成本、资源有界，并绑定不可预知 challenge、任务 ID 和提交者身份。链上节点只验证短证明，不能执行昂贵任务。请求方必须先 escrow 赏金，伪需求不能增发基础奖励。

| 失败模式 | 必须满足的门槛 |
| --- | --- |
| 验证和计算一样贵 | 节点只验证资源有界的短证明；基准必须公开证明验证成本显著更低 |
| 预计算 | 任务实例绑定不可预测链上 challenge、过期高度和提交者，旧结果不能复用 |
| 挑最便宜任务 | 调度/定价规则必须让任务选择可审计，并用异构任务实验测量有效工作与收益公平性 |
| 请求方与矿工串通制造伪需求 | 赏金全部由请求方 escrow 支付，不能铸造额外基础发行或提高 chain weight |
| 外部需求归零 | 基础 HyphenPoW 继续独立决定 chain weight 和安全下界 |
| GPU/TPU 集中化 | 有用任务只能是附加市场；必须公开跨 CPU/GPU/加速器的收益和集中度实验 |

优先研究可确定验证的密码学/系统任务，例如 proof aggregation、公开 Merkleized 数据转换或受约束的编码/科学计算；通用大模型训练和依赖浮点/私有模型环境的推理不符合当前准入条件。

完整研究边界见 [docs/research/useful-work-augmented-pow.md](docs/research/useful-work-augmented-pow.md)。在版本化规范、两个独立实现、形式化安全/经济模型和外部密码学审查之前，该功能必须保持关闭。

## 创新必须如何证明

项目要求“非拼装式创新”，所以不能把隐私、PoW、矿池、WASM 和 Useful-Work 放在同一张架构图里就称为创新。每个候选贡献必须脱离其他卖点，独立回答：它新解决了什么问题、攻击者能力是什么、删除该机制后哪条性质不再成立、相对最接近已有方案改善了哪个可测指标。

| 候选贡献 | 独立研究命题 | 仓库已有证据 | 仍缺少的决定性证据 |
| --- | --- | --- | --- |
| NCAP/Pool v3 | 池可聚合收益时，已求解区块的最终 header 与收益绑定不能被池单独改变 | 域分离的矿工授权、链身份绑定、交易根/收益篡改测试、share 回执链 | BetterHash/Stratum V2/P2Pool/DATUM prior-art claim chart、矿工自主模板、直接提交、形式化不可委托定义、独立实现与审查 |
| 可审计池账本 | 池崩溃或选择性记账后，矿工能得到可验证且顺序绑定的贡献证据 | 签名 hash-chain receipt、截断恢复与幂等结算测试 | 公共数据可用性、Merkle inclusion/non-inclusion proof、偿付证明、自动链上付款和大规模故障注入 |
| Useful-Work Augmented PoW | 外部任务只增加请求方出资收益，不改变基础 PoW chain weight 和零需求安全下界 | 研究规范和关闭门槛 | 原型、任务有效性证明、反预计算/串通模型、异构硬件公平实验、经济仿真和外审 |

每项创新进入默认构建或共识前，必须完成以下证据链：

1. 写出版本化问题定义、威胁模型、安全性质和明确的非目标。
2. 检索论文、协议、专利和真实部署，形成逐 claim 的 prior-art 对照，不只比较产品名称。
3. 提供最小独立原型和 ablation：关闭该机制后性质或指标确实退化。
4. 提供公开测试向量、攻击测试、基准方法、原始数据和可复现实验脚本。
5. 至少由第二个团队做互操作实现，并由独立密码学/系统评审验证。
6. 只有证据支持的部分才能写成“贡献”；否则必须标记为候选、实验或开放问题。

密码哈希、签名、KDF、零知识证明等基础原语应优先复用经过审查的标准实现。为了“看起来原创”而重写密码学会增加漏洞，不属于有价值创新。

## 与其他链和矿池协议的对比

下表只比较设计维度，不代表 Hyphen 更安全或更先进。Bitcoin、Monero、Zcash 和 Ethereum 经历了远多于 Hyphen 的生产运行和外部审查。

| 维度 | Hyphen 当前 | Bitcoin | Monero | Zcash | Ethereum 当前 PoS |
| --- | --- | --- | --- | --- | --- |
| 共识 | 实验 PoW，devnet v1 冻结 | SHA-256 PoW | RandomX PoW | PoW | PoS，无 PoW 矿工 |
| 隐私 | shielded 库实现，未外审 | 默认透明，可使用上层协议 | 默认隐私交易 | 透明与 shielded 地址/池 | L1 默认公开 |
| 硬件/参与门槛 | CPU-first 假设，尚无真实分布数据 | ASIC 主导 | 面向通用 CPU | ASIC 挖矿生态 | 质押、客户端与服务器运维 |
| 池控制研究 | Pool v3 绑定矿工最终授权，但池仍选交易集 | 传统池常由运营者提供模板 | 传统池类似，可使用 P2Pool | 依矿池实现 | 不是 PoW 矿池模型 |
| Fork choice/reorg | **未完成竞争分支 rollback** | 累计工作成熟实现 | 累计难度成熟实现 | 生产实现 | PoS fork choice/finality 生产实现 |
| 合约 | VM 独立库，链上未启用 | 有限脚本 | 非通用合约 L1 | 以支付隐私为主 | 通用合约生产运行 |
| 生产证据 | 研究/devnet，无外审 | 长期生产与广泛审查 | 长期生产与广泛审查 | 长期生产与密码学审查 | 长期生产与广泛审查 |

矿池协议必须单独比较，因为它们不是新的 L1：

| 方案 | 谁构造/协商模板 | Share/结算可见性 | 与 Hyphen 的关键差异 |
| --- | --- | --- | --- |
| 传统 Stratum V1 | 通常由池运营者构造 | 通常依赖池私有数据库 | Hyphen legacy adapter 不能携带冻结区块授权，默认关闭 |
| BetterHash / Stratum V2 Job Negotiation | 目标是让终端矿工协商或构造工作 | 取决于部署和池结算 | Hyphen 必须证明 miner authorization + reward binding 相对 job negotiation 新增了独立性质 |
| P2Pool | 矿工通过去中心化 sharechain 协作 | sharechain 公开可验证 | Hyphen 当前是中心服务 + 私有持久账本 + 可验证回执，不具备 P2Pool 的公共数据可用性 |
| DATUM 等近期去中心化模板方向 | 矿工/网关减少中心池模板控制 | 取决于具体协议 | 必须进入 prior-art 检索，不能只与 Stratum V1 比较后宣称原创 |
| Hyphen Pool v3 | 池下发交易集，矿工重算并签最终 solved header | 矿工本地验证池签名回执链 | 防授权后篡改已有原型；模板自主、直提、强制付款与抗 withholding 尚未完成 |

Hyphen 应重点借鉴已有系统的攻击经验和成熟密码库，再用可验证的新协议贡献证明差异。自创名称、模块组合或“非结合创新”不能证明新颖性、专利自由或安全性。正式创新主张至少需要 prior-art 检索、形式化性质、对照实验、测试向量和独立同行审查。

建议从各项目的规范、实现和论文原文复核，而不是只看本表：Bitcoin whitepaper/Bitcoin Core、Monero Research Lab 和开发文档、Zcash Protocol Specification、Ethereum consensus specifications、P2Pool 设计、Stratum V2 specification、BetterHash 论文以及 DATUM specification。对比结论要固定版本和日期；上表只提供研究问题，不构成安全评级。

复核入口：[Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf)、[Bitcoin Core](https://github.com/bitcoin/bitcoin)、[Monero Research Lab](https://www.getmonero.org/resources/research-lab/)、[RandomX](https://github.com/tevador/RandomX)、[Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)、[Ethereum consensus specifications](https://github.com/ethereum/consensus-specs)、[Stratum V2 specification](https://stratumprotocol.org/specification/)、[BetterHash](https://arxiv.org/abs/1803.03846)、[P2Pool](https://github.com/p2pool/p2pool) 和 [DATUM Gateway](https://github.com/OCEAN-xyz/datum_gateway)。正式对比应把引用版本/commit、日期、测量硬件、配置和原始结果一起归档。

### 如何做公平、可复核的跨链实验

README 的表格是事实/设计对照，不是性能测试。真正对比时先写实验协议，再运行程序：

| 实验问题 | 必须统一的条件 | 至少记录的指标 | 当前 Hyphen 状态 |
| --- | --- | --- | --- |
| 初始同步资源 | 同一机器、磁盘、网络限速、同等历史规模和缓存策略 | 总时间、峰值 RSS、CPU 时间、读写字节、下载字节 | 尚无长期公开历史可公平测量 |
| 区块传播与 reorg | 同节点数、拓扑、延迟/丢包模型和竞争分支工作量 | p50/p95/p99 传播、孤块率、reorg 深度和收敛时间 | reorg 未完成，不能声称优于任何生产链 |
| PoW 去中心化 | 固定观测窗口和实体归并方法 | 矿池份额、Top-3、HHI、硬件/地区分布、收益方差 | 只有 CPU-first 设计假设，无真实分布证据 |
| 隐私/匿名集 | 相同威胁模型、样本量和时间范围 | 有效匿名集、年龄/索引偏差、可链接率和置信区间 | 只有小型偏差实验，未达到生产证据等级 |
| 矿池控制 | 同时测模板来源、完整区块提交权和支付可验证性 | 自主模板比例、审查成功率、receipt 缺口、拒付/延迟 | 授权绑定原型存在，自主模板/直提/强制付款缺失 |
| 钱包恢复 | 同链规模、设备级别和故障脚本 | 恢复成功率、重扫时间、峰值资源、错误余额/历史 | 单元测试存在，真实移动设备演练仍缺 |

每个实验目录至少包含 `README.md`（假设/步骤）、`versions.txt`（各实现 commit）、`hardware.txt`、原始 CSV/JSON、日志、分析脚本和结果哈希。不得用不同历史规模比较同步速度，不得把实验 devnet TPS 与成熟主网 TPS 直接排名，也不得只报告平均值而隐藏尾延迟、失败样本或不利结果。在这些实验完成前，正确结论是“尚未测量”，不是“Hyphen 更快/更去中心化/更隐私”。

## 激励测试网监控与上线门槛

当前缺少完整 reorg，因此还不能进入有价值激励测试网。补齐竞争分支和状态回滚后，至少监控：

- reorg 次数、深度、替换工作量和收敛时间；
- 孤块率，按矿工、矿池、版本和区域拆分；
- P2P peer 数、连接抖动、dial 失败、畸形/重复 gossip；
- 出块间隔和 PoW/硬件分布；
- 单池占比与前三矿池集中度；
- 初始同步时间、CPU、峰值内存、磁盘和带宽；
- share receipt 缺口、账本恢复来源和待付款；
- 移动钱包 crash-free、扫描延迟、恢复/重扫时间和发送失败。

分阶段门槛、起始告警阈值和故障演练见 [docs/operations/incentivized-testnet.md](docs/operations/incentivized-testnet.md)。参数只能根据公开真实数据收敛；共识参数变化必须改变链身份。

## 外部验证、审计与 bug bounty

外部独立审查和真实 bounty 不能由本地代码“模拟完成”。目前：

- 没有已完成的独立密码学、共识、钱包、P2P/RPC 或矿池审计。
- 没有已资助 bug bounty，也不承诺奖励。
- 安全问题应通过 GitHub private vulnerability reporting 私下提交。
- 任何有价值上线都被 [SECURITY.md](SECURITY.md) 中的审计和发布条件阻断。

审计必须发布精确 commit、范围、报告、修复和 retest。Critical/High 未关闭时不能宣布通过。

推荐按固定顺序执行：先冻结被审 revision 和威胁模型；再分别委托共识/网络、密码学/隐私、钱包/密钥管理和矿池/经济账本审查；修复后由原审计方复测；最后才开放有明确范围、响应时限、safe harbor 和已落实奖励资金的 bug bounty。项目自己写的单元测试、朋友的非正式浏览或只覆盖 UI 的报告都不能替代独立审查。

## 钱包备份与恢复演练

`keys/devnet-miner.key` 和 `keys/devnet-pool.key` 是协议身份，不是钱包 seed。真正钱包恢复必须验证“相同 seed 恢复相同地址”，然后从高度 0 重扫。当前自动测试明确要求恢复钱包的余额和扫描高度先归零，不能把旧设备的缓存余额当成链上事实。

```powershell
cargo test -p hyphen-wallet seed_recovery_restores_keys_but_requires_rescan --locked
cargo test -p hyphen-wallet encrypted_wallet_rejects_single_byte_corruption --locked
```

生产前还必须完成跨实现助记词/派生向量、干净设备恢复、全链重扫、历史与余额比对、错误密码、损坏备份和移动设备中断演练。当前加密钱包文件实现未经过独立密钥存储/KDF 审查。

## 服务端口与暴露建议

| 服务 | Devnet | Testnet | Mainnet research | 建议 |
| --- | ---: | ---: | ---: | --- |
| P2P | `48334` | `38334` | `18334` | 公共节点可开放 |
| Protobuf RPC | `48333` | `38333` | `18333` | 仅回环或私网，无内置 TLS/auth |
| Template Provider | `3350` | `3350` | `3350` | 仅节点到矿池私有链路 |
| Explorer HTTP | `8080` | `8080` | `8080` | 回环或认证反向代理 |
| Pool v3 | `3340` | `3340` | `3340` | 仅服务矿工时开放 |
| Legacy Stratum V1 | `3333` | `3333` | 禁止 | 默认关闭，只能做本地兼容测试 |
| 矿池账本 HTTP | `8081` | `8081` | `8081` | 保持私有，当前无认证且 CORS 宽松 |

签名 envelope 提供完整性和身份，不提供机密性、访问控制或传输加密。不要把 RPC、TP、Explorer 或账本 API 直接暴露到公网。

## 主网模式不是生产主网

`--network mainnet` 目前只是研究参数 profile。普通 mainnet 模式节点必须提供带 `/p2p/<peer-id>` 的 `--boot-nodes`；只有有意启动第一个种子时才允许 `--allow-isolated-mainnet`。这项启动保护不等于生产就绪。

任何真实价值上线前必须全部完成：冻结生产规范和创世流程、完整 fork choice/reorg、跨实现向量、独立审计、长期公开测试网、多运营方节点、可复现签名构建与 SBOM、监控/备份/恢复/事件响应、RPC/TP/Pool 边缘加密认证、自动可审计矿池付款、钱包恢复演练，以及已资助漏洞计划。

## 仓库结构

| 路径 | 用途 |
| --- | --- |
| `crates/hyphen-core` | 区块、冻结配置、时间戳和矿工授权 |
| `crates/hyphen-crypto` | Blake3、Ed25519、承诺、stealth、CLSAG、Merkle、WOTS+ |
| `crates/hyphen-proof` | range proof 与 inner-product proof |
| `crates/hyphen-pow` | epoch arena、kernel、求解器和难度算法 |
| `crates/hyphen-tx` | shielded UTXO 交易结构和 builder |
| `crates/hyphen-state` | Sled 区块、tip、nullifier 和 commitment 状态 |
| `crates/hyphen-consensus` | 创世、验证、链追加、archive 和 replay |
| `crates/hyphen-network` | libp2p discovery、gossip 和同步 |
| `crates/hyphen-rpc` | protobuf RPC |
| `crates/hyphen-transport` | 节点到矿池 TP v2 |
| `crates/hyphen-explorer` | 节点内置浏览器和 HTTP API |
| `crates/hyphen-wallet` | 核心钱包与外部 signer 协议 |
| `crates/hyphen-vm` | 尚未接入共识的确定性 WASM 库 |
| `crates/hyphen-fuzz` | transaction/RPC/P2P fuzz targets |
| `HyphenPool` | 独立矿池 Cargo workspace |
| `HyphenMiner` | 独立 CPU 矿工 Cargo workspace |
| `HyphenWallet` | Flutter 应用和 Rust backend |
| `scripts/devnet-smoke.ps1` | Windows 一键端到端验证 |

矿池和矿工有各自的 `Cargo.lock` 和 `target`，必须分别构建和测试。

## 常见问题

- **提示 genesis/consensus mismatch：** 数据目录属于另一个网络、另一个 profile 或旧的动态创世实现。保留备份后使用新的空目录，不要硬改数据库身份。
- **PowerShell 提示某个参数不是命令：** 上一行反引号后有空格，或漏了反引号。先把整条命令写成一行再试。
- **Cargo 很久没有新输出：** 首次编译 Wasmer/密码学依赖或最大聚合证明测试会很慢。先看任务管理器 CPU/磁盘；不要同时启动多份相同构建。
- **浏览器打不开 `38333/48333`：** 这是 protobuf RPC，不是 HTTP。浏览器应访问 Explorer 的 `8080`；钱包按设置连接 RPC。
- **矿池连不上节点：** 先确认节点的 `--template-bind` 与矿池 `--node` 完全一致，并检查防火墙和日志。
- **矿工登录被拒绝：** 节点、池、矿工必须选择相同 `--network`，Pool 使用 v3，TP 使用 v2，二进制必须来自同一 revision。
- **钱包地址被拒绝：** mainnet 地址版本为 `0x01`，testnet/devnet 为 `0x02`。三者都显示 `hy1` 前缀，必须检查版本和 checksum。
- **share accepted 但钱包没有钱：** SOLO 只有节点接受完整区块后才有 coinbase；普通 share 不是链上奖励。共享模式 pending balance 也不是已付款。
- **日志只有 stale job：** 新 tip 或已提交完整区块会使旧 job 失效。持续只有 stale 时检查节点/池模板刷新和系统时间。
- **NTP 警告：** 沙箱或离线环境可能无法访问公共 NTP。devnet 可继续测试；公共网络必须有可信时间源和告警。
- **无法通过 RPC 部署 WASM：** 当前没有合约交易和共识执行路径，这是预期限制。

## 从“能运行”到“可发布”的完整检查单

以下项目必须按顺序推进，前一阶段失败就不能跳到后一阶段：

- [ ] 固定并发布 revision、devnet 规范、链身份和机器可读向量；三种 profile 的实现输出与向量一致。
- [ ] workspace、矿池、矿工、钱包后端测试和 fuzz target 编译通过；warning、ignored test 和失败样本均有归属。
- [ ] 一键 smoke 和手动三进程流程通过；操作者能区分 share、完整区块、池内余额和链上余额。
- [ ] 导出一段真实生成的历史，轻量 verifier 和全量 replay 在全新目录得到一致 tip；第二实现/语言无关编码仍是发布阻断项。
- [ ] 完整 fork choice、竞争分支验证和原子状态 rollback 实现，并通过 partition、eclipse、时间戳/难度和深 reorg 故障演练。
- [ ] Pool 协议补齐矿工自主模板、池拒绝转发时的直接提交、公共可验证账本、偿付证明和自动幂等链上付款；分别测试六类攻击。
- [ ] 钱包在干净的 Windows/Android/Linux/macOS 测试设备完成创建、备份、错误输入、损坏、中断、从高度 0 重扫和余额/历史核对。
- [ ] 小规模无价值多运营方测试网满足稳定性门槛，再开启有上限的激励；公开 reorg、孤块、P2P、PoW/矿池集中度、同步资源和移动故障原始数据。
- [ ] 独立共识、密码学、钱包和矿池审计完成；所有 Critical/High 修复并复测；正式 bug bounty 已资助和上线。
- [ ] 生产规范、创世仪式、可复现签名构建、SBOM、许可证全文、第三方 notices、监控、备份、恢复和事件响应全部就绪。

在最后一项完成前，只能称实验性研究/devnet 软件。任何一项“看起来差不多”都不能替代证据，也不能据此宣传可保存真实大额价值。

## 许可证

Cargo 元数据声明 `AGPL-3.0`。仓库根目录当前仍缺少对应许可证全文；分发 release 制品前必须添加完整许可证并审查第三方 notices。
