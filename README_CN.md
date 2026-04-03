# Hyphen

一个以隐私为核心、CPU优先的工作量证明区块链，完全使用 Rust 构建。

Hyphen 将内存硬多内核 PoW 与纪元变异常量 (EMK)、完整隐私原语（CLSAG 环签名、Bulletproofs 范围证明、隐身地址、多维 VRE）、后量子混合签名、NTP 同步毫秒级时间戳、GHOST 风格的叔块机制、MDAD-SPR 多相位难度调整与抗 51% 阻尼、时间纪元参照锚定 (TERA) 防重放、挖矿稳定均衡器 (MSE) 收入平滑、渐进信任挖矿 (GTM) 抗 Sybil 矿池准入、以及共识层 coinbase 验证整合到一个生产级区块链中。

## 架构

Hyphen 采用“核心节点工作区 + 独立挖矿程序”架构：主工作区负责链上核心，`hyphen-pool` 与 `hyphen-miner` 是完全独立的链下程序。

| Crate | 功能 |
| --- | --- |
| `hyphen-crypto` | Blake3 哈希、Ed25519 密钥、Pedersen 承诺、隐身地址、Merkle 树、CLSAG 环签名、WOTS+ 后量子签名 |
| `hyphen-core` | 区块/区块头类型、链配置、NTP 时间戳同步、错误类型 |
| `hyphen-pow` | **HyphenPoW** CPU优先 PoW — epoch arena、scratchpad、12 个变换内核、MDAD-SPR 多相位难度调整与抗 51% 阻尼 |
| `hyphen-proof` | Bulletproofs 范围证明（64位，最多聚合 16 个）和内积论证、批量验证 |
| `hyphen-tx` | 隐蔽 UTXO 模型 — 票据、交易、废止符、交易构建器 |
| `hyphen-token` | 多资产发行，支持固定供应和可铸造策略 |
| `hyphen-economics` | 洛伦兹连续衰减 (LCD) 发行模型与尾部发行、手续费计算与部分销毁 |
| `hyphen-state` | 基于 sled 的持久化存储 — 区块存储、链状态、废止符集合、承诺树 |
| `hyphen-consensus` | 区块/交易/叔块验证、链管理、创世区块 |
| `hyphen-mempool` | 按手续费密度优先的交易池（类比特币手续费市场）— 交易按每字节手续费排序（负手续费密度用于最大堆提取），密钥映像冲突检测防止双花，池容量有界并自动驱逐最低手续费交易 |
| `hyphen-wallet` | 钱包，含 ICD 密钥派生、子地址、隐身地址扫描 |
| `hyphen-network` | libp2p P2P 网络栈 — Gossipsub 广播、Kademlia 发现、Request-Response 同步 |
| `hyphen-transport` | Template Provider 协议 — 签名信封帧、protobuf 消息类型、`TemplateProvider` trait，用于节点与矿池之间的通信 |
| `hyphen-vm` | 智能合约虚拟机，含 gas 计量 |
| `hyphen-rpc` | 长度前缀 protobuf RPC — 链信息查询、区块查询、交易提交、输出索引查询（GET_RANDOM_OUTPUTS 用于诱饵选择、GET_OUTPUT_INFO 用于发送前输出预验证） |
| `hyphen-node` | 全节点二进制程序，含模板提供者服务器和内置区块浏览器；也是浏览器默认运行宿主 |
| `hyphen-explorer` | 浏览器库 crate，向 `hyphen-node` 提供 HTTP UI/API 路由与服务启动能力 |

## 创新与数学基础

### 1. HyphenPoW — 12 内核内存硬工作量证明

HyphenPoW 是一种新颖的 CPU 优先 PoW，结合 2 GiB epoch arena、8 MiB scratchpad 和**12 个动态选择的计算内核**。现有 PoW 算法中没有使用异构内核集的运行时内核选择。

**算法。** 对于每个 nonce，求解器运行 1024 轮。每轮：

1. 从 epoch arena 中按数据依赖地址读取一页
2. 通过 $k = (\mathtt{state}[16] \oplus \mathtt{page}[32]) \bmod 12$ 选择内核
3. 对页面数据执行内核 $k$
4. 通过 XOR 将内核输出混入状态
5. 沿页间链接跳转到下一页（数据依赖的 DAG 遍历）
6. 每隔 `writeback_interval` 轮将状态写回 scratchpad（写后读依赖链）

**12 个异构内核。** 每个内核针对不同的 CPU 执行单元：

| 内核 | 名称 | 利用的特性 |
| --- | --- | --- |
| K0 | DivChain | 64 次迭代整数除法链 — 惩罚无硬件除法器的 GPU/ASIC |
| K1 | BitWeave | 旋转/XOR，使用黄金比例常数 $\phi_{64} = \mathtt{0x9E3779B97F4A7C15}$ |
| K2 | SparseStep | 模拟稀疏矩阵-向量乘法，带间接读取 |
| K3 | PrefixScan | 完整 Blelloch 并行前缀和（上扫 + 下扫），64 个元素 |
| K4 | MicroSort | 32 个元素的插入排序 — 分支预测密集 |
| K5 | VarDecode | LEB128 变长解码，串行字节游标 |
| K6 | HashMix | AES S-Box 替换 + MixColumns 风格的 GF($2^8$) 扩散 |
| K7 | BranchMaze | 8 路数据依赖分支，带游标跳转 |
| K8 | AESCascade | 完整 AES SubBytes→ShiftRows→XOR→MixColumns，24 轮，64 字节串行（利用 AES-NI） |
| K9 | FloatEmulate | 定点 32.32 乘法 + Newton-Raphson 求倒数 |
| K10 | ScatterGather | 2 KiB L1 scratchpad，数据依赖的读写模式 |
| K11 | ModExpChain | 128 位模幂（u128 乘法 + 取模），串行依赖 |

**ASIC 抗性定理。** 令 $\mathcal{K} = \{K_0, \ldots, K_{11}\}$ 为内核集。对于给定 nonce，内核调用序列 $\sigma = (\sigma_1, \ldots, \sigma_{1024})$（其中 $\sigma_i \in \mathcal{K}$）取决于运行时状态。针对严格子集 $\mathcal{K}' \subset \mathcal{K}$ 优化的 ASIC 必须以更高成本模拟其余内核。令 $p = |\mathcal{K}'|/|\mathcal{K}|$ 为拥有原生硬件的内核比例，$\alpha = T_{\text{emulate}} / T_{\text{native}}$ 为模拟内核的成本比率。预期每哈希减速为：

$$S = p + (1 - p) \cdot \alpha$$

当 $p = 1/6$（12 个内核中 2 个有硬件支持）且 $\alpha = 5$ 时：$S = 1/6 + 5/6 \cdot 5 = 26/6 \approx 4.33\times$。当 $p = 1/2$ 且 $\alpha = 3$ 时：$S = 1/2 + 1/2 \cdot 3 = 2.0\times$。由于内核涵盖整数除法、AES 流水线、分支预测、浮点运算和缓存层次结构，任何单一 ASIC 架构都无法在不复现通用 CPU 的前提下使 $p$ 接近 1。

**与现有 PoW 的对比：**

| | CryptoNight | RandomX | Ethash | HyphenPoW |
|---|---|---|---|---|
| 内存 | 2 MiB | 256 MiB | 4+ GiB DAG | 2 GiB arena + 8 MiB scratchpad |
| 指令多样性 | 固定 AES+MUL | 每块随机程序 | 轻量哈希链 | 12 内核，每轮选择 |
| 数据依赖分支 | 无 | 有限 | 无 | 有（BranchMaze, ScatterGather）|
| 纪元变异常量 | 无 | 有（随机程序） | 无 | 有（EMK：S-Box、旋转、乘数、置换、步幅）|

### 1a. 纪元变异内核 (EMK)

HyphenPoW 的内核常量不是静态的 — 每个纪元都从纪元种子通过 Blake3 XOF **重新派生**。这使得预计算查找表和固定功能 ASIC 流水线在每个纪元边界处失效。

**派生。** `EpochKernelParams::derive(epoch_seed)` 使用 Blake3 带密钥模式，域为 `"EMK_epoch_kernel_params_v1"`，生成确定性 XOF 流来产生：

| 组件 | 大小 | 算法 |
| --- | --- | --- |
| `sbox` | `[u8; 256]` | 使用 XOF 流的 u16 值对 AES S-Box 进行 Fisher-Yates 洗牌 |
| `rot_offsets` | `[u32; 12]` | 每内核旋转偏移量，掩码至 `[0, 63]` |
| `mix_constants` | `[u64; 12]` | 每内核奇数乘数（`raw \| 1` 保证可逆性） |
| `slot_perm` | `[usize; 8]` | 对 `[0..8]` 的 Knuth 洗牌，用于跨车道混合 |
| `stride_salt` | `[u64; 12]` | 每内核步幅变异子，范围 `[31, 251]`（`31 + (raw % 221)`） |

**ASIC 放大效应。** 硬连线单个纪元 S-Box 或乘数表的 ASIC 面临 $S_{\text{total}} = S_{\text{kernel}} \cdot E$，其中 $E \geq 2$ 反映在纪元边界重新配置硬连线常量的成本。

### 2. 迭代承诺派生 (ICD) — 新颖的密钥派生方案

ICD 是一种新颖的密钥派生方案，使用 Ristretto255 曲线上的 Pedersen 承诺，替代基于 HMAC 的链码（BIP32）或 HKDF。

**构造。** 给定父标量 $s_p$ 和用途字符串 $\pi$：

$$P_{\text{chain}} = s_p \cdot G + H_s(\pi) \cdot T$$
$$s_{\text{child}} = H_s(\text{compress}(P_{\text{chain}}))$$

其中 $T = H_p(\texttt{"Hyphen\_ICD\_twist\_generator\_v1"})$ 是一个 nothing-up-my-sleeve 扭曲生成元，其相对于 $G$ 的离散对数未知，$H_s$ 是域分离的 blake3 哈希到标量，$H_p$ 是哈希到点。

**安全性声明。** 在 Ristretto255 上的判定性 Diffie-Hellman (DDH) 假设下：

*给定 $(G, T, s_c \cdot G)$，其中 $s_c$ 是子密钥，没有 PPT 敌手能区分 $s_c$ 是通过 ICD 从 $s_p$ 派生的还是均匀随机采样的。*

**证明概要。** 链点 $P_{\text{chain}} = s_p \cdot G + H_s(\pi) \cdot T$ 是对 $s_p$ 的 Pedersen 承诺，致盲因子为 $H_s(\pi)$。根据 Pedersen 承诺的隐藏性（源于群上的 DDH），$P_{\text{chain}}$ 不会泄露关于 $s_p$ 的任何信息。子密钥 $s_c = H_s(\text{compress}(P_{\text{chain}}))$ 是该承诺的哈希。由于 blake3 被建模为随机预言机，给定 $P_{\text{chain}}$，$s_c$ 是伪随机的，而 $P_{\text{chain}}$ 在给定 $(G, T)$ 和 DDH 假设下本身也是伪随机的。

**子地址派生。** 使用账户索引 $a$ 和子地址索引 $i$ 扩展 ICD：

$$P_{\text{sub}} = s_p \cdot G + H_s(a \| i) \cdot T$$
$$s_{\text{sub}} = H_s(\text{compress}(P_{\text{sub}}))$$

从单个主密钥生成无限个不可关联的子地址。

### 3. 抗 51% 难度阻尼（已集成到 MDAD-SPR）

在标准 LWMA 难度调整之上，Hyphen 包含一个二级检查，防止高算力攻击者快速降低难度。

**检测。** 令 $\{t_i\}_{i=1}^{N}$ 为最近 $N$ 个区块的时间戳。定义观测跨度 $\Delta = t_N - t_1$，预期跨度 $E = (N-1) \cdot T_{\text{target}}$，其中 $T_{\text{target}}$ 为目标出块时间。

当 $\Delta < E / 4$（区块到达速度低于预期的 25%）时，阻尼机制激活，强制难度按钳位乘数上调：

$$D_{\text{next}} = D_{\text{prev}} \cdot C_{\text{up}}$$

其中 $C_{\text{up}} = 3$（可配置）。

**原理。** 控制 > 50% 算力的 51% 攻击者会产生比预期更快的区块。如果没有阻尼，攻击者可以：
1. 快速挖矿，使难度下降
2. 释放算力，让诚实矿工面对人为降低的难度
3. 以更低成本重新发起攻击

阻尼确保在异常快速出块期间难度不会下降。

### 4. 带隐私保护的 GHOST 风格叔块

Hyphen 将以太坊风格的叔块（ommer）包含机制与完整的隐私币架构相结合。现有隐私币中没有支持叔块的。

**叔块奖励**——对于距包含块深度为 $d$ 的叔块：

$$R_{\text{uncle}}(d) = R_{\text{base}} \cdot \frac{(\text{max\_depth} + 1 - d) \cdot n_u}{\text{max\_depth} \cdot d_u}$$

其中 $n_u / d_u = 7/8$ 可配置。

**侄块奖励**——对于包含 $u$ 个叔块的区块：

$$R_{\text{nephew}}(u) = R_{\text{base}} \cdot \frac{n_n \cdot u}{d_n}$$

其中 $n_n / d_n = 1/32$ 可配置。

**参数：** 每块最多 2 个叔块，最大叔块深度 7。

### 5. NTP 同步共识时间

Hyphen 中所有时间戳均为毫秒精度的 UTC 时间，从 NTP 服务器获取，而非本地系统时钟。

**协议：**
1. 查询 11 个 NTP 服务器（Google、Cloudflare、Apple、NIST、腾讯、阿里云等）
2. 要求法定最少 $\geq 3$ 个响应
3. 计算偏移量的中位数
4. 拒绝偏离中位数 $> 2$ 秒的异常值
5. 对过滤后的集合取平均得到校正偏移量
6. 将偏移量应用于所有 `ntp_adjusted_timestamp_ms()` 调用

**自适应轮询：** 时钟可信时 30 秒间隔，不可信时 5 秒，默认 10 秒。

**共识集成：** 时间戳超过节点 NTP 校正时钟 `timestamp_future_limit_ms`（主网 120 秒，测试网 60 秒）的区块将被拒绝。

### 6. MDAD-SPR — 多维自适应难度与统计相位识别

Hyphen 使用 **MDAD-SPR** 替代标准 LWMA 难度调整，这是一种新颖的多相位算法，能够检测并响应不同的网络状态（稳定挖矿、闪崩、持续攻击、恢复期）。

**相位检测。** 令 $\{t_i, D_i\}_{i=1}^{N}$ 为最近的区块时间戳和难度。定义：

- **求解时间比：** $r = \text{median}(\Delta t) / T_{\text{target}}$
- **变异系数：** $\text{cv} = \sigma(\Delta t) / \mu(\Delta t)$
- **算力梯度：** $g = (H_{\text{recent}} - H_{\text{old}}) / H_{\text{old}}$

算法基于这三个指标对当前网络相位进行分类：

| 相位 | 检测条件 | 响应 |
| --- | --- | --- |
| 稳定 | $r \in [0.8, 1.2]$ 且 $\text{cv} < 0.5$ | 标准 LWMA 带阻尼 |
| 闪崩 | $r > 2.0$ 或 $g < -0.3$ | 激进向下修正，带紧急下限 |
| 持续攻击 | $r < 0.5$ 且 $\text{cv} < 0.3$ | 向上爬升，带抗 51% 钳位 |
| 恢复期 | 在相位之间过渡 | 混合 EMA 带动量跟踪 |

**抗振荡。** 当相位发生转换时，MDAD-SPR 使用可配置惯性因子 $\alpha$ 进行指数平滑，防止难度在不同状态之间来回振荡。

**抗操纵。** 偏离窗口中位数超过 $3\sigma$ 的时间戳异常值在难度计算前会被钳位，防止时间戳注入攻击。

**形式化保证。** 在 MDAD-SPR 下，任何算力扰动后，预期出块时间在 $O(N)$ 个区块内收敛到 $T_{\text{target}}$，且过冲有界：

$$|D_{\text{next}} / D_{\text{ideal}} - 1| \leq C_{\text{clamp}}^{-1}$$

其中 $C_{\text{clamp}} = 3$，$D_{\text{ideal}}$ 是在当前算力下恰好产生 $T_{\text{target}}$ 出块时间的难度。

### 7. 后量子混合签名

Hyphen 在协议级别内置双重签名后量子准备。

**WOTS+ 参数：** $w = 16$，67 条链（64 消息 + 3 校验和），基于 blake3 的链函数：

$$C_i^{(j)} = H(\texttt{"Hyphen\_WOTS\_chain"} \| \text{addr\_seed} \| i \| j \| C_i^{(j-1)})$$

**混合签名：** `HybridSignature` 同时包含 Ed25519 签名和 WOTS+ 签名。验证要求**两者都通过**。即使 Curve25519 被量子计算机破解，WOTS+ 签名（基于哈希，抗量子）仍然安全。

**签名大小：** $67 \times 32 + 32 = 2{,}176$ 字节 (WOTS+) + 64 字节 (Ed25519) = **2,240 字节**。

### 8. 统一的 Blake3 密码学栈

Hyphen 中每一个密码学哈希操作都使用带域分离的 blake3：

- `blake3_hash` — 标准 256 位摘要
- `blake3_keyed` — 带密钥哈希 (MAC)
- `hash_to_scalar` — blake3 XOF → 512 位 → 对 $\ell$ 取模
- `hash_to_point` — blake3 XOF → 512 位 → `RistrettoPoint::from_uniform_bytes`

所有域分离使用 `b"Hyphen_..."` 前缀。代码库中没有 SHA-256 或 Keccak。Blake3 在现代 CPU 上的哈希速度比 SHA-256/Keccak 快约 6 倍，并原生支持 XOF 模式。

### 9. 抗量子 BIP39 口令变换

Hyphen 通过后量子密码变换增强 BIP39 助记词到种子的派生。用户密码不直接用作 BIP39 口令，而是先经过 WOTS+ 哈希链变换：

1. 通过域分离的 BLAKE3 从密码派生 WOTS+ 密钥：$\text{seed} = H(\texttt{"Hyphen\_PQ\_seed"} \| \text{password})$
2. 计算完整 WOTS+ 公钥（67 条链，$w = 16$，每条 15 步哈希 = 共 1,005 次 blake3 调用）
3. 对公钥进行哈希生成硬化口令：$\text{passphrase} = H(\texttt{"Hyphen\_PQ\_passphrase"} \| H(\text{pubkey}) \| \text{addr\_seed})$

**安全性质：** 即使攻击者能逆转 PBKDF2-HMAC-SHA512（BIP39 KDF），仍需要逆转 WOTS+ 哈希链才能恢复原始密码。WOTS+ 在 blake3 的第二原像抗性下可证明对量子攻击安全。

### 10. 时间纪元参照锚定 (TERA)

TERA 将每个交易输入绑定到特定的纪元窗口，防止重放攻击和陈旧交易注入。

**构造。** 每个 `TxInput` 携带三个 32 字节 TERA 字段：

$$\texttt{epoch\_context} = \text{Blake3\_keyed}(\texttt{"TERA\_v1\_context\_\_Hyphen\_2025\_ctx"},\; \text{epoch\_seed})$$

$$\texttt{temporal\_nonce} = H_s(\texttt{"TERA\_nonce"} \| \text{spend\_sk} \| \texttt{epoch\_context})$$

$$\texttt{causal\_binding} = \text{Blake3}(\texttt{"TERA\_causal"} \| \text{spend\_sk} \| \text{note\_hash} \| \texttt{epoch\_context})$$

**验证。** 验证器维护一个覆盖链尖 $\pm T$ 个纪元的有效 epoch context 列表，其中 $T = \texttt{tera\_epoch\_tolerance}$（主网：2，测试网：4）。`epoch_context` 不在此列表中的交易以 `TeraEpochMismatch` 拒绝。

**防重放。** 为纪元 $e$ 签名的交易在 $e + T$ 个纪元过后无法重放，因为其 `epoch_context` 不再在有效集中。

### 11. 挖矿稳定均衡器 (MSE)

MSE 根据实际难度与目标难度的比率调整区块奖励，创建负反馈循环以平滑矿工收入在算力波动中的变化。

**公式。** 令 $D_{\text{ratio}} = D_{\text{actual}} / D_{\text{target}}$。MSE 乘数为：

$$\mu = \text{clamp}\!\left(1 + \gamma \cdot (D_{\text{ratio}} - 1),\; 0.80,\; 1.20\right)$$

其中 $\gamma = 0.10$（`mse_gamma = 100` 基点）。有效区块奖励为：

$$R_{\text{eff}}(h) = R_{\text{lcd}}(h) \cdot \mu$$

| 条件 | $\mu$ 范围 | 效果 |
| --- | --- | --- |
| $D_{\text{actual}} > D_{\text{target}}$ | $\mu > 1$（最高 1.20） | 奖励增加 — 补偿更高的安全成本 |
| $D_{\text{actual}} = D_{\text{target}}$ | $\mu = 1$ | 中性 — 基础 LCD 奖励 |
| $D_{\text{actual}} < D_{\text{target}}$ | $\mu < 1$（最低 0.80） | 奖励减少 — 防止过度支付 |

这创建了经济均衡：当奖励高时矿工向网络迁移，当奖励低时矿工离开，从而稳定算力和矿工收入。

### 12. 渐进信任挖矿 (GTM)

GTM 通过将新矿工的份额难度从 $d_{\text{init}}$ 指数級地攀升至 $d_{\text{target}}$，防止矿池级别的 Sybil 难度操纵。

**预热公式：**

$$d(n) = d_{\text{init}} + (d_{\text{target}} - d_{\text{init}}) \cdot \left(1 - e^{-5n/W}\right)$$

其中 $W = 100$（`GTM_WARMUP_SHARES`），$d_{\text{init}} = 100$（`VARDIFF_INITIAL`）。

**收敛：**
- 在 $n = 0$ 时：$d \approx d_{\text{init}} = 100$
- 在 $n = 20$ 时：$d \approx 0.63 \cdot d_{\text{target}}$（实际运行难度）
- 在 $n = W = 100$ 时：$d \approx 0.993 \cdot d_{\text{target}}$（目标的 1% 以内）

**Sybil 抗性。** 开启 $k$ 个并行连接的 Sybil 攻击者受限于 `GTM_MAX_CONNECTIONS_PER_IP = 32` 每 IP 连接数。每个连接无论声称多少算力都从 $d_{\text{init}}$ 开始，因此攻击者必须在所有连接上投入 $k \cdot W$ 份真实工作才能达到全部难度。

### 13. 共识层 Coinbase 验证

Hyphen 在共识层面通过五条结构规则验证 coinbase 交易：

1. **无输入** — coinbase 必须有零个 `TxInput` 条目
2. **单输出** — 恰好一个承诺输出
3. **零手续费** — coinbase 手续费必须为 0
4. **Extra 字段** — 至少 8 字节（编码区块高度）
5. **范围证明** — 输出承诺上的有效 Bulletproof

此外，`accept_block` 验证 `block.header.reward` 必须精确匹配 `lcd_base_reward(height, cfg)`，防止矿工声称膨胀的奖励。

## 隐私模型

Hyphen 使用隐蔽 UTXO 模型，结合：

1. **Pedersen 承诺** — 金额隐藏为 $C = v \cdot H + r \cdot G$，其中 $H = H_p(\texttt{"Hyphen\_pedersen\_value\_generator\_v1"})$
2. **隐身地址** — 基于 ECDH 的一次性输出密钥，带输出索引绑定和 blake3 加密金额
3. **CLSAG 环签名** — Ristretto255 上的紧凑可链接环签名，含密钥映像和承诺密钥映像；交易构建器在签名后立即对每个 CLSAG 签名执行自验证（提交前完整性检查）
4. **Bulletproofs 范围证明** — 证明 $v \in [0, 2^{64})$，$O(\log n)$ 的证明大小；最多聚合 16 个输出
5. **视图标签** — 单字节标签 $\tau = H(\texttt{"Hyphen\_view\_tag"} \| ss)[0]$，通过无需完整 ECDH 即可过滤非己输出，实现 256× 扫描加速
6. **确定性承诺盲因子** — 盲因子 $r = H_s(\texttt{"Hyphen\_commitment\_blind"} \| ss)$ 由共享密钥确定性推导，确保发送方和接收方始终计算相同承诺（无盲因子不匹配问题）
7. **发送前输出预验证** — 构建交易前，钱包通过 GET_OUTPUT_INFO RPC 从链上获取输出数据，验证每个选定输入的公钥和承诺与本地缓存值一致，防止过期输出和索引不匹配错误
8. **已花费输出追踪** — 交易发送成功后，钱包从构建器接收已花费的全局索引并立即从本地 UTXO 缓存中移除，防止对已消费输出的重复花费尝试

### 可验证环熵 (VRE) — 新颖共识创新

Hyphen 是首个在**共识层面强制执行环签名质量**的区块链。

在所有现有的环签名隐私币（门罗币等）中，诱饵选择算法纯粹在客户端执行 — 网络无法验证诱饵是否选择良好。这造成了关键盲区：

- 恶意钱包可以从**同一区块**选择所有诱饵，使真实输入变得一目了然
- 对诱饵年龄分布的统计分析可以缩小匿名集
- 网络**无法拒绝**诱饵质量差的交易

**Hyphen 的 VRE** 通过四条共识强制规则解决此问题：

**VRE-1：最小高度跨度。** 给定环成员区块高度 $\{h_1, \ldots, h_n\}$：

$$\max(h_i) - \min(h_i) \geq S_{\min}$$

其中 $S_{\min} = 100$（主网），$S_{\min} = 20$（测试网）。确保环成员跨越显著的时间范围，防止时间聚类攻击。

**VRE-2：最小不同高度比例。** 设 $D = |\{h_1, \ldots, h_n\}|$ 为环中不同高度的数量：

$$D \geq \lceil 3n/4 \rceil$$

对于环大小 16，至少 12 个成员必须来自不同的区块高度。防止从热门区块大量重用诱饵。

**VRE-3：年龄带多样性。** 每个环成员的年龄 $a_i = \max(h) - h_i$ 被分配到带 $b_i = \lfloor a_i / w \rfloor$，其中 $w = \texttt{vre\_age\_band\_width}$（主网：2048，测试网：128）。不同带的数量必须满足：

$$|\{b_1, \ldots, b_n\}| \geq B_{\min}$$

其中 $B_{\min} = \texttt{vre\_min\_age\_bands}$（主网：3，测试网：2）。这强制环成员跨越多个时间区域，击败年龄聚类去匿名化。

**VRE-4：全局索引跨度。** 设 $g_{\min}, g_{\max}$ 为环中最小和最大的全局输出索引，$N$ 为总输出集大小：

$$\frac{(g_{\max} - g_{\min}) \cdot 10000}{N} \geq \tau$$

其中 $\tau = \texttt{vre\_min\_index\_span\_bps}$（主网：500 = 5%，测试网：300 = 3%）。这确保环成员从输出集的广泛范围中抽取，防止索引聚类攻击。

**安全性提升。** 在四条 VRE 规则下，有效匿名集是可证明有下界的。没有 VRE 时，所有诱饵来自高度 $h$ 的交易有效匿名度 $\leq 1$。有 VRE-1 至 VRE-4 时，最小有效匿名度为：

$$A_{\text{eff}} \geq \lceil 3n/4 \rceil = 12 \text{ （当 } n=16\text{）}$$

且诱饵保证跨越多个年龄带和全局输出空间的最小比例。

**现有隐私币均不提供共识层面的环匿名质量保证。**

### 加密钱包存储

包含主种子和密钥材料的钱包文件受密码加密保护：

1. **KDF：** 使用随机 32 字节盐的 100,000 轮迭代 blake3 哈希
2. **流密码：** blake3 带密钥 XOF 流模式
3. **MAC：** 对密文的 blake3 带密钥哈希（加密后 MAC）
4. **格式：** `[salt:32] [mac:32] [ciphertext:N]`

错误密码在任何解密尝试之前通过 MAC 验证检测。

### 内存安全的密钥管理

- `DerivedKeys` 在丢弃时通过自定义 `Drop` 实现自动归零秘密标量
- `MasterKey` 派生 `Zeroize` 带丢弃语义
- `OwnedNote` 省略 `Debug` 以防止意外记录花费密钥
- `ViewKey` 和 `SpendKey` 派生 `Zeroize` 带丢弃语义

## 经济模型

### 洛伦兹连续衰减 (LCD) 发行模型

Hyphen 使用新颖的**洛伦兹连续衰减**发行模型，替代离散减半：

$$R(h) = R_{\text{tail}} + (R_0 - R_{\text{tail}}) \cdot \frac{c^2}{h^2 + c^2}$$

| 参数 | 值 |
| --- | --- |
| 初始奖励 ($R_0$) | 每块 100 HPN |
| 尾部发行 ($R_{\text{tail}}$) | 每块 0.6 HPN（永久） |
| 衰减常数 ($c$) | 1,048,576 块（$2^{20}$，按 60 秒/块约为 2 年） |
| 中点 ($h = c$) | 每块 ≈ 50.3 HPN |
| 总有限供应量 | ≈ 1.64 亿 HPN |
| 尾部发行速率 | ≈ 每年 315,000 HPN |
| 手续费销毁 | 50% 销毁，50% 给矿工 |
| 原子单位 | 1 HPN = $10^{12}$ 原子单位 |

**特性：**
- 平滑、连续、无限可微 — 没有离散减半事件
- $R(0) = R_0 = 100$ HPN（创世区块获得完整初始奖励）
- $R(c) \approx (R_0 + R_{\text{tail}}) / 2 \approx 50.3$ HPN（约 2 年时达到中点）
- $R(\infty) \to R_{\text{tail}} = 0.6$ HPN（永久尾部发行作为矿工激励）
- 总供应量收敛至约 $(R_0 - R_{\text{tail}}) \cdot c \cdot \pi / 2 \approx 1.64\text{亿}$ HPN

## 共识参数

| 参数 | 主网 | 测试网 |
| --- | --- | --- |
| 出块时间 | 60 秒 | 30 秒 |
| 难度窗口 | 60 块 | 30 块 |
| 难度钳位 | 3× 上/下 | 3× 上/下 |
| 最大叔块数 | 2 | 2 |
| 最大叔块深度 | 7 | 7 |
| 环大小 | 16 | 4 |
| 最小环跨度 (VRE-1) | 100 块 | 20 块 |
| 最小不同高度 (VRE-2) | ⌈3n/4⌉ | ⌈3n/4⌉ |
| 最小年龄带数 (VRE-3) | 3 | 2 |
| 年龄带宽度 (VRE-3) | 2048 块 | 128 块 |
| 最小索引跨度 (VRE-4) | 500 基点 (5%) | 300 基点 (3%) |
| TERA 纪元容忍度 | ±2 纪元 | ±4 纪元 |
| MSE γ | 100 基点 (0.10) | 100 基点 (0.10) |
| MSE 下限 | 8000 基点 (0.80×) | 8000 基点 (0.80×) |
| MSE 上限 | 12000 基点 (1.20×) | 12000 基点 (1.20×) |
| 纪元长度 | 2048 块 | 2048 块 |
| 时间戳未来限制 | 120,000 毫秒 | 60,000 毫秒 |
| Arena 大小 | 2 GiB | 64 MiB |
| Scratchpad 大小 | 8 MiB | 256 KiB |
| PoW 轮数 | 1024 | 64 |
| 最大区块大小 | 2 MiB | 2 MiB |

### 网络端口

| 端口 | 用途 |
| --- | --- |
| 18333 | 主网 P2P 和 RPC |
| 20333 | 主网节点发现 (UDP) |
| 38333 | 测试网 P2P 和 RPC |
| 20334 | 测试网节点发现 (UDP) |
| 3350 | 模板提供者（节点 → 矿池）|
| 3340 | 矿池协议（矿池 → 矿工）|
| 3333 | Stratum V1 JSON-RPC |
| 8080 | 内置区块浏览器 HTTP |

默认种子/RPC 域名：`bytesnap.tech`

## 独立挖矿架构

Hyphen 采用严格的节点 / 矿池 / 矿工三层分离。挖矿侧程序刻意不加入根 `Cargo.toml` 的 workspace，也不继承主工程的 `workspace.dependencies`。

```
节点（模板提供者 :3350，浏览器 :8080，P2P :18333/:38333）
  ↕  TP 协议（长度前缀 protobuf over TCP）
独立矿池服务器（:3340）
  ↕  矿池协议（长度前缀 protobuf over TCP）
独立矿工 — CPU (hyphen-miner) 和/或 GPU (hyphen-miner-gpu)
```

挖矿协议包含基于算力的初始难度协商：矿工在登录时报告线程数和估计算力，矿池据此计算合适的起始 share 难度。

节点负责区块链与内存池。矿池从节点拉取模板、构建矿工任务、本地校验 share，只有当 share 达到区块难度时才向节点提交完整区块。矿工只与矿池通信，不链接主节点核心 crate。

### TP 消息解复用器

矿池的 Template Provider 客户端通过单条 TCP 连接同时进行请求-响应协议（get_template、submit_block）和订阅推送（节点推送新模板）。后台解复用任务读取所有入站信封，并按消息类型路由：

- `TP_TEMPLATE (101)` 由节点在订阅后推送 → 转发到订阅通道
- `TP_SUBMIT_RESULT (103)`、`TP_DECLARE_JOB_RESULT (105)` → 匹配到对应的待处理请求-响应 oneshot 发送端

这消除了推送模板被误当做 submit_block 响应消费（或反之）的竞态条件，该竞态会产生"expected type X, got Y"错误。

当矿工提交达到区块难度的 share 后，矿池立即向节点提交区块并请求新模板，然后将新任务分发给所有连接的矿工，确保他们在正确的高度上挖矿。

这两个独立程序位于 `hyphen-pool/` 和 `hyphen-miner/`。它们各自具备自己的清单文件、自己的 crates.io 依赖集合，以及本地实现的区块/区块头兼容层、信封签名、难度目标、arena 生成和 HyphenPoW 求值逻辑。

## 构建

### 前置条件

- Rust 1.75+（edition 2021）
- 可用的 C/C++ 工具链，用于原生依赖编译
- Windows 环境推荐安装 MSVC Build Tools
- Linux 环境推荐安装 `build-essential`、`pkg-config` 以及较新的 GCC/Clang

### 已验证的构建命令

下面所有命令都与当前仓库的真实结构一致。

```bash
# 核心工作区（链、节点、钱包后端、共识、RPC 等）
cargo build --manifest-path Cargo.toml --workspace --release

# 可选：工作区测试
cargo test --manifest-path Cargo.toml --workspace

# 工作区 lint
cargo clippy --manifest-path Cargo.toml --workspace -- -W clippy::all

# 浏览器库 crate
cargo build --manifest-path Cargo.toml -p hyphen-explorer --lib --release
cargo clippy --manifest-path Cargo.toml -p hyphen-explorer --all-targets -- -W clippy::all

# 独立矿池
cargo build --manifest-path hyphen-pool/Cargo.toml --release
cargo clippy --manifest-path hyphen-pool/Cargo.toml -- -W clippy::all

# 独立矿工
cargo build --manifest-path hyphen-miner/Cargo.toml --release
cargo clippy --manifest-path hyphen-miner/Cargo.toml -- -W clippy::all

# 独立 GPU 矿工（需要 Vulkan/DX12/Metal SDK）
cargo build --manifest-path hyphen-miner-gpu/Cargo.toml --release
cargo clippy --manifest-path hyphen-miner-gpu/Cargo.toml -- -W clippy::all
```

## 运行总览

Hyphen 完整挖矿部署需要 3 个进程（区块浏览器已内置于节点中）：

1. `hyphen-node`：全节点，负责 P2P、链状态、本地数据库、模板提供接口、内置 HTTP 区块浏览器（端口 8080）
2. `hyphen-pool-server`：矿池，连接节点模板接口并向矿工分发工作
3. `hyphen-miner`：CPU 矿工，连接矿池
4. `hyphen-miner-gpu`：（可选）GPU 矿工，使用与 CPU 矿工相同的协议连接矿池

### 内置区块浏览器

区块浏览器现已**由 `hyphen-explorer` 库 crate 提供，并默认由 `hyphen-node` 承载运行**。节点启动后自动在 `--explorer_bind`（默认 `0.0.0.0:8080`）提供浏览器界面和 API。

在节点运行时访问 `http://<节点IP>:8080/` 即可实时浏览区块链。

`hyphen-explorer` 不再维护单独的 `main.rs` 可执行入口。浏览器的数据库所有权、监听地址、生命周期与关闭流程统一由 `hyphen-node` 管理，而可复用的 HTTP 路由与处理逻辑保留在 `hyphen-explorer` 库中。

## CLI 参数总表

### 全节点：`hyphen-node`

以下参数来自真实命令 `cargo run --manifest-path Cargo.toml -p hyphen-node -- --help`：

```text
Usage: hyphen-node.exe [OPTIONS]

Options:
  --data-dir <DATA_DIR>            [default: hyphen_data]
  --network <NETWORK>              [default: testnet]
  --listen <LISTEN>                P2P 监听 multiaddr（默认从链配置读取 /ip4/0.0.0.0/tcp/<port>）
  --boot-nodes <BOOT_NODES>        [default: ""]
  --template-bind <TEMPLATE_BIND>  [default: 0.0.0.0:3350]
  --explorer_bind <EXPLORER_BIND>  [default: 0.0.0.0:8080]
```

参数含义：

- `--data-dir`：节点使用的 sled 链数据库目录
- `--network`：`mainnet` 或 `testnet`；当前代码中只对 `mainnet` 做特殊处理，其他值都会回退到 testnet
- `--listen`：libp2p 入站监听 multiaddr；默认使用链配置端口（主网：18333，测试网：38333）
- `--boot-nodes`：逗号分隔的 libp2p multiaddr 字符串，必须包含 `/p2p/<peer_id>`
- `--template-bind`：供矿池连接的 Template Provider TCP 地址
- `--explorer_bind`：内置区块浏览器 HTTP 绑定地址

### 矿池：`hyphen-pool-server`

以下参数来自真实命令 `cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- --help`：

```text
Usage: hyphen-pool-server.exe [OPTIONS] [COMMAND]

Commands:
  keygen

Options:
  --node <NODE>                              [default: 127.0.0.1:3350]
  --bind <BIND>                              [default: 0.0.0.0:3340]
  --stratum-bind <STRATUM_BIND>              [default: 0.0.0.0:3333]
  --api-bind <API_BIND>                      [default: 0.0.0.0:8081]
  --share-difficulty <SHARE_DIFFICULTY>      [default: 100]
  --network <NETWORK>                        [default: testnet]
  --pool-id <POOL_ID>                        [default: hyphen-pool/0.1]
  --key-file <KEY_FILE>                      [default: ""]
  --standalone
  --data-dir <DATA_DIR>                      [default: data]
  --pool-state-dir <POOL_STATE_DIR>          [default: pool_state]
  --no-stratum
  --no-api
  --payout-mode <PAYOUT_MODE>                [default: solo] [possible values: solo, prop, pps, pplns, pps+, fpps]
  --pool-fee-bps <POOL_FEE_BPS>
  --pplns-window-factor <PPLNS_WINDOW_FACTOR> [default: 2]
  --pool-wallet <POOL_WALLET>                [default: ""]
```

参数含义：

- `--node`：全节点暴露出来的 Template Provider 地址
- `--bind`：矿工 protobuf 协议监听地址
- `--stratum-bind`：Stratum V1 JSON-RPC 监听地址
- `--api-bind`：供钱包与外部面板读取矿池账本的 HTTP API 监听地址
- `--share-difficulty`：矿工提交 share 的目标难度
- `--network`：`mainnet` 或 `testnet`；当前实现中非 `mainnet` 都回退到 testnet
- `--pool-id`：矿池向矿工广播的池标识字符串
- `--key-file`：矿池签名身份使用的 32 字节原始 Ed25519 私钥文件
- `--standalone`：矿池自己带内部链状态，不连接外部全节点
- `--data-dir`：仅在 `--standalone` 模式下使用的数据目录
- `--pool-state-dir`：矿工账本、待结算余额、最近结算记录与矿池会计状态的持久化目录
- `--no-stratum`：关闭 Stratum JSON-RPC 接口
- `--no-api`：关闭矿池会计 HTTP API
- `--payout-mode`：矿池分配模式，支持 `solo`、`prop`、`pps`、`pplns`、`pps+`、`fpps`
- `--pool-fee-bps`：显式指定矿池费率，单位为基点；若不填写，`SOLO` 默认 `0`，其他共享收益模式默认 `100`（1%）
- `--pplns-window-factor`：PPLNS 窗口系数，按当前区块难度倍数计算
- `--pool-wallet`：接收区块奖励的钱包地址 — 支持 `hy1...` Hyphen 地址格式（base58 解码、校验和验证、自动提取花费公钥）或 32 字节公钥的 64 位十六进制字符串

### 矿池分配语义与钱包显示

Hyphen 现在在钱包里明确区分两类挖矿收益：

- 链上挖矿收益：已经上链记账到矿工收益地址的奖励，对应浏览器接口 `/api/miner/{pubkey}/rewards`
- 矿池待结算余额：矿池内部账本中已经赚取、但尚未执行链上付款的余额，对应矿池接口 `/api/pool/wallet/{wallet}/balance`

不同分配模式的行为如下：

- `SOLO`：区块奖励直接打到矿工收益钱包，因此区块一旦上链，浏览器和钱包都能看到这笔链上收益
- `PROP`、`PPS`、`PPLNS`、`PPS+`、`FPPS`：区块奖励先打到矿池钱包，矿工收益先记入 `pool_state` 内部账本；钱包通过矿池 API 展示“待结算余额”，直到矿池运营方真正发起链上结算交易

这个区分是生产级正确行为，不是演示逻辑：“待结算余额”不等于“已经可花费的链上余额”。只有矿池实际把款项打到矿工钱包后，矿工的钱包可花费余额才会增加。

钱包现在会同时聚合两类挖矿活动来源：

- 来自浏览器的已确认活动：`/api/miner/{pubkey}/rewards` 与 `/api/miner/{pubkey}/blocks?limit=<n>`
- 来自矿池账本的奖励活动：`/api/pool/wallet/{wallet}/balance` 返回的最近奖励事件，用来展示矿池已经把找到的区块结算到哪个钱包账本上

“矿池钱包地址”和“矿工钱包地址”相同的情况也做了明确处理：

- 在 `SOLO` 模式下，这仍然视为矿工自己的直接链上区块奖励
- 在共享收益模式下，钱包不会把矿池运营钱包收到的 coinbase 回款误判成矿工已经到账的个人奖励；这部分会单独显示为 pool coinbase receipt，而矿工真正应得的金额仍以矿池账本为准

这样可以避免“同一个地址既做矿池收款地址又做矿工收益地址”时出现重复记账或重复显示的问题。

矿池 API 约定：

- 健康检查：`GET /healthz`
- 矿池元信息：`GET /api/pool/info`
- 钱包维度聚合账本：`GET /api/pool/wallet/{wallet}/balance`

钱包余额接口现在还会返回以下生产级字段：

- `is_pool_wallet`：当前查询的钱包是否就是矿池配置的 coinbase 收款钱包
- `direct_coinbase_mode`：当前分配模式是否直接把区块奖励打给矿工，而不是先打给矿池钱包
- `recent_blocks`：最近区块结算记录，包含奖励接收方和是否 direct coinbase
- `recent_reward_events`：按钱包维度整理后的最近奖励事件

其中 `{wallet}` 支持 `hy1...` 地址或 64 位十六进制公钥。返回结果会把所有结算到同一个收益钱包的矿工身份聚合到一起。

### 主网上线部署说明

对于 `PROP`、`PPS`、`PPLNS`、`PPS+`、`FPPS` 这类共享收益矿池，主网上线时至少要同时满足以下条件：

1. 启动 `hyphen-pool-server` 时正确配置 `--payout-mode`、`--pool-wallet`，并按需配置 `--pool-fee-bps`、`--pplns-window-factor`、`--api-bind`、`--pool-state-dir`。
2. 让矿池会计 API 对钱包可达。可以直接公开，也可以放在你自己的反向代理或鉴权网关后面，但钱包必须能通过 HTTP 读到待结算余额。
3. 在 Hyphen 钱包里配置 `Pool API Endpoint`。如果留空，钱包会根据 RPC 主机自动推导，并默认使用 `8081` 端口。
4. 运行真实的结算流程，把矿池内部待结算余额转换成链上付款交易。否则钱包会正确显示待结算金额，但这些金额不会变成用户可花费余额。
5. 备份 `pool_state/`。在非 `SOLO` 模式下，它是矿工待结算余额、最近区块结算记录和矿池账务历史的真实来源。

### 生产环境下的难度同步与拒绝率控制

现在的矿工/矿池链路不再只在登录时协商一次难度，而是整个会话期间持续同步：

- 矿工登录时会上报估计算力，矿池可据此给出更合理的起始 share 难度
- 矿工每 5 秒上报一次 hashrate，并每 15 秒发送一次 keepalive
- 矿池既可以根据 accepted share 的 VarDiff 统计调难度，也可以根据矿工主动上报的 hashrate 直接重定向 share 难度
- 每次矿池下发新难度时，都会同时发送 `MSG_SET_DIFFICULTY` 和一个全新的 clean `MSG_JOB`，避免矿工继续拿旧任务和旧 share target 挖
- 矿工线程现在会在“任务更新”或“难度代际变化”任一发生时中断当前 batch，从而降低启动阶段和调难度后的 stale share / reject

运维建议：

- 不要因为 accepted share 很多就忽略启动阶段 reject，启动时 reject 偏高通常说明难度同步滞后或 batch 过大
- `--batch-size` 不要盲目调大。默认 `100000` 只是吞吐与响应延迟之间的折中，不是所有机器上的最优值
- 矿工和矿池之间要保持稳定长连接。实时难度更新依赖持续在线的 TCP 会话，而不是频繁重连

### 矿工：`hyphen-miner`

以下参数来自真实命令 `cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- --help`：

```text
Usage: hyphen-miner.exe [OPTIONS] [COMMAND]

Commands:
  keygen

Options:
  --pool <POOL>                              [default: 127.0.0.1:3340]
  --threads <THREADS>                        [default: 0]
  --network <NETWORK>                        [default: testnet]
  --key-file <KEY_FILE>                      [default: ""]
  --user-agent <USER_AGENT>                  [default: hyphen-miner/0.1]
  --batch-size <BATCH_SIZE>                  [default: 100000]
  --wallet-address <WALLET_ADDRESS>          [default: ""]
```

参数含义：

- `--pool`：矿池 protobuf 地址
- `--threads`：工作线程数；`0` 表示自动检测逻辑 CPU 数量
- `--network`：`mainnet` 或 `testnet`；当前实现中非 `mainnet` 都回退到 testnet
- `--key-file`：矿工签名身份使用的 32 字节原始 Ed25519 私钥文件
- `--user-agent`：登录时上报给矿池的 UA 字符串
- `--batch-size`：每批 nonce 计算量
- `--wallet-address`：矿工收益接收地址，支持 `hy1...` Hyphen 地址（BIP44，校验和验证，自动提取 spend 公钥）或 32 字节公钥的 64 位十六进制字符串；若省略，则默认使用矿工签名公钥作为收益目标

和生产调优直接相关的当前运行行为：

- 矿工会保持与矿池的持续连接，而不是只拉一次任务就本地长时间闷头挖
- 矿工会持续测量本地算力，并每 5 秒把结果上报给矿池
- 矿池可以在会话中途主动调整难度，矿工收到后会立刻中断当前 nonce batch
- 当暂时没有 job 时，矿工也会更快重新检查任务，缩短重连后的冷启动时间

### GPU 矿工：`hyphen-miner-gpu`

```text
Usage: hyphen-miner-gpu.exe [OPTIONS] [COMMAND]

Commands:
  keygen
  list-gpus

Options:
  --pool <POOL>                              [default: 127.0.0.1:3340]
  --network <NETWORK>                        [default: testnet]
  --key-file <KEY_FILE>                      [default: ""]
  --user-agent <USER_AGENT>                  [default: hyphen-gpu-miner/0.1]
  --gpu-device <GPU_DEVICE>
  --backend <BACKEND>                        [default: auto]
  --batch-size <BATCH_SIZE>
  --wallet-address <WALLET_ADDRESS>          [default: ""]
```

参数含义：

- `--gpu-device`：从 `list-gpus` 输出中选择的 0 基索引适配器编号；省略则自动选择（优先离散 GPU）
- `--backend`：指定图形 API — `vulkan`（NVIDIA/AMD/Intel/摩尔线程，Linux/Windows/Android）、`dx12`（Windows）、`metal`（macOS/iOS）、`gl`（OpenGL ES 兼容模式）、`auto`（全部尝试）
- `--batch-size`：每次 GPU 调度的 nonce 数量；省略则根据显存容量自动计算

**支持的 GPU 厂商与后端：**

| 厂商 | Vulkan | DX12 | Metal | OpenGL ES |
| --- | --- | --- | --- | --- |
| NVIDIA (GeForce/Quadro/Tesla) | 支持 | 支持 (Windows) | — | — |
| AMD (Radeon/RX) | 支持 | 支持 (Windows) | — | — |
| Intel (Arc/Iris/UHD) | 支持 | 支持 (Windows) | — | 支持 |
| Apple (M1/M2/M3/M4) | — | — | 支持 | — |
| Qualcomm Adreno (Android) | 支持 | — | — | 支持 |
| ARM Mali (Android) | 支持 | — | — | 支持 |
| 摩尔线程 (MTT S 系列) | 支持 | — | — | — |

**架构：** GPU 矿工采用混合 CPU/GPU 架构：
1. Arena 生成和 scratchpad 种子在 CPU 上运行（Blake3 XOF）
2. PageWeave 12 内核求解循环在 GPU 上通过 WGSL 计算着色器运行
3. Blake3 带密钥哈希最终化和目标比较在 GPU 回读后于 CPU 上执行

这种设计确保在相同硅片预算下 CPU 挖矿效率高于 GPU — GPU 仅处理可并行化的求解循环，而 CPU 处理无法在 WGSL 中高效并行化的顺序 Blake3 最终化。

### 浏览器库：`hyphen-explorer`

`hyphen-explorer` 现在是库 crate，而不是面向终端用户的二进制程序。它导出供 `hyphen-node` 使用的浏览器路由和服务启动函数。

当前集成契约：

- `hyphen-node` 持有 sled 数据库与 `Blockchain` 句柄
- `hyphen-node` 通过 `--explorer_bind` 暴露浏览器 HTTP 监听地址
- `hyphen-explorer` 以 Rust 库代码形式提供可复用的 UI/API 实现

## 密钥生成

### 推荐方式：使用内置 keygen 子命令

生成矿池密钥：

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- keygen --output pool.key
```

生成矿工密钥：

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- keygen --output miner.key
```

生成 GPU 矿工密钥：

```bash
cargo run --manifest-path hyphen-miner-gpu/Cargo.toml --bin hyphen-miner-gpu -- keygen --output miner-gpu.key
```

这些命令会打印对应公钥的十六进制字符串。若你后续要把该公钥作为收益目标或身份标识，请把输出保存好。

### 文件格式要求

`pool.key` 和 `miner.key` 都必须是 **恰好 32 字节的原始二进制文件**，不是 PEM，不是十六进制文本，不是 JSON。

## 钱包地址 / 收益地址规则

这一节对矿工和矿池都非常关键，必须理解正确。

### `--wallet-address` 和 `--pool-wallet` 实际要求的内容

支持以下**两种格式之一**：

**格式 A：`hy1...` Hyphen 地址**（推荐）

- 以 `hy1` 开头的标准 Hyphen 钱包地址
- Base58 编码载荷：`version[1] | view_public[32] | spend_public[32] | blake3_checksum[4]`
- 矿池/矿工会自动验证 blake3 校验和并提取 32 字节 spend 公钥
- 这就是 Hyphen 钱包应用中显示的地址格式

示例：

```text
hy1<base58 编码的 69 字节载荷>
```

**格式 B：64 个十六进制字符**（原始公钥）

- **32 字节公钥**
- 以 **64 个十六进制字符** 编码
- **不带 `0x` 前缀**
- **中间不能有空格、逗号或额外引号**

示例：

```text
6f8d7c4d1b2a...<总长度 64 个 hex 字符>...99aabbccddeeff00
```

### 哪些内容不是合法值

以下内容都不能作为 `--wallet-address` 或 `--pool-wallet`：

- 助记词
- 密码
- `wallet.dat` 之类的路径
- 32 字节私钥
- 长度不是 64 个 hex 字符的字符串
- 校验和无效的 `hy1` 地址

### 当前代码中的收益行为

- 如果矿工省略 `--wallet-address`，矿工会把自己的签名公钥作为 `payout_pubkey`
- 如果矿池省略 `--pool-wallet`，矿池会把自己的签名公钥作为区块奖励接收公钥

### 生产环境建议

生产环境请显式设置以下两个参数：

- 矿池设置 `--pool-wallet`
- 每个矿工设置 `--wallet-address`

这样可以避免收益误发到临时身份公钥或基础设施签名公钥上。

## 已验证的启动命令

### A. 仅启动测试网全节点

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

### B. 仅启动主网全节点

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network mainnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

### C. 带启动节点的测试网全节点

`--boot-nodes` 必须是包含 `/p2p/<peer_id>` 的完整 libp2p multiaddr，并且使用逗号分隔，例如：

```text
/ip4/203.0.113.10/tcp/38333/p2p/12D3KooWExamplePeerA,/ip4/203.0.113.11/tcp/38333/p2p/12D3KooWExamplePeerB
```

启动命令如下：

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "/ip4/203.0.113.10/tcp/38333/p2p/12D3KooWExamplePeerA,/ip4/203.0.113.11/tcp/38333/p2p/12D3KooWExamplePeerB" \
  --template-bind 0.0.0.0:3350
```

### D. 矿池连接全节点运行

推荐测试网命令（使用 Hyphen 钱包应用中的 `hy1...` 地址）：

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet hy1YourWalletAddressFromTheApp
```

或使用 64 个十六进制字符的原始公钥：

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

如果你希望区块奖励默认跟随矿池签名公钥，可以删除 `--pool-wallet` 参数。

### E. 矿池 standalone 模式

该模式 **不会连接全节点**，而是在矿池内部维护自己的链状态。

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --standalone \
  --data-dir pool_data \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

只有在你明确需要 standalone 时才使用该模式。若你要做真实的“节点 + 矿池”流程，就不要加 `--standalone`。

### F. 矿工连接矿池运行

推荐测试网命令，使用 `hy1...` 钱包地址：

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address hy1YourWalletAddressFromTheApp
```

或使用 64 个十六进制字符的原始公钥：

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

### G. 主网 release 形式启动命令

先编译：

```bash
cargo build --manifest-path Cargo.toml --workspace --release
cargo build --manifest-path Cargo.toml -p hyphen-explorer --lib --release
cargo build --manifest-path hyphen-pool/Cargo.toml --release
cargo build --manifest-path hyphen-miner/Cargo.toml --release
cargo build --manifest-path hyphen-miner-gpu/Cargo.toml --release
```

启动节点：

```bash
./target/release/hyphen-node \
  --data-dir hyphen_data \
  --network mainnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

启动矿池：

```bash
./hyphen-pool/target/release/hyphen-pool-server \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network mainnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

启动矿工：

```bash
./hyphen-miner/target/release/hyphen-miner \
  --pool 127.0.0.1:3340 \
  --threads 16 \
  --network mainnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

## 区块浏览器使用方式

### 正确且受支持的启动流程

1. 使用目标 `--data-dir` 和 `--network` 启动 `hyphen-node`
2. 保持默认内置浏览器启用，或者通过 `--explorer_bind` 覆盖监听地址
3. 在浏览器中打开节点的 explorer HTTP 地址

### 测试网浏览器命令

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --template-bind 0.0.0.0:3350 \
  --explorer_bind 127.0.0.1:8080
```

然后访问：

```text
http://127.0.0.1:8080/
```

### 主网浏览器命令

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network mainnet \
  --template-bind 0.0.0.0:3350 \
  --explorer_bind 0.0.0.0:8080
```

### 浏览器提供的接口

- `/`：网页界面
- `/api/info`：链高度、供应量、奖励、epoch 信息
- `/api/updates?since=<height>`：轻量轮询接口，用于首页在新区块出现时自动刷新
- `/api/blocks?page=0&limit=20`：最近区块列表
- `/api/block/<height_or_hash>`：完整区块详情
- `/api/tx/<tx_hash>`：交易所在区块位置
- `/api/miner/<pubkey>/rewards`：某个矿工收益公钥的已确认挖矿奖励聚合结果
- `/api/miner/<pubkey>/blocks?limit=<n>`：某个矿工收益公钥最近挖到的区块
- `/api/search?q=<term>`：区块/交易搜索

内置浏览器首页现在会自动轮询 `/api/updates`，因此节点接收到新区块后，首页会自动刷新，不需要手工重载。矿工奖励查询也不再是每次请求都全链扫描，而是通过增量更新的内存索引提供，避免随着区块高度增长而越来越慢。

### 浏览器正确运行的必要条件

想要浏览器显示正确内容，必须满足：

- `--data-dir` 必须指向由节点持有的目标数据库目录
- `--network` 必须和要服务的链网络一致
- `--explorer_bind` 必须对你的浏览器可达

否则就会出现链错误、连不上服务、或者监听在错误地址上的问题。

## 本地测试网完整流程

这是最适合本地验证的一套完整顺序。

### 第 1 步：生成密钥

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- keygen --output pool.key
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- keygen --output miner.key
```

### 第 2 步：启动全节点

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350 \
  --explorer_bind 0.0.0.0:8080
```

### 第 3 步：启动矿池

请把下面的 `--pool-wallet` 替换成钱包应用中的 `hy1...` 地址或 64 个十六进制字符的公钥。

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet hy1YourWalletAddressFromTheApp
```

### 第 4 步：启动矿工

请把下面的 `--wallet-address` 替换成钱包应用中的 `hy1...` 地址或 64 个十六进制字符的公钥。

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address hy1YourWalletAddressFromTheApp
```

### 第 5 步：打开内置浏览器

保持第 2 步中的节点持续运行，然后直接打开 `http://127.0.0.1:8080/`。

## 运行注意事项

### 节点启动链路

- 节点通过 `--template-bind` 暴露 Template Provider
- 矿池通过 `--node` 连接该接口
- 矿工通过 `--pool` 连接矿池

### 线程行为

- 矿工的 `--threads 0` 表示自动检测可用并行度
- 如果你要做稳定基准测试，请显式设置线程数

### 网络选择行为

当前所有二进制都只对 `mainnet` 做专门处理，否则回退到 `testnet`。为了避免误操作，实际运行时请始终显式传 `mainnet` 或 `testnet`。

### 密钥持久化行为

如果省略 `--key-file`：

- 矿池会为当前进程生成临时签名密钥
- 矿工会为当前进程生成临时签名密钥

这适合快速测试，不适合正式生产身份。

## 故障排查

### 浏览器提示打不开数据库

原因：节点仍然占用 sled 数据库，或者 `--data-dir` 填错。

处理方法：

1. 干净停止节点
2. 确认浏览器的 `--data-dir` 与节点完全一致
3. 重新启动浏览器

### 矿工能启动，但收益发错地址

原因：`--wallet-address` 没填或者填错。

处理方法：

1. 确认该值是有效的 `hy1...` 钱包地址或 64 个十六进制字符的公钥
2. 用正确的 `--wallet-address` 重启矿工

### 矿池能启动，但区块奖励发错地址

原因：`--pool-wallet` 没填或者填错。

处理方法：

1. 确认该值是有效的 `hy1...` 钱包地址或 64 个十六进制字符的公钥
2. 用正确的 `--pool-wallet` 重启矿池

### 矿池连不上节点

原因：节点没启动，或 `--template-bind` 与矿池的 `--node` 不一致。

处理方法：

1. 确认节点日志中已经输出 Template Provider 正在监听的地址
2. 在矿池 `--node` 中填写完全相同的地址

### 启动节点配置的 boot nodes 无效

原因：`--boot-nodes` 必须是包含 `/p2p/<peer_id>` 的完整 libp2p multiaddr。

处理方法：使用逗号分隔的完整 peer multiaddr，不要只写裸 IP:port。

## 项目结构

```
Hyphen/
├── Cargo.toml
├── src/lib.rs
├── crates/
│   ├── hyphen-crypto/      # 环签名、隐身地址、后量子签名
│   ├── hyphen-core/        # 区块类型、配置、NTP 时间戳
│   ├── hyphen-pow/         # HyphenPoW（12 内核、arena、难度）
│   ├── hyphen-proof/       # Bulletproofs 范围证明
│   ├── hyphen-tx/          # 隐蔽 UTXO 交易
│   ├── hyphen-token/       # 多资产发行
│   ├── hyphen-economics/   # 发行与手续费
│   ├── hyphen-state/       # 持久化存储
│   ├── hyphen-consensus/   # 验证 + 链 + 叔块
│   ├── hyphen-mempool/     # 交易池
│   ├── hyphen-wallet/      # 钱包 + ICD 派生
│   ├── hyphen-network/     # libp2p P2P
│   ├── hyphen-transport/   # Template Provider 协议（节点-矿池）
│   ├── hyphen-vm/          # 智能合约 VM
│   ├── hyphen-rpc/         # JSON-RPC
│   └── hyphen-node/        # 全节点二进制
│   ├── hyphen-explorer/    # 由 hyphen-node 调用的浏览器库 crate
├── hyphen-pool/            # 独立矿池服务器（独立 Cargo 项目）
├── hyphen-miner/           # 独立 CPU 矿工（独立 Cargo 项目）
├── hyphen-miner-gpu/       # 独立 GPU 矿工（wgpu 多厂商，独立 Cargo 项目）
└── hyphen_wallet/          # 跨平台 Flutter 钱包应用
```

## Hyphen 钱包应用

`hyphen_wallet/` 目录包含跨平台 Flutter 钱包应用，通过 `flutter_rust_bridge` 连接 Rust 后端。

### 功能

- **优先支持平台** — 当前优先维护 Windows、Android、Linux、macOS 四个平台；iOS/Web 仍为次级目标
- **轻节点 / 全节点模式** — 创建钱包时选择轻节点（通过 bytesnap.tech 远程 RPC）或全节点（本地区块链同步含内置浏览器）；可在设置中随时切换
- **抗量子 BIP39 口令** — 钱包密码经 WOTS+ 哈希链变换（67 条链 × 15 步）后用作 BIP39 口令，提供助记词派生的后量子硬化
- **多钱包管理** — 在单个应用内创建、导入、重命名、切换和删除多个钱包
- **7 种语言国际化** — 英语、中文、德语（Deutsch）、法语（Français）、西班牙语（Español）、意大利语（Italiano）、日语（日本語）
- **量子抗性安全** — WOTS+ 混合签名、基于 blake3-XOF 的流式加密加上 encrypt-then-MAC 钱包存储、blake3 10 万轮 KDF
- **ICD 密钥派生** — 基于 Ristretto255 Pedersen 承诺的 BIP44 兼容密钥树
- **隐身地址** — 一次性输出密钥与 view tag 扫描
- **私密转账** — 完整的隐蔽交易流水线：通过 RPC 扫描区块链输出、从节点输出索引获取诱饵输出（GET_RANDOM_OUTPUTS）构建 CLSAG 环签名、通过 GET_OUTPUT_INFO 进行发送前输出预验证、签名后 CLSAG 自验证、Bulletproofs 范围证明、bincode 序列化并提交交易到内存池；贪心输入选择与自动找零输出生成；已花费输出追踪与成功发送后自动 UTXO 缓存失效
- **NFC 无接触** — 通过 NFC 触碰分享钱包地址，Android 支持完整 NFC，iOS 支持 NDEF/TAG 读取会话（已配置 entitlements）；使用 `nfc_manager` 3.5.0，已包含 Kotlin 2.2 兼容性处理
- **生物识别认证** — 通过 `local_auth` 2.3.0 支持指纹和 Face ID 解锁；Android 使用 `FlutterFragmentActivity` 以兼容 BiometricPrompt API；助记词查看和交易确认受生物识别保护
- **网络切换** — 在主网和测试网之间切换，自动重新派生地址
- **挖矿收款地址** — 显示钱包 `hy1...` 地址，用于在矿池或矿工配置中作为 `--pool-wallet` 或 `--wallet-address` 的值；支持一键复制
- **收款二维码** — 在收款页面为钱包 `hy1...` 地址生成可扫描的 QR 码，使用 `qr_flutter` 渲染圆角眼型和数据模块样式
- **轻节点连接状态** — 设置页面实时显示到当前 RPC 端点的 TCP 连接状态，支持在可用节点间切换或添加自定义端点
- **Wise 风格 Material Design 3 界面** — 浅绿色调（#9FE870 亮绿、#163300 森林绿）、Inter 字体、圆角表面、动态余额主叡卡片、底部 NavigationBar 四个目的地、操作药丸按钮、矿池信息条
- **可自定义主题色彩** — 六种预设主题色彩方案（Wise Green、Ocean Blue、Royal Purple、Sunset Orange、Rose Pink、Slate Gray）通过设置页面选择；选择结果通过加密存储跨会话持久化；MaterialApp ColorScheme、按钮、导航栏、分段控件和 SnackBar 均跟随所选预设
- **实时余额更新** — 钱包余额每 10 秒通过定时器轮询矿池和浏览器 API 自动刷新；首页支持下拉刷新触发即时数据获取；`Consumer<WalletService>` 响应式重建确保余额主叡卡片、挖矿明细和活动列表始终反映最新数据
- **安全助记词备份** — 24 词 BIP39 助记词，支持显示/隐藏和剪贴板复制
- **3D 动画界面** — 透视倾斜卡片交互和关键页面上的浮动球动画

### 构建钱包

```bash
cd hyphen_wallet
flutter pub get

# 每次修改 Rust API 后重新生成 flutter_rust_bridge Dart 绑定。
flutter_rust_bridge_codegen generate

# 当前仓库使用的静态检查。
flutter analyze

# 在当前宿主平台运行。
flutter run
```

当前优先维护的平台入口：

- Windows：`flutter run -d windows` 或 `flutter build windows`
- Android：`flutter run -d android` 或 `flutter build apk`
- Linux：`flutter run -d linux` 或 `flutter build linux`
- macOS：`flutter run -d macos` 或 `flutter build macos`

平台说明：

- Flutter 应用依赖 `hyphen_wallet/lib/src/rust/` 下的生成绑定；如果该目录缺失，请在 `hyphen_wallet/` 目录执行 `flutter_rust_bridge_codegen generate`。
- Android 发布签名不会提交到仓库。上线前请自行配置 release keystore。
- Linux 构建要求宿主机安装 GTK3 开发包。
- macOS 二进制必须在 macOS 主机上完成构建与签名。

本次更新已执行的仓库检查命令：

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo check --manifest-path hyphen-miner-gpu/Cargo.toml
cd hyphen_wallet && flutter analyze
```

本次更新的验证结果：

- `cargo test --workspace`：通过
- `flutter analyze`：通过
- `cargo clippy --workspace --all-targets`：通过
- `cargo check` (hyphen-miner-gpu)：通过

### 生成应用图标

将 `Hyphen.png` 放在 `assets/images/` 中并运行：

```bash
dart run flutter_launcher_icons
```

## 许可证

AGPL-3.0
