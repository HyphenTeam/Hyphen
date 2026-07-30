# Hyphen 主链

[English](README.md)

Hyphen 是一条用 Rust 编写、面向隐私交易和 CPU 优先工作量证明的实验性主链。这个仓库只负责节点、共识、状态转换、交易验证、P2P、RPC、密码学库、研究机制参考实现和共识测试向量。

`HyphenMiner`、`HyphenPool`、`HyphenWallet` 是三个独立仓库。它们可以为了联调放在主链目录旁边，但有自己的依赖锁、CI、Release 和安全边界。主链协议变化可能要求它们同步升级，不代表它们属于主链仓库。

## 先说清楚现在能做什么

当前 devnet v2 可以构建、运行和复核链身份；交易、区块、状态根、PoW、矿工授权、历史重放和分支切换后端都有测试。项目尚未完成独立密码学/共识审计，也没有长期公开主网。命令行里的 `mainnet` 仍是研究配置，不应承载真实资产。

| 能力 | 当前事实 | 不能据此声称的内容 |
| --- | --- | --- |
| 基础 PoW 主链 | 已接入区块验证与状态提交 | 未证明长期经济安全或主网安全 |
| 隐私交易库 | 有承诺、范围证明、CLSAG、隐身输出与测试 | 未经过外部密码学审计 |
| 分支切换 | 后端可验证候选分支、原子切换、失败恢复 | P2P 自动收集分支和全系统 reorg 对账仍未贯通 |
| H-WES / H-BFM / H-FOC / H-SAC | 有不激活的参考实现和测试向量 | 不能写成已进入 devnet 共识或已完整形式化证明 |
| Useful-Work | 只有研究规范，功能关闭 | 不能写成 AI 挖矿或已提供安全收益 |
| WASM VM | 独立库可测试 | 没有合约交易、区块执行、状态根、回执和 RPC 接线 |

## 构建与启动

本项目在 Rust 1.97.0 和系统 C/C++ 构建工具上测试通过，可使用依赖构建命令如下：

```powershell
cargo build --release --locked -p hyphen-node
```

首次启动或重新使用旧数据库前，先打印链身份：

```powershell
.\target\release\hyphen-node.exe --network devnet --print-chain-identity
```

当前 devnet v2 必须输出：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=bb0c74b93362b8265d65af5dd48796084448e6b3022c39825476ce1b84439902
genesis_hash=854adc605062fb872dcd20a535dca1ec25d4af58689f1be50e6c26df0c841295
```

本地节点示例：

```powershell
.\target\release\hyphen-node.exe `
  --network devnet `
  --data-dir .\data\devnet-node `
  --listen /ip4/127.0.0.1/tcp/48334 `
  --rpc-bind 127.0.0.1:48333 `
  --template-bind 127.0.0.1:3350 `
  --explorer-bind 127.0.0.1:8080
```

浏览器只能访问 Explorer HTTP。RPC、P2P、模板端口都是二进制协议，浏览器空白不是故障。所有命令行参数以当前二进制的 `--help` 为准。

## 主链实际验证了什么

节点接收区块后，会验证网络与共识身份、父块、高度、时间戳、难度、PoW、交易编码、签名、范围证明、nullifier、费用、交易根、状态根、奖励和矿工授权。状态变化采用原子提交，失败不会留下半个新区块。

研究配置中的规范交易排序只解决一个较窄的问题：当矿工声明了交易集合后，节点可以检测排序或内容是否被替换，mempool 也不再用到达顺序打破同优先级冲突。矿工仍可主动遗漏交易，所以这不是“消灭审查”，也不是完整 MEV 方案。

## 研究机制的数学定义与必要证明

下面只证明当前代码真实表达的性质。每一项都把假设、命题和未完成义务分开写，避免把“有一个算法”包装成“整个协议已经安全”。

### 统一符号

定义域分离哈希：

```text
H_d(x) = BLAKE3(d || 0x00 || x).
```

证明使用 `H_d` 的抗碰撞和抗二次原像假设。签名方案使用 EUF-CMA 不可伪造假设。椭圆曲线群使用素数阶 Ristretto255，基点为 `G`，标量域为 `Z_l`，离散对数被假设为困难。这些都是计算安全假设，不是无条件数学真理。

### 一、H-WES：可恢复状态过期为什么不能只靠 MMR

对状态键 `x`，高度 `t` 的最新版认证映射保存：

```text
V_t[x] = (v_t, status_t, j_t, h_value, h_record),
```

其中 `v_t` 是最新版本，`j_t` 是归档 MMR 位置。归档根记为 `A_t`，当前活动状态根、最新版映射根、nullifier 根、归档根和数据可用性根共同进入组合状态根。

恢复见证必须同时证明：

```text
r.key = x
H_record(encode(r)) = V_t[x].h_record
r.version = V_t[x].v_t
V_t[x].status = Expired
r.value_hash = V_t[x].h_value
MMRVerify(A_t, j_t, H_record(encode(r)), pi_archive) = 1
MapVerify(root(V_t), x, V_t[x], pi_latest) = 1.
```

**命题 1：旧版本不可恢复。** 如果最新版映射承诺具有 binding 性，且 `H_record` 抗碰撞、抗二次原像，那么攻击者用 `version < v_t` 的旧记录通过恢复验证的概率可忽略。

**证明。** `pi_latest` 把键 `x` 唯一绑定到根中承诺的元组 `V_t[x]`。验证条件又强制 `r.version = V_t[x].v_t`。旧记录满足 `r.version < v_t`，与等式直接矛盾。若攻击者修改旧记录的版本或内容，同时保持 `h_record` 不变，就构造了 `H_record` 的二次原像或碰撞；若攻击者让同一个映射根对同一个键打开成另一个版本，则破坏认证映射的 binding 性。因此成功只能来自底层假设被攻破，概率可忽略。

这也解释了为什么 MMR inclusion proof 不够：MMR 只能证明“某条记录曾被追加”，不能证明“这是这个键目前最新的记录”。归档证明和最新版证明缺一不可。

但“只靠 append-only archive 一定不可能安全恢复”这个原始说法也过强：恢复者可以在一轮中发送完整 archive，验证者重算 commitment 并线性扫描，因此仍满足常数轮，只是付出 `Theta(N)` 通信和计算。严格下界必须加入 succinctness。对 membership-only 黑盒 archive，候选记录后还有 `m` 个 cell；若 verifier 最多认证查询 `q<m` 个位置，总存在一个未查询位置可分别放置“无关记录”或“同 key 的更新版本”，而 verifier 的已见 transcript 相同。允许漏检概率 `epsilon` 时必须满足：

```text
q >= (1-epsilon)m.
```

所以安全恢复至少承担一项成本：认证 latest state、持续 witness/index 更新，或线性后缀数据/prover 工作。H-WES 选择保留 fixed-size latest root，把 `O(K+N)` tree/body 存储交给可替换 provider，并由恢复交易携带 `O(log K+log N)` 新鲜证明；它没有违反下界。

生命周期严格属于 incarnation `(x,v)`：

```text
Live(x,v) -> Expired(x,v) -> Recovered(x,v; successor=v+1)
                              \-> Consumed(x,v).
```

恢复在同一个线性化点追加终态历史事件并创建 `Live(x,v+1)`；消费没有后继。授权摘要绑定 action、高度、新租期和 pre-state root，旧授权不能被改成另一动作或租期。当前 reference model 已覆盖恢复回执、消费终态和 no-resurrection 负向测试，但仍未接持久 SMT、真实授权、DA、reorg 和 shielded 电路。

对可花费对象，nullifier 集满足单调性：

```text
N_t subseteq N_(t+1).
```

若 `z` 在高度 `i` 已被花费，则 `z in N_i`，所以对所有 `t >= i` 都有 `z in N_t`。恢复转换在当前 `N_t` 中检查并拒绝 `z`，已经花费的对象就不能因过期再生。当前参考配置明确排除 shielded note，因为它还缺少把所有权与 nullifier 非成员证明绑定起来的隐私电路。

**仍未完成：** 数据可用性证书、存储层去中心化激励、状态租金参数、每块过期工作上限、持久化原子接线、隐私所有权电路和长期空间基准。

### 二、H-BFM：必要的规范融合机制，不作为新颖性声明

设一个 epoch 中已达成集合一致的有限有向无环图为 `G_e=(B_e,E_e)`。每一步取当前所有入度为零的区块，并按下面的全序选择最小者：

```text
rank(b) = (parent_frontier_hash(b), producer_key(b), block_hash(b)).
```

将它加入融合序列，再删除它的出边。

**引理 2：固定 DAG 的规范融合序列唯一。**

**证明。** 任意非空有限 DAG 至少存在一个入度为零的顶点，否则从任意顶点不断沿入边回溯，有限性会迫使顶点重复，从而产生环，与 DAG 矛盾。`rank` 是全序，所以所有候选中存在唯一最小者。删除该顶点后仍是有限 DAG。对顶点数做归纳，每一步选择都唯一，并在恰好 `|B_e|` 步后终止。一个顶点只有在全部前驱被删除后才会变成零入度，因此输出满足全部边的拓扑先后关系。

这个引理只证明“相同 DAG 得到相同顺序”。它没有证明全球节点一定拿到相同 DAG。集合一致、数据缺失、双提议、冲突状态访问、奖励分配、反垃圾和活性仍是独立且未完成的问题。代码因此不能声称已经得到成熟 DAG 共识，也不能声称通过换名字绕开已有系统。

真正继续研究的是隐私交易的**可见域公平性**。令共识唯一允许观察的投影为：

```text
M(tx)=(txid, fee_class, encoded_len, public_conflict_tag).
```

seat `i` 签名本地接收序列 `seq_i`。对 `n=3f+1,q=2f+1`，定义

```text
x <_E y iff |{i : pos_i(x)<pos_i(y)}| >= q.
```

两个相反方向不可能同时成立，因为需要 `2q=4f+2>3f+1=n` 个 seat 方向贡献；但长度至少 4 的强多数 cycle 仍可能存在，所以实现把 strongly connected component 作为一个 fair batch，只对 component 间顺序给保证。隐藏金额、地址和语义不进入排序函数，因此也不对它们声称公平。当前参考实现验证 seat 签名、quorum visibility、SCC batch、cutoff 后随机 tie-break 和 CPU 工作上限，尚未接入 mempool、P2P 或区块执行。

### 三、H-FOC：快速排序证书的安全边界

设委员会有 `n=3f+1` 个席位，最多 `f` 个 Byzantine 席位。一个有效排序证书需要 `q=2f+1` 个不同席位的有效签名。对任意两个 quorum `Q_1,Q_2`：

```text
|Q_1 intersect Q_2|
>= |Q_1| + |Q_2| - n
= 2(2f+1) - (3f+1)
= f+1.
```

交集至少有 `f+1` 个席位，而恶意席位至多 `f` 个，所以交集至少包含一个诚实席位。

**定理 3：同上下文冲突证书不可同时成立。** 假设诚实席位对同一个 `(chain_id, epoch, view, slot, parent_frontier)` 最多签一个 `order_root`，签名不可伪造，且恶意席位不超过 `f`。那么两个不同 `order_root` 的有效证书不能同时存在。

**证明。** 两个证书的签名席位集合交集至少包含一个诚实席位。该席位若同时出现在两个不同根的证书中，就必须签署两个冲突 statement，违反诚实投票规则；若它并未签署其中之一，则对应签名是伪造。两种情况都与假设矛盾。

这只给出 safety，不给出无条件 100 ms finality。100 ms 还要求在同步窗口内网络延迟 `Delta`、提议广播、排队、签名生成、聚合和验证总耗时低于预算。异步网络下不存在确定性有界时间共识保证。因此正确表述是“目标为乐观 100 ms 排序证书”，不是“全球几百节点已经在 100 ms 最终确认”。

PoW 委员会从前一 finalized epoch 按工作量有放回抽取 seat。攻击工作份额为 `alpha` 且 seed 不可偏置时，委员会失陷概率为：

```text
P_bad = sum_(i=f+1)^n C(n,i) alpha^i (1-alpha)^(n-i).
```

若矿工可在 `g` 个 seed 中 grinding，只能给出 `P_bad_grind <= min(1,gP_bad)`。固定委员会的 quorum 交集不能自动证明跨 epoch 安全；H-FOC' 还要求旧、新委员会分别对同一 finalized PoW checkpoint 形成 handoff QC，并要求 view change 继承 lock。当前代码没有完整 prepare/commit/view-change/handoff，所以证书仍是非最终 preorder。

**仍未完成：** 委员会捕获概率与工作量分布实测、DoS、view change、超时证书、时钟偏差、跨洲基准、慢路径最终性结合和主链接线。

### 四、H-SAC：可控披露到底证明了什么

交易输出金额承诺为：

```text
C = vG + rH,
```

`v` 是金额，`r` 是随机盲因子，`H` 与 `G` 的离散对数关系未知。单输出披露给出 `(v,r)`，验证者重算等式。

**binding 推导。** 若同一个 `C` 有两个不同 opening `(v,r)` 与 `(v',r')`，则：

```text
vG+rH = v'G+r'H
(v-v')G = (r'-r)H.
```

当 `r != r'` 时，可以由比值求得 `G` 与 `H` 的离散对数关系，违反离散对数困难假设；退化情形同样要求金额相等。因此在该假设下承诺具有计算 binding 性。随机 `r` 则提供 Pedersen 承诺的 hiding 性。

所有权使用 Schnorr 关系。一次性公钥 `P=xG`，证明者随机取 `k`：

```text
R = kG
c = H_challenge(context, R, P)
s = k + cx.
```

验证者检查：

```text
sG = R + cP.
```

完整性来自代入：`sG=(k+cx)G=kG+c(xG)=R+cP`。知识可靠性使用 forking-lemma 模型：若同一 `R` 对两个不同 challenge `c,c'` 都有有效响应 `s,s'`，则可提取

```text
x = (s-s') / (c-c') mod l.
```

所以不知道 `x` 的伪造者会导出离散对数解。当前 context 绑定链 ID、交易 ID、输出位置、全局索引、审计者公钥、scope hash、有效期、随机 nonce、承诺、公钥、金额和盲因子，修改任一字段都会改变 challenge。

当前 disclosure 包本身没有加密，只能通过外部机密信道交付；它只证明某个输出的金额 opening 和一次性密钥所有权，不证明完整资金来源合法，不证明交易图 provenance，也没有聚合审计和撤销协议。把它称为完整“审计密钥”是不准确的。

更一般地，设私有状态为 `X`，公开链信息为 `P`，合规任务输出 `Y=F(X,P)`，adversary 最终视图为 `V`。若 auditor 零错误恢复 `Y`，链式法则给出不可避免的泄漏下界：

```text
I(X;V | P)
= I(Y;V | P)+I(X;V | Y,P)
>= H(Y | P).
```

错误率为 `epsilon`、输出空间大小为 `M` 时，由 Fano inequality：

```text
I(X;V | P) >= H(Y|P)-h_2(epsilon)-epsilon log_2(M-1).
```

若存在只用 `(P,Y)` 模拟真实 transcript 的 simulator，则协议在计算意义上不泄漏任务输出之外的信息。当前 v0 明文公开 amount 与 blinding，显然没有达到仅输出合规 bit 时的下界；代码现在提供机器可读 `DISCLOSED_FIELDS_V0`，避免把 auditor binding 误写成包加密。

完整证明与边界分别见 [H-WES 下界与对象模型](docs/research/h-wes-theorem-and-object-model.md)、[隐私可见域公平排序与 H-FOC'](docs/research/private-visible-fair-ordering.md)、[H-SAC 最小泄漏下界](docs/research/h-sac-leakage-lower-bound.md) 以及总台账 [`docs/research/four-core-innovations.md`](docs/research/four-core-innovations.md)。

## 测试与 CI 门禁

本地执行与 CI 相同的主链门禁：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
```

Nightly workflow 会对交易、RPC、P2P 解码器执行有时间上限的真实 fuzz。绿色 CI 证明的是“这个提交通过了这些可重复检查”，不是外部审计或完整形式化验证。

## 自动 Release

`CI` 在 push 和 pull request 上运行。只有 `main` 分支的 `CI` 成功后，`Release` 才获得 `contents: write` 权限并重新构建 Linux、Windows、macOS 三个平台的 `hyphen-node`。每个包包含可执行文件、提交号、工具链信息和可用调试信息，并单独发布 SHA-256。

Release 标签绑定到 CI run、attempt 和提交，不会把 PR 代码发布出去。当前项目未达到主网安全门槛，所以自动发布的是 GitHub prerelease 开发产物；“能自动下载”不等于“可以安全托管真实资产”。

## 协议变更顺序

修改 wire format、状态根或链身份时，顺序必须是：先改规范，再改固定向量，再让主链测试通过，然后让 Miner、Pool、Wallet 分别固定到这个主链提交并运行各自 CI。仓库边界详见 [`docs/architecture/repository-boundaries.md`](docs/architecture/repository-boundaries.md)。

## 安全报告

不要在 issue、日志或截图中提交 mnemonic、身份私钥、payout token 或未公开漏洞细节。报告方式和当前支持范围见 [SECURITY.md](SECURITY.md)。

## 许可证

Hyphen 使用 GNU Affero General Public License v3.0，完整条款见 [LICENSE](LICENSE)。
