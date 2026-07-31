# 隐私可见域公平排序与 H-FOC'

状态：未激活研究规范。本文不给出“消灭 MEV”或“100 ms 全球最终性”结论。

## 1. 为什么公开交易 fairness 不能直接搬到隐私链

隐私交易写成

```text
tx = (pub(tx), hid(tx); witness),
```

其中 `pub(tx)` 是共识可见投影，`hid(tx)` 包含金额、发送方、接收方、真实 ring
member 和应用语义。Hyphen 候选 profile 只允许以下字段进入 fairness 函数：

```text
M(tx)=(txid, fee_class, encoded_len, public_conflict_tag).
```

`txid` 是不透明 commitment identifier；`public_conflict_tag` 可实例化为 nullifier
或公开冲突类别。任何新增字段都必须先进入 leakage ledger。共识不能对
`hid(tx)` 定义“按金额公平”“同一用户公平”或“真实经济意图公平”，因为它既
看不到这些值，也不应通过排序协议推断它们。

## 2. 公平证据

epoch `e` 的 PoW 抽样委员会有 `n=3f+1` 个 work-weighted seat，阈值
`q=2f+1`。seat `i` 在 cutoff `tau` 后签名本地接收序列：

```text
O_i=(cid,e,committee_id,view,slot,tau,i,R_M,seq_i),
sigma_i=Sign_i(H_ds("OBS",O_i)).
```

`R_M` 是完整 visible metadata set 的规范根。一个证据集必须包含至少 `q` 个
不同 seat 的有效签名；重复 seat、未知交易、序列内重复和上下文重放全部拒绝。

交易 `x` 的 quorum visibility 定义为：

```text
Visible_q(x) iff |{i : x in seq_i}| >= q.
```

只有 `Visible_q` 交易进入本 slot 的公平候选集。这给出可检查的 inclusion
前提，但不保证未取得 quorum receipt 的交易不会被网络层审查。

## 3. Visible Strong Receive Order（VSRO）

对两个 quorum-visible 交易，定义：

```text
before_i(x,y)=1 iff x,y in seq_i and pos_i(x)<pos_i(y),
x <_E y iff sum_i before_i(x,y) >= q.
```

关系 `<_E` 可能不是全序。构造 directed evidence graph
`G_E=(T,E)`，边为 `x -> y iff x <_E y`。把每个 strongly connected component
收缩成一个 fair batch，再对 condensation DAG 做确定性拓扑排序。

batch 内顺序不属于 VSRO 保证。实现使用

```text
rank(x)=H_ds("TIE",rho_after_cutoff || txid_x),
```

其中 `rho_after_cutoff` 必须在接收 cutoff 后才固定且不可偏置。若提交者提前知道
seed，可改变 commitment randomness grinding `txid`；若 leader 能选择 seed，
则 leader 仍可操纵 batch 内顺序。

### 定理 VF-S1：冲突强边不可同时成立

对任意 `x != y`，不能同时有 `x <_E y` 和 `y <_E x`。

**证明。** 每个合法 seat sequence 对同一 pair 只能贡献一个方向。两个方向各需
`q` 个不同 seat，因此需要至少 `2q=4f+2` 个方向贡献；委员会只有 `3f+1` 个
seat，且 `4f+2>3f+1`，矛盾。`□`

三环同样不可能：每个全序对一个有向三环最多支持两条边，因此全部 `n=3f+1`
个 sequence 最多给出 `2n=6f+2` 次环边支持，小于三条强边要求的
`3q=6f+3`。长度至少 4 的 Condorcet cycle 则可能存在；所以实现保留 SCC batch，
而不是任意删边伪造 pairwise fairness。

### 定理 VF-S2：强接收前提导出 evidence edge

若至少 `q` 个 seat 提交有效 observation，且这些 observation 都包含 `x,y` 并把
`x` 放在 `y` 前，则 `x <_E y`，构造输出中 `batch(x)` 不晚于 `batch(y)`。

第一部分由定义直接得到。若两者不在同一 SCC，condensation DAG 保留该边，任何
拓扑序把 `x` 的 component 放在 `y` 前；若在同一 SCC，只保证同 batch。`□`

### 定理 VF-P1：隐藏投影不增加排序泄漏

令两个隐藏世界 `W0,W1` 在交易有效性证明和公开投影上计算不可区分，并给出相同
签名接收证据分布。排序算法是 `(M,E,rho)` 的确定性多项式函数。若存在 PPT
distinguisher 通过排序输出区分 `W0,W1`，将该算法作为后处理即可区分公开投影，
与前提矛盾。这是 data-processing/post-processing 性质，不证明底层交易本身零知识。

## 4. “局部 MEV 抵抗”的严格边界

固定 admissible evidence `E` 和 cutoff 后 seed `rho`，令 `Ord(E,rho)` 是唯一输出。
leader ordering-manipulation advantage 定义为：

```text
Adv_order(A | E,rho)
 = Pr[Verify(order_A,E,rho)=1 and order_A != Ord(E,rho)].
```

在哈希 binding、签名 EUF-CMA 和 deterministic verifier 假设下，该概率可忽略；
leader 不能在同一证据上选择另一 order root。这只抵抗**证据固定后的排序自由度**。

以下 MEV/审查渠道不在该结论内：

- 延迟传播，使目标交易拿不到 `q` 份 receipt；
- 聚合者从已经收到的有效 observation 中选择一个对自己有利的子集；
- Byzantine seat 谎报自身接收顺序；
- 可见 fee class 或 nullifier 引出的策略；
- sender/relay 的 txid grinding 或 selective submission；
- cutoff、随机 seed、委员会 seed 的操纵；
- 隐藏语义在执行后公开造成的 back-running；
- 多 slot 跨批次重排。

因此准确名称是 visible-domain local ordering resistance，不是“MEV solved”。

## 5. PoW 动态委员会

前一 finalized PoW epoch 的身份工作量为 `w_j`，总工作量 `W=sum_j w_j`。先按
公钥聚合工作量，再用不可偏置 seed `rho_e` 有放回抽样 `n=3f+1` 个 seat：

```text
u_l = H_to_[0,W)(rho_e || e || l),
seat_l = min {j : sum_(a<=j) w_a > u_l}.
```

同一公钥可拥有多个 seat；它们不是多个独立运营者。安全假设必须写成“攻击者
控制至多 `f` 个 seat”，不能写成“至多 `f` 个节点”。

若攻击工作份额为 `alpha`，抽样独立且 seed 不可偏置：

```text
P_bad(n,f,alpha)
 = sum_(i=f+1)^n C(n,i) alpha^i (1-alpha)^(n-i).
```

若攻击者可 grinding `g` 个候选 seed，union bound 只能给出

```text
P_bad_grind <= min(1, g * P_bad).
```

实际抽样相关、自适应腐化和矿池身份集中会破坏简单二项模型，必须另行测量。

当前链的 epoch seed 是上一 epoch 末块哈希的 BLAKE3，矿工可 grinding；它不满足
本节“不可偏置”前提。若 `g` 个候选在随机预言机模型下独立且事件单次概率为 `p`，
攻击者择优后事件概率为 `1-(1-p)^g`；相关候选不满足该等式，只能按联合分布分析，
并有 union bound 上界 `min(1,gp)`。哈希后处理不能消除选择通道。激活 H-FOC'
必须先满足 [`cryptographic-activation-gates.md`](../security/cryptographic-activation-gates.md)
中的 unique threshold beacon 或 VDF 门槛。

## 6. H-FOC' 证书阶段

每个 slot 的候选协议至少包含：

1. `PROPOSE`：传播 metadata set/root，不解密隐藏 payload；
2. `OBSERVE`：收集签名 reception sequences；
3. `FAIR-AGGREGATE`：验证 quorum、生成 evidence root、SCC batches 和 order root；
4. `PREPARE/COMMIT`：seat 对绑定
   `(cid,e,committee,view,slot,parent,R_M,R_E,R_order)` 的 statement 投票；
5. `HANDOFF`：epoch 边界把新委员会身份绑定到 finalized PoW checkpoint。

`fast_ordering.rs` 保留单 statement preorder kernel；`fair_finality.rs` 另行实现
PREPARE/COMMIT QC、commit lock、timeout certificate、最高 prepare 继承、view-change
proposal 检查和双委员会 handoff。诚实 voter 在返回 phase/timeout/handoff 签名前以
CAS 写入 sled 并 flush，重启后仍执行相同 lock 与 anti-equivocation 规则。它仍是
不激活状态机：没有在线 pacemaker、leader、已最终委员会来源或 block execution。

### 定理 FOC-S1：固定委员会 QC 交集

任意两个 `q=2f+1` quorum 的交集大小至少

```text
|Q1 intersect Q2| >= 2q-n = f+1.
```

攻击 seat 至多 `f` 时，交集中至少一个诚实 seat。若诚实 seat 在同一
`(epoch,view,slot,phase)` 不签冲突 order root，则该阶段不能形成两个冲突 QC。

注意：这不是完整 HotStuff/PBFT safety proof；跨 view 安全还需要 lock carry-over
规则，跨 epoch 安全还需要 handoff。

### 定理 FOC-S1b：跨 view commit safety

设值 `X` 在 view `v` 形成 COMMIT QC。其 signer 先验证同 view 的 PREPARE QC 并锁定
`(v,X)`。假设存在冲突值 `Y` 在更高 view 取得 PREPARE QC，取其 view `w>v` 最小。
view `w` proposal 必须携带 view `w-1` 的 timeout certificate `TC`。`TC` 的 `q` 个
signer 与 `X` 的 COMMIT QC signer 相交至少 `f+1`，故至少一个诚实 signer 已锁 `X`，
并在 timeout vote 中携带其最高 PREPARE QC，其 view 至少为 `v`。

令 `TC` 中最高 PREPARE QC 为 `Q_h`，view 为 `h>=v`。实现要求新 proposal 的 value
等于 `Q_h.value`：

- 若 `h=v`，固定 view 的 PREPARE QC 交集定理使 `Q_h.value=X`；
- 若 `v<h<w` 且 `Q_h.value` 与 `X` 冲突，则 `Q_h` 是比 `w` 更早的冲突 PREPARE QC，
  与 `w` 的最小性矛盾；
- 若 `v<h<w` 且 `Q_h.value=X`，proposal 仍只能提议 `X`。

三种情况都不能在 `w` 为 `Y` 形成 PREPARE QC，矛盾。因此不存在与已 commit 值
冲突的更高 view commit。该证明依赖 timeout vote 不隐瞒本地最高 prepare、proposal
强制采用 `Q_h`、诚实 lock 持久且最多 `f` 个恶意 seat。`□`

### 定理 FOC-S2：双委员会 handoff 的归纳安全

令 epoch `e` 的最终 handoff statement 同时需要旧委员会 `C_e` 和新委员会
`C_(e+1)` 各自的 commit QC，并绑定同一 finalized PoW checkpoint。若至少旧、新
委员会各自都满足 `<=f` adversarial seats 且其诚实 voter 遵守跨 view lock，则
两个冲突 handoff 不可能同时成立：每一侧的冲突 QC 都分别违反 FOC-S1。以 genesis
handoff 为基例可对 epoch 归纳。`□`

如果任一委员会失陷、PoW checkpoint 未最终、密钥可即时自适应腐化或 view-change
不保留 lock，该定理前提不成立。

归纳基例必须是配置中唯一承认的 genesis checkpoint。归纳步把 epoch `e` 已唯一
finalized checkpoint 作为 handoff statement 的 `previous_handoff`/checkpoint 输入；
旧、新委员会各自的 quorum 交集排除同一 role 的冲突 handoff，两个 role 又签同一
statement digest，因此 epoch `e+1` 只能继承一个 checkpoint。代码验证 chain、epoch、
committee ID、role、previous handoff 和 finalized checkpoint，不能把单委员会 QC
重放成双委员会 handoff。

## 7. 活性与性能式

在 GST 后网络延迟上界为 `Delta`，签名验证/聚合为 `T_sig`，fairness 计算为
`T_fair(s,m)=Theta(s*m^2)`，若协议使用 `r` 个串行广域网阶段，则只能给出：

```text
T_final <= r*Delta + T_sig + T_fair(s,m) + T_queue
```

参考实现设置确定性 pair-work 上限，防止攻击者用超大 observation 触发无界 CPU。
当前 observation 证据大小是 `Theta(s*m)`，未使用聚合签名；“100 ms”必须通过
公开地区、ASN、带宽、丢包、committee size、batch size 和原始样本 benchmark，
不能从渐近式推导。

## 8. 代码状态

`crates/hyphen-consensus/src/private_fair_ordering.rs` 已实现：

- visible metadata 规范 commitment；
- Ed25519 seat observation 验证；
- quorum visibility 与强 pairwise edge；
- SCC fair batch 和 cutoff 后 seed tie-break；
- 输入排列不变、伪签名/重复 seat 拒绝、四节点强证据 cycle 测试；
- pairwise CPU 工作预算。

`fairness_receipts.rs` 现在提供：每个 vote 自带并签署 `observed_at`；cutoff 后 vote
拒绝；quorum receipt 做 distinct-seat/signature/context/metadata 校验；
`HonestReceiptVoter` 在释放签名前持久化 transaction obligation，支持幂等重传、
冲突拒绝、每 slot 容量界和重启恢复；finality prepare 会拒绝遗漏 obligation 的
order。P2P 有独立 receipt topic 和 512 KiB 上限，传输 typed vote/quorum receipt。

**纳入定理。** receipt quorum `Q_r` 与任一 proposal quorum `Q_p` 都有 `2f+1`
seat，故交集至少 `f+1`，其中至少一个诚实 seat。诚实 receipt signer 在签名前已经
持久化义务，因而不会为遗漏该交易的 order 投 prepare vote；该 proposal 至多取得
`2f` 票，不能形成 QC。`□`

该定理只在生产 profile 强制所有诚实 seat 使用 voter API、receipt 与 proposal 属于
同一 active committee、metadata/slot/cutoff 一致且交易本身有效可用时成立。当前节点
没有已最终委员会来源，收到 receipt 后明确不激活 obligation；也没有可信 receive
timestamp、聚合服务、mempool/fusion/block execution 接线，因此仍不构成生产公平共识。

## 9. Prior art

已经确认的直接相关工作包括：

- Kelkar et al., *Order-Fairness for Byzantine Consensus*, CRYPTO 2020,
  DOI `10.1007/978-3-030-56877-1_16`；
- Kursawe, *Wendy, the Good Little Fairness Widget*, AFT 2020,
  DOI `10.1145/3419614.3423263`；
- Cachin et al., *Quick Order Fairness*, FC 2022,
  DOI `10.1007/978-3-031-18283-9_15`；
- *Order-Fair Consensus in the Permissionless Setting*, AFT 2022,
  DOI `10.1145/3494105.3526239`；
- Zhang et al., *Themis: Fast, Strong Order-Fairness in Byzantine Consensus*,
  CCS 2023, DOI `10.1145/3576915.3616658`；
- *Separation is Good: A Faster Order-Fairness Byzantine Consensus*, NDSS 2024,
  DOI `10.14722/ndss.2024.24693`；
- *Bitcoin meets strong consistency* (ByzCoin), CCS 2016,
  DOI `10.1145/2833312.2833321`。

这些工作已经覆盖 BFT fairness、permissionless fairness 和 PoW/BFT 组合的多个
方向。Hyphen 当前只能把“明确隐藏投影、只对 visible domain 给出 batch fairness、
并与 PoW seat evidence 绑定”作为待比较候选框架；完成系统文献和攻击实验前不能
声称首次。
