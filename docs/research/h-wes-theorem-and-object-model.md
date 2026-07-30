# H-WES：从恢复下界到可过期认证对象

状态：研究规范，未激活到任何 Hyphen 网络。本文固定问题、模型、定理和实现
接口；它不是新颖性证明，也不是密码学审计报告。

## 1. 先修正一个过强的不可能性陈述

仅有以下四条不足以推出不可能性：

1. 旧版本不可恢复；
2. 客户端最初只保存历史 witness；
3. 验证者不持久维护 `key -> latest` 认证索引；
4. 恢复协议为无交互或常数轮。

反例是单轮发送完整 archive。恢复者从不可信 archive provider 下载全部记录，
把记录和认证数据一次发送给验证者；验证者重算 append-only commitment，线性扫描
同一 key 的所有版本，再判断候选是否最新。它不保存 latest index，协议只有一轮，
而且可以拒绝旧版本。代价是 `Theta(N)` 通信、prover I/O 和 verifier 工作。

因此可证明的命题必须明确加入 H-WES 真正需要的目标：**succinct recovery**。
下文使用黑盒认证 archive 模型，并要求恢复只打开次线性数量的 archive cell。

## 2. 状态与 archive 模型

令安全参数为 `lambda`，key 空间为 `K`，值空间为 `V`。对象 incarnation 为

```text
I = (cid, class, k, v, h_val, P_owner, h_create, h_lease),
```

其中 `cid` 是链身份，`k in K`，`v in N` 是版本，`h_val=H(value)`，
`P_owner` 是授权策略 commitment。对固定 key，版本严格递增。

在高度 `t`，历史为有序记录数组

```text
Hist_t = (r_0, ..., r_(N_t-1)),
A_t = CommitArchive(Hist_t).
```

archive 只暴露：

```text
Open(A_t, i) -> (r_i, pi_i),
VerifyOpen(A_t, i, r_i, pi_i) -> {0,1},
VerifyAppend(A_s, A_t, pi_(s,t)) -> {0,1},  s <= t.
```

它不原生暴露按 key 查询、范围内不存在性或最大版本。MMR 是该接口的一个实例：
它认证位置和 append-only 历史，但不赋予叶内容按 key 的顺序。

定义当前头函数：

```text
Head_t(k) = arg max_v { r in Hist_t : r.key=k and r.version=v },
```

若同一版本可出现多个记录，历史无效；共识转换必须在 append 前拒绝该情况。

### 2.1 “等价 latest 信息”不是特定数据结构

认证 latest oracle 是任意 `(D_t, ProveLatest, VerifyLatest)`，满足：

```text
VerifyLatest(D_t, k, v, status, pi)=1
    iff Head_t(k).(version,status)=(v,status),
```

其中错误概率可忽略。`D_t` 可以是 SMT root、Verkle root、vector commitment、
SNARK statement 或其他摘要；所以“没有 BTreeMap”不等于“没有 latest 等价信息”。
只要一个短证明能认证 freshness，它在安全意义上就是 latest dictionary。

## 3. 两个下界定理

### 定理 H-WES-N0：安全恢复蕴含 latest 认证能力

设恢复协议 `Pi=(ProveRec,VerifyRec)` 满足：

- 完备性：当前处于 `Expired` 的最新 incarnation 可产生接受 transcript；
- latest-only 健全性：任何旧 incarnation 或非 `Expired` incarnation 的接受概率
  至多为 `negl(lambda)`；
- verifier 的公开状态为 `S_t`。

则 `Pi` 可黑盒构造一个针对可恢复对象的认证 latest oracle。

**构造。** 令 `D_t=S_t`。`ProveLatest` 运行 `ProveRec`，但不提交最终状态；
`VerifyLatest` 运行 `VerifyRec` 的只读阶段。对最新 `Expired` 记录，恢复完备性给出
latest 完备性；对旧版本、`Live`、`Recovered` 或 `Consumed`，latest-only
健全性给出拒绝。故恢复 transcript 本身就是 latest 状态的认证证明。`□`

这个定理说明“安全恢复但不存在任何 latest 等价认证信息”在语义上矛盾。该信息
不一定由 validator 保存完整索引，但必须以某种 commitment 和证明关系存在。

### 定理 H-WES-N1：membership-only archive 的后缀查询下界

考虑 archive-generic verifier：`A_t` 是只能作为 `Open/VerifyOpen` 参数使用的
opaque oracle handle；verifier 不能读取、哈希、比较或根据 handle 的表示分支，
只能通过成功打开 cell 获知历史内容。这个限制排除了把额外 latest 信息偷偷编码
进 commitment 表示的构造。候选记录位于
位置 `i`，其后有 `m=N_t-i-1` 个 cell。若 verifier 不使用 latest oracle，且对
所有合法历史零错误判断候选是否为 `Head_t(k)`，则最坏情况必须认证打开全部
`m` 个后缀 cell。

**证明。** 假设某次接受执行只打开后缀位置集合 `Q`，且 `|Q|<m`。取未打开位置
`j notin Q`。构造两个合法历史：

```text
H0: 所有 j>i 的记录 key 均不等于 k；
H1: 与 H0 相同，但位置 j 是 key=k、version>v 的合法记录。
```

在该 oracle 接口中，以相同随机带运行 verifier 时，两个世界对已打开位置返回
完全相同的 `(index,record)`；handle 本身不可观察，未打开位置也不能影响执行。
候选在 `H0` 是 latest，在 `H1` 不是 latest。
verifier 对两者输出相同，因此完备性或健全性至少一个失败，矛盾。故最坏情况
`|Q|=m`。`□`

对允许错误 `epsilon` 的随机 verifier，取如下 Yao 分布：先给出无后继的历史，
或者在 `m` 个后缀位置中均匀放置唯一的新版本，其余 cell 与前者相同。固定任意
随机带后，若算法最坏最多查询 `q` 个不同后缀位置，命中新版本的概率至多
`q/m`；对随机带取期望仍不改变该上界。要让存在新版本时的漏检概率不超过
`epsilon`，必须有

```text
q >= (1-epsilon)m.
```

这里的 `q` 是最坏查询上限；若只约束期望查询数，则对应结论是
`E[q] >= (1-epsilon)m`。这是黑盒、无序、membership-only archive 的
cell-probe 下界，不是对所有 commitment 或所有 SNARK 的无条件密码学下界。
以下方法都避开了定理前提：

- 维护按 key 的认证 latest dictionary；
- 让客户端或 witness service 持续更新 freshness witness；
- 给 archive 增加按 key 排序的认证索引；
- 用 SNARK 证明完整后缀扫描，保持 verifier 简短但 prover 仍做 `Omega(m)` 工作；
- 信任在线 freshness oracle。

### 推论 H-WES-N2：三项成本不能同时消失

在上述模型中，安全恢复至少承担下列一项：

```text
authenticated latest state;
ongoing witness/index maintenance;
linear suffix data/prover work.
```

H-WES 的目标不是违反该下界，而是选择一个清晰的新权衡：validator 共识状态只
承诺 fixed-size roots；latest map 和历史 body 可由分离存储层维护；恢复者按需
取得 `O(log K)+O(log N)` 新鲜证明；长期离线 owner 不持续更新 witness。

## 4. Expirable Authenticated Object Model（EAOM）

### 4.1 incarnation 与 key head

生命周期属于 incarnation `(k,v)`，不是模糊的“账户”。状态为：

```text
Live(k,v) -> Expired(k,v) -> Recovered(k,v; successor=v+1)
                           \-> Consumed(k,v)
```

`Recovered(k,v)` 和 `Consumed(k,v)` 都是终态。恢复会在同一个原子转换中关闭
`(k,v)` 并创建 `Live(k,v+1)`；因此不会出现可被其他交易观察到的中间状态。

全局认证状态为：

```text
S_t = (R_live,t, R_latest,t, R_null,t, R_hist,t, R_DA,t).
```

- `R_live`：当前 live body hash；
- `R_latest`：每个 key 的 `(version,status,archive_index,value_hash,head_hash)`；
- `R_null`：不可删除的消费/nullifier 集；
- `R_hist`：append-only 生命周期历史 MMR；
- `R_DA`：恢复后数据可用性证书根。

组合根采用域分离：

```text
R_state = H_ds("HYPHEN_STATE_V1",
               R_live || R_latest || R_null || R_hist || R_DA).
```

### 4.2 转换与线性化点

`Expire(k,v,t)` 的前置条件：

```text
Head_t(k)=(v,Live), t>=lease_end(k,v).
```

它删除 live entry，向历史追加 `Expired` record，并把 latest head 改成
`(v,Expired,index,...)`。区块原子状态提交是线性化点。

恢复授权 statement 为：

```text
AuthRec = H_ds("HYPHEN_WES_AUTHORIZATION_V1",
  Recover || cid || k || v || H(expired_record) || t || new_lease || R_state,t).
```

`Recover(k,v,t,new_lease)` 验证：

1. expired record 在 `R_hist,t` 中；
2. `R_latest,t` 证明 `(k,v,Expired)` 是当前 head，并绑定同一 archive index；
3. owner policy 对 `AuthRec` 授权；
4. `new_lease>t>=old_lease_end`；
5. DA policy 证明 successor body 对 `R_DA,t` 可用。

成功后构造 `Live(k,v+1)`，向历史追加：

```text
E_rec=(cid,class,k,v,Recover,t,H(expired),H(live_successor)),
```

并原子更新 live/latest。历史 append、successor 插入和 latest 更新共同构成唯一
线性化点；任一步失败必须整体回滚。

消费授权将 `Recover` 换成 `Consume`，`new_lease` 使用规范哨兵值。成功后追加

```text
E_con=(cid,class,k,v,Consume,t,H(expired),0^256)
```

并把 latest head 设为 `(v,Consumed,...)`。没有从 `Consumed(k,v)` 出发的转换。

## 5. 安全游戏

### 5.1 Latest-only recoverability

挑战者运行任意合法历史得到 `S_t`，允许攻击者取得所有历史 body、membership
proof、旧授权和旧 DA proof。攻击者输出 `(k,v,pi_rec)`。若验证接受但

```text
Head_t(k) != (v,Expired),
```

则攻击者获胜。H-WES 要求胜率为 `negl(lambda)`。

归约分三种：伪造 history membership 破坏 MMR binding；伪造 latest membership
破坏 authenticated dictionary soundness；让 witness 中版本/状态/index/hash
不一致则被确定性检查拒绝。

### 5.2 No resurrection

挑战者先让 `(k,v)` 线性化到 `Consumed`，随后攻击者可重放任意旧材料并输出恢复
请求。由于 current latest status 为 `Consumed` 而恢复关系要求 `Expired`，接受
需要伪造 latest proof 或破坏其 commitment binding。因此成功概率可忽略。

`Recovered(k,v)` 也不能再次恢复：current head 已是 `Live(k,v+1)` 或其后继状态。

### 5.3 History accountability

给定 current `R_hist`，攻击者若输出未真实追加的终态事件和有效 inclusion proof，
即构成 MMR binding/底层哈希抗碰撞攻击。恢复事件还承诺 successor hash，所以
审计者可检查“哪个 incarnation 被关闭、何时关闭、是否产生后继”。这不证明
历史 body 永久可用；availability 是独立假设。

### 5.4 可组合结论及边界

在以下假设同时成立时，EAOM 满足前三个游戏：

```text
H collision resistant;
MMR and latest dictionary binding/sound;
owner policy EUF-CMA or knowledge sound;
state transition atomic and deterministic;
consensus exposes one canonical pre-state root.
```

可恢复性另外需要至少一个 provider 保留 body 和新鲜证明，并满足 DA policy。
commitment 不能从信息论上恢复已被所有人删除的 body。

## 6. 时间、存储与 witness 权衡

令 `N` 为历史记录数，`K` 为不同 key 数，`m` 为候选后的历史长度。

| 构造 | validator 共识摘要 | 外部索引存储 | owner 持续更新 | 恢复 proof/数据 | prover 工作 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 仅 append archive + 扫描 | `O(1)` | `O(N)` body | `O(1)` | `Theta(m)` | `Theta(m)` |
| 客户端动态 accumulator | `O(1)` | `O(N)` | 每次相关/全局更新 | 方案相关 | 方案相关 |
| 版本化认证字典 | `O(1)` root | `O(K)` | `O(1)`，按需取新 proof | `O(log K)` | `O(log K)` |
| archive-scan SNARK | `O(1)` | `O(N)` body | `O(1)` | 常数或 polylog | `Omega(m)` scan |
| H-WES EAOM reference | 5 个固定根 | `O(K+N)` | `O(1)` | `O(log K+log N)+body` | `O(log K+log N)` 查询 |

最后一行不是“无存储”：它把 body、latest tree nodes 和 proof serving 移到可替换
provider；validator 仍必须认证 roots，数据可用性和 provider 去中心化仍需协议。
当前 Rust reference 使用 `BTreeMap` 重建树，更新成本不是生产级 `O(log K)`；表中
复杂度是目标后端接口，必须用持久 SMT/Verkle 实现和 benchmark 才能关闭。

## 7. 可覆盖的对象类别

模型只要求稳定 key、单调 version、owner policy 和可认证 body hash，因此可实例化：

- 租赁 UTXO：`Consumed` 同时插入永久 nullifier；
- 可恢复账户权限：owner policy 可为阈值/延迟恢复策略；
- 可撤销凭证：credential incarnation 过期后恢复或终止，revocation 仍需公开语义；
- 数据可用对象：恢复前必须给出目标 DA root 的证书；
- 合约 KV：必须额外定义合约代码对恢复/消费的授权关系。

shielded note 暂不在实现 profile：若 owner、真实输入和 nullifier 关系需要隐藏，
必须有零知识电路把 EAOM transition 与现有隐私交易关系绑定。

## 8. 实现对应与未关闭义务

`crates/hyphen-state/src/expiring_state.rs` 当前实现：

- 159-byte record 规范编码；
- deterministic expiry queue；
- history MMR 与 latest membership proof；
- 绑定 action/height/lease/pre-state 的 authorization digest；
- 原子语义的 recovery successor 与 terminal history receipt；
- consumed terminal 和负向 no-resurrection 测试；
- 纯 verifier API，只需 roots 与 witness。

它尚未实现持久 SMT、proof-serving 网络、真实 owner policy、DA certificate、reorg
journal 接入、shielded relation、并发事务隔离、benchmark 和独立审计，所以不能
激活到现有网络或称为生产协议。

## 9. Prior-art 边界

必须逐项比较 Utreexo/UTXO accumulators、stateless-client witness 更新、Ethereum
state expiry、版本化 authenticated dictionaries、可撤销凭证 accumulators 和
历史 KV authentication。当前可核验入口包括：

- Utreexo, IACR ePrint 2019/611: <https://eprint.iacr.org/2019/611>
- Ethereum statelessness/state expiry:
  <https://ethereum.org/en/roadmap/statelessness/>
- Practical Revocable Anonymous Credentials, FC 2012,
  DOI `10.1007/978-3-642-32805-3_22`。

在系统检索、专利检索和独立同行评审完成前，H-WES 只能声称“给出了上述模型、
黑盒下界和一个候选权衡”，不能声称首次解决状态过期或首次实现可恢复状态。
