# Hyphen Research Mechanisms: Proofs, Prior Work and Implementation Charter

Status: pre-specification, 2026-07-31.

This is not a deployed-feature statement. None of the four mechanisms is part
of current `hyphen-devnet-v2` consensus. Activation requires a new research
profile, chain identity, specification version and vectors. README and white
papers must not call a mechanism solved, proved or production-ready before its
proof obligations, attack tests and independent review are complete.

## 1. Current foundation and prerequisite gaps

Hyphen is a linear-tip PoW chain with shielded UTXOs, a persistent commitment
tree and nullifier set. State storage provides atomic multi-tree block commit,
single-tip undo logs, immutable hash-checked competing-branch bodies and
strictly-heavier-work reorg plans. The real `Blockchain` backend recomputes
work, holds an exclusive transition lock, detaches to the common ancestor and
revalidates every attach block against fork state through the authoritative
acceptance path. It restores the old branch after failure and resumes a durable
journal after reopen.

Live P2P competing-branch intake, automatic fork choice, reconciliation of
mempool/wallet/explorer/pool, mesh fusion, BFT finality and complete selective
audit proofs remain absent. The research profile atomically commits the signed
WASM ledger and H-WES public creation/bounded expiry into the unified state root
and reorg path; shielded recovery and consume remain disabled.

The required order is reproducible encoding and atomic transitions; competing
branches, fork choice and rollback; witness-carrying state; parallel production
and fusion; fast ordering over an explicit Sybil/network model. Audit circuits
may proceed in parallel but must bind final transaction encoding and state roots.
The relevant primitives are in `hyphen-state` atomic/branch/journal modules and
`hyphen-consensus::chain`. Existing tests cover successful heavier switches,
interrupted detach/restore, invalid attach recovery, forged-work rejection and
database-reopen continuation. Network automation, subsystem reconciliation,
OS-level kill tests and formal state-machine checks are still release blockers.

## 2. Common notation and assumptions

| Symbol | Definition |
| --- | --- |
| `lambda` | security parameter, target at least 128 bits |
| `H_ds(tag, parts)` | domain-separated 256-bit BLAKE3; collision and second-preimage resistance assumed |
| `Sig` | digital signature, assumed EUF-CMA secure |
| `t`, `e` | transition height/logical slot and expiry/fusion epoch |
| `k`, `n`, `f` | lane count, committee seat count and Byzantine-seat bound; BFT requires `n>=3f+1` |
| `Delta` | honest-node delay bound after GST |
| `L_t`, `V_t`, `N_t`, `A_t`, `D_t` | live, latest, nullifier, archive and availability commitments |
| `S_t` | `H_ds("HYPHEN_STATE_V1", L_t || V_t || N_t || A_t || D_t)` |
| `F_e` | prior anchor and fusion frontier/vector commitment |
| `QC` | certificate of at least `2f+1` committee signatures |
| `G_v`, `G_r` | Ristretto value generator and standard blinding/output-key basepoint |
| `C(v,r)` | Pedersen commitment `v*G_v + r*G_r` |

Consensus objects require canonical, language-neutral, bounded encoding. Rust
uses the repository-owned `hyphen-codec` v1. Its fixed-width format, limits and
schema-relative canonicality are documented in the codec README. It remains
unaudited; cross-language implementations need fixed vectors, not just Rust
round trips.

## 3. Candidate contribution one: H-WES

Hyphen Witness-Carried Expiring State is a working name, not a novelty claim.
Nullifiers/key images, consensus and issuance limits, state referenced by live
contracts or pending transactions, and commitments needed to prove freshness
cannot simply be forgotten. MMR inclusion alone proves that a record existed,
not that it is the latest or remains unspent.

For versioned record

```text
R = (chain_id, class, x, version, value_hash, owner_policy,
     created_at, lease_end, status)
```

`V_t[x]` commits the latest version/status/archive index/value/head hashes.
Expiry appends an authenticated historical record, removes the live entry and
updates latest status using a bounded authenticated lease queue. Recovery
carries archive and latest proofs, the value blob, owner proof, nullifier proof
where applicable and an availability proof. The first profile uses hash-based
SMT/MMR proofs rather than prematurely adopting an unaudited pairing scheme.

H-WES-S1 reduces stale-version resurrection to latest-tree soundness and hash
collision resistance. H-WES-S2 follows from monotonic nullifiers checked and
inserted before commit. H-WES-L1 is conditional: recovery requires at least one
honest provider retaining the body and fresh witness; no commitment restores
data deleted by everyone.

The reference fixes 159-byte records, deterministic expiry order, MMR/latest
proofs, terminal recovery/consume semantics, authorization context and negative
tests. Persistent namespaced SMTs, authenticated blob/chunk storage, P2P proof
serving and DA certificate verification exist. The research-profile chain now
persists all five roots and public creation/bounded expiry in the same atomic
block/reorg transition. Shielded owner/nullifier recovery and consume, provider
challenge/repair, long-term retention evidence and independent review remain
closed. The complete lower bounds and EAOM model are in
[`h-wes-theorem-and-object-model.md`](h-wes-theorem-and-object-model.md).

## 4. H-BFM fusion and visible-domain fairness

Hyphen Braided Fusion Mesh is also a working name and cannot claim novelty for
block DAGs or GHOSTDAG blue-set ordering. The candidate treats parallel blocks
as availability/execution batches: deterministic lanes reference the previous
fusion checkpoint and other lane frontiers; consensus fixes one frontier
vector; the reachable available closure is canonically topologically ordered;
conflicts yield one deterministic success and later failure receipts; reward
rules must not pay spam or duplicate payloads.

For DAG `G_e=(B_e,E_e)`, order by Kahn's algorithm and choose the minimum

```text
rank(B) = (logical_round(B), lane(B), H(canonical_block(B)))
```

among zero-indegree nodes. H-BFM-S1 follows by induction: equal DAG, encoding
and pre-state yield one sequence and state. H-BFM-S2 includes timely valid
certified blocks in the reachable closure but does not promise success for
conflicts or inclusion for delayed, withheld, uncertified or lane-invalid
blocks.

Open problems include permissionless lane assignment, withholding and
equivocation, cross-lane double spend, frontier agreement and DA, spam-safe
credit, the exact PoW-weight/issuance relationship and atomic deep-mesh reorg.
The inactive `fusion.rs` model and vectors cover unique lane chains, certified
closure, canonical order, conflict receipts and permutation invariance, not a
complete mesh consensus. Visible-domain fairness is specified separately in
[`private-visible-fair-ordering.md`](private-visible-fair-ordering.md).

## 5. Candidate contribution two: H-FOC'

Hyphen Fast Ordering Certificates cannot promise unconditional 100 ms global
finality. FLP applies in full asynchrony; partial synchrony bounds finality by
actual `Delta` and protocol rounds; permissionless `n` and `f` need an
enforceable Sybil-resistance mechanism. Separate metrics are required:

```text
T_preorder_p50 <= 100 ms
T_final_p95 <= r*Delta + T_verify + T_queue
```

Any result must publish geography, node count, bandwidth, loss, delay,
Byzantine fraction and failures.

For `n=3f+1`, `q=2f+1`, votes bind chain, epoch, committee, view, slot, parent
frontier and order root. Two quorums intersect in at least `f+1` seats, hence
one honest seat when at most `f` are adversarial. Persistent same-phase locking
prevents conflicting QCs. This combinatorial lemma is not a complete
view-change or handoff proof. Partial-synchrony liveness still requires a live
leader election, timeout protocol and pacemaker.

The inactive kernel samples work-weighted seats with replacement from a prior
finalized PoW epoch, aggregates work by public key, verifies Ed25519 seat votes,
enforces threshold/context and rejects duplicate seats/double-signing. One key
may own multiple seats, so the premise is adversarial seats, not nodes. The
current epoch seed is grindable and cannot activate the layer. Old/new
committee dual-QC handoff, final committee sourcing, online pacemaker and block
execution remain unwired; H-FOC' is not a BFT finality layer.

## 6. Candidate contribution three: H-SAC

Hyphen Selective Audit Capabilities is not a regulatory backdoor and must have
no chain-wide master decryption key. It distinguishes selective plaintext
opening from a zero-knowledge provenance-compliance proof. Cryptography proves
only a specified on-chain/external predicate; issuer correctness and real-world
identity are external trust assumptions.

The candidate relation binds chain, transaction, selected commitments,
nullifiers, policy root, scope and expiry to private values, blindings, spend
secrets, true ring indices, ownership and policy paths. It must constrain
commitment openings, nullifiers, ring membership, credential membership,
canonical scope and transaction balance. Completeness, knowledge soundness and
out-of-scope zero knowledge require a finalized circuit, proof system, simulator
and independent review.

The inactive v0 wallet package is deliberately narrower. It reveals one value
and blinding, verifies the Pedersen opening and a Schnorr proof of the one-time
output key, and binds chain, transaction, index, auditor, scope, expiry and
nonce. It rejects identity public keys/nonces and noncanonical scalars. It is
not encrypted, does not prove canonical inclusion, real ring input or legal
provenance, and is called targeted opening disclosure. The leakage lower bound,
composition analysis and v0 distance are in
[`h-sac-leakage-lower-bound.md`](h-sac-leakage-lower-bound.md).

## 7. Proof ledger

| ID | Property | Current status | Closure condition |
| --- | --- | --- | --- |
| BASE-R1 | Crash-resumable reorg or old-chain restore | Real backend and fork-state tests complete | P2P selection, subsystem reconciliation, kill/reopen, formal and multi-node tests |
| H-WES-N0/N1 | Latest authentication implication and archive suffix bound | Black-box proofs complete | Independent formal review and broader randomized/batch models |
| H-WES-S1/S2 | No stale resurrection and monotonic nullifiers | Five roots, public create/expiry and atomic reorg wired | Shielded recovery/consume relations and review |
| H-WES-L1 | Conditional recovery | Assumptions explicit | DA withholding drills and recovery benchmarks |
| H-BFM-S1/S2 | Deterministic same-set fusion and certified inclusion | Reference model/candidate property | Set agreement, DA/reward rules and model checking |
| VF-S1 | Nonconflicting strong edges and SCC batching | Signed evidence model | Enforced receipts, beacon, benchmarks and review |
| H-FOC-S1/S2 | QC intersection and conditional handoff safety | Lemma and conditional proof | Live view change, dual QC, adaptive model and PoW finality |
| H-FOC-L1 | Partial-synchrony liveness | Incomplete | Leader, timeout, pacemaker and proof |
| H-SAC-D1/N1 | Targeted disclosure and leakage lower bound | Implementation/sketch and derivation | Canonical inclusion, task distribution, simulation and review |
| H-SAC-C1/S1/Z1 | Provenance completeness/soundness/zero knowledge | Incomplete | Circuit, proof system, vectors, simulator, ceremony and audit |

## 8. Acceptance evidence

Each mechanism must ship a versioned specification, threat model,
language-neutral encoding, positive/negative vectors, reference verifier,
property/fuzz tests, fault injection, raw benchmark data, a formal model or
model-checking result and an independent review. Without raw data it is
"unmeasured". Rust tests directly load the v0 vectors and H-WES lifecycle v1
vector, but this is not a second implementation or external review.

## 9. Verified prior-work entry points

The Chinese section below retains the complete bibliography: Utreexo,
FlyClient, Ethereum state expiry, PHANTOM/GHOSTDAG, Narwhal/Tusk, DAG-Rider,
Prism, HotStuff, FLP, partial synchrony, order-fair consensus, Themis and Zcash
disclosure. The search date is 2026-07-31. These references prove that related
fields exist, not that Hyphen is novel. Formal novelty requires systematic
literature, patent and independent review.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen 研究机制：证明、先验工作与实现章程

状态：预规范（pre-specification），2026-07-31。

本文不是已部署功能声明。四项机制均未进入当前
`hyphen-devnet-v2` 共识。任何激活都必须使用新的研究 profile、链身份、
规范版本和测试向量；在证明义务、攻击测试和独立审查关闭前，不得在
README 或白皮书中写成“已解决”“已证明”或“生产可用”。

## 1. 当前基础与必须先修复的差距

Hyphen 当前是线性 tip、shielded UTXO、持久化 commitment tree 与
nullifier set 的 PoW 链。状态库已经有原子跨树区块提交、持久化单 tip
撤销日志、不可变且带哈希校验的竞争分支区块体存储，以及严格较重工作量
reorg 计划。真实 `Blockchain` 后端会重算计划工作量，持有独占状态转换锁，
先撤回到共同祖先，再通过权威区块接收路径按分叉状态完整重验每个候选块；
候选失败时恢复原分支，数据库重开时自动续跑持久日志。它仍没有 P2P 竞争
分支接入、自动 fork choice 触发、mempool/钱包/浏览器/矿池对账、区块网状融合、
BFT 最终性或完整选择性审计证明。研究链 profile 已将签名 WASM 账本与 H-WES
公共创建/限量过期接入统一状态根和原子 reorg；shielded 恢复/消费仍保持关闭。

因此实现顺序必须是：

1. 冻结可复现编码、状态转换和失败原子性（部分完成，规范编码仍开放）；
2. 实现竞争分支、fork choice 与 rollback（真实后端完成，网络自动化与跨子系统对账未完成）；
3. 再引入 witness-carrying state；
4. 再研究并行生产与融合；
5. 最后在明确的 Sybil resistance 和网络模型上叠加快速排序；
6. 隐私审计电路可并行研究，但必须绑定最终交易编码和状态根。

跳过前两步直接修改 `BlockHeader` 不会产生可证明协议。

基础原语位于 `crates/hyphen-state/src/atomic.rs`、
`crates/hyphen-state/src/branch_store.rs`、
`crates/hyphen-state/src/branch_archive.rs`、
`crates/hyphen-state/src/reorg_journal.rs` 与
`crates/hyphen-consensus/src/chain.rs`。第一模块在一个 sled 事务中提交或撤销
区块体之外的全部规范索引、tip、epoch seed、commitment tree 与 nullifier，
并通过故障注入和“提交 B、撤销 B、重开、重放 B”测试。第二模块持久记录唯一创世根、
不可变父子关系、验证阶段和累计工作量；只有完成分支状态验证且严格重于当前 tip
的候选才会生成 `(common_ancestor, detach, attach)` 计划。同工作量不会按可磨取的
区块哈希切链。第三模块按大小上限保存不可变区块体，并在读取时复核键与实际
区块哈希。第四模块先持久化静态计划，再逐块调用原子后端；进度不另存游标，
而由持久 tip 与不可变路径推断。候选 attach 失败后，它先持久化恢复模式，再移除
候选前缀并按 `reverse(detach)` 恢复旧链。测试覆盖成功切换、detach 后中断续跑、
候选中途失败、恢复中再次中断、非法路径和恢复失败时保留日志。第五模块提供
真实后端：它复核 canonical detach 路径、attach 父子/高度连续性、每块声明工作量
与总工作量，并复用权威 `accept_block_locked` 路径验证难度、PoW、授权、交易、
nullifier 和分叉 ring 状态。端到端后端测试覆盖较重三块分支替换两块旧分支、
非法候选恢复精确旧 tip/commitment root/coinbase bytes、伪造 `new_work` 无状态变更
拒绝，以及数据库重开续跑部分 reorg。它已进入 devnet v2 的线性链管理基础，
但尚无自动 P2P 分支接入/选择、跨子系统对账、操作系统级 kill 测试或形式化状态机
检查，因此仍不能称为完整活动 reorg。

## 2. 统一符号与密码学假设

| 符号 | 唯一定义 |
| --- | --- |
| `lambda` | 安全参数，目标至少 128 bit |
| `H_ds(tag, parts)` | 域分离的 256-bit Blake3：`BLAKE3(tag || 0x00 || parts)`；证明中假设抗碰撞和二次原像 |
| `Sig` | 数字签名方案；证明中假设 EUF-CMA 安全 |
| `t` | 状态转换高度或逻辑时隙 |
| `e` | 状态过期/融合 epoch |
| `k` | 并行生产 lane 数 |
| `n` | 快速排序委员会成员数 |
| `f` | Byzantine 成员上界；BFT 部分要求 `n >= 3f + 1` |
| `Delta` | GST 之后诚实节点间消息传播上界 |
| `L_t` | 高度 `t` 的活跃状态 commitment |
| `V_t` | key 到最新版本/状态的认证注册表 commitment |
| `N_t` | 永不删除的 nullifier accumulator commitment |
| `A_t` | 过期记录的 append-only MMR commitment |
| `D_t` | 状态 blob 数据可用性 commitment |
| `S_t` | 组合状态根 `H_ds("HYPHEN_STATE_V1", L_t || V_t || N_t || A_t || D_t)` |
| `B` | 并行生产区块 |
| `F_e` | epoch `e` 的前序 anchor 与融合 frontier/vector commitment |
| `QC` | 至少 `2f+1` 个委员会签名形成的 quorum certificate |
| `G_v` | Ristretto255 上由域分离 hash-to-point 得到的金额生成元 `G_VALUE` |
| `G_r` | Ristretto255 标准基点，也是 Pedersen blinding 与一次性输出密钥生成元 `G_BLIND` |
| `C(v,r)` | Pedersen commitment `v*G_v + r*G_r` |
| `pi` | 与上下文对应的密码学证明；不同关系不得复用同一域 |

所有共识对象必须使用规范化、语言无关、长度有界的编码。当前 Rust 实现已改用
仓库内的 `hyphen-codec` v1；其固定宽度格式、资源上限和 schema-relative
canonicality 论证见 `crates/hyphen-codec/README.md`。该实现尚未经过独立审计，
跨语言实现也必须以固定测试向量验证，不能仅凭 Rust round-trip 宣称兼容。

## 3. 候选贡献一：H-WES 可恢复过期状态与见证携带执行

暂定名称：Hyphen Witness-Carried Expiring State（H-WES）。名称不构成
学术新颖性声明。

### 3.1 不可回避的安全事实

Hyphen 是 UTXO/Note 模型，不是传统账户模型。“几年没动过的账户”必须
具体化为可过期的状态类别。以下状态不得直接遗忘：

- 已出现的 nullifier/key image；否则旧输出可再次花费；
- 共识参数、发行量和资产发行上限；
- 仍被活跃合约或未决交易引用的状态；
- 证明最新版本所需的认证 commitment。

MMR 只能高效证明“某记录曾被追加”，不能独自证明“它是该 key 的最新
版本”或“它后来没有被花费”。所以恢复证明不能只有 MMR inclusion proof。

### 3.2 状态记录与过期转换

对可过期 key `x`，定义版本化记录：

```text
R = (chain_id, class, x, version, value_hash, owner_policy,
     created_at, lease_end, status)
status in {Live, Expired, Recovered, Consumed}
```

`V_t[x]` 始终承诺最新
`(version, status, archive_index, value_hash, head_hash)`；验证节点
只需保存 `V_t` 的根，证明和 blob 可由交易发送者/存储提供者携带。过期时：

```text
A_{t+1} = MMR.Append(A_t, H_ds("EXPIRED", R))
L_{t+1} = L_t 删除 x
V_{t+1}[x] = (R.version, Expired, A_{t+1}.index, R.value_hash)
```

过期集合必须由按 `lease_end` 认证的 epoch queue 决定，且每块处理量有上限。
不能要求全节点扫描全部状态寻找过期项。

### 3.3 恢复证明

恢复交易携带：

```text
pi_restore = (pi_archive, pi_latest, blob, pi_owner, pi_unspent, pi_availability)
```

- `pi_archive`：记录叶到当前/认可 checkpoint 的 MMR inclusion proof；
- `pi_latest`：`V_t[x]` 的 Merkle/向量承诺证明，证明版本最新且状态为 Expired；
- `blob`：原状态数据，满足 `H(blob) = value_hash`；
- `pi_owner`：满足 `owner_policy` 的签名或零知识所有权证明；
- `pi_unspent`：仅对可花费对象，证明未违反 `N_t`；
- `pi_availability`：恢复后数据已进入规定的数据可用性层的证明/证书。

第一版应使用哈希型 SMT/MMR，接受 `O(log m)` 证明，而不是为了“常数大小”
立即引入未经审查的 pairing/vector commitment。证明大小和验证时间必须实测，
不能把“低”写成没有数字的形容词。

### 3.4 定理与证明义务

**H-WES-S1（旧版本不可复活）**：若 `H` 抗碰撞、`V_t` 的认证路径健全，
且状态转换只接受 `V_t[x].version = version(pi_restore)`，攻击者不能用旧于最新
版本的 archive leaf 恢复 `x`。

证明草图：假设旧版本恢复成功。验证通过意味着旧版本与 `V_t[x]` 承诺的
最新版本相等，或攻击者构造了另一条对同一根有效的路径。前者与“旧于最新”
矛盾，后者给出 `H` 碰撞。因此在假设下成功概率可忽略。状态：规范树编码、
纯 verifier、旧版本负向测试和独立的持久 SMT 已完成；研究 profile 已将 EAOM 五根、
公开创建和有界过期与主链状态统一原子接线，但 shielded recovery/consume 关系和
独立密码学评审仍未完成。

**H-WES-S2（nullifier 单调安全）**：如果 `N_t subseteq N_{t+1}` 且每次花费
在状态提交前检查并插入 nullifier，则状态过期不会使已花费 Note 再次有效。

证明：对任意已在高度 `i` 花费的 nullifier `z`，有 `z in N_i`。由单调性，
对所有 `j > i` 都有 `z in N_j`。恢复/花费规则要求 `z notin N_j`，故第二次
花费被拒绝。状态：数学论证完整；实现尚未有 witness-carrying accumulator，
需状态机测试与外审。

**H-WES-L1（有条件可恢复性）**：若至少一个诚实存储提供者保留 `blob` 和更新
见证，且数据可用性假设成立，则合法 owner 能构造恢复交易。若所有提供者都
删除或扣留 `blob`，任何 commitment 都不能从信息论上恢复原文。因此白皮书
不得声称无条件数据恢复。

### 3.5 代码落点

- `hyphen-state`：状态 commitment、版本注册表、expiry queue、witness verifier；
- `hyphen-tx`：状态 witness 与恢复交易类型；
- `hyphen-consensus`：原子验证/应用/rollback；
- `hyphen-network`：有界 witness/blob 传输和 DoS 预算；
- 新研究 profile：不得原地修改 `hyphen-devnet-v2`。

首个未激活参考实现位于 `crates/hyphen-state/src/expiring_state.rs`，跨语言
向量位于 `test-vectors/h-wes-v0.json`。它已经固定 159 字节记录编码、确定性
到期顺序、MMR 包含证明、最新版证明、恢复/消费终态和原子恢复转换，并覆盖
旧版本、终态复活、篡改证明、授权上下文替换与重复 nullifier 的负向测试。
研究 profile 已把五根、公开创建和有界过期接入持久主链状态与原子 rollback。
配套的持久命名空间 SMT、认证 blob/chunk proof store、P2P proof serving 以及 DA
证书验证器已经实现，但 DA 证书只证明诚实签名者在签名时取得完整 blob，不证明未来
持续保存。shielded Note 的零知识恢复/消费关系仍不存在。因此当前状态仍是受限研究
profile 生命周期，不是生产可用的完整 H-WES 协议。

原始“四条件不可能性”缺少 succinctness，完整 archive 单轮扫描是反例。补强
后的 membership-only 黑盒后缀查询下界、EAOM 生命周期、线性化点、授权关系、
安全游戏和复杂度表见
[`h-wes-theorem-and-object-model.md`](h-wes-theorem-and-object-model.md)。当前代码
已加入 action/height/lease/pre-state 绑定、恢复终态回执、消费终态和
no-resurrection 测试；持久 SMT、五根和公开创建/过期已接入研究 profile，shielded
恢复/消费、长期 DA challenge/repair 和独立审查仍未完成。

## 4. H-BFM 规范融合机制与隐私可见域公平候选

暂定名称：Hyphen Braided Fusion Mesh（H-BFM）。它不能使用 PHANTOM/
GHOSTDAG 的 blue-set 排序或把“block DAG”本身作为创新声明。

### 4.1 与 Kaspa/GHOSTDAG 的结构性区别目标

H-BFM 候选设计把并行区块视为可用性与执行批次，不把 DAG 蓝色集合当作
PoW fork choice：

1. epoch `e` 有 `k` 个确定性 lane；
2. lane block 只延长本 lane，并引用上一融合 checkpoint；
3. block 可以声明其已见的其他 lane frontier，形成 braid edges；
4. epoch 结束时共识确定唯一 frontier vector `F_e`；
5. 对 `F_e` 可达的可用区块执行规范化拓扑排序；
6. 所有及时、有效、数据可用的区块可获得 inclusion credit，但冲突交易仅有
   一个成功执行，奖励必须限制重复/无效 payload 的刷量收益。

这仍需与 Prism、Chainweb、Narwhal/Tusk、DAG-Rider、Bullshark、OHIE、
Blockmania 等逐项对比。在 prior-art 审查完成前，只能称候选协议。

### 4.2 规范化融合

对融合可达集合 `G_e = (B_e, E_e)`，边 `u -> v` 表示 `v` 因果引用 `u`。
定义 rank：

```text
rank(B) = (logical_round(B), lane(B), H(canonical_block(B)))
```

融合顺序 `Order(G_e)` 是 Kahn 拓扑排序，但在每一步从零入度集合中选择最小
`rank`。交易按区块顺序及区块内索引排序。对同一 nullifier/状态 key 的冲突，
第一个通过状态转换者成功，后续者产生确定性失败 receipt。

**H-BFM-S1（确定性融合）**：若两个诚实验证者拥有相同的 `G_e`、规范编码和
前置状态 `S`, 则其 `Order(G_e)` 与最终状态相同。

证明：有限 DAG 必有零入度节点；`rank` 是全序，因此每一步选择唯一。删除同一
节点及其边后归纳得到唯一序列。确定性状态转换对同一序列和 `S` 输出同一结果。
状态：排序证明完整；“诚实节点获得相同 `G_e`”依赖下节 set-agreement/DA，
整个协议安全性尚未证明。

**H-BFM-S2（无传统孤块损失，有条件）**：若区块在 cutoff 前获得数据可用性
证书且属于最终 frontier 的可达闭包，则其非冲突有效交易进入融合序列。该性质
不覆盖延迟、扣留、无证书或违反 lane 规则的区块，也不承诺冲突交易成功。

### 4.3 必须解决的开放问题

- permissionless lane 分配与抗 Sybil；
- withheld block、equivocation 和跨 lane 双花；
- frontier set agreement 和数据可用性；
- inclusion credit 不诱发垃圾区块；
- 与 PoW chain weight、难度和发行的唯一关系；
- 深 reorg 时整个 mesh、状态、mempool 的原子 rollback。

在这些问题关闭前，不得宣称“消除孤块”或“无限并行”。

首个未激活融合参考模型位于 `crates/hyphen-consensus/src/fusion.rs`，跨语言
向量位于 `test-vectors/h-bfm-v0.json`。它已经实现 certified frontier 的
可达闭包、每 lane 唯一链、规范拓扑序、原子冲突回执以及输入排列不变性
测试。它把区块 ID 和 DA 证书验证作为显式前置条件，尚未实现 frontier
set agreement、permissionless lane 分配、奖励或网络协议，所以不能据此
声称整个 mesh 共识已经完成。

规范拓扑排序本身不再列为新颖性贡献。继续研究的候选性质是：只对
`(txid,fee_class,encoded_len,public_conflict_tag)` 可见投影聚合签名接收序列，
以 `2f+1` 强证据生成 pairwise edge，把 cycle 收缩成 fair batch，并明确放弃对
隐藏金额、地址和语义的 fairness 声明。定义、证明、局部 MEV 边界和代码状态见
[`private-visible-fair-ordering.md`](private-visible-fair-ordering.md)。参考实现位于
`crates/hyphen-consensus/src/private_fair_ordering.rs`，尚未接入 fusion 或区块。

## 5. 候选贡献二：H-FOC' 动态委员会公平排序证书

暂定名称：Hyphen Fast Ordering Certificates（H-FOC）。

### 5.1 不可能性与诚实指标

无条件的“全球几百节点 100ms 最终一致”不可证明：

- 在完全异步模型中，即使只有一个 crash fault，确定性共识也可能不终止
  （FLP）；
- 在部分同步模型中，最终性时间受实际 `Delta` 和协议通信轮数下界约束；
- permissionless 网络若没有 PoW/PoS/身份等 Sybil resistance，`n` 与 `f` 没有
  可执行定义。

因此目标必须拆成：

```text
T_preorder_p50 <= 100 ms     # 正常网络下的非最终预排序回执
T_final_p95 <= r*Delta + T_verify + T_queue
```

其中 `r` 是最终协议所需的广域网消息轮数。任何性能声明必须同时发布地区、
节点数、带宽、丢包、`Delta` 分布、Byzantine 比例和失败样本。

### 5.2 候选安全核心

委员会大小 `n = 3f+1` 个工作量 seat，quorum 大小 `q = 2f+1`。每个 seat 对
`(chain_id, epoch, committee_id, view, slot, parent_frontier, order_root)` 签名。
锁定规则禁止诚实控制者在同一安全阶段为冲突 order root 投票。

**H-FOC-S1（QC 交集安全）**：把 quorum 定义为 seat 索引集合。任意两个大小为
`2f+1` 的 quorum 在 `n=3f+1` 个 seat 中至少相交 `f+1` 个 seat。

证明：`|Q1 intersect Q2| >= |Q1| + |Q2| - n = 4f+2-(3f+1)=f+1`。
若攻击者控制至多 `f` 个 seat，则交集中至少一个 seat 由诚实密钥控制。结合
“同一密钥拥有的所有 seat 复用同一决定”的锁定规则，该密钥不能为两个冲突值
签名，从而排除冲突 QC。状态：组合证明完整；完整安全性还需指定 view-change、
锁定阶段和签名聚合。

**H-FOC-L1（部分同步活性）**：GST 后若诚实 leader 持续至少协议所需轮数，
且诚实消息在 `Delta` 内送达，则在有界时间内形成 QC。状态：待选定 leader
选举、timeout 和 view-change 后给出完整证明。

### 5.3 去中心化前提

快速 BFT 不能凭空获得 permissionless 身份。研究必须从以下方案中选一个并
公开权衡：

- 由前一 PoW epoch 的不可转移工作证明抽样短期委员会；
- 所有节点参与数据传播，随机轮换的小委员会只签排序；
- PoW checkpoint 对快速排序提供最终回退，委员会失败时链继续但降速。

“几百节点”不是去中心化证明。必须测量运营者集中度、地区/ASN、委员会控制
概率和审查恢复时间。

当前未激活参考模型选择第一种方案：从上一个已最终确认 PoW epoch 中按已验证
工作量有放回抽取 `n=3f+1` 个 seat；同一矿工公钥可以拥有多个 seat，因此安全
假设是“攻击者控制不超过 `f` 个工作量 seat”，不是“不超过 `f` 个节点”。若
攻击工作量份额为 `alpha`，并在随机预言机下独立抽样，则委员会失陷概率为：

```text
P_bad(n,f,alpha) = sum_{i=f+1}^{n} binom(n,i)
                   * alpha^i * (1-alpha)^(n-i)
```

该概率必须随 profile 参数公开。直接使用可被矿工选择的末块哈希会引入 seed
grinding；在确定不可偏置或可验证延迟的 epoch 随机源、处理自适应腐化并给出
完整 view-change/locking 证明前，H-FOC 只能签发非最终预排序证书。

参考安全内核位于 `crates/hyphen-consensus/src/fast_ordering.rs`，向量位于
`test-vectors/h-foc-v0.json`。它实现工作量聚合和无模偏抽样、真实 Ed25519
seat 签名、`2f+1` 门限、重复 seat 拒绝和同一
`(epoch, view, slot)` 防双签。投票者和证书验证器都显式绑定预期 `chain_id`，
并拒绝没有可表示后继值的 `source_epoch`。它没有证明或实现 100ms WAN 最终性；
100ms 仍是必须通过公开部署条件和原始延迟样本验收的 `T_preorder_p50` 指标。

固定委员会交集不证明跨 epoch 安全。候选 H-FOC' 需要 old/new committee 对同一
finalized PoW checkpoint 的双 QC handoff，并把 fairness evidence root 纳入
prepare/commit lock。完整动态抽样、grinding 上界、handoff 归纳证明和性能式见
[`private-visible-fair-ordering.md`](private-visible-fair-ordering.md)。当前代码没有
view-change/handoff，因此不能称为 BFT finality layer。

## 6. 候选贡献三：H-SAC 任务条件选择性透明

暂定名称：Hyphen Selective Audit Capabilities（H-SAC）。它不是监管后门，
不得存在链级 master decryption key。

### 6.1 两种不同能力

1. **选择性明文披露**：用户对指定交易/时间范围生成 capability，审计者可验证
   对应 commitment 的金额、所有权和链上包含性；
2. **零知识来源合规证明**：用户证明真实输入属于某个公开 policy root 所承诺的
   合法来源集合，但不公开真实 ring index 或其他交易。

密码学最多证明“满足给定链上/外部认证谓词”，不能证明现实世界中抽象的
“资金绝对合法”。政策签发者、名单准确性和现实身份绑定属于外部信任假设。

### 6.2 审计关系

公开输入：

```text
X = (chain_id, txid, selected_output_commitments,
     input_nullifiers, policy_root, scope_hash, expiry)
```

私有 witness：

```text
W = (values, blindings, spend_secrets, real_ring_indices,
     ownership_paths, policy_membership_paths, disclosure_nonce)
```

证明关系 `R_audit(X,W)=1` 至少约束：

```text
C_i = C(values_i, blindings_i)
nullifier_j = NF(spend_secret_j, real_output_j)
real_output_j 位于交易声明的 ring
real_output_j 对应的来源 credential 位于 policy_root
scope_hash = H(规范化披露范围)
sum(inputs) = sum(outputs) + fee
```

审计包必须绑定 chain identity、txid、审计者公钥、scope 和 expiry，防止跨链、
跨审计者和扩大范围重放。

### 6.3 安全性质

**H-SAC-C1（完备性）**：合法交易 owner 持有满足关系的 witness 时，验证接受。

**H-SAC-S1（健全性）**：不知道有效 opening/ownership/policy witness 的攻击者
生成可接受证明的概率可忽略。该结论依赖所选证明系统的 knowledge soundness、
commitment binding 和 hash/signature 假设。

**H-SAC-Z1（范围外零知识）**：对相同公开输入与披露结果，存在 PPT simulator
在不知道范围外 witness 时生成与真实证明计算不可区分的 transcript。只有在
最终电路、公共输入和证明系统确定后才能给出正式 simulator/归约。

当前自研 range proof 和 CLSAG 代码不能自动提供上述 provenance 证明。首个
原型必须选用成熟、维护中且可审计的通用证明系统，固定电路与参数生成流程，
发布测试向量，并接受独立密码学审查。

### 6.4 已实现的有限披露能力与证明边界

`crates/hyphen-wallet/src/audit.rs` 已实现未激活的单输出选择性披露，编码向量
位于 `test-vectors/h-sac-disclosure-v0.json`。披露包公开 `(value, blinding)`，
验证 `C = value*G_v + blinding*G_r`，并用一次性输出公钥 `P=xG_r` 的 Schnorr
知识证明绑定 chain ID、当前交易哈希、输出索引、审计者公钥、scope、有效期
和随机 nonce。设 prover 取 `k`，发送 `R=kG_r`，令
`c=H(context,R,P)`、`s=k+c*x`；验证等式为：

```text
s*G_r = R + c*P
```

生成器要求 `x != 0`、`k != 0` 和 `c != 0`；验证器拒绝恒等点公钥、恒等点
nonce 和非规范响应标量，避免把公开的零标量误写成排他所有权证明。

完备性直接由 `s*G_r=(k+c*x)G_r=R+cP` 得到。对相同 `R` 的两个接受 transcript
`(c,s)` 与 `(c',s')`，若 `c != c'`，可提取
`x=(s-s')/(c-c')`；在随机预言机模型下结合 forking lemma 得到知识健全性。
金额打开的唯一性依赖 Pedersen commitment binding，即攻击者不知道 `G_v` 与
`G_r` 间的离散对数关系。

这不是零知识 provenance 证明：金额和 blinding 会明文披露，包本身不加密，
审计者泄露后任何持包者都可读取。当前交易哈希使用 `hyphen-codec` v1 的固定
schema 编码；链上包含性和 `global_index` 仍必须由区块/状态证明另行验证。它只证明“该用户拥有并
正确打开这个输出”，不证明现实资金来源合法，也不披露 ring 中真实输入。
完整 H-SAC 仍需经审计的通用证明系统、policy credential 语义、正式电路和
独立审查。

对私有状态 `X`、事前公开链信息 `P`、任务输出 `Y=F(X,P)` 和 adversary view
`V`，零错误正确性要求 `I(X;V|P)>=H(Y|P)`；允许错误时由 Fano inequality 减去
`h_2(epsilon)+epsilon log_2(M-1)`。达到该下界需要 transcript 可仅由 `(P,Y)`
模拟。完整推导、组合查询泄漏和当前 v0 偏离程度见
[`h-sac-leakage-lower-bound.md`](h-sac-leakage-lower-bound.md)。

## 7. 证明账本

| ID | 性质 | 当前状态 | 关闭条件 |
| --- | --- | --- | --- |
| BASE-R1 | 静态 reorg 计划可崩溃续跑或恢复旧链 | 真实后端、分叉状态重验、恢复与数据库重开测试完成 | P2P 自动接入/选择、mempool/钱包/浏览器/矿池对账、操作系统级 kill/reopen、形式化状态机检查和多节点故障演练 |
| H-WES-N0 | 安全恢复语义蕴含 latest 认证能力 | 定理与黑盒构造完成 | 独立形式化评审 |
| H-WES-N1 | membership-only archive 后缀查询下界 | 黑盒 cell-probe 证明完成 | 随机化/批证明模型扩展与同行评审 |
| H-WES-S1 | 旧版本不可复活 | reference verifier、五根持久化、公共创建/过期与原子 reorg 测试完成 | shielded 恢复关系、外审 |
| H-WES-S2 | nullifier 单调防双花 | 参考模型与持久五根已接线 | shielded consume 电路、执行交易、外审 |
| H-WES-L1 | 有条件恢复 | 明确假设 | DA 协议、扣留演练、恢复基准 |
| H-BFM-S1 | 同集合确定性融合（非新颖性声明） | 证明及参考模型完成 | set agreement、状态机模型检查 |
| H-BFM-S2 | 有证书区块可融合 | 候选性质 | cutoff/DA/奖励规则与攻击仿真 |
| VF-S1 | visible strong edge 不冲突、cycle 形成 batch | 证明及签名 evidence 模型完成 | P2P receipt 强制纳入/遗漏追责、seed、benchmark、外审 |
| H-FOC-S1 | QC 交集安全 | 引理及预排序证书模型完成 | 完整锁定/view-change 安全证明 |
| H-FOC-S2 | old/new committee handoff 安全 | 条件归纳证明 | 双 QC 实现、自适应腐化模型、PoW finality |
| H-FOC-L1 | 部分同步活性 | 未完成 | leader/timeout 协议和活性证明 |
| H-SAC-D1 | 单输出定向披露 | 实现及证明草图完成 | 规范交易编码、链包含证明、外审 |
| H-SAC-N1 | 合规任务最小条件互信息泄漏 | 零错误及 Fano 版本推导完成 | 分布/任务实例、simulation proof、同行评审 |
| H-SAC-C1 | provenance 审计完备性 | 未完成 | 电路、证明系统、正向向量 |
| H-SAC-S1 | provenance 审计健全性 | 未完成 | 正式关系、归约、外审 |
| H-SAC-Z1 | 范围外零知识 | 未完成 | simulator、参数仪式与泄漏分析 |

## 8. 验收证据

每项机制必须同时交付：版本化规范、威胁模型、语言无关编码、正/负测试向量、
reference verifier、属性测试/fuzz、故障注入、基准原始数据、形式化模型或模型
检查结果、独立审查报告。没有原始数据时只能写“未测量”。

五个 v0 JSON 向量和 H-WES lifecycle v1 向量现在由各自 Rust 参考测试直接
读取并核对，不再只做 JSON 语法检查。该门禁曾发现并修正 H-BFM 向量中的
30 字节伪区块 ID；所有协议哈希
字段必须是完整 32 字节。向量联动通过仍不等于第二个独立实现或外部审查。

建议最先实现 H-WES 的纯函数状态模型和 H-BFM 的确定性融合模型；两者都能在
不激活网络共识的条件下产生测试向量。H-FOC 必须等待 Sybil resistance 和网络
假设决定；H-SAC 必须等待交易编码稳定和证明系统选型。

## 9. 已核验的先验工作入口

以下入口仅证明研究领域已有相关工作，不证明 Hyphen 的候选设计新颖：

- Thaddeus Dryja, *Utreexo: A dynamic hash-based accumulator optimized for
  the Bitcoin UTXO set*, IACR ePrint 2019/611:
  <https://eprint.iacr.org/2019/611>
- Benedikt Bunz et al., *FlyClient: Super-Light Clients for Cryptocurrencies*,
  IACR ePrint 2019/226: <https://eprint.iacr.org/2019/226>
- Ethereum, *Statelessness, state expiry and history expiry*:
  <https://ethereum.org/en/roadmap/statelessness/>
- Yonatan Sompolinsky et al., *PHANTOM and GHOSTDAG*, IACR ePrint 2018/104:
  <https://eprint.iacr.org/2018/104>
- George Danezis et al., *Narwhal and Tusk*, arXiv:2105.11827:
  <https://arxiv.org/abs/2105.11827>
- Ittai Abraham et al., *DAG-Rider / All You Need is DAG*, arXiv:2102.08325:
  <https://arxiv.org/abs/2102.08325>
- Vivek Bagaria et al., *Prism*, arXiv:1810.08092:
  <https://arxiv.org/abs/1810.08092>
- Maofan Yin et al., *HotStuff*, arXiv:1803.05069:
  <https://arxiv.org/abs/1803.05069>
- Fischer, Lynch, Paterson, *Impossibility of Distributed Consensus with One
  Faulty Process*, JACM 1985: <https://doi.org/10.1145/3149.214121>
- Dwork, Lynch, Stockmeyer, *Consensus in the Presence of Partial Synchrony*,
  JACM 1988: <https://doi.org/10.1145/42282.42283>
- Kelkar et al., *Order-Fairness for Byzantine Consensus*, CRYPTO 2020:
  <https://doi.org/10.1007/978-3-030-56877-1_16>
- *Order-Fair Consensus in the Permissionless Setting*, AFT 2022:
  <https://doi.org/10.1145/3494105.3526239>
- Zhang et al., *Themis: Fast, Strong Order-Fairness in Byzantine Consensus*,
  CCS 2023: <https://doi.org/10.1145/3576915.3616658>
- *Separation is Good: A Faster Order-Fairness Byzantine Consensus*, NDSS 2024:
  <https://doi.org/10.14722/ndss.2024.24693>
- Zcash Protocol Specification and ZIP-310 payment disclosure:
  <https://zips.z.cash/protocol/protocol.pdf> and <https://zips.z.cash/zip-0310>

检索日期为 2026-07-31。正式新颖性结论还需要系统文献检索、专利检索和独立
评审；不得用本清单替代。
