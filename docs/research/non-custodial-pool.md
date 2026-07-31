# Hyphen Non-Custodial Pool Protocol

Status: experimental protocol v3. It reduces delegated block authority, but
does not yet provide a complete trustless shared-pool system.

## Objective

Hyphen separates two powers that conventional pools often combine:

```text
shared reward variance reduction
AND
miner-held final block authorization
```

The pool can account for shares, operate VarDiff, relay templates, and provide
PPLNS/PPS/FPPS calculations. It cannot produce a consensus-valid block for a
miner unless that miner authorizes the exact solved header and reward keys.

This document calls the node-to-pool Template Provider protocol TP v2 and the
pool-to-miner protobuf protocol Pool v3. Legacy Stratum V1 is a local share-only
adapter; it cannot carry the frozen block authorization and is forbidden on
mainnet mode.

## Roles and trust boundaries

- The node validates consensus and supplies a chain-bound base template.
- The pool authenticates miners, maintains share difficulty, relays work, and
  records settlement events.
- The miner owns an Ed25519 protocol identity and a separate `hy1...` payout
  address. It validates each job before spending work.
- The chain accepts only blocks with a valid miner block authorization.

Pool and miner identity keys are raw 32-byte protocol secrets. They are not
wallet seeds and do not replace wallet backup.

## Protocol flow

1. TP v2 binds signed requests and templates to network magic, consensus
   parameters hash, and genesis hash.
2. Pool v3 login sends the miner identity, payout view/spend public keys,
   thread count, and the same chain identity.
3. The pool personalizes the header with the miner public key and advertises
   exact reward keys, transaction blobs, transaction root, difficulty, epoch
   seed, arena size, and page size.
4. The miner recomputes the transaction root and rejects chain, header,
   difficulty, arena, miner-key, or reward-key mismatches. A shared mode may
   redirect coinbase to the pool wallet only when the miner explicitly starts
   with `--allow-shared-reward-recipient`.
5. The miner evaluates PoW. Ordinary shares carry no reusable block
   authorization. A full-block solution carries `BlockAuthorization` signed by
   the miner over the full solved header, chain identity, and reward keys.
6. The pool recomputes PoW and verifies miner authorization before relaying a
   full block to the node.
7. Every accepted share result has a pool-signed envelope and a hash-chain
   receipt committing to pool identity, miner identity, sequence, previous
   receipt, exact submission hash, and exact result hash. The miner recomputes
   the receipt and keeps a bounded queue of unanswered submissions.

## Implemented properties

| Property | Current enforcement |
| --- | --- |
| Share identity binding | Signed envelopes and per-session sender checks |
| Replay resistance | Signed envelope nonce/freshness checks and a 4,096-entry submission-nonce window |
| Miner-specific work | Header commits the miner public key |
| Template integrity after receipt | Miner recomputes the transaction root and validates all advertised metadata |
| Reward redirection resistance | Miner checks payout keys; consensus authorization commits exact reward keys |
| Pool cannot finish a block alone | Consensus requires the miner's authorization over the solved header |
| Share omission/substitution detection | Miner-verified, sequence-linked share receipts |
| Publicly inspectable local accounting | Wallet-scoped HTTP summaries and persisted settlement history |
| Ledger crash recovery | Atomic next-file replacement plus last committed backup recovery |

These properties mean a pool cannot take an already authorized solution and
change its transactions, reward address, chain, or miner identity. They do not
mean the pool has no remaining control.

## Attack analysis and open work

| Attack | Status | Remaining work |
| --- | --- | --- |
| Share stealing | Mitigated for identity substitution and payload replay | Test hostile proxies, reconnect races, and same-identity key compromise |
| Template hijacking | Post-delivery mutation is detected | Pool currently chooses the transaction list it sends; miner-originated job declaration is not exposed through Pool v3 |
| Pool censorship / MEV | Not solved | Add miner-selected transaction sets or direct miner-to-TP job declaration with bounded validation and fallback nodes |
| Block withholding by miner | Not solved | Economic detection/penalties require a formal model and cannot prove a private solution existed |
| Block withholding by pool | Not solved | Miner needs a safe direct submission path or encrypted/adaptor relay design after finding a block |
| Clandestine pools | Not solved | Non-transferability against deliberate off-protocol work sale needs a separate cryptographic construction and impossibility analysis |
| Payout griefing | Receipts expose accepted-share omission or mutation | Shared balances still depend on the operator to create on-chain payouts |
| Ledger forgery | Local snapshot recovery and miner receipts improve auditability | Publish append-only checkpoints, inclusion proofs, independent mirrors, and reconciliation tooling |
| Pool hopping | PPLNS uses a work-weighted trailing window | Strategy simulation and parameter calibration are still required; PROP/PPS economics remain operator-dependent |

The present shared modes (`prop`, `pps`, `pplns`, `pps+`, `fpps`) produce
internal `pending_payout_atomic` entries. No automatic transaction builder,
broadcaster, confirmation tracker, reserve proof, or solvency guarantee exists.
Those entries MUST NOT be represented as wallet funds or completed payments.

## Next protocol milestone

A Pool v4 proposal should be evaluated before implementation and should include:

1. Miner-declared transaction sets with deterministic size/fee policy and TP
   validation, without allowing unbounded parsing or memory use.
2. Direct full-block fallback submission that does not expose a transferable
   solution before miner authorization is fixed.
3. Periodic Merkle commitments to accepted share receipts and settlement
   events, with miner inclusion proofs and independent archival mirrors.
4. A specified payout transaction state machine: constructed, signed,
   broadcast, confirmed, reorged, retried, and reconciled.
5. Simulation and fault injection for withholding, delayed replies, reordered
   receipts, disk corruption, pool hopping, and adversarial VarDiff changes.

Activation requires a standalone specification, test vectors, a reference
verifier, cryptographic review, and evidence that each claimed property follows
from the protocol rather than from operator policy.

## Novelty discipline

The miner-bound authorization plus auditable share-receipt chain is
project-specific work, not proof of academic novelty or patent freedom. A
novelty claim requires a documented prior-art search and independent review
against at least decentralized pool protocols, job-declaration protocols,
blind/adaptor signatures, non-outsourceable puzzles, and payment-channel or
commitment-ledger systems. Standard cryptographic primitives should remain in
reviewed libraries; reimplementing them merely to look different would reduce
security.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen 非托管矿池协议

状态：实验性协议 v3。它减少了委托的区块权限，但尚未提供完整的无信任共享矿池系统。

## 目标

Hyphen 将传统矿池经常合并的两种权力分开：

```text
共享奖励方差降低
以及
矿工持有最终区块授权
```

矿池可以统计 share、运行 VarDiff、转发 template 并提供 PPLNS/PPS/FPPS 计算。除非矿工授权精确的已求解区块头和奖励密钥，否则矿池不能为该矿工生成共识有效区块。

本文把 node-to-pool Template Provider 协议称为 TP v2，把 pool-to-miner protobuf 协议称为 Pool v3。旧 Stratum V1 只是本地 share adapter，无法携带冻结区块授权，在 mainnet 模式下禁用。旧的 `--standalone` 内置伪链同样 fail-closed 禁用；生产入口必须连接真实主链 Template Provider。

## 角色和信任边界

- 节点验证共识并提供绑定链的基础 template。
- 矿池认证矿工、维护 share 难度、转发工作并记录结算事件。
- 矿工拥有 Ed25519 协议身份和独立的 `hy1...` 收款地址，并在消耗工作量前验证每个 job。
- 链只接受带有有效矿工区块授权的区块。

矿池和矿工身份密钥是原始 32 字节协议 secret，不是钱包种子，也不能替代钱包备份。

## 协议流程

1. TP v2 把签名请求和 template 绑定到 network magic、共识参数哈希和创世哈希。
2. Pool v3 登录发送矿工身份、收款 view/spend 公钥、线程数和相同链身份。
3. 矿池以矿工公钥个性化区块头，并公布精确奖励密钥、交易 blob、交易根、难度、epoch seed、arena 大小和 page 大小。
4. 矿工重算交易根，并拒绝链、区块头、难度、arena、矿工密钥或奖励密钥不匹配。只有矿工明确以 `--allow-shared-reward-recipient` 启动时，共享模式才可把 coinbase 重定向到矿池钱包。
5. 矿工计算 PoW。普通 share 不携带可复用区块授权。完整区块解携带 `BlockAuthorization`，由矿工对完整已求解区块头、链身份和奖励密钥签名。
6. 矿池重算 PoW 并验证矿工授权，然后才把完整区块转发给节点。
7. 每个接受的 share 结果具有矿池签名 envelope 和 hash-chain receipt，承诺矿池身份、矿工身份、序号、前一 receipt、精确提交哈希和精确结果哈希。矿工重算 receipt，并保留有界的未回答提交队列。

## 已实现性质

| 性质 | 当前强制方式 |
| --- | --- |
| Share 身份绑定 | 签名 envelope 与逐 session sender 检查 |
| 重放抵抗 | 签名 envelope nonce/新鲜度检查及 4,096 项 submission nonce 窗口 |
| 矿工特定工作 | 区块头承诺矿工公钥 |
| 接收后的 template 完整性 | 矿工重算交易根并验证所有公布元数据 |
| 奖励重定向抵抗 | 矿工检查收款密钥；共识授权承诺精确奖励密钥 |
| 矿池不能独自完成区块 | 共识要求矿工对已求解区块头授权 |
| Share 遗漏/替换检测 | 矿工验证的序列链接 share receipt |
| 可公开检查的本地账目 | 按钱包划分的 HTTP summary 和持久化结算历史 |
| 账本崩溃恢复 | 原子 next-file 替换与最近已提交备份恢复 |

这些性质意味着矿池不能拿已授权解去更换交易、奖励地址、链或矿工身份，但并不意味着矿池不再有控制权。

## 攻击分析与未完成工作

| 攻击 | 状态 | 剩余工作 |
| --- | --- | --- |
| Share stealing | 缓解身份替换和 payload 重放 | 测试恶意代理、重连竞态及同身份密钥泄露 |
| Template hijacking | 可检测交付后修改 | Pool v3 尚未暴露矿工发起的 job declaration，矿池仍选择发送的交易列表 |
| 矿池审查/MEV | 未解决 | 增加矿工选择交易集，或矿工直连 TP 的 job declaration，并提供有界验证和备用节点 |
| 矿工扣留区块 | 未解决 | 经济检测/惩罚需要正式模型，且不能证明私人解曾存在 |
| 矿池扣留区块 | 未解决 | 矿工找到区块后需要安全直提路径，或加密/adaptor relay 设计 |
| 隐蔽矿池 | 未解决 | 针对有意协议外出售工作、实现不可转移性，需要独立密码构造和不可能性分析 |
| 付款阻挠 | Receipt 暴露接受 share 的遗漏或修改 | 共享余额仍依赖运营者创建链上付款 |
| 账本伪造 | 本地快照恢复和矿工 receipt 改善可审计性 | 发布 append-only checkpoint、inclusion proof、独立 mirror 和对账工具 |
| Pool hopping | PPLNS 使用工作量加权尾窗口 | 仍需策略模拟和参数校准；PROP/PPS 经济性仍取决于运营者 |

当前共享模式（`prop`、`pps`、`pplns`、`pps+`、`fpps`）生成内部 `pending_payout_atomic` 项。自动交易构建器、广播器、确认跟踪器、储备证明和偿付保证均不存在。这些项不得被表示为钱包资金或已完成付款。

账本加载采用 fail-closed：主状态和备份同时无法规范解码时，进程必须停止，不能静默创建空账本。旧的非规范 map 存储若无法迁移，也不能通过清空状态继续运行。

## 下一协议里程碑

Pool v4 提案应先评估后实现，并包括：

1. 矿工声明的交易集和有界 TP 验证。
2. 不在固定矿工授权前暴露可转移解的完整区块直提 fallback。
3. 接受 share receipt 与结算事件的周期 Merkle commitment、矿工 inclusion proof 和独立归档 mirror。
4. 包含 constructed、signed、broadcast、confirmed、reorged、retried 和 reconciled 的付款交易状态机。
5. 针对扣留、延迟回复、receipt 重排、磁盘损坏、pool hopping 和恶意 VarDiff 的模拟与故障注入。

激活需要独立规范、测试向量、参考 verifier、密码学审查，以及每项声明来自协议而非运营者政策的证据。

## 新颖性纪律

绑定矿工的授权与可审计 share-receipt 链是项目特定工作，不证明学术新颖性或专利自由。新颖性声明至少需要针对去中心矿池协议、job-declaration 协议、blind/adaptor 签名、non-outsourceable puzzle 和 payment-channel/commitment-ledger 系统开展有记录的现有技术检索和独立审查。标准密码原语应继续使用经过审查的库；仅为显得不同而重写会降低安全性。
