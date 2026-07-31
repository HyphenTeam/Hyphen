# Incentivized Testnet Readiness and Monitoring

Status: proposed operations gate. The current node is suitable for local
devnet experiments, but not yet for an incentivized public testnet. Persistent
branch metadata, bounded immutable branch-body storage, heavier-work planning,
and atomic rollback now feed a real `Blockchain` reorg backend. Backend tests
cover a successful heavier branch, candidate-validation failure with exact old
state restoration, forged-work rejection without mutation, and database-reopen
recovery. Live P2P branch ingestion, automatic fork-choice triggering,
dependent-subsystem reconciliation, and multi-node fault evidence are still
missing.

## Entry blockers

Do not attach monetary value or public rewards until the following are
implemented and tested:

- bounded live P2P competing-branch ingestion and automatic cumulative-work
  fork-choice triggering, using the existing fork-state validation and
  crash-recoverable multi-block backend;
- deterministic reorg reconciliation for the mempool, wallet, explorer, and
  pool settlement, plus process-kill/reopen and multi-node partition evidence;
- authenticated and rate-limited public RPC/pool edges;
- automatic pool payout lifecycle or a testnet-only statement that balances
  have no monetary value;
- reproducible builds and signed release artifacts;
- independent consensus, cryptography, wallet, and network review; and
- incident response, vulnerability disclosure, and operator runbooks.

## Phased rollout

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| Local devnet | One host, deterministic identity, smoke/replay/fault tests | Repeatable clean start, mining, export, verify, and replay |
| Private multi-node | At least 5 nodes under 3 independent operators | Partition/reconnect and deep-reorg drills with identical final state |
| Public no-value testnet | Permissionless peers, faucets only | 30 continuous days, published dashboards and incident log |
| Small incentive pilot | Capped rewards and explicit loss limits | 60 continuous days with all thresholds below and no unresolved critical issue |

Durations are minimum observation windows, not proof of security.

## Required metrics

Every release must label metrics by binary version, chain identity, operator,
and region without collecting wallet seeds, IP histories longer than needed, or
transaction metadata beyond the published privacy policy.

| Area | Measurements | Initial alert |
| --- | --- | --- |
| Reorgs | count, depth, replaced work, convergence time | any depth >= 3; any node divergence > 2 target blocks |
| Orphans | blocks mined, accepted, orphaned by miner/pool | 1-hour rate > 5% or 24-hour rate > 2% |
| P2P | peers, churn, dial failures, gossip rejects, duplicate/malformed frames | peer count < 4 for 10 minutes; reject spike 5x baseline |
| PoW | solve-time distribution, reported/observed work, hardware class | median block interval outside 0.7x-1.3x target for 6 hours |
| Concentration | blocks and accepted work by pool/miner/operator | one pool > 35% for 24 hours; top 3 > 70% |
| Sync | initial sync time, CPU, peak RSS, disk growth, bandwidth | regression > 25% release-over-release |
| Pool ledger | accepted/rejected shares, receipt gaps, pending payouts, recovery source | any receipt-chain gap or unexplained balance delta |
| Wallet | scan lag, failed sends, restore/rescan time, mobile crashes | restore mismatch; crash-free sessions < 99.5% |

Thresholds are starting operational limits and should be changed only from
published measurements, never silently.

## Mandatory drills

Run and retain reports for:

1. Network split with unequal work, reconnection, fork choice, and state-root
   convergence.
2. Timestamp reversal/future-time and oscillating-hashrate simulations.
3. Malformed transaction, RPC, P2P, pool, and TP corpora plus bounded fuzzing.
4. Pool primary-ledger truncation, backup recovery, reordered/missing receipts,
   delayed payout, and duplicate settlement injection.
5. Wallet restore from seed on a clean device followed by full rescan and
   balance/history comparison against the original wallet.
6. Node database snapshot restore, archive verification, and full replay into
   a fresh directory.
7. Mobile background/foreground, process kill, storage pressure, network
   switching, and interrupted-send scenarios on supported OS versions.

## Release decision

A pilot release is blocked by any unresolved critical/high finding, consensus
divergence, unexplained supply/accounting mismatch, failed wallet recovery, or
missing raw monitoring data. Parameter changes require a written hypothesis,
before/after dashboards, a new chain identity when consensus-critical, and a
rollback plan.

---

<!-- hyphen-bilingual-chinese -->

# 激励测试网就绪条件与监控

状态：拟议的运维门槛。当前节点适用于本地 devnet 实验，但尚不适用于有激励的公开测试网。持久化分支元数据、有界不可变分支区块体存储、较重工作量规划和原子回滚已接入真实 `Blockchain` reorg 后端。后端测试覆盖较重分支成功切换、候选验证失败时精确恢复旧状态、伪造工作量被拒绝且不改变状态，以及数据库重开恢复。实时 P2P 分支接入、自动 fork-choice 触发、依赖子系统对账和多节点故障证据仍缺失。

## 准入阻断项

在实现并测试以下事项前，不得附加货币价值或公开奖励：

- 有界实时 P2P 竞争分支接入与自动累计工作量 fork-choice 触发，并使用现有分叉状态验证和可从崩溃恢复的多区块后端；
- mempool、wallet、explorer 和 pool 结算的确定性 reorg 对账，以及杀进程/重开和多节点分区证据；
- 经过认证和限流的公开 RPC/pool 边界；
- 自动矿池付款生命周期，或者明确声明余额不具货币价值的仅测试网方案；
- 可复现构建和签名发布产物；
- 独立的共识、密码学、钱包和网络审查；
- 事件响应、漏洞披露和运营者手册。

## 分阶段上线

| 阶段 | 范围 | 退出证据 |
| --- | --- | --- |
| 本地 devnet | 单主机、确定性身份、冒烟/重放/故障测试 | 可重复的干净启动、挖矿、导出、验证和重放 |
| 私有多节点 | 至少 5 个节点，由 3 个独立运营者管理 | 分区/重连和深度 reorg 演练后最终状态一致 |
| 无价值公开测试网 | 无许可 peer，仅使用水龙头 | 连续 30 天，并发布 dashboard 和事件日志 |
| 小规模激励试点 | 奖励有上限并明确损失上限 | 连续 60 天满足下述全部阈值，且没有未解决的严重问题 |

这些持续时间只是最短观察窗口，不构成安全性证明。

## 必需指标

每个版本必须按二进制版本、链身份、运营者和区域标记指标；不得收集钱包种子、超过必要期限的 IP 历史，或超出公开隐私政策范围的交易元数据。

| 范围 | 测量项 | 初始告警 |
| --- | --- | --- |
| Reorg | 次数、深度、替换工作量、收敛时间 | 任意深度 >= 3；任意节点分歧超过 2 个目标区块间隔 |
| 孤块 | 按 miner/pool 统计已挖、已接受和孤立区块 | 1 小时比例 > 5% 或 24 小时比例 > 2% |
| P2P | peer、波动、拨号失败、gossip 拒绝、重复/畸形帧 | peer 数低于 4 持续 10 分钟；拒绝量达到基线 5 倍 |
| PoW | 出块时间分布、报告/观察工作量、硬件类别 | 中位出块间隔连续 6 小时超出目标的 0.7x-1.3x |
| 集中度 | 按 pool/miner/operator 统计区块和接受工作量 | 一个 pool 连续 24 小时 > 35%；前三名 > 70% |
| 同步 | 初始同步时间、CPU、RSS 峰值、磁盘增长、带宽 | 相对上个版本退化 > 25% |
| 矿池账本 | 接受/拒绝 share、receipt 缺口、待付余额、恢复来源 | 任意 receipt 链缺口或无法解释的余额差异 |
| 钱包 | 扫描延迟、发送失败、恢复/重扫时间、移动端崩溃 | 恢复不一致；无崩溃会话 < 99.5% |

这些阈值是初始运维界限，只能依据公开测量结果调整，不能静默修改。

## 强制演练

运行并保留以下报告：

1. 工作量不等的网络分区、重连、fork choice 和状态根收敛。
2. 时间戳回退/超前以及哈希率振荡模拟。
3. 畸形交易、RPC、P2P、pool 和 TP 语料，以及有界模糊测试。
4. 矿池主账本截断、备份恢复、receipt 重排/缺失、延迟付款和重复结算注入。
5. 在干净设备上从种子恢复钱包，随后全量重扫，并将余额/历史与原钱包比较。
6. 节点数据库快照恢复、归档验证，以及重放至全新目录。
7. 受支持操作系统版本上的移动端前后台切换、进程终止、存储压力、网络切换和发送中断场景。

## 发布决定

存在任何未解决的 critical/high 问题、共识分歧、无法解释的供应量/账目不一致、钱包恢复失败或原始监控数据缺失时，必须阻止试点发布。参数变更需要书面假设、变更前后 dashboard；若影响共识，还需要新链身份和回滚方案。
