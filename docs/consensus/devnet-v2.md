# Hyphen Devnet v2 Consensus Profile

Status: active development profile, 2026-07-30. It is not a production or
value-bearing network.

Devnet v2 inherits the numeric parameter table and disabled research-feature
set from the historical [devnet v1 profile](devnet-v1.md), with these normative
changes:

1. `network_name` is `hyphen-devnet-v2`.
2. `STATE_TRANSITION_VERSION` is `2` and is committed by
   `ChainConfig::consensus_params_hash`.
3. A post-genesis coinbase output and its range proof MUST be derived
   deterministically from the domain-separated block hash, reward public keys,
   amount, height and commitment blinding. Ordinary wallet sends continue to
   use operating-system randomness.
4. A v1 database MUST be rejected by the consensus-parameter and genesis-hash
   checks. There is no in-place database migration.
5. H-WES, H-BFM, H-FOC and H-SAC remain inactive research mechanisms.

The exact network magic, parameter hash and genesis hash are normative only in
`test-vectors/chain-identity-v3.json`. Block version 3 activates scientific
PoUW v1; authorization remains version 1.
remain unchanged because this revision changes state-transition semantics, not
their encoding.

The state library contains atomic one-block commit/rollback, immutable branch
body storage, persistent reorg journals and a real `Blockchain` reorg backend.
The backend recomputes plan work, holds an exclusive transition lock, validates
each candidate against its fork state, restores the old branch on failure and
resumes a journal during database open. Automatic P2P competing-branch intake,
fork-choice triggering and mempool/wallet/explorer/pool reconciliation are not
implemented, so complete live reorg handling remains a release blocker.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen Devnet v2 共识 Profile

状态：2026-07-30 启用的开发 profile。它不是生产网络，也不承载价值。

Devnet v2 继承历史 [devnet v1 profile](devnet-v1.md) 的数值参数表和禁用研究功能集合，并作出以下规范性变更：

1. `network_name` 为 `hyphen-devnet-v2`。
2. `STATE_TRANSITION_VERSION` 为 `2`，并由 `ChainConfig::consensus_params_hash` 承诺。
3. 创世后 coinbase 输出及其范围证明必须根据域分离的区块哈希、奖励公钥、金额、高度和 commitment blinding 确定性派生。普通钱包发送仍使用操作系统随机源。
4. 共识参数和创世哈希检查必须拒绝 v1 数据库，不提供原地数据库迁移。
5. H-WES、H-BFM、H-FOC 和 H-SAC 仍为未激活的研究机制。

精确 network magic、参数哈希和创世哈希仅以 `test-vectors/chain-identity-v3.json` 为规范依据。区块版本 3 激活科学计算 PoUW v1；授权格式仍为版本 1。

状态库包含原子单区块提交/回滚、不可变分支区块体存储、持久化 reorg journal 和真实的 `Blockchain` reorg 后端。后端重算计划工作量，持有独占状态转换锁，在分叉状态上验证每个候选区块，失败时恢复旧分支，并在数据库打开期间恢复 journal。自动 P2P 竞争分支接入、fork-choice 触发以及 mempool/wallet/explorer/pool 对账尚未实现，因此完整实时 reorg 处理仍是发布阻断项。
