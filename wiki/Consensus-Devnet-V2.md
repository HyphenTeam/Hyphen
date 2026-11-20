# Hyphen Devnet v2 Consensus Profile

Status: active development profile, 2026-07-30. It is not a production or
value-bearing network.

The `devnet` row defines the active development network's parameters, format and feature gates. The historical v1 identity is retained for interpreting old records. [Active consensus table](Consensus-Profiles.md) · [Historical v1](Consensus-Devnet-V1.md)

1. `network_name` is `hyphen-devnet-v2`.
2. `STATE_TRANSITION_VERSION` is `2` and is committed by
   `ChainConfig::consensus_params_hash`.
3. A post-genesis coinbase output and its range proof MUST be derived
   deterministically from the domain-separated block hash, reward public keys,
   amount, height and commitment blinding. Ordinary wallet sends continue to
   use operating-system randomness.
4. A v1 or v3 database MUST be rejected by the consensus-parameter and
   genesis-hash checks. There is no in-place database migration.
5. The current format, witness count and exact work-commitment byte layout are specified in the [consensus profile table and transition rules](Consensus-Profiles.md).
6. The v1 parameters `arena_size`, `scratchpad_size`, `page_size`,
   `pow_rounds`, `writeback_interval`, `kernel_count` and `merkle_depth` are
   removed. The active kernel never read them, so committing them to
   `consensus_params_hash` advertised an identity that did not affect
   execution.
7. H-WES, H-BFM, H-FOC and H-SAC remain inactive research mechanisms.

The exact network magic, parameter hash and genesis hash are normative only in
`test-vectors/chain-identity-v6.json`. Authorization remains version 1, but the
binary profile moved to the schema-guided compact encoding (see the README
section on serialization), which is why the genesis hashes changed with this
identity and why `chain-identity-v5.json` is now a historical record.

The state library contains atomic one-block commit/rollback, immutable branch
body storage, persistent reorg journals and a real `Blockchain` reorg backend.
The backend recomputes plan work, holds an exclusive transition lock, validates
each candidate against its fork state, restores the old branch on failure and
resumes a journal during database open. The node uses this backend to adopt
bounded, strictly heavier P2P branches. A local contract-devnet run exercised
detached transaction admission, canonical transaction lookup, wallet rescan and
pool reward and payout recovery. Cross-host recovery under a public network
partition remains a release condition. [Acceptance records](Operations-Verification.md)

---

<!-- hyphen-bilingual-chinese -->

# Hyphen Devnet v2 共识 Profile

状态：2026-07-30 启用的开发 profile。它不是生产网络，也不承载价值。

现行开发网采用 `devnet` 行规定的参数、格式和启用条件。v1 身份保留用于解释历史记录。[现行共识表](Consensus-Profiles.md) · [历史 v1](Consensus-Devnet-V1.md)

1. `network_name` 为 `hyphen-devnet-v2`。
2. `STATE_TRANSITION_VERSION` 为 `2`，并由 `ChainConfig::consensus_params_hash` 承诺。
3. 创世后 coinbase 输出及其范围证明必须根据域分离的区块哈希、奖励公钥、金额、高度和 commitment blinding 确定性派生。普通钱包发送仍使用操作系统随机源。
4. 共识参数和创世哈希检查必须拒绝 v1 与 v3 数据库，不提供原地数据库迁移。
5. 现行区块格式、见证数以及工作承诺的精确字节编码见[共识 profile 表与状态转移规则](Consensus-Profiles.md)。
6. 移除 v1 遗留参数 `arena_size`、`scratchpad_size`、`page_size`、`pow_rounds`、`writeback_interval`、`kernel_count` 和 `merkle_depth`。现行参数承诺已移除这些字段。
7. H-WES、H-BFM、H-FOC 和 H-SAC 仍为未激活的研究机制。

精确 network magic、参数哈希和创世哈希仅以 `test-vectors/chain-identity-v6.json` 为规范依据。授权格式仍为版本 1，但二进制编码已切换到 schema 驱动的紧凑档（见 README 序列化一节），这正是本次身份下创世哈希发生变化、且 `chain-identity-v5.json` 转为历史记录的原因。

状态库包含原子单区块提交和回滚、不可变分支区块体存储、持久化 reorg journal 和 `Blockchain` reorg 后端。后端重算计划工作量，在独占状态转换锁内验证每个候选块，失败时恢复旧分支，重开数据库时恢复 journal。节点通过该后端接入有界、累计工作量严格更高的 P2P 分支。合约开发网已在单机验证原交易重新准入、规范链交易查询、钱包重扫和矿池奖励与付款恢复，公网多机分区恢复仍待验收。[验收记录](Operations-Verification.md)
