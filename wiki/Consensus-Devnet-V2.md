# Hyphen Devnet v2 Consensus Profile

Status: active development profile, 2026-07-30. It is not a production or
value-bearing network.

Devnet v2 inherits the numeric parameter table and disabled research-feature
set from the historical [devnet v1 profile](Consensus-Devnet-V1), with these normative
changes:

1. `network_name` is `hyphen-devnet-v2`.
2. `STATE_TRANSITION_VERSION` is `2` and is committed by
   `ChainConfig::consensus_params_hash`.
3. A post-genesis coinbase output and its range proof MUST be derived
   deterministically from the domain-separated block hash, reward public keys,
   amount, height and commitment blinding. Ordinary wallet sends continue to
   use operating-system randomness.
4. A v1 or v3 database MUST be rejected by the consensus-parameter and
   genesis-hash checks. There is no in-place database migration.
5. Block version 5 activates PoUW v3. `difficulty` is the number of distinct
   single-use Cunningham-chain witnesses a block must claim, `pouw_chain_length`
   is the epoch-invariant chain length, and `pow_commitment` is
   `BLAKE3(domain || parent_commitment || height || witnesses)`.
6. The v1 parameters `arena_size`, `scratchpad_size`, `page_size`,
   `pow_rounds`, `writeback_interval`, `kernel_count` and `merkle_depth` are
   removed. The active kernel never read them, so committing them to
   `consensus_params_hash` advertised an identity that did not affect
   execution. Transaction, authorization and archive encodings are unchanged.
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
resumes a journal during database open. Automatic P2P competing-branch intake,
fork-choice triggering and mempool/wallet/explorer/pool reconciliation are not
implemented, so complete live reorg handling remains a release blocker.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen Devnet v2 共识 Profile

状态：2026-07-30 启用的开发 profile。它不是生产网络，也不承载价值。

Devnet v2 继承历史 [devnet v1 profile](Consensus-Devnet-V1) 的数值参数表和禁用研究功能集合，并作出以下规范性变更：

1. `network_name` 为 `hyphen-devnet-v2`。
2. `STATE_TRANSITION_VERSION` 为 `2`，并由 `ChainConfig::consensus_params_hash` 承诺。
3. 创世后 coinbase 输出及其范围证明必须根据域分离的区块哈希、奖励公钥、金额、高度和 commitment blinding 确定性派生。普通钱包发送仍使用操作系统随机源。
4. 共识参数和创世哈希检查必须拒绝 v1 与 v3 数据库，不提供原地数据库迁移。
5. 区块版本 5 激活 PoUW v3。`difficulty` 是区块必须认领的互异单次使用 Cunningham 链见证数，`pouw_chain_length` 是 epoch 不变的链长，`pow_commitment` 为 `BLAKE3(domain || parent_commitment || height || witnesses)`。
6. 移除 v1 遗留参数 `arena_size`、`scratchpad_size`、`page_size`、`pow_rounds`、`writeback_interval`、`kernel_count` 和 `merkle_depth`。现行内核从不读取这些字段，把它们承诺进 `consensus_params_hash` 只会对外公布一个不影响执行的链身份。交易、授权与归档编码保持不变。
7. H-WES、H-BFM、H-FOC 和 H-SAC 仍为未激活的研究机制。

精确 network magic、参数哈希和创世哈希仅以 `test-vectors/chain-identity-v6.json` 为规范依据。授权格式仍为版本 1，但二进制编码已切换到 schema 驱动的紧凑档（见 README 序列化一节），这正是本次身份下创世哈希发生变化、且 `chain-identity-v5.json` 转为历史记录的原因。

状态库包含原子单区块提交/回滚、不可变分支区块体存储、持久化 reorg journal 和真实的 `Blockchain` reorg 后端。后端重算计划工作量，持有独占状态转换锁，在分叉状态上验证每个候选区块，失败时恢复旧分支，并在数据库打开期间恢复 journal。自动 P2P 竞争分支接入、fork-choice 触发以及 mempool/wallet/explorer/pool 对账尚未实现，因此完整实时 reorg 处理仍是发布阻断项。
