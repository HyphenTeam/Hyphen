# Hyphen Frozen Devnet v1 Consensus Profile (Historical)

> Withdrawn on 2026-07-30. V1 generated coinbase outputs with node-local
> randomness, so equal block histories could produce unequal spendable-output
> state. Its identity is retained only as historical evidence and MUST NOT be
> used for a new database. Active development uses [devnet v2](devnet-v2.md).

Status: frozen for reproducible development and adversarial testing. This is
not a production-mainnet specification or a security claim.

Normative words such as MUST and MUST NOT apply to `hyphen-devnet-v1`. The
Rust implementation in this repository is the reference implementation.

## Chain identity

| Field | Frozen value |
| --- | --- |
| Profile | `hyphen-devnet-v1` |
| Network magic | `48594456` (`HYDV`) |
| Block version | `2` |
| Consensus feature mask | `0` |
| Difficulty algorithm | `LwmaV1` |
| Consensus parameters hash | `e9591468e6b53e922b67f6dbecd0dccec4217e95f0f09a21bce7244fbe8e8322` |
| Genesis hash | `4ee146f63ec54ded2ed743e88ee4ff0981598afc0412d4261e17e43a731a1b92` |
| Genesis timestamp | `1767225600000` ms (`2026-01-01T00:00:00Z`) |

The machine-readable vectors are in
`test-vectors/chain-identity-v1.json`. A database stores the genesis hash and
consensus parameters hash and MUST refuse to open under a different identity.

Verify the checked-out implementation with:

```bash
cargo run -p hyphen-node --locked -- --network devnet --print-chain-identity
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
```

## Frozen parameters

| Parameter | Value |
| --- | ---: |
| Target block time | 30 seconds |
| Difficulty window | 30 blocks |
| Initial difficulty | 1,000 |
| Per-step difficulty clamp | previous / 3 through previous * 3 |
| Future timestamp allowance | 60,000 ms |
| Epoch length | 128 blocks |
| Epoch arena | 64 MiB |
| Scratchpad | 256 KiB |
| Page size | 4,096 bytes |
| PoW rounds | 64 |
| Writeback interval | 8 |
| Kernel count | 12 |
| Maximum block size | 2 MiB |
| Ring size | 4 |
| Initial reward | 100,000,000,000,000 atomic units |
| Tail emission | 600,000,000,000 atomic units |
| Fee burn | 5,000 basis points |

The complete ordered parameter commitment is implemented by
`ChainConfig::consensus_params_hash`. A change to any committed field creates a
different chain identity and MUST NOT be deployed as devnet v1.

## Disabled research mechanisms

Uncles, TERA, VRE consensus enforcement, MSE, and MDAD-SPR are disabled. The
code may retain these mechanisms for research profiles, but a devnet v1 node
MUST NOT activate them. Useful-Work is not a consensus feature and is not part
of devnet v1.

## Header and chain rules

For every post-genesis block, the verifier MUST enforce at least:

1. Header version is exactly 2.
2. Height is the current tip height plus one and `prev_hash` is the current
   tip hash.
3. Timestamp is strictly greater than its parent after height 1 and no more
   than 60 seconds ahead of the verifier's adjusted time.
4. Transaction and uncle roots match block contents. Uncle contents MUST be
   empty because the uncle feature is disabled.
5. Miner block authorization is present and valid.
6. PoW satisfies the expected epoch seed and difficulty.
7. Transactions pass size, balance, signature, proof, nullifier, and state
   transition checks before the tip is committed.

At withdrawal, the v1 chain manager accepted only a block extending the active tip. The
state library contains inactive persistent branch metadata, strictly-heavier
cumulative-work reorg planning, atomic one-tip rollback primitives, and a
generic durable coordinator that can resume a static reorg plan or restore the
original branch after a candidate attach failure. No live backend yet performs
fork-specific transaction/state validation, selects a competing branch, or
drives that coordinator. The coordinator model therefore is not active reorg
support.
Consequently complete reorg handling remains a release blocker for an
incentivized public testnet, not a frozen devnet v1 capability.

## Difficulty

`LwmaV1` computes a linear weighted mean over adjacent solve times. Each solve
time is clamped to `[target/10, 6*target]`. The weighted average difficulty is
scaled by target time divided by weighted solve time, then clamped to
`[max(1, previous/3), max(1, previous*3)]`. Calculations use integer arithmetic
in the reference implementation. Reversed timestamp samples cannot force an
adjustment outside the final clamp.

## Miner block authorization

Every accepted block contains a `BlockAuthorization` version 1. The miner's
Ed25519 signature commits to a domain-separated Blake3 digest of:

```text
"Hyphen/NCAP/block-authorization/v1"
authorization_version
network_magic
consensus_params_hash
genesis_hash
full_header_hash
reward_view_public
reward_spend_public
```

The header contains the miner public key. Changing the nonce, extra nonce,
transaction root, reward keys, chain identity, or any other header field after
authorization invalidates the signature. This is a consensus rule, not only a
pool policy.

## Archive, reference verification, and replay

Archive version 1 contains network magic, consensus parameters hash, genesis
hash, and contiguous post-genesis blocks. The lightweight reference verifier
checks archive identity, linkage, timestamps, roots, and miner authorization.
Full replay additionally executes authoritative PoW, transaction, and state
validation into a fresh height-zero database.

```bash
# Export from a stopped or separately copied source database.
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-source \
  --export-history ./devnet-history-v1.bin

# Lightweight verification without writing chain state.
cargo run -p hyphen-node --locked -- \
  --network devnet --verify-history ./devnet-history-v1.bin

# Full replay. The destination must be new and empty.
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-replay \
  --replay-history ./devnet-history-v1.bin
```

Archive files are currently Rust/`hyphen-codec` v1 implementation artifacts, capped at
512 MiB by the CLI. A language-neutral canonical block/archive encoding and
cross-implementation vectors remain required before production consensus.

## Change policy

No in-place activation is allowed on devnet v1. Any consensus change requires:

- a new named profile and network identity;
- a written rationale and threat model;
- updated machine-readable vectors;
- reference-verifier and negative tests;
- successful replay from that profile's genesis; and
- independent review before promotion beyond a research network.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen 冻结 Devnet v1 共识 Profile（历史）

> 已于 2026-07-30 撤回。V1 使用节点本地随机性生成 coinbase 输出，因此相同区块历史可能产生不同的可花费输出状态。其身份仅作为历史证据保留，禁止用于新数据库。当前开发使用 [devnet v2](devnet-v2.md)。

状态：为可复现开发和对抗测试而冻结。这不是生产 mainnet 规范或安全声明。MUST、MUST NOT 等规范词适用于 `hyphen-devnet-v1`，本仓库 Rust 实现是参考实现。

## 链身份

| 字段 | 冻结值 |
| --- | --- |
| Profile | `hyphen-devnet-v1` |
| Network magic | `48594456`（`HYDV`） |
| 区块版本 | `2` |
| 共识功能 mask | `0` |
| 难度算法 | `LwmaV1` |
| 共识参数哈希 | `e9591468e6b53e922b67f6dbecd0dccec4217e95f0f09a21bce7244fbe8e8322` |
| 创世哈希 | `4ee146f63ec54ded2ed743e88ee4ff0981598afc0412d4261e17e43a731a1b92` |
| 创世时间戳 | `1767225600000` ms（`2026-01-01T00:00:00Z`） |

机器可读向量位于 `test-vectors/chain-identity-v1.json`。数据库存储创世哈希与共识参数哈希，身份不同时必须拒绝打开。

```bash
cargo run -p hyphen-node --locked -- --network devnet --print-chain-identity
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
```

## 冻结参数

| 参数 | 值 |
| --- | ---: |
| 目标区块时间 | 30 秒 |
| 难度窗口 | 30 个区块 |
| 初始难度 | 1,000 |
| 单步难度 clamp | previous / 3 到 previous * 3 |
| 未来时间戳容差 | 60,000 ms |
| Epoch 长度 | 128 个区块 |
| Epoch arena | 64 MiB |
| Scratchpad | 256 KiB |
| Page size | 4,096 字节 |
| PoW rounds | 64 |
| Writeback interval | 8 |
| Kernel 数量 | 12 |
| 最大区块大小 | 2 MiB |
| Ring size | 4 |
| 初始奖励 | 100,000,000,000,000 atomic units |
| Tail emission | 600,000,000,000 atomic units |
| Fee burn | 5,000 basis points |

完整、有序的参数 commitment 由 `ChainConfig::consensus_params_hash` 实现。改变任一已承诺字段都会产生不同链身份，禁止部署为 devnet v1。

## 禁用的研究机制

Uncle、TERA、VRE 共识强制、MSE 和 MDAD-SPR 被禁用。代码可为研究 profile 保留这些机制，但 devnet v1 节点不得激活。Useful-Work 不是共识功能，也不属于 devnet v1。

## 区块头与链规则

对每个创世后区块，verifier 至少必须强制：

1. 区块头版本恰为 2。
2. 高度为当前 tip 加一，`prev_hash` 为当前 tip 哈希。
3. 高度 1 后时间戳严格大于父区块，且不超过 verifier 调整后时间 60 秒。
4. 交易根和 uncle 根匹配区块内容；因 uncle 功能禁用，uncle 内容必须为空。
5. Miner block authorization 存在且有效。
6. PoW 满足预期 epoch seed 和难度。
7. 提交 tip 前，交易通过大小、余额、签名、证明、nullifier 和状态转换检查。

撤回时，v1 chain manager 只接受扩展 active tip 的区块。状态库包含未激活的持久化分支元数据、仅严格更重的累计工作量 reorg 规划、原子单 tip 回滚原语，以及能够恢复静态 reorg 计划或在候选 attach 失败后恢复原分支的通用持久化 coordinator。尚无实时后端执行分叉特定交易/状态验证、选择竞争分支或驱动 coordinator，因此该模型不是已激活 reorg 支持。完整 reorg 处理仍是激励公开测试网发布阻断项，不是冻结 devnet v1 能力。

## 难度

`LwmaV1` 对相邻 solve time 计算线性加权平均。每个 solve time clamp 到 `[target/10, 6*target]`。加权平均难度乘以目标时间并除以加权 solve time，随后 clamp 到 `[max(1, previous/3), max(1, previous*3)]`。参考实现使用整数算术。逆序时间戳样本不能使调整超出最终 clamp。

## 矿工区块授权

每个已接受区块包含版本 1 `BlockAuthorization`。矿工 Ed25519 签名承诺以下内容的域分离 Blake3 digest：

```text
"Hyphen/NCAP/block-authorization/v1"
authorization_version
network_magic
consensus_params_hash
genesis_hash
full_header_hash
reward_view_public
reward_spend_public
```

区块头包含矿工公钥。授权后改变 nonce、extra nonce、交易根、奖励密钥、链身份或任何其他区块头字段会使签名失效。这是共识规则，不只是矿池政策。

## 归档、参考验证与重放

Archive v1 包含 network magic、共识参数哈希、创世哈希和连续创世后区块。轻量参考 verifier 检查 archive 身份、链接、时间戳、根和矿工授权。完整重放还会把权威 PoW、交易和状态验证执行到全新高度零数据库。

```bash
# 从已停止节点或单独复制的源数据库导出。
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-source \
  --export-history ./devnet-history-v1.bin

# 不写链状态的轻量验证。
cargo run -p hyphen-node --locked -- \
  --network devnet --verify-history ./devnet-history-v1.bin

# 完整重放。目标必须是全新空目录。
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-replay \
  --replay-history ./devnet-history-v1.bin
```

Archive 文件目前是 Rust/`hyphen-codec` v1 实现产物，CLI 上限为 512 MiB。生产共识前仍需语言无关的规范 block/archive 编码和跨实现向量。

## 变更政策

Devnet v1 不允许原地激活。任何共识变更都需要新的命名 profile 和网络身份、书面理由与威胁模型、更新的机器可读向量、参考 verifier 与负向测试、从该 profile 创世开始的成功重放，以及升级到研究网络之外前的独立审查。
