# Hyphen: Verifiable Mathematical Work for a Private Settlement Chain

Status: research base chain. No mainnet has been launched, no independent
consensus, cryptographic or circuit audit has been performed, and nothing in
this document should be read as a safety claim about real value. Every mechanism
below is labelled with what the code actually establishes today.

---

## 0. Summary

Hyphen is a Rust base chain that replaces digest grinding with a **search for
number-theoretic witnesses**, and separates that workload from a private
settlement layer built on CLSAG ring signatures, Pedersen commitments and
recoverable state expiry.

Three claims are made here, and only these three:

1. **The workload is real mathematics, not a burned digest.** A witness is a
   Cunningham chain of the first kind whose elements must all be prime. A
   verifier pays `L` deterministic primality tests; a solver pays a search whose
   expected cost grows as `(ln n)^L`.
2. **Witness single-use is what makes the binding sound.** Filter-based and
   residue-based header binding — the intuitive designs — are provably broken
   against an adversary who pools chains (§3.2). Single-use witnesses make
   precomputation degenerate into mining in advance, with no advantage.
3. **Fail-closed is the default.** Scientific result settlement rejects every
   proof until an audited verifier is installed; unknown features are disabled;
   the clock is untrusted until multiple independent servers agree; a database
   created under different consensus parameters is refused before any mutation.

Everything else in this document is engineering: how the state transitions
atomically, how difficulty is controlled without floating point, how keys and
addresses are derived, and what remains unproven.

## 1. Design philosophy

Five rules produced most of the decisions in this repository. They are listed
with the concrete consequence, because a principle without a consequence is
decoration.

**Determinism beats performance, always.** Consensus values must be identical on
every host, so no `libm` call, no floating point and no JIT sits on that path.
The difficulty controller is integer-only; the contract VM was moved from a
Cranelift JIT to a pure-Rust interpreter with built-in fuel metering — a
deliberate acceptance of lower throughput in exchange for reproducible fuel
accounting and the removal of a code generator from consensus.

**Every dependency must justify itself against a hand-written alternative.** The
hex codec, the base58 codec, the SNTP client and the NTP-adjusted clock live in
the workspace, because a consensus crate should not import a supply chain for
forty lines of byte shuffling. The dependency graph is 267 crates; it dropped by
101 crates in one step when the Wasm runtime changed, and the whole Cranelift,
`bindgen`, CMake and `libclang` surface disappeared with it.

**Fail closed, and make the failure loud.** An unsupported circuit, a refused
database, an untrusted clock and disabled research features are all states the
system openly reports; only the neural challenge circuit has an active
settlement verifier. Silent fallback is treated as a bug: an encoding path
that "tries something else" on parse failure is exactly how consensus splits.

**Write down what is missing, next to what works.** The repository's own README
carries a table of mechanisms that are *not* active, and §11 of this document
repeats it. A chain that overstates its maturity is not a research chain, it is
a liability with a logo.

**Keep the useful output.** A proof of work should leave something behind. The
witness set is a deduplicated, independently checkable dataset of prime chains
that any observer can export and verify; it is the chain's scientific output,
not an internal counter.

## 2. System overview

| Layer | Implementation | Status |
| --- | --- | --- |
| Workload | `hyphen-pow::vms` — single-use Cunningham-chain witnesses, proven-deterministic primality | Active (block format 5) |
| Work commitment | `BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)` in the header | Active |
| Witness uniqueness | `hyphen-state::WitnessSet` sparse Merkle set, released on reorg | Active |
| Difficulty | Integer momentum-damped LWMA (research profiles), frozen integer LWMA (devnet) over witness counts | Active |
| State | Atomic multi-root transition with undo journal, reorg coordinator, H-WES expiry | Active |
| Privacy | Stealth addresses, CLSAG rings, Pedersen commitments, Bulletproof-style range proofs | Active |
| Disclosure | H-SAC one-output opening with scoped Schnorr ownership proof | Research, inactive |
| Execution | Wasmi 2.0 interpreter, fuel metering, bounded host ABI | Active |
| Settlement | AetherCompute task lifecycle, rejecting proof verifier | Fail-closed |
| Network | libp2p (gossipsub, Kademlia, identify, relay, DCUtR), template protocol TP v4 | Active |
| Pool | NCAP miner authorization, share receipts, Pool Protocol v6 | Active, spec in `Research-Non-Custodial-Pool` |
| Wallet | Flutter client over a Rust core: derivation, encrypted storage, isolated signer | Active |

## 3. Consensus

### 3.1 Block and epoch structure

A block header commits, in order, to: format version, height, timestamp,
parent hash, transaction root, commitment root, nullifier root, state root,
receipt root, uncle root, work commitment, epoch seed, difficulty, nonce, extra
nonce, miner public key, total fee, reward, view tag and block size. Block format
`4` and state-transition version `2` are the current frozen values, and both are
committed by `ChainConfig::consensus_params_hash`.

The epoch seed rotates every `epoch_length` blocks from the hash of the last
block of the previous epoch. It is the only chain-derived entropy the workload
consumes, which is why the workload cannot be precomputed before the parent
exists.

### 3.2 Workload: verifiable mathematical search

**Retired predecessor.** Block format 4 used a Q12 diffusion field as its work
function: the header seeded a 64x64 integer field, a convex combination with
weights summing to 4096 was applied for a fixed depth, and acceptance was
`claim * difficulty < 2^256` over the field commitment. It was deterministic and
had a one-evaluation verification cost, but its output was a burned digest with
no independent value. Block format 5 replaced it with the witness search above;
the v1/v2 parameters (`arena_size`, `scratchpad_size`, `page_size`, `pow_rounds`,
`writeback_interval`, `kernel_count`, `merkle_depth`, `pouw_depth`) no longer
exist, because a consensus parameter that does not affect execution is a lie in
the chain identity.

**Designed rule (PoUW v3).** The workload becomes a real number-theoretic
search:

```text
witness n <=> n, 2n+1, 4n+3, … (length L) are all prime and all < 2^64
```

Two properties make this usable in consensus rather than merely attractive:

- **Primality is provable, not probable.** Miller-Rabin with the seven-base set
  `{2, 325, 9375, 28178, 450775, 9780504, 1795265022}` is *proven* exact for
  every `n < 2^64` (Jaeschke; Sorenson and Webster). No probabilistic error
  bound enters consensus, and no big-integer crate is required.
- **Search cost and verification cost are separated by design.** A verifier
  performs `L` primality tests — microseconds. A solver tests candidates whose
  density falls as `A_L · (ln n)^-L` — seconds to minutes.
**Why the obvious binding is wrong.** The intuitive way to bind a witness to a
block is a header-derived filter (`H(header ‖ n) < T`) or a residue class
(`n ≡ r(header) mod 2^b`). Both fail, and the failure is worth stating precisely
because it is not obvious:

- *Filter binding.* A solver who builds a pool of `m / p` chains satisfies every
  future header: the filter is evaluated independently per header while the pool
  persists, so once the pool exists, each further block costs a handful of
  hashes. Lowering `p` only multiplies the honest cost, not the attacker's,
  because the pool is reusable indefinitely.
- *Residue binding.* Covering every residue class of width `b` with `m` chains
  each costs `2^b · m / density` candidate tests. One honest block costs
  `m · 2^b / density`. The two are equal: one block's worth of work buys a
  permanent table.

Both failures share one cause — the predicate is *stateless*, so a witness found
for one header can be tested against every other header for free.

**Single-use witnesses close the loop.** The chain records claimed witnesses. A
precomputed pool can then be spent exactly once, so total work is conserved, and
precomputation is revealed as mining in advance with no advantage at all. This is
why the design does not attempt clever header binding at all: uniqueness is
cheaper to enforce than binding, and strictly stronger.

**Implementation status.** The workload is active in block format 5.
`hyphen-pow::vms` provides the sieve, the deterministic primality test, chain
construction with overflow checks, witness-list validation (ascending, distinct,
count-bounded), a stride-partitioned search and the parent-relative witness
commitment; tests cover known Cunningham chains (89 → 179 → 359 → 719 → 1439 →
2879), sixteen Carmichael numbers, strong pseudoprimes, the largest prime below
`2^64`, overflow boundaries and commitment binding (parent, height, order,
count). `hyphen-state::WitnessSet` enforces single use in a sparse Merkle set
and releases a detached block's witnesses during reorg, and block validation
checks the predicate, the membership oracle and the commitment in that order.

What is not yet established, stated plainly: the epoch-to-epoch variance of
chain density has not been measured on a live network, so block-time variance at
a fixed witness count is an open empirical question; the single-use set is a
node-local oracle rather than a proof, so a light client can follow the
commitment chain but cannot verify non-membership without the set; and the
dataset has no exporter yet.

### 3.3 Difficulty control without floating point

`difficulty` is the expected amount of work a solver performs, and cumulative
difficulty is the fork-choice weight. The controller scales the previous value by
the ratio of target block time to observed solve time, using integer arithmetic
throughout:

- **Significance gate.** While the LWMA estimate stays within ±10% of the
  previous value, only a bounded micro-correction of at most ±2% is applied. A
  solve-time series with no measurable drift must not move difficulty.
- **Momentum term.** Recent solve times are compared against the window mean;
  when the work rate is accelerating, up to 30% of the raw correction is added.
- **Manipulation dampener.** A significant negative lag-1 autocorrelation —
  alternating fast/slow blocks, the signature of pool hopping or a pulsing miner
  — attenuates the requested change. The significance test squares both sides
  instead of taking a square root, and an integer Newton iteration supplies the
  threshold, so no `libm` call exists anywhere on this path.
- **Guards.** Per-block clamps bound the change, timestamps are clamped to
  `[target/10, 6·target]` so a fully controlled clock can move one sample by at
  most a factor of 60, and a chain producing blocks at under a quarter of the
  target rate can never have its difficulty lowered.

Devnet uses the frozen integer LWMA with unmodified algebra; the research
profiles use the controller above. Both are integer-only, so a difficulty value
that decides fork choice cannot differ between platforms.

### 3.4 Fork choice, reorg and time

Fork choice is strictly-heaviest by cumulative difficulty. The reorg coordinator
persists a journal, recomputes plan work, holds an exclusive transition lock,
validates each candidate against its fork state, restores the original branch on
failure, and resumes a partial journal during database open. Blocks are applied
through an atomic transition: every participating store is snapshotted, the
update is committed, and a failure restores the exact previous state.

Timestamps come from a multi-server NTP clock implemented in the workspace:
eleven independent servers are queried in parallel with a three-second deadline,
outliers beyond 2 s from the median are discarded, and fewer than three agreeing
responses marks the clock untrusted and drops the poll interval from 30 s to 5 s.
The SNTP client requires the server's originate field to echo the timestamp the
node sent, which binds each reply to its request and rejects replayed or
unsolicited packets.

## 4. State model

The canonical state is a small number of roots combined into the header's state
root: the AetherCompute snapshot, the WASM ledger, and the H-WES reference
expiring state. Block application is atomic across all of them plus the
commitment tree, nullifier set, chain tip and the branches. A serialised undo
record per block carries the previous snapshots, the transaction hashes, output
indices and nullifiers needed for exact rollback, so a reorg is a deterministic
inverse operation rather than a re-derivation.

H-WES (recoverable state expiry) keeps a five-root atomic state: signed public
creation, bounded deterministic expiry and reorg rollback are implemented and
integrated on research profiles; a shielded recovery circuit, incentives and
benchmarks are not.

## 5. Privacy layer

Transactions spend ring inputs and create stealth outputs:

- **Stealth addresses.** A one-time output key per payment is derived from the
  recipient's view and spend public keys, so a published address is not
  linkable across payments.
- **CLSAG ring signatures.** Each input signs against a ring of output
  references, and the pseudo-output is part of the signed message, which is what
  makes double-spend detection local to the signature rather than to a separate
  disclosure.
- **Pedersen commitments and range proofs.** Values are committed; the balance
  equation is `Σ pseudo_outputs == Σ output_commitments + fee·H`, so the fee is
  implicit and no cleartext amount exists in the transaction. Range proofs are
  Bulletproof-style inner-product proofs with aggregated and batch verification
  paths, which keeps verification cost sublinear in the number of outputs.
- **View and spend separation.** The view key can detect and decrypt incoming
  payments without the ability to spend them; the signer protocol keeps the
  spend key behind a validated boundary with explicit network binding.
- **H-SAC selective audit disclosure** (research, inactive): one-output amount
  opening, a scoped Schnorr ownership proof and a published leakage lower bound.
  What is missing is the frozen compliance relation, confidential delivery, a
  chain-provenance circuit and an independent circuit audit.

## 6. Execution and scientific settlement

Contracts are WASM modules executed by a pure-Rust interpreter. The validator
forbids floating point, SIMD, threads, shared memory, memory64, multi-memory,
component model and exception handling; exactly one bounded exported memory is
required; a start section is rejected; imports are restricted to the frozen host
ABI. Fuel is charged by the interpreter itself, so out-of-gas is a deterministic
consensus outcome rather than a wall-clock accident, and host calls add their own
explicit charges for storage, hashing and logging.

AetherCompute publishes external tasks onto the chain and settles results only
through a node-configured proof verifier. The default verifier rejects every
result, fraud and custody proof, which is the intended production posture: the
settlement layer has no economic effect until an audited verifier, key and
circuit are installed.

## 7. Economics

Block reward follows a logistic decay:

```text
R_lcd(h) = R_tail + (R_0 − R_tail) · c² / (h² + c²)
R(h)     = R_lcd(h) · μ(h)
```

with `R_0` the initial reward, `R_tail` the asymptotic floor, `c` the decay
constant, and `μ(h)` an optional multiplier bounded by the MSE floor and ceiling
in basis points. The deviation from a hard cap is intentional: a chain with
perpetual tail emission has a predictable long-run security budget, whereas a
capped chain converts into a fee-only regime whose security depends on fee
demand. Fees are partly burned (`fee_burn_bps`), which offsets tail issuance at
the margin without pretending to make supply deflationary.

Uncle blocks are supported on research profiles with an explicit reward split
(7/8 to the uncle miner, 1/32 to the nephew) so that orphaned work is partially
compensated and the incentive to withhold blocks is reduced.

## 8. Network and pool protocol

Peers run libp2p with Noise, Yamux, gossipsub, Kademlia, identify, ping,
request-response, relay and DCUtR, all with DNS and mDNS excluded from the
runtime graph. Node-to-pool communication is the Template Provider protocol
(TP v4); pool-to-miner is Pool Protocol v6. A template is bound to network
magic, the consensus parameters hash and the genesis hash, and the miner
recomputes the transaction root and rejects any mismatch in chain identity,
header, difficulty, depth, miner key or reward key.

Block authorization is miner-signed: the pool may relay an authorised block but
cannot change the header or the reward recipient, and the signature covers the
full solved header, the chain identity and the reward keys. Share accounting uses
pool-signed envelopes with a hash-chain receipt, so a miner can prove what it
submitted even if the pool disappears.

## 9. Wallet

The wallet derives a master key from a seed, then independent account and
sub-address keys, and builds an `hy1…` address from the version byte, the view
and spend public keys and a checksum. Storage supports plaintext and
password-encrypted save/load. Scan height is persisted so a restored wallet
resumes detection instead of rescanning from genesis, and spent outputs are
tracked locally to present a balance without trusting a server.

The signer is a separate protocol boundary: a request carries the network
binding, the key locator, the ring signing inputs and a reviewable output set,
and a response is verified against the network binding before use. This is what
allows a hardware or remote signer to be dropped in without changing the wallet
core.

## 10. Engineering standards

- Rust 1.97.0, pinned in CI, with `--locked` everywhere.
- Gates that must all pass before anything is called done: workspace build,
  `clippy --all-targets -- -D warnings`, `rustfmt --check`,
  `cargo test --workspace --all-targets`, `cargo doc --no-deps` with
  `RUSTDOCFLAGS=-D warnings`, the fuzz workspace build, a RustSec audit, a
  regression check that `bincode` cannot re-enter the dependency graph, and a
  check that the excluded DNS resolver is absent from the build graph.
- No dependency mirror and no `[patch.crates-io]` override: every dependency is
  a crates.io release pinned by the committed lockfile.
- Determinism review as a category: floating point, `libm`, hash-map iteration
  order and platform-dependent integer widths are treated as consensus bugs
  rather than style issues.

## 11. Limitations and roadmap

Stated plainly, because a reader who discovers these later has been misled:

1. **No audit, no mainnet.** `mainnet` here is a research profile.
2. **PoUW v3 is new.** The workload, single-use set and commitment rule are
   implemented and tested, but no live-network measurement of per-epoch chain
   density, block-time variance or adversarial mining behaviour exists yet.
3. **PoUW v3 does not justify SNARK, useful-dataset or energy-efficiency
   claims.** The witness set is real mathematical data with a measured
   structural verification asymmetry, and that is the whole claim.
4. **Research mechanisms are inactive on devnet.** H-WES shielded recovery,
   H-BFM DAG set agreement, H-FOC' live pacemaker and beacon, and the H-SAC
   compliance circuit are unimplemented beyond the reference models.
5. **Settlement is fail-closed outside one circuit.** Only the Alice neural
   challenge settles by default, and that verifier proves determinism rather
   than search effort, so the AetherCompute economy stays inert.
6. **Cross-repository coordination is mandatory.** Miner, Pool and Wallet pin
   chain identity and block version; a consensus change requires updating all
   three before any joint test can pass.

The order of work is therefore: land the PoUW v3 consensus switch with its state
component and vectors, then the beacon and pacemaker that H-FOC' needs, then the
circuits, and only then a claim about production readiness.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen：可验证数学工作量与隐私结算链

状态：研究型主链。尚未启动主网，也没有经过独立的共识、密码学或电路审计；本文任何内容都不构成对真实资产安全的声明。下面每个机制都标注了代码今天真正建立的东西。

## 0. 摘要

Hyphen 是一条 Rust 基础链，它用**数论见证搜索**取代摘要碰撞，并把该工作量与建立在 CLSAG 环签名、Pedersen 承诺和可恢复状态过期之上的隐私结算层分离。

这里只主张三件事：

1. **工作量是真实数学，不是烧掉的摘要。** 见证是一条第一类 Cunningham 链，其元素必须全部为素数。验证者付 `L` 次确定性素性检验；求解者付期望成本随 `(ln n)^L` 增长的搜索。
2. **见证的单次使用才是绑定成立的原因。** 直觉上的 header 过滤器绑定与剩余类绑定都能被"链池"证明性击破（§3.2）。单次使用让预计算退化为提前挖矿，毫无优势。
3. **默认 fail-closed。** 科学结果结算在审计过的验证器装入前拒绝一切证明；未知功能默认关闭；时钟在多台独立服务器达成一致前不可信；用不同共识参数创建的数据库在任何状态变更前被拒绝打开。

其余内容都是工程：状态如何原子迁移、难度如何在不使用浮点的前提下控制、密钥与地址如何派生，以及还有什么尚未证明。

## 1. 设计哲学

五条规则决定了本仓库的大部分决策。它们与具体后果一起列出——没有后果的原则只是装饰。

**确定性永远优先于性能。** 共识值必须在所有主机上完全一致，因此该路径上不允许出现 `libm`、浮点和 JIT。难度控制器全程整数；合约 VM 从 Cranelift JIT 换成纯 Rust 解释器并内建 fuel 计量——这是刻意用吞吐换可复现的 fuel 计费，并把代码生成器逐出共识路径。

**每个依赖都必须与手写替代方案竞争上岗。** hex 编解码、base58 编解码、SNTP 客户端和 NTP 校正时钟都实现在本仓库内，因为共识 crate 不该为几十行字节处理引入一条供应链。依赖图共 267 个 crate；仅更换 Wasm 运行时一步就砍掉 101 个，Cranelift、`bindgen`、CMake、`libclang` 整套原生面随之消失。

**Fail closed，并且让失败可见。** 拒绝型验证器、拒绝打开的数据库、不可信时钟和关闭的研究功能都是系统明确报告的状态。静默回退被视为缺陷：解析失败后"再试别的方式"的编码路径正是共识分裂的成因。

**把缺失写在能工作的东西旁边。** 仓库 README 自带一张"未激活机制"表，本文 §11 重复了它。夸大自身成熟度的链不是研究链，而是带着 logo 的负债。

**留下有用的产出。** 工作量证明应当留下东西。见证集是一份去重、可独立核验的素数链数据集，任何观察者都能导出并验证；它是链的科学产出，而不是内部计数器。

## 2. 系统总览

| 层 | 实现 | 状态 |
| --- | --- | --- |
| 工作量 | `hyphen-pow::vms` —— 单次使用 Cunningham 链见证、可证明正确的素性判定 | 生效（区块格式 5） |
| 工作量承诺 | `BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)` 写入区块头 | 生效 |
| 见证唯一性 | `hyphen-state::WitnessSet` 稀疏 Merkle 集合，重组时释放 | 生效 |
| 难度 | 整数 momentum-damped LWMA（研究 profile）、冻结整数 LWMA（devnet） | 生效 |
| 状态 | 带 undo journal 的多根原子迁移、reorg 协调器、H-WES 过期 | 生效 |
| 隐私 | 隐身地址、CLSAG 环签名、Pedersen 承诺、Bulletproof 型范围证明 | 生效 |
| 披露 | H-SAC 单输出 opening + 受限 Schnorr 所有权证明 | 研究，未激活 |
| 执行 | Wasmi 2.0 解释器、fuel 计量、受限主机 ABI | 生效 |
| 结算 | AetherCompute 任务生命周期、神经挑战验证器（其余电路 fail-closed） | 研究，仅神经电路生效 |
| 网络 | libp2p（gossipsub、Kademlia、identify、relay、DCUtR）、TP v4 模板协议 | 生效 |
| 矿池 | NCAP 矿工授权、share receipt、Pool Protocol v6 | 生效，规范见 `Research-Non-Custodial-Pool` |
| 钱包 | Flutter 客户端 + Rust 核心：派生、加密存储、隔离签名器 | 生效 |

## 3. 共识

### 3.1 区块与 epoch 结构

区块头依次承诺：格式版本、高度、时间戳、父哈希、交易根、承诺根、nullifier 根、状态根、receipt 根、叔块根、工作量承诺、epoch seed、难度、nonce、额外 nonce、矿工公钥、总费用、奖励、view tag 与区块大小。当前冻结值为区块格式 `4` 与状态迁移版本 `2`，两者都被 `ChainConfig::consensus_params_hash` 承诺。

epoch seed 每 `epoch_length` 个区块由上一条 epoch 最后区块的哈希轮换，是工作量唯一消费的链上熵——这正是工作量无法在父区块存在前被预计算的原因。

### 3.2 工作量：可验证数学搜索

**已退役的前身。** 区块格式 4 用 Q12 扩散场作为工作量函数：区块头播种 64×64 整数字段，按权重和为 4096 的凸组合施加固定步数的扩散，命中条件为对场承诺的 `claim * difficulty < 2^256`。它确定性良好、验证成本仅一次求值，但产出是与独立价值无关的烧掉摘要。区块格式 5 已用上面的见证搜索取代它；v1/v2 的参数（`arena_size`、`scratchpad_size`、`page_size`、`pow_rounds`、`writeback_interval`、`kernel_count`、`merkle_depth`、`pouw_depth`）已不存在，因为一个不影响执行的共识参数就是链身份里的谎言。

**设计中的规则（PoUW v3）。** 工作量变成真实的数论搜索：

```text
见证 n <=> n, 2n+1, 4n+3, …（长度 L）全为素数且全部 < 2^64
```

两个性质让它能用于共识，而不只是听起来漂亮：

- **素性判定是可证明的，不是概率性的。** Miller-Rabin 使用七基集合 `{2, 325, 9375, 28178, 450775, 9780504, 1795265022}`，对全部 `n < 2^64` 被**证明**精确（Jaeschke；Sorenson 与 Webster）。共识路径不存在概率误差上界，也不需要大整数 crate。
- **搜索成本与验证成本在设计上分离。** 验证者做 `L` 次素性检验——微秒级；求解者测试的候选密度按 `A_L · (ln n)^-L` 下降——秒到分钟级。

**为什么直觉绑定是错的。** 把见证绑定到区块的直觉做法是 header 派生过滤器（`H(header ‖ n) < T`）或剩余类（`n ≡ r(header) mod 2^b`）。两者都失败，而这个失败值得精确写出来，因为它并不显然：

- *过滤器绑定。* 构造 `m / p` 条链的求解者可以满足**之后每一个** header：过滤器按 header 独立求值，而池子持久存在，于是池子一旦建成，每多一个区块只需几次哈希。调低 `p` 只会放大诚实成本，而不是攻击者成本——池子可以无限次复用。
- *剩余类绑定。* 用每个类 `m` 条链覆盖宽度 `b` 的全部剩余类，代价是 `2^b · m / density` 次候选测试；一个诚实区块的代价是 `m · 2^b / density`。两者相等：一个区块的工作量就能买到一张永久表。

两种失败同源——谓词是**无状态**的，因此为一个 header 找到的见证可以免费地对每一个其他 header 反复测试。

**单次使用见证闭合了这个回路。** 链上记录已认领的见证，预计算池只能被花掉一次，于是总工作量守恒，预计算被揭示为"提前挖矿"、零优势。这正是本设计完全不去做巧妙 header 绑定的原因：唯一性比绑定更便宜、也严格更强。

**实现状态。** 工作量在区块格式 5 中已生效。`hyphen-pow::vms` 提供筛法、确定性素性判定、带溢出检查的链构造、见证列表验证（升序、互异、数量受限）、按 stride 划分的搜索以及父区块相对的见证承诺；测试覆盖已知 Cunningham 链（89 → 179 → 359 → 719 → 1439 → 2879）、16 个 Carmichael 数、强伪素数、小于 `2^64` 的最大素数、溢出边界，以及承诺绑定（父区块、高度、顺序、数量）。`hyphen-state::WitnessSet` 用稀疏 Merkle 集合强制单次使用，并在重组时释放被拆下区块的见证；区块校验按谓词、唯一性神谕、承诺的顺序检查。

尚未建立的东西也直说：链密度在 epoch 之间的波动还没有在真实网络上测量过，因此固定见证数下的出块时间方差仍是开放的经验问题；单次使用集合是节点本地神谕而不是证明，轻客户端可以跟踪承诺链，但没有集合就无法验证非成员性；数据集导出器尚未实现。

### 3.3 不使用浮点的难度控制

`difficulty` 是求解者期望付出的工作量，累计难度是分叉选择权重。控制器用观测出块时间与目标时间的比值缩放上一个值，全程整数运算：

- **显著性闸门。** LWMA 估计落在上一个值 ±10% 内时，只施加不超过 ±2% 的有界微修正——没有可测漂移的出块时间序列不该推动难度。
- **动量项。** 近期出块时间与窗口均值比较；工作量速率加速时，最多额外施加原始修正量的 30%。
- **操纵抑制器。** 显著的负一阶自相关（快慢交替，矿池跳池或脉冲式矿工的签名）会衰减所请求的调整。显著性判据用两边平方代替开方，阈值由整数牛顿迭代提供，因此该路径上不存在任何 `libm` 调用。
- **护栏。** 每区块钳制限制变化幅度；时间戳被钳到 `[target/10, 6·target]`，完全受控的时钟也只能把单个样本移动最多 60 倍；出块速率低于目标四分之一时，难度绝不允许下调。

devnet 使用代数完全未改动的冻结整数 LWMA；研究 profile 使用上述控制器。两者都是纯整数，因此决定分叉选择的难度值不可能因平台而异。

### 3.4 分叉选择、重组与时间

分叉选择按累计难度严格最重。重组协调器持久化 journal、重算计划工作量、持有独占迁移锁、在分叉状态上验证每个候选、失败时恢复原分支，并在数据库打开期间恢复未完成的 journal。区块通过原子迁移应用：所有参与存储先做快照，更新提交，失败时恢复精确的先前状态。

时间来自本仓库实现的多服务器 NTP 时钟：并行查询 11 台独立服务器、3 秒截止；偏离中位数 2 秒以上的结果被剔除；一致应答少于 3 台即标记不可信并把轮询从 30 秒降到 5 秒。SNTP 客户端要求服务器的 originate 字段回显本节点发出的时间戳——这把每次应答绑定到对应请求，拒绝重放与非请求报文。

## 4. 状态模型

规范状态是少量根的组合，汇总进区块头的状态根：AetherCompute 快照、WASM ledger、H-WES 引用过期状态。区块应用在它们以及承诺树、nullifier 集、链尖和分支归档上原子完成。每个区块序列化一条 undo 记录，携带先前快照以及精确回滚所需的交易哈希、输出索引与 nullifier，因此重组是确定性的逆操作，而不是重新推导。

H-WES（可恢复状态过期）维护五根原子状态：签名公开创建、有界确定性过期与重组回滚已实现并接入研究 profile；屏蔽恢复电路、激励与基准尚未完成。

## 5. 隐私层

交易花费环输入并创建隐身输出：

- **隐身地址。** 每笔支付派生一次性输出密钥，来自收款方的 view 与 spend 公钥，因此公开地址在多次支付之间不可关联。
- **CLSAG 环签名。** 每个输入对一组输出引用签名，且伪输出是被签名消息的一部分——这正是让双重花费检测局部于签名、而不依赖额外披露的原因。
- **Pedersen 承诺与范围证明。** 金额被承诺；余额方程为 `Σ pseudo_outputs == Σ output_commitments + fee·H`，因此手续费是隐含的，交易中不存在明文金额。范围证明是 Bulletproof 型内积证明，带聚合与批验证路径，使验证成本对输出数量保持次线性。
- **view/spend 分离。** view key 能检测并解密入账却无法花费；签名器协议把 spend key 挡在带显式网络绑定的校验边界之后。
- **H-SAC 选择性审计披露**（研究，未激活）：单输出金额开启、受限 Schnorr 所有权证明，以及已公开的泄露下界。尚缺的是冻结的合规关系、机密交付、链来源电路与独立电路审计。

## 6. 执行与科学结算

合约是纯 Rust 解释器执行的 WASM 模块。校验器禁止浮点、SIMD、线程、共享内存、memory64、多内存、组件模型与异常；要求恰好一个受限导出内存；拒绝 start section；导入被限制在冻结的主机 ABI 内。fuel 由解释器自身计费，因此 out-of-gas 是确定性的共识结果而不是墙钟意外；主机调用对存储、哈希和日志另行显式计费。

AetherCompute 把外部任务发布到链上，并只通过节点配置的证明验证器结算结果。默认验证器拒绝一切结果、欺诈与托管证明——这就是刻意的生产姿态：在审计过的验证器、密钥和电路装入之前，结算层不产生任何经济效果。

## 7. 经济模型

出块奖励遵循 logistic 衰减：

```text
R_lcd(h) = R_tail + (R_0 − R_tail) · c² / (h² + c²)
R(h)     = R_lcd(h) · μ(h)
```

其中 `R_0` 为初始奖励，`R_tail` 为渐近下限，`c` 为衰减常数，`μ(h)` 为可选的、受 MSE 上下限（基点）约束的乘子。偏离硬顶是刻意的：永续尾部排放的链拥有可预测的长期安全预算，而硬顶链会转入依赖手续费需求的安全模型。手续费按 `fee_burn_bps` 部分销毁，在边际上抵消尾部发行，但不会假装让供给变成通缩。

研究 profile 支持叔块并带显式奖励分配（叔叔矿工 7/8，侄块 1/32），以部分补偿被孤立的算力并降低扣块激励。

## 8. 网络与矿池协议

节点使用 libp2p，包含 Noise、Yamux、gossipsub、Kademlia、identify、ping、request-response、relay 与 DCUtR，且 DNS 与 mDNS 已被排除出运行图。节点到矿池通信是 Template Provider 协议（TP v4），矿池到矿工是 Pool Protocol v6。模板绑定 network magic、共识参数哈希与创世哈希；矿工重算交易根，并拒绝链身份、区块头、难度、深度、矿工密钥或奖励密钥的任何不匹配。

区块授权由矿工签名：矿池可以转发被授权的区块，但不能改动区块头或收款方；签名覆盖完整已求解区块头、链身份与奖励密钥。Share 记账使用矿池签名信封加哈希链 receipt，因此即使矿池消失，矿工也能证明自己提交过什么。

## 9. 钱包

钱包由种子派生主密钥，再派生独立账户与子地址密钥，并用版本字节、view/spend 公钥与校验和构造 `hy1…` 地址。存储支持明文与口令加密的保存/载入。扫描高度被持久化，使恢复的钱包能从断点继续检测而不必从创世重扫；已花费输出在本地跟踪，从而无需信任任何服务器即可给出余额。

签名器是独立的协议边界：请求携带网络绑定、密钥定位符、环签名输入与可审阅输出集合，响应在使用前必须对照网络绑定校验。这正是硬件或远程签名器可以即插即用、而无需改动钱包核心的原因。

## 10. 工程标准

- Rust 1.97.0，CI 固定版本，所有命令带 `--locked`。
- 称之为"完成"前必须全绿的门禁：工作区构建、`clippy --all-targets -- -D warnings`、`rustfmt --check`、`cargo test --workspace --all-targets`、`cargo doc --no-deps` 且 `RUSTDOCFLAGS=-D warnings`、fuzz 工作区构建、RustSec 审计、`bincode` 不得重回依赖图的回归检查，以及被排除的 DNS 解析器不得出现在构建图中的检查。
- 没有依赖镜像、没有 `[patch.crates-io]` 覆盖：每个依赖都是由提交的锁文件固定的 crates.io 正式发布版本。
- 把确定性当作一个审查类别：浮点、`libm`、哈希表迭代顺序与平台相关整型宽度被当作共识缺陷，而不是风格问题。

## 11. 局限与路线

直说，因为读者若在之后才发现这些，就是被误导了：

1. **没有审计，没有主网。** 这里的 `mainnet` 是研究 profile。
2. **PoUW v3 是新东西。** 工作量、单次使用集合与承诺规则已实现并测试，但尚无真实网络上的逐 epoch 链密度、出块方差或对抗性挖矿行为测量。
3. **PoUW v3 不支持 SNARK、有用数据集或能效声明。** 见证集是带结构性验证不对称性的真实数学数据，这就是全部主张。
4. **研究机制在 devnet 上未激活。** H-WES 屏蔽恢复、H-BFM DAG 集合一致性、H-FOC' 在线 pacemaker 与 beacon、H-SAC 合规电路都只有参考模型之外的实现尚缺。
5. **结算在单一电路之外按构造 fail-closed。** 默认只结算 Alice 神经挑战，且该验证器证明的是确定性而非搜索量，因此 AetherCompute 经济仍是惰性的。
6. **跨仓库协同是强制的。** Miner、Pool、Wallet 各自固定链身份与区块版本；任何共识变更都必须同步更新三者，否则联合测试无法通过。

因此工作顺序是：先落地 PoUW v3 共识切换及其状态分量与向量，再补 H-FOC' 所需的 beacon 与 pacemaker，然后是电路，最后才谈生产就绪。
