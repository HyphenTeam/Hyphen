# Hyphen

[中文说明](README_CN.md)

Hyphen is an experimental privacy-oriented, CPU-first proof-of-work base chain
written in Rust. This repository contains the node, consensus and state
transition code, transaction validation, networking, RPC, cryptographic
libraries, executable research models, and consensus test vectors.

It does not contain the Hyphen Miner, Hyphen Pool, or Hyphen Wallet products.
Those are independent repositories with independent lockfiles, CI, releases,
and security boundaries. A protocol change can require coordinated updates,
but it does not make those repositories part of this one.

## Read this first

Hyphen is not a launched mainnet and has not had an independent consensus or
cryptographic audit. `mainnet` is a research profile. The current devnet can be
built and tested, but that is not evidence that real assets are safe.

The four named research mechanisms are executable reference models, not active
devnet consensus:

| Mechanism | Code and vectors | What is actually established | Missing before activation |
| --- | --- | --- | --- |
| H-WES recoverable state expiry | Public profile integrated on research chains | Atomic five-root state, signed public creation, bounded deterministic expiry and reorg rollback | Shielded recovery/consume circuit, incentives, benchmarks, audit |
| H-BFM parallel block fusion | Present | Unique deterministic order for one agreed finite DAG | DAG set agreement, availability, conflict semantics, incentive and liveness proof |
| H-FOC' fair finality | Present, inactive | Durable PREPARE/COMMIT locks, timeout certificates, lock-carrying view change, dual-committee handoff, receipt obligations and typed P2P receipt transport | Unbiasable beacon, live pacemaker/leader, finalized committee source, block-execution integration, WAN benchmarks, audit |
| H-SAC selective audit disclosure | Present, inactive | One-output amount opening, scoped Schnorr ownership proof, and a leakage lower bound | Frozen compliance relation, confidential delivery, chain-provenance ZK circuit, proving/verifying integration, independent circuit audit |

AetherCompute task publication and the deterministic WASM ledger are integrated
with research-chain block execution, RPC/P2P ingress, mempool templates, state
roots and reorg rollback. Scientific result settlement remains fail-closed
until an exact audited proof verifier is installed. See the
[AetherCompute boundary](docs/research/aether-compute.md).

Consensus and storage serialization now uses the in-repository
[`hyphen-codec`](crates/hyphen-codec/README.md). It is bounded, canonical,
trailing-byte rejecting, and contains no unsafe code. Published devnet v2 chain
identity vectors remain unchanged. The crate is tested but not independently
audited.

## Run a node

Install Rust 1.97.0 and a host C/C++ toolchain, then build with the committed
lockfile:

```bash
cargo build --release --locked -p hyphen-node
```

Print the chain identity before opening an existing database:

```bash
./target/release/hyphen-node --network devnet --print-chain-identity
```

The current devnet v2 identity is:

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=bb0c74b93362b8265d65af5dd48796084448e6b3022c39825476ce1b84439902
genesis_hash=854adc605062fb872dcd20a535dca1ec25d4af58689f1be50e6c26df0c841295
```

Start a local node:

```bash
./target/release/hyphen-node \
  --network devnet \
  --data-dir ./data/devnet-node \
  --listen /ip4/127.0.0.1/tcp/48334 \
  --rpc-bind 127.0.0.1:48333 \
  --template-bind 127.0.0.1:3350 \
  --explorer-bind 127.0.0.1:8080
```

The explorer is HTTP. RPC, P2P, and the template protocol are binary protocols;
opening those ports in a browser is not a valid health check. Use `--help` as
the authoritative CLI reference.

## What the base chain verifies

A block is accepted only after its chain identity, parent, height, timestamp,
difficulty, proof of work, transaction encodings, signatures, range proofs,
nullifiers, fees, roots, reward, and miner authorization pass validation. State
updates are committed atomically. The backend can validate and execute a
planned branch switch with rollback, but complete live reorg handling still
needs P2P branch intake, automatic branch selection, and reconciliation of all
dependent services.

Canonical transaction ordering is a research-profile rule. It makes a declared
set mutation-detectable and removes arrival order as a tie-breaker. It does not
force a miner to include a transaction and therefore does not eliminate
censorship or MEV.

## Mathematical core and proof ledger

This section states only the properties represented by the current reference
code. Full protocol claims require the open obligations listed after each
result.

### Common notation and assumptions

Let `H_d(x) = BLAKE3(d || 0x00 || x)` be a domain-separated 256-bit hash. The
arguments below assume collision resistance and second-preimage resistance of
`H_d`. `Sig` is assumed EUF-CMA secure. `G` is the prime-order Ristretto255 base
point, scalars are in `Z_l`, and discrete logarithms in the group are assumed
hard. These are computational assumptions, not unconditional proofs.

### H-WES: rejecting stale state restoration

For a key `x`, let the authenticated latest-version map at height `t` contain

```text
V_t[x] = (version, status, archive_index, value_hash, head_hash).
```

The archive is append-only and committed by an MMR root `A_t`. A restoration
witness contains an archived record `r`, an MMR inclusion path for `r`, and a
membership path proving `V_t[x]`. Validation requires:

```text
r.key = x
H_record(encode(r)) = V_t[x].head_hash
r.version = V_t[x].version
V_t[x].status = Expired
r.value_hash = V_t[x].value_hash
MMRVerify(A_t, V_t[x].archive_index, H_record(encode(r)), pi_archive) = 1
MapVerify(root(V_t), x, V_t[x], pi_latest) = 1.
```

**Proposition (stale-version rejection).** If the latest map is binding and the
record hash is collision resistant, an adversary cannot restore a record
`r_old` with version lower than the committed version except with negligible
probability.

**Proof.** A successful witness must satisfy both authenticated paths. The map
path fixes one tuple `V_t[x]`; binding prevents a second tuple at the same root
and key. Equality of versions then requires
`r_old.version = V_t[x].version`, contradicting that `r_old` is older. If the
adversary substitutes record fields while preserving `record_hash`, it produces
a second preimage or collision for `H_record`. Therefore success reduces to
breaking one of the assumptions. The MMR alone is insufficient: it proves only
that a record was appended, not that it is latest. That is why both proofs are
mandatory.

The unqualified claim that append-only recovery is impossible would itself be
false: a prover can send the complete archive in one round and let the verifier
recompute its commitment and scan every suffix record. The actual lower bound
needs a succinctness condition. In a membership-only authenticated-array model,
if `m` cells follow the candidate and a verifier opens only `q<m`, an unqueried
cell can contain either an unrelated record or a newer version of the same key.
With perfect completeness and miss probability at most `epsilon`, its expected
number of authenticated queries `Q` must satisfy

```text
E[Q] >= (1-epsilon)m.
```

With two-sided error at most `epsilon`, the corresponding bound is
`E[Q] >= (1-2epsilon)m` for `epsilon < 1/2`.

Secure recovery must therefore pay for authenticated latest state, continuing
witness/index maintenance, or linear suffix data/prover work. H-WES chooses a
fixed-size latest root with provider-held tree/body data and on-demand
`O(log K + log N)` proofs; it does not evade this lower bound.

Lifecycle is defined per incarnation `(x,v)`:

```text
Live(x,v) -> Expired(x,v) -> Recovered(x,v; successor=v+1)
                              \-> Consumed(x,v).
```

Recovery atomically appends a terminal event and creates `Live(x,v+1)`;
consumption has no successor. Authorization binds the action, height, new lease,
and pre-state root. The reference model now tests terminal receipts,
action-bound authorization, and no resurrection after consumption.

For spendable objects, the nullifier set is monotone:
`N_t subseteq N_(t+1)`. If a nullifier `z` was inserted at height `i`, then
`z in N_i` and hence `z in N_t` for every `t >= i`. A restoration transition
that rejects membership in `N_t` cannot revive an already-spent object. The
reference profile deliberately excludes shielded notes until ownership,
latest-state, and non-membership are constrained by a circuit soundly bound to
the chain's Ristretto255/BLAKE3 commitments.

The persistent SMT stores only non-default nodes. For namespace `ns`, leaf
`(k,v)` is `H_leaf(ns,k,v)` and every internal node commits to namespace, depth,
left child, and right child. A 256-sibling membership or non-membership proof
reconstructs exactly one root. Two different openings for one `(ns,k,root)`
imply a first level at which equal parent hashes have different ordered child
pairs, reducing binding to a collision in the domain-separated node/leaf hash.
All changed leaves, ancestors, and the root are committed by one optimistic
sled transaction and flushed before success is returned.

The proof store commits each bounded blob by content hash and each chunk by
`H_chunk(object,index,count,len,bytes)`, then commits chunk leaves in a Merkle
root. A valid chunk proof binds position, count, length, object identity, and
bytes. Full reconstruction checks the complete blob hash. P2P sync serves typed
SMT proofs, blob metadata, and chunk proofs under strict response limits.

An availability certificate means that `2f+1` distinct committee seats signed
after validating the complete blob and exact chain/epoch/retention context. At
least `f+1` signers are honest under the seat fault bound, so honest signers had
the blob at signing time. It does **not** prove that any copy remains available
later; durable retention still needs an enforceable provider/slashing or
erasure-coded availability protocol.

The research-chain public H-WES profile now commits all five roots atomically,
expires at most 1024 objects per block in canonical order, and rolls state back
with reorgs. Open obligations are provider incentives and repair, state-rent
policy, a complete shielded recovery/consume relation, benchmarks, and
independent review.

### H-BFM: a necessary fusion mechanism, not a novelty claim

Let `G_e = (B_e, E_e)` be a finite acyclic braid for epoch `e`. At each step,
take the currently zero-indegree blocks and choose the minimum under the total
rank

```text
rank(b) = (parent_frontier_hash(b), producer_key(b), block_hash(b)).
```

Append that block to the fused order and delete its outgoing edges.

**Lemma (unique canonical order).** For a fixed finite DAG and a total `rank`,
the algorithm terminates and returns exactly one topological order.

**Proof.** Every non-empty finite DAG has at least one zero-indegree vertex.
Because `rank` is total, the eligible set has one unique minimum. Removing that
vertex preserves acyclicity. Induction on `|B_e|` gives a unique choice at every
step and termination after exactly `|B_e|` steps. Every edge's source is
removed before its destination becomes eligible, so the result is topological.

This lemma does not prove that two nodes possess the same `G_e`. Agreement on
the braid, missing-data behavior, conflicting state accesses, and rewards are
separate consensus problems and remain open.

The research candidate is instead fairness over a deliberately finite visible
domain. Consensus admits only

```text
M(tx) = (txid, fee_class, encoded_len, public_conflict_tag).
```

For signed receive sequences from `n=3f+1` work seats and `q=2f+1`, define
`x <_E y` when at least `q` seats report `x` before `y`. Opposite edges cannot
both exist because `2q=4f+2>n`, but longer strong-majority cycles can exist.
The implementation therefore emits strongly connected components as fair
batches. Hidden amounts, parties, and semantics never enter the ordering
function and receive no fairness claim.

For an inclusion receipt and proposal certificate, both signer sets have size
`q=2f+1` in `n=3f+1`, hence intersect in at least `f+1` seats. The durable
`HonestReceiptVoter` records the transaction obligation and flushes it before
returning a seat-bound signature. Therefore the intersection contains an honest
seat that refuses an order omitting that transaction. This proves omission
resistance only when the same active committee and honest-voter APIs are
mandatory. P2P transports typed vote/quorum receipts, but the node does not
activate them because no finalized committee profile is wired in.

### H-FOC: quorum safety, not unconditional 100 ms finality

For a committee of `n = 3f + 1` seats, a certificate contains `q = 2f + 1`
valid signatures over one chain-bound ordering statement. For any two quorum
sets `Q1` and `Q2`,

```text
|Q1 intersect Q2| >= |Q1| + |Q2| - n
                  = 2(2f + 1) - (3f + 1)
                  = f + 1.
```

At most `f` seats are Byzantine, so the intersection contains an honest seat.
If honest voters sign at most one order root for the same `(chain, epoch, view,
slot, parent_frontier)`, two conflicting certificates require that honest seat
to equivocate. Thus two conflicting certificates cannot both exist unless the
fault bound, signature assumption, or honest-voter rule is broken.

This is a safety argument only. A 100 ms path additionally needs a synchronous
period with network delay `Delta`, signature aggregation and verification,
proposal dissemination, and scheduling all fitting the budget. In an
asynchronous network, deterministic bounded-time consensus is impossible; the
repository therefore makes no global 100 ms finality claim.

Seats are sampled with replacement from finalized prior-epoch work. Under an
independent unbiasable-seed model and adversarial work fraction `alpha`, capture
probability is

```text
P_bad = sum_(i=f+1)^n C(n,i) alpha^i (1-alpha)^(n-i).
```

Grinding over `g` candidate seeds raises the union-bound estimate to at most
`min(1,gP_bad)`. Fixed-committee intersection does not by itself prove
cross-epoch safety. The inactive H-FOC' state machine now implements durable
PREPARE/COMMIT locks, timeout votes carrying the highest prepare QC,
lock-preserving view-change proposal checks, and old/new committee handoff QCs
bound to one finalized checkpoint. Safety tests include crash/restart
anti-equivocation and handoff context replay rejection. It still has no live
pacemaker, leader election, committee beacon, or block-execution path.

The current chain seed is `BLAKE3(last epoch block hash)` and is grindable. It
must not be substituted into the independent-seed probability model as if it
were unbiasable. Acceptable activation routes and the Circom field-bridge
obstruction are stated in
[`cryptographic-activation-gates.md`](docs/security/cryptographic-activation-gates.md).

### H-SAC: amount opening and scoped ownership

An output commitment is

```text
C = vG + rH,
```

where `v` is the amount, `r` is a blinding scalar, and `H` is a generator whose
discrete-log relation to `G` is unknown. A disclosure reveals `(v, r)` for one
output and verifies `C = vG + rH`. Binding follows from discrete-log hardness:
two distinct openings imply

```text
(v - v')G = (r' - r)H,
```

which reveals the discrete-log relation between `G` and `H` when
`r != r'`. Hiding is provided by uniformly random `r` in the usual Pedersen
model.

Ownership uses a Schnorr proof. For one-time public key `P = xG`, the prover
samples `k`, sets `R = kG`, computes
`c = H_challenge(context, R, P)`, and returns `s = k + cx`. Verification checks
`sG = R + cP`. The context binds chain ID, transaction ID, output index, global
index, auditor public key, scope hash, validity interval, nonce, commitment,
public key, amount, and blinding. Under the forking-lemma model, two accepting
transcripts with the same `R` and different challenges extract
`x = (s-s')/(c-c')`; forging therefore reduces to discrete log plus the random
oracle assumption.

The package is not encrypted and proves neither full transaction provenance nor
source-of-funds legality. Confidential transport and the larger provenance
circuit are still required.

For private state `X`, prior public chain information `P`, compliance output
`Y=F(X,P)`, and adversarial view `V`, zero-error correctness implies

```text
I(X;V | P) >= H(Y | P).
```

With error `epsilon` and output range size `M`, Fano's inequality gives

```text
I(X;V | P) >= H(Y|P)-h_2(epsilon)-epsilon log_2(M-1).
```

A transcript simulatable from `(P,Y)` is task-optimal in the computational
sense. The current v0 package reveals the amount and blinding, so it is not
optimal for a task that needs only one compliance bit. Its exact plaintext
fields are now exposed through `DISCLOSED_FIELDS_V0`.

Full statements and boundaries are in the [H-WES lower bound and object
model](docs/research/h-wes-theorem-and-object-model.md), [private visible-domain
fair ordering and H-FOC'](docs/research/private-visible-fair-ordering.md),
[H-SAC leakage lower bound](docs/research/h-sac-leakage-lower-bound.md), and the
[research ledger](docs/research/four-core-innovations.md).

No shielded H-WES or H-SAC Circom circuit is claimed. The live transaction
relations use Ristretto255 and BLAKE3 while ordinary Circom artifacts operate
over BN254; a sound bit-level/group bridge or a versioned commitment migration
is required. No independent circuit audit has been commissioned or supplied.

## Verification

Run the same base-chain gates used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
cargo audit --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
cargo audit --file crates/hyphen-fuzz/Cargo.lock --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
```

Nightly CI runs bounded transaction, RPC, P2P, and canonical-codec decoder
fuzzing. Passing these
checks establishes reproducibility for the tested revision; it is not a formal
proof or an external security review.

The two audit exceptions are optional `hickory-proto` dependencies retained in
libp2p's lock graph. Hyphen disables libp2p default features, DNS, and mDNS, so
those crates are not in the built runtime graph; boot nodes must currently use
IP multiaddresses. Any new non-ignored RustSec vulnerability fails CI.
Informational unmaintained/unsound transitive warnings remain tracked and are
not presented as resolved.

## CI and automated releases

`CI` runs on pushes and pull requests. A successful `CI` run on `main` triggers
the `Release` workflow. It rebuilds `hyphen-node` on Linux, Windows, and macOS,
packages the executable with build metadata and available debug information,
publishes SHA-256 files, and creates a GitHub prerelease tied to the exact commit.
Pull requests never receive release permissions.

Automated releases are reproducible development artifacts, not a declaration
of mainnet readiness. Verify the checksum and the embedded commit before use.

## Repository boundaries

Wire formats and chain identity are compatibility contracts. Change them in
this order: update the specification, update canonical vectors, update and test
the base chain, then update each independent client against the exact base-chain
commit. See
[`docs/architecture/repository-boundaries.md`](docs/architecture/repository-boundaries.md).

## Security

Do not publish mnemonics, identity keys, payout tokens, or private vulnerability
details. See [SECURITY.md](SECURITY.md) for reporting instructions and the
current support boundary.

## License

Hyphen is licensed under the GNU Affero General Public License v3.0. See
[LICENSE](LICENSE) for the complete terms.

---

<!-- hyphen-bilingual-chinese -->

# 中文版

# Hyphen 主链

[English](README.md)

Hyphen 是一条用 Rust 编写、面向隐私交易和 CPU 优先工作量证明的实验性主链。这个仓库只负责节点、共识、状态转换、交易验证、P2P、RPC、密码学库、研究机制参考实现和共识测试向量。

`HyphenMiner`、`HyphenPool`、`HyphenWallet` 是三个独立仓库。它们可以为了联调放在主链目录旁边，但有自己的依赖锁、CI、Release 和安全边界。主链协议变化可能要求它们同步升级，不代表它们属于主链仓库。

## 先说清楚现在能做什么

当前 devnet v2 可以构建、运行和复核链身份；交易、区块、状态根、PoW、矿工授权、历史重放和分支切换后端都有测试。项目尚未完成独立密码学/共识审计，也没有长期公开主网。命令行里的 `mainnet` 仍是研究配置，不应承载真实资产。

| 能力 | 当前事实 | 不能据此声称的内容 |
| --- | --- | --- |
| 基础 PoW 主链 | 已接入区块验证与状态提交 | 未证明长期经济安全或主网安全 |
| 隐私交易库 | 有承诺、范围证明、CLSAG、隐身输出与测试 | 未经过外部密码学审计 |
| 分支切换 | 后端可验证候选分支、原子切换、失败恢复 | P2P 自动收集分支和全系统 reorg 对账仍未贯通 |
| H-WES | 研究链已接入五根原子状态、签名公共创建、限量确定性过期与重组回滚 | 缺 shielded 恢复/消费电路、provider 激励和外审 |
| H-BFM | 对一个已一致的有限 DAG 给出唯一规范拓扑序 | 尚未解决 DAG 集合一致、缺数、冲突执行、激励与活性 |
| H-FOC' | 已有持久 PREPARE/COMMIT lock、timeout/view-change、双委员会 handoff、receipt obligation 和 P2P receipt 类型 | 缺不可偏置 beacon、在线 pacemaker/leader、已最终委员会来源、区块执行接线和 WAN 基准 |
| H-SAC | 已有单输出 opening、绑定 auditor/scope 的 Schnorr 所有权证明和泄漏下界 | 缺冻结的合规关系、provenance ZK 电路、证明器/验证器接线和独立电路审计 |
| AetherCompute | 已接入任务/结果/挑战/续存/结算状态机、RPC/P2P、mempool 和状态根 | 默认证明验证器拒绝结算，需激活真实电路/VK 后端 |
| WASM VM | 研究链已接入签名部署/调用、nonce、gas、状态根和原子回滚 | 仍需经济收费、回执 RPC 与外审 |

共识与持久状态序列化已切换到仓库内自研的
[`hyphen-codec`](crates/hyphen-codec/README.md)。其格式固定宽度、有限长、拒绝尾随字节、
map 输出规范化，并以 `forbid(unsafe_code)` 禁止不安全代码。公开 devnet v2 链身份向量
保持不变；该 crate 有对抗测试，但没有经过独立审计。

## 构建与启动

本项目在 Rust 1.97.0 和系统 C/C++ 构建工具上测试通过，可使用依赖构建命令如下：

```powershell
cargo build --release --locked -p hyphen-node
```

首次启动或重新使用旧数据库前，先打印链身份：

```powershell
.\target\release\hyphen-node.exe --network devnet --print-chain-identity
```

当前 devnet v2 必须输出：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=bb0c74b93362b8265d65af5dd48796084448e6b3022c39825476ce1b84439902
genesis_hash=854adc605062fb872dcd20a535dca1ec25d4af58689f1be50e6c26df0c841295
```

本地节点示例：

```powershell
.\target\release\hyphen-node.exe `
  --network devnet `
  --data-dir .\data\devnet-node `
  --listen /ip4/127.0.0.1/tcp/48334 `
  --rpc-bind 127.0.0.1:48333 `
  --template-bind 127.0.0.1:3350 `
  --explorer-bind 127.0.0.1:8080
```

浏览器只能访问 Explorer HTTP。RPC、P2P、模板端口都是二进制协议，浏览器空白不是故障。所有命令行参数以当前二进制的 `--help` 为准。

## 主链实际验证了什么

节点接收区块后，会验证网络与共识身份、父块、高度、时间戳、难度、PoW、交易编码、签名、范围证明、nullifier、费用、交易根、状态根、奖励和矿工授权。状态变化采用原子提交，失败不会留下半个新区块。

研究配置中的规范交易排序只解决一个较窄的问题：当矿工声明了交易集合后，节点可以检测排序或内容是否被替换，mempool 也不再用到达顺序打破同优先级冲突。矿工仍可主动遗漏交易，所以这不是“消灭审查”，也不是完整 MEV 方案。

## 研究机制的数学定义与必要证明

下面只证明当前代码真实表达的性质。每一项都把假设、命题和未完成义务分开写，避免把“有一个算法”包装成“整个协议已经安全”。

### 统一符号

定义域分离哈希：

```text
H_d(x) = BLAKE3(d || 0x00 || x).
```

证明使用 `H_d` 的抗碰撞和抗二次原像假设。签名方案使用 EUF-CMA 不可伪造假设。椭圆曲线群使用素数阶 Ristretto255，基点为 `G`，标量域为 `Z_l`，离散对数被假设为困难。这些都是计算安全假设，不是无条件数学真理。

### 一、H-WES：可恢复状态过期为什么不能只靠 MMR

对状态键 `x`，高度 `t` 的最新版认证映射保存：

```text
V_t[x] = (v_t, status_t, j_t, h_value, h_record),
```

其中 `v_t` 是最新版本，`j_t` 是归档 MMR 位置。归档根记为 `A_t`，当前活动状态根、最新版映射根、nullifier 根、归档根和数据可用性根共同进入组合状态根。

恢复见证必须同时证明：

```text
r.key = x
H_record(encode(r)) = V_t[x].h_record
r.version = V_t[x].v_t
V_t[x].status = Expired
r.value_hash = V_t[x].h_value
MMRVerify(A_t, j_t, H_record(encode(r)), pi_archive) = 1
MapVerify(root(V_t), x, V_t[x], pi_latest) = 1.
```

**命题 1：旧版本不可恢复。** 如果最新版映射承诺具有 binding 性，且 `H_record` 抗碰撞、抗二次原像，那么攻击者用 `version < v_t` 的旧记录通过恢复验证的概率可忽略。

**证明。** `pi_latest` 把键 `x` 唯一绑定到根中承诺的元组 `V_t[x]`。验证条件又强制 `r.version = V_t[x].v_t`。旧记录满足 `r.version < v_t`，与等式直接矛盾。若攻击者修改旧记录的版本或内容，同时保持 `h_record` 不变，就构造了 `H_record` 的二次原像或碰撞；若攻击者让同一个映射根对同一个键打开成另一个版本，则破坏认证映射的 binding 性。因此成功只能来自底层假设被攻破，概率可忽略。

这也解释了为什么 MMR inclusion proof 不够：MMR 只能证明“某条记录曾被追加”，不能证明“这是这个键目前最新的记录”。归档证明和最新版证明缺一不可。

但“只靠 append-only archive 一定不可能安全恢复”这个原始说法也过强：恢复者可以在一轮中发送完整 archive，验证者重算 commitment 并线性扫描，因此仍满足常数轮，只是付出 `Theta(N)` 通信和计算。严格下界必须加入 succinctness。对 membership-only 黑盒 archive，候选记录后还有 `m` 个 cell；若 verifier 没有查询其中位置 `j`，那么“无关记录”和“同 key 更新版本”两个世界的已见 transcript 相同。在完美完备性、漏检概率至多 `epsilon` 时，期望认证查询数 `Q` 必须满足：

```text
E[Q] >= (1-epsilon)m.
```

若完备性和健全性都允许至多 `epsilon` 的错误，则 coupling 论证给出的严格界是
`E[Q] >= (1-2epsilon)m`，其中 `epsilon < 1/2`。

所以安全恢复至少承担一项成本：认证 latest state、持续 witness/index 更新，或线性后缀数据/prover 工作。H-WES 选择保留 fixed-size latest root，把 `O(K+N)` tree/body 存储交给可替换 provider，并由恢复交易携带 `O(log K+log N)` 新鲜证明；它没有违反下界。

生命周期严格属于 incarnation `(x,v)`：

```text
Live(x,v) -> Expired(x,v) -> Recovered(x,v; successor=v+1)
                              \-> Consumed(x,v).
```

恢复在同一个线性化点追加终态历史事件并创建 `Live(x,v+1)`；消费没有后继。授权摘要绑定 action、高度、新租期和 pre-state root，旧授权不能被改成另一动作或租期。当前 reference model 已覆盖恢复回执、消费终态和 no-resurrection 负向测试；持久 SMT、认证 blob store、P2P proof serving 和 DA 证书验证器也已有独立实现。研究 profile 已把五根、公开创建和有界过期原子接入当前区块状态转换与 reorg；shielded recovery/consume 仍关闭。

对可花费对象，nullifier 集满足单调性：

```text
N_t subseteq N_(t+1).
```

若 `z` 在高度 `i` 已被花费，则 `z in N_i`，所以对所有 `t >= i` 都有 `z in N_t`。恢复转换在当前 `N_t` 中检查并拒绝 `z`，已经花费的对象就不能因过期再生。当前参考配置明确排除 shielded note，因为它还缺少把所有权与 nullifier 非成员证明绑定起来的隐私电路。

持久 SMT 对 namespace、depth、左右子节点做域分离承诺。成员或非成员证明都固定包含 256 个 sibling。若同一 `(namespace,key,root)` 能打开为两个不同值，沿两条重算路径自叶向根取第一个发生差异但父哈希相等的位置，就得到 leaf hash 或 node hash 的碰撞。因此在哈希抗碰撞假设下 opening 具有 binding 性。叶、全部受影响祖先和新根在同一个 sled 乐观事务中提交，并在返回成功前 flush；失败或 root CAS 冲突不会留下半个状态。

认证 blob store 对完整对象计算 content hash，并对每个 chunk 计算 `H(object,index,count,len,bytes)` 后建立 Merkle root。chunk proof 同时绑定对象、位置、总块数、长度和内容；完整重组还会再次核对 content hash。DA 证书要求 `2f+1` 个不同 seat 在签名前验证完整 blob，所以最多 `f` 个恶意 seat 时，至少 `f+1` 个诚实 signer 在签名时持有该 blob。这个结论不等于“未来永久可用”；如果之后所有副本都删除，任何 commitment 都不能恢复信息。

**仍未完成：** 存储 provider 激励与 challenge/repair、状态租金参数、shielded 所有权/nullifier recovery/consume 电路、长期空间与恢复基准、独立审计。

### 二、H-BFM：必要的规范融合机制，不作为新颖性声明

设一个 epoch 中已达成集合一致的有限有向无环图为 `G_e=(B_e,E_e)`。每一步取当前所有入度为零的区块，并按下面的全序选择最小者：

```text
rank(b) = (parent_frontier_hash(b), producer_key(b), block_hash(b)).
```

将它加入融合序列，再删除它的出边。

**引理 2：固定 DAG 的规范融合序列唯一。**

**证明。** 任意非空有限 DAG 至少存在一个入度为零的顶点，否则从任意顶点不断沿入边回溯，有限性会迫使顶点重复，从而产生环，与 DAG 矛盾。`rank` 是全序，所以所有候选中存在唯一最小者。删除该顶点后仍是有限 DAG。对顶点数做归纳，每一步选择都唯一，并在恰好 `|B_e|` 步后终止。一个顶点只有在全部前驱被删除后才会变成零入度，因此输出满足全部边的拓扑先后关系。

这个引理只证明“相同 DAG 得到相同顺序”。它没有证明全球节点一定拿到相同 DAG。集合一致、数据缺失、双提议、冲突状态访问、奖励分配、反垃圾和活性仍是独立且未完成的问题。代码因此不能声称已经得到成熟 DAG 共识，也不能声称通过换名字绕开已有系统。

真正继续研究的是隐私交易的**可见域公平性**。令共识唯一允许观察的投影为：

```text
M(tx)=(txid, fee_class, encoded_len, public_conflict_tag).
```

seat `i` 签名本地接收序列 `seq_i`。对 `n=3f+1,q=2f+1`，定义

```text
x <_E y iff |{i : pos_i(x)<pos_i(y)}| >= q.
```

两个相反方向不可能同时成立，因为需要 `2q=4f+2>3f+1=n` 个 seat 方向贡献；但长度至少 4 的强多数 cycle 仍可能存在，所以实现把 strongly connected component 作为一个 fair batch，只对 component 间顺序给保证。隐藏金额、地址和语义不进入排序函数，因此也不对它们声称公平。当前参考实现验证 seat 签名、quorum visibility、SCC batch、cutoff 后随机 tie-break 和 CPU 工作上限；P2P 已能传输有大小界的 typed receipt vote/quorum receipt，但尚未接入 mempool 和区块执行。

receipt 强制纳入依赖另一个 quorum 交集：receipt signer 集与 proposal QC signer 集均为 `q=2f+1`，交集至少 `f+1`，其中至少一个诚实 seat。`HonestReceiptVoter` 在返回 seat-bound 签名前先把纳入义务写入 sled 并 flush，崩溃重启后仍拒绝遗漏。因此，只要生产网络强制同一委员会通过该 API 投票，遗漏已形成 quorum receipt 的交易就无法取得 proposal QC。当前节点没有已最终委员会 profile，所以只解析并拒绝激活这些消息，不能声称线上已经抗审查。

### 三、H-FOC：快速排序证书的安全边界

设委员会有 `n=3f+1` 个席位，最多 `f` 个 Byzantine 席位。一个有效排序证书需要 `q=2f+1` 个不同席位的有效签名。对任意两个 quorum `Q_1,Q_2`：

```text
|Q_1 intersect Q_2|
>= |Q_1| + |Q_2| - n
= 2(2f+1) - (3f+1)
= f+1.
```

交集至少有 `f+1` 个席位，而恶意席位至多 `f` 个，所以交集至少包含一个诚实席位。

**定理 3：同上下文冲突证书不可同时成立。** 假设诚实席位对同一个 `(chain_id, epoch, view, slot, parent_frontier)` 最多签一个 `order_root`，签名不可伪造，且恶意席位不超过 `f`。那么两个不同 `order_root` 的有效证书不能同时存在。

**证明。** 两个证书的签名席位集合交集至少包含一个诚实席位。该席位若同时出现在两个不同根的证书中，就必须签署两个冲突 statement，违反诚实投票规则；若它并未签署其中之一，则对应签名是伪造。两种情况都与假设矛盾。

这只给出 safety，不给出无条件 100 ms finality。100 ms 还要求在同步窗口内网络延迟 `Delta`、提议广播、排队、签名生成、聚合和验证总耗时低于预算。异步网络下不存在确定性有界时间共识保证。因此正确表述是“目标为乐观 100 ms 排序证书”，不是“全球几百节点已经在 100 ms 最终确认”。

PoW 委员会从前一 finalized epoch 按工作量有放回抽取 seat。攻击工作份额为 `alpha` 且 seed 不可偏置时，委员会失陷概率为：

```text
P_bad = sum_(i=f+1)^n C(n,i) alpha^i (1-alpha)^(n-i).
```

若矿工可在 `g` 个 seed 中 grinding，只能给出 `P_bad_grind <= min(1,gP_bad)`。固定委员会的 quorum 交集不能自动证明跨 epoch 安全。当前不激活的 H-FOC' 状态机已经实现 PREPARE/COMMIT QC、commit lock、携带最高 prepare QC 的 timeout/view-change、lock downgrade 拒绝、旧/新委员会分别签署同一 finalized checkpoint 的 handoff，以及签名前持久化的 crash anti-equivocation。

当前 epoch seed 实际为 `BLAKE3(上一 epoch 末块哈希)`，矿工可通过 nonce、extra nonce、交易集和 withholding grinding，因此它不是不可偏置 seed。不能把上述独立二项分布直接套到当前链。严格的 threshold-VRF/unique threshold signature + DKG 或 VDF 激活条件见 [`docs/security/cryptographic-activation-gates.md`](docs/security/cryptographic-activation-gates.md)。

**仍未完成：** 不可偏置 beacon、在线 pacemaker/leader、已最终委员会来源、receipt 聚合服务、时钟/DoS 策略、跨洲原始基准、慢路径最终性结合和主链接线。

### 四、H-SAC：可控披露到底证明了什么

交易输出金额承诺为：

```text
C = vG + rH,
```

`v` 是金额，`r` 是随机盲因子，`H` 与 `G` 的离散对数关系未知。单输出披露给出 `(v,r)`，验证者重算等式。

**binding 推导。** 若同一个 `C` 有两个不同 opening `(v,r)` 与 `(v',r')`，则：

```text
vG+rH = v'G+r'H
(v-v')G = (r'-r)H.
```

当 `r != r'` 时，可以由比值求得 `G` 与 `H` 的离散对数关系，违反离散对数困难假设；退化情形同样要求金额相等。因此在该假设下承诺具有计算 binding 性。随机 `r` 则提供 Pedersen 承诺的 hiding 性。

所有权使用 Schnorr 关系。一次性公钥 `P=xG`，证明者随机取 `k`：

```text
R = kG
c = H_challenge(context, R, P)
s = k + cx.
```

验证者检查：

```text
sG = R + cP.
```

完整性来自代入：`sG=(k+cx)G=kG+c(xG)=R+cP`。知识可靠性使用 forking-lemma 模型：若同一 `R` 对两个不同 challenge `c,c'` 都有有效响应 `s,s'`，则可提取

```text
x = (s-s') / (c-c') mod l.
```

所以不知道 `x` 的伪造者会导出离散对数解。当前 context 绑定链 ID、交易 ID、输出位置、全局索引、审计者公钥、scope hash、有效期、随机 nonce、承诺、公钥、金额和盲因子，修改任一字段都会改变 challenge。

当前 disclosure 包本身没有加密，只能通过外部机密信道交付；它只证明某个输出的金额 opening 和一次性密钥所有权，不证明完整资金来源合法，不证明交易图 provenance，也没有聚合审计和撤销协议。把它称为完整“审计密钥”是不准确的。

更一般地，设私有状态为 `X`，公开链信息为 `P`，合规任务输出 `Y=F(X,P)`，adversary 最终视图为 `V`。若 auditor 零错误恢复 `Y`，链式法则给出不可避免的泄漏下界：

```text
I(X;V | P)
= I(Y;V | P)+I(X;V | Y,P)
>= H(Y | P).
```

错误率为 `epsilon`、输出空间大小为 `M` 时，由 Fano inequality：

```text
I(X;V | P) >= H(Y|P)-h_2(epsilon)-epsilon log_2(M-1).
```

若存在只用 `(P,Y)` 模拟真实 transcript 的 simulator，则协议在计算意义上不泄漏任务输出之外的信息。当前 v0 明文公开 amount 与 blinding，显然没有达到仅输出合规 bit 时的下界；代码现在提供机器可读 `DISCLOSED_FIELDS_V0`，避免把 auditor binding 误写成包加密。

完整证明与边界分别见 [H-WES 下界与对象模型](docs/research/h-wes-theorem-and-object-model.md)、[隐私可见域公平排序与 H-FOC'](docs/research/private-visible-fair-ordering.md)、[H-SAC 最小泄漏下界](docs/research/h-sac-leakage-lower-bound.md) 以及总台账 [`docs/research/four-core-innovations.md`](docs/research/four-core-innovations.md)。

仓库目前没有可声称为 shielded H-WES 或 H-SAC 的 Circom 电路。链上关系使用 Ristretto255 与 BLAKE3，普通 Circom/R1CS 位于 BN254 标量域；直接把 256-bit digest 取模放入 field 会产生非单射映射，不能证明原始 digest 相等。必须实现并审查 bit-level BLAKE3、Ristretto 编码/群关系，或采用带严格 binding bridge 的版本化 field-friendly commitment。也没有任何外部机构出具电路审计报告，因此 README 不使用“已审计”表述。

## 测试与 CI 门禁

本地执行与 CI 相同的主链门禁：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
cargo audit --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
cargo audit --file crates/hyphen-fuzz/Cargo.lock --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
```

Nightly workflow 会对交易、RPC、P2P 和规范 codec 解码器执行有时间上限的真实 fuzz。绿色 CI 证明的是“这个提交通过了这些可重复检查”，不是外部审计或完整形式化验证。

两个 RustSec 例外来自 libp2p 锁图中可选的 `hickory-proto`。本项目关闭 libp2p 默认 feature、DNS 和 mDNS，构建运行图不包含它们，boot node 当前必须使用 IP multiaddress；CI 对除此之外的新 vulnerability 直接失败。审计输出中的 unmaintained/unsound 传递依赖 warning 仍在跟踪，不能写成已全部消除。

## 自动 Release

`CI` 在 push 和 pull request 上运行。只有 `main` 分支的 `CI` 成功后，`Release` 才获得 `contents: write` 权限并重新构建 Linux、Windows、macOS 三个平台的 `hyphen-node`。每个包包含可执行文件、提交号、工具链信息和可用调试信息，并单独发布 SHA-256。

Release 标签绑定到 CI run、attempt 和提交，不会把 PR 代码发布出去。当前项目未达到主网安全门槛，所以自动发布的是 GitHub prerelease 开发产物；“能自动下载”不等于“可以安全托管真实资产”。

## 协议变更顺序

修改 wire format、状态根或链身份时，顺序必须是：先改规范，再改固定向量，再让主链测试通过，然后让 Miner、Pool、Wallet 分别固定到这个主链提交并运行各自 CI。仓库边界详见 [`docs/architecture/repository-boundaries.md`](docs/architecture/repository-boundaries.md)。

## 安全报告

不要在 issue、日志或截图中提交 mnemonic、身份私钥、payout token 或未公开漏洞细节。报告方式和当前支持范围见 [SECURITY.md](SECURITY.md)。

## 许可证

Hyphen 使用 GNU Affero General Public License v3.0，完整条款见 [LICENSE](LICENSE)。
