# Neural-Cryptography Challenge (Alice / Bob)

Status: research. `crates/hyphen-neural` and `contracts/alice-neural` are
executable, tested and deployable on any chain in this repository that runs the
`hyphen-vm` contract ABI. The challenge is **not** the block proof-of-work: block
eligibility remains the PoUW v3 Cunningham-witness rule described in the
[whitepaper](Whitepaper). Nothing here changes chain weight, issuance or
fork choice.

## The mechanism in one paragraph

Alice is a two-layer perceptron whose weights are derived from a public chain
seed. The contract publishes the network `A` and one target `y* = A(x*)`, and a
prover earns the epoch by submitting any `x` with `A(x)` inside a published
tolerance of `y*`. Verification is a single `O(input_dim * hidden_dim)` forward
pass. Producing `x` requires inverting a non-convex integer map, which is the
only asymmetry the mechanism has.

## Why the challenge is the inverse problem

The intuitive design — publish 1,000 plaintext/ciphertext pairs and ask miners to
learn Alice's weights — is unsound, and not in a subtle way. The contract must
hold Alice's weights in order to verify anything, so the weights are public by
construction. Copying them satisfies every loss threshold without doing work. The
same objection kills any scoring rule that rewards reproducing `A`.

The inverse formulation publishes `A` and a target `A(x*)`, and asks for any `x`
whose image lands inside the tolerance. The verifier is one forward pass.

**`x*` is not secret.** `ChallengeDescriptor::derive_preimage` recomputes it from
the public `chain_seed`, so the target can be produced without searching at all.
That is acceptable for a contract that settles a result someone declared, and it
is disqualifying for a proof of work: a block gated on this circuit would be
free to produce.

`crates/hyphen-neural/src/work.rs` supplies the one-way variant that a block may
use. The seed fixes the *network*, a published threshold fixes the difficulty,
and a solution is any `x` with `score(A(x)) < threshold`. Nothing derives such an
`x`; the only way to obtain one is to run forward passes. The task commits to the
exact descriptor through `program_hash`, so the threshold cannot be relaxed after
publication. `hyphen_compute::NeuralWorkVerifier` is the node's default
settlement verifier for this reason, and the inverse circuit is not eligible.

## Numbers are integers, on purpose

A verifier that runs on every node cannot use floating point. Rounding modes,
fused multiply-add contraction and NaN payloads differ across targets, so the
same program can accept a solution on one host and reject it on another. Every
value here is Q32.32 fixed point (`i64`, 32 fractional bits):

- multiplication is `(a * b) >> 32` computed in `i128` and saturated, so it floors
  toward negative infinity;
- division is `(a << 32) / b`, truncated toward zero, and returns `None` outside
  the representable range;
- the activation is the Padé (3,2) approximant `x(27 + x²)/(27 + 9x²)`, saturated
  to `±1` outside `±3`, evaluated with a fixed operation order;
- derivation is ChaCha20 (RFC 8439) keyed by the chain seed with the epoch and a
  domain tag in the nonce, so weights, preimages and solver restarts cannot be
  derived from one another.

Two independent implementations that follow these rules compute the same
activations bit for bit. The crate is `no_std` with no allocator so the contract
and the miner execute the same code, not two ports of it.

## Acceptance rule

```text
accept(desc, x)  <=>  max_i |A(x)_i - y*_i| <= desc.tolerance_ulp
```

`tolerance_ulp` is a protocol field, bounded at open time to
`1 / 1_000` of the unit range. The default is `4_295` ulps, one millionth of the
range. A random `x` misses by `O(1)`, so the tolerance does not admit guesses.

## Difficulty

The hidden width is the difficulty axis. Cost per solve rises with
`output_dim * hidden_dim * input_dim` for the Jacobian plus `hidden_dim * input_dim`
per forward pass; verification pays only the forward pass. The controller is:

```text
observed < target / 2  -> width *= 2
observed > target * 2  -> width /= 2
otherwise              -> width unchanged
```

with the result clamped to `[16, 512]`. The band is hysteresis, not smoothing: a
controller that reacts to every sample oscillates between adjacent widths and
publishes a different challenge shape every epoch.

**Measured envelope.** `cargo run --release -p hyphen-neural --example envelope`
on the development machine, release build, one core: the reference prover solves
the 16-wide profile in about 6 ms and the widest 512-wide profile in about 15 ms,
while one verification costs 0.01–0.21 ms over the same range. The measured
compute-to-verify ratio is roughly 30–70×, and 770× at the smallest width where
fixed costs dominate. The controller can therefore not hold a ten-minute epoch:
at the widest width the contract profile is still three orders of magnitude below
the target, so the controller saturates at `MAX_HIDDEN_DIM`.

This is a property of the design, not a tuning problem. An on-chain verifier must
regenerate Alice's weights from the seed, which costs the same `O(hidden_dim *
input_dim)` as the forward pass; raising the width until solving takes ten
minutes would make one verification cost minutes of contract gas. A ten-minute
target requires a second hardness axis that is cheap to verify — a solution
filter, a proof system, or off-chain settlement — and each of those is a different
security argument. They are deliberately not part of this profile.

What the controller still does is honest: it publishes the dimension that matches
the observed solve time within the accepted range, and the range is a protocol
constant rather than an operator setting.

## Security properties and obligations

Established by the code and its tests:

- **Determinism.** Same descriptor, same weights, same target, same acceptance on
  every host. Pinned by unit tests, an RFC 8439 vector, and an end-to-end test
  that runs the compiled contract inside `hyphen-vm`.
- **No weight copying, and no derived preimage.** The inverse circuit's answer is
  recomputable from the public seed, so only the one-way work circuit
  (`work.rs`) may gate work; the weights are
  never part of a submission.
- **Single settlement.** The first accepted preimage is stored under
  `hyphen:sol:v1:<epoch>`; later submissions return `2` and mutate nothing.
- **No epoch rewrite.** A second, different descriptor for an open epoch returns
  `EpochConflict`. Re-opening with the identical descriptor is idempotent.
- **Read-only queries.** `hyphen_query` answers `Status` and performs no storage
  write; the VM rejects a query that mutates state.
- **Bounded verification.** `Max` dimensions are compile-time constants, the
  request size is capped at 1 KiB, and the widest profile executes within the
  test gas limit.

Open obligations, stated plainly:

- **Seed provenance.** The contract binds a descriptor to an epoch but cannot
  verify that `chain_seed` is a real chain value. Whoever opens the epoch chooses
  the seed. A deployment must derive the seed from a value the operator cannot
  pick — the parent block hash or a beacon — and that wiring belongs to the
  application that calls `Open`, not to this contract.
- **No succinctness.** Verification is a full forward pass, not a proof. It is
  cheap, not constant-size.
- **No external audit.** The fixed-point profile, the activation constants and the
  contract ABI have not been reviewed outside this repository.
- **No economic model.** The contract records settlements; it does not pay
  anyone. Rewards belong to whatever escrow or token layer calls it.

## Contract ABI

`hyphen_execute` and `hyphen_query` accept:

```text
Open   0x01 || descriptor(56)
Submit 0x02 || epoch(8) || width(2) || Q32.32 values(width * 8)
Status 0x03 || epoch(8)
```

The descriptor is little-endian:

```text
0..2    version u16 (= 1)
2..10   epoch u64
10..12  input_dim u16
12..14  hidden_dim u16
14..16  output_dim u16
16..24  tolerance_ulp u64
24..56  chain_seed [u8; 32]
```

Every response is 17 bytes: status, worst per-component error (`u64` ulps), mean
squared error (`u64`, saturated). Status codes:

| Code | Meaning |
| --- | --- |
| 0 | solution rejected |
| 1 | accepted and recorded (or descriptor opened) |
| 2 | epoch already settled |
| 3 | epoch open (query only) |
| 4 | epoch missing (query only) |
| 5..12 | `NeuralError` codes: spec, buffer, weights, descriptor, tolerance, encoding, solution, not solved, epoch conflict, budget, operation, host |

Storage keys are `hyphen:chal:v1:<epoch>` (56 bytes) and `hyphen:sol:v1:<epoch>`
(`caller(32) || values(width * 8) || max_error(8)`).

## Running it

Build and test the library:

```bash
cargo test -p hyphen-neural --locked
```

Derive an epoch, then solve and verify it. The seed is any 32-byte hex value; in a
deployment it is the chain value the caller chooses:

```bash
SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
cargo run --release -p hyphen-neural --bin bob-miner -- challenge --seed $SEED --epoch 1
cargo run --release -p hyphen-neural --bin bob-miner -- solve --seed $SEED --epoch 1 --hidden 512
```

Build the contract and run it in the chain VM:

```powershell
.\scripts\build-alice-contract.ps1
cargo test -p hyphen-vm --test alice_contract
```

Opening, submitting and querying from an application uses the same three request
bodies and the `hyphen-vm` ledger, exactly like any other application contract.

## Related reading

- [Useful-work augmented PoW](Research-Useful-Work-Augmented-PoW) — why external tasks
  do not replace the block work rule.
- [AetherCompute](Research-Aether-Compute) — the fail-closed settlement layer for
  user-funded work.

---

<!-- hyphen-bilingual-chinese -->

# 神经密码学挑战（Alice / Bob）

状态：研究。`crates/hyphen-neural` 与 `contracts/alice-neural` 已实现、已测试，可部署在仓库内任意支持 `hyphen-vm` 合约 ABI 的链上。该挑战**不是**区块工作量证明：出块资格仍然由白皮书描述的 PoUW v3 Cunningham 见证链规则决定。本模块不改变链权重、发行或分叉选择。

## 一句话机制

Alice 是一个两层感知机，权重由公开链种子派生。合约公布网络 `A` 与目标 `y* = A(x*)`；矿工提交任意 `x`，只要 `A(x)` 落在已公布的容差内即赢得该 epoch。验证只需一次 `O(input_dim * hidden_dim)` 前向传播；求出 `x` 需要反转一个非凸整数映射，这就是机制唯一的非对称性。

## 为什么判定必须是求逆

直觉方案——公布 1000 组明密文、让矿工学习 Alice 权重——在安全上是坏的，而且坏得很直接：合约要验证就必须持有 Alice 的权重，因此权重必然公开；矿工直接复制权重即可通过任何 loss 阈值，完全不需要做功。任何奖励「复现 `A`」的评分规则都有同样的问题。

求逆方案只保留 `A` 公开，隐藏的是原像 `x*`。知道函数不代表知道原像，目标公开，「是否找到 `x`」是合约一次前向即可判定的布尔值——这才是机制真正需要的性质。

## 全程整数

每个节点都要执行的验证器不能用浮点：舍入模式、乘加融合收缩和 NaN 载荷在跨平台时并不一致，同一份程序可能在一个主机接受、在另一个主机拒绝。本方案全部使用 Q32.32 定点（`i64`，32 位小数）：

- 乘法 `(a * b) >> 32` 以 `i128` 计算并饱和，向负无穷取整；
- 除法 `(a << 32) / b` 向零取整，超出表示范围返回 `None`；
- 激活函数为 Padé (3,2) 近似 `x(27 + x²)/(27 + 9x²)`，`±3` 之外饱和到 `±1`，运算顺序固定；
- 派生使用 ChaCha20（RFC 8439），以链种子为密钥、epoch 与域标签放入 nonce，权重、原像与求解重启彼此不可互推。

遵循同样规则的两份独立实现会逐位得到相同激活值。该 crate 默认 `no_std`、不使用分配器，因此合约与矿工执行的是同一份代码，而不是两份移植。

## 判定规则

```text
accept(desc, x)  <=>  max_i |A(x)_i - y*_i| <= desc.tolerance_ulp
```

`tolerance_ulp` 是协议字段，开 epoch 时被限制在单位区间的 `1/1000` 以内。默认 `4_295` ulp，即百万分之一。随机 `x` 的误差是 `O(1)` 量级，容差不会放过瞎猜。

## 难度

隐藏层宽度是难度轴。求解成本随 `output_dim * hidden_dim * input_dim`（Jacobian）与每次前向的 `hidden_dim * input_dim` 增长；验证只付前向传播。控制器规则：

```text
observed < target / 2  -> width *= 2
observed > target * 2  -> width /= 2
otherwise              -> width 不变
```

结果被夹在 `[16, 512]`。该带宽是迟滞而非平滑：对每个样本都反应的控制器会在相邻宽度之间振荡，导致每个 epoch 公布不同形状。

**实测边界。** 在开发机上以 release、单核运行 `cargo run --release -p hyphen-neural --example envelope`：参考求解器解 16 宽配置约 6 ms，最宽 512 宽配置约 15 ms；同一区间内一次验证为 0.01–0.21 ms。实测「计算/验证」比约 30–70 倍，在固定开销占主导的最小宽度上约 770 倍。因此控制器无法维持十分钟 epoch：最宽配置仍比目标低三个数量级，控制器会饱和在 `MAX_HIDDEN_DIM`。

这是设计本身的约束，不是调参问题。链上验证器必须从种子重新生成 Alice 权重，这个成本与一次前向传播同为 `O(hidden_dim * input_dim)`；把宽度提高到求解需要十分钟，就意味着一次验证要消耗数分钟的合约 gas。十分钟目标需要第二条可廉价验证的难度轴——解过滤、证明系统或链下结算——而每一种都对应不同的安全论证。本 profile 有意不包含它们。

控制器仍然诚实地工作：在允许范围内公布与实测求解时间匹配的维度，而范围是协议常量，不是运维可调参数。

## 安全性质与待办

代码与测试已确立：

- **确定性**：同一 descriptor 在所有主机上得到相同权重、相同目标、相同判定。由单元测试、RFC 8439 向量，以及在 `hyphen-vm` 内运行真实合约的端到端测试钉住。
- **不可抄权重**：唯一被接受的见证是原像，权重从不进入提交内容。
- **只结算一次**：第一个被接受的原像写入 `hyphen:sol:v1:<epoch>`，之后提交返回 `2` 且不修改状态。
- **不可改写 epoch**：对已开启 epoch 提交不同 descriptor 返回 `EpochConflict`；相同 descriptor 重复开启是幂等的。
- **查询只读**：`hyphen_query` 只回答 `Status`，不写存储；VM 会拒绝任何写入状态的查询。
- **验证有界**：维度上限是编译期常量，请求上限 1 KiB，最宽配置在测试 gas 上限内执行完成。

明确未完成：

- **种子来源**：合约把 descriptor 绑定到 epoch，但无法验证 `chain_seed` 是真实链上取值；开启者选种子。生产部署必须从运维无法选择的值派生种子（父区块哈希或信标），这段接线属于调用 `Open` 的应用，而不属于本合约。
- **非简洁证明**：验证是完整前向传播，不是证明；便宜，但不是常数大小。
- **未经外部审计**：定点 profile、激活常量与合约 ABI 尚未经过仓库外评审。
- **无经济模型**：合约只记录结算，不发放奖励；奖励属于调用它的托管或代币层。
