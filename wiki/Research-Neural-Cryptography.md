# Neural-Cryptography Challenge (Alice / Bob)

Status: research. `crates/hyphen-neural` and `contracts/alice-neural` are
executable, tested and deployable on any chain in this repository that runs the
`hyphen-vm` contract ABI. Block mining uses the [neural nonce and BLAKE3 scratchpad predicate](Consensus-Neural-Work.md).

## Public reference input

The descriptor defines the network `A` and a reference input `x*`. Anyone can derive `x*` from the public seed and epoch and submit it directly. The verifier derives the weights, evaluates `A(x*)` and `A(x)`, and checks the maximum component error. Each of the two forward passes costs `O(hidden_dim × (input_dim + output_dim))`. An accepted submission establishes this numerical relation. [Descriptor evaluation](../crates/hyphen-neural/src/challenge.rs)

On HYN3, the block carries a nonce. The verifier derives its input, evaluates the fixed-point network and checks the BLAKE3 scratchpad digest for a qualifying score. Application tasks carry their own descriptor and solution. The inline Alice verifier checks the task against its signed specification. [Block work](Consensus-Neural-Work.md) · [Application tasks](Research-Aether-Compute.md)

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
range.

## Difficulty

The experimental solver adjusts hidden width according to the observed time. Its Jacobian calculation depends on all three layer widths. Deriving the public reference input takes one ChaCha20 word per input component, independently of hidden width.

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

Those timings describe the iterative solver. Direct reference-input derivation remains available at every width.

## Security properties and obligations

Established by the code and its tests:

- **Determinism.** Same descriptor, same weights, same target, same acceptance on
  every host. Pinned by unit tests, an RFC 8439 vector, and an end-to-end test
  that runs the compiled contract inside `hyphen-vm`.
- **Public weights.** The inverse circuit's reference answer can be recomputed from the public seed. HYN3 validators derive the block challenge and weights locally and check both gates for the submitted nonce.
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
- **Verification cost.** Reconstructing the reference output and checking the submitted input requires two network evaluations.
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

- [Useful-work augmented PoW](Research-Useful-Work-Augmented-PoW.md) — why external tasks
  do not replace the block work rule.
- Signed task publication, result checking and the declared reward field. [AetherCompute](Research-Aether-Compute.md)

---

<!-- hyphen-bilingual-chinese -->

# 神经密码学挑战（Alice / Bob）

Alice 与 Bob 实现应用层挑战。区块使用独立的[神经工作量验证规则](Consensus-Neural-Work.md)。

## 公开参考输入

描述符定义网络 `A` 和参考输入 `x*`。任何人都可以从公开种子和 epoch 派生 `x*`，直接提交并取得零误差。验证器派生权重，分别计算 `A(x*)` 和 `A(x)`，再检查最大分量误差。两次前向传播各需 `O(hidden_dim × (input_dim + output_dim))` 运算。签名提交证明的计算性质是该数值关系成立。[描述符验证](../crates/hyphen-neural/src/challenge.rs)

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

`tolerance_ulp` 是协议字段，开 epoch 时被限制在单位区间的 `1/1000` 以内。默认 `4_295` ulp，约为百万分之一。

## 难度

实验求解器根据观测时间调整隐藏层宽度。其雅可比矩阵计算量与三层宽度相关。直接派生参考输入时，每个输入分量只需一个 ChaCha20 输出字，成本与隐藏层宽度无关。

```text
observed < target / 2  -> width *= 2
observed > target * 2  -> width /= 2
otherwise              -> width 不变
```

结果被夹在 `[16, 512]`。该带宽是迟滞而非平滑：对每个样本都反应的控制器会在相邻宽度之间振荡，导致每个 epoch 公布不同形状。

**实测边界。** 在开发机上以 release、单核运行 `cargo run --release -p hyphen-neural --example envelope`：参考求解器解 16 宽配置约 6 ms，最宽 512 宽配置约 15 ms；同一区间内一次验证为 0.01–0.21 ms。实测「计算/验证」比约 30–70 倍，在固定开销占主导的最小宽度上约 770 倍。因此控制器无法维持十分钟 epoch：最宽配置仍比目标低三个数量级，控制器会饱和在 `MAX_HIDDEN_DIM`。

这些耗时仅描述迭代求解器。在每种宽度下，提交者都能直接派生参考输入。

## 安全性质与待办

代码与测试已确立：

- **确定性**：同一 descriptor 在所有主机上得到相同权重、相同目标、相同判定。由单元测试、RFC 8439 向量，以及在 `hyphen-vm` 内运行真实合约的端到端测试钉住。
- **公开参考输入**。链上复算参考输出与提交输出，接受所有满足容差的输入。
- **只结算一次**：第一个被接受的原像写入 `hyphen:sol:v1:<epoch>`，之后提交返回 `2` 且不修改状态。
- **不可改写 epoch**：对已开启 epoch 提交不同 descriptor 返回 `EpochConflict`；相同 descriptor 重复开启是幂等的。
- **查询只读**：`hyphen_query` 只回答 `Status`，不写存储；VM 会拒绝任何写入状态的查询。
- **验证有界**：维度上限是编译期常量，请求上限 1 KiB，最宽配置在测试 gas 上限内执行完成。

明确未完成：

- **种子来源**：合约把 descriptor 绑定到 epoch，但无法验证 `chain_seed` 是真实链上取值；开启者选种子。生产部署必须从运维无法选择的值派生种子（父区块哈希或信标），这段接线属于调用 `Open` 的应用，而不属于本合约。
- **验证成本**。重建目标并验证提交值需要两次完整的网络求值。
- **未经外部审计**：定点 profile、激活常量与合约 ABI 尚未经过仓库外评审。
- **无经济模型**：合约只记录结算，不发放奖励；奖励属于调用它的托管或代币层。
