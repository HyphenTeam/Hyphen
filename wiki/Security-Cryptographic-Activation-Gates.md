# Cryptographic activation gates

Status: mandatory preconditions, not implemented-feature claims. This document
records why the current PoW-derived seed and the current Ristretto255/BLAKE3
transaction relations cannot honestly be called an unbiasable beacon or an
audited Circom circuit.

## 1. Seed bias is a protocol property

Let a candidate source produce independent, identically distributed outputs
`Y_1,...,Y_g`, and let an adversary see the candidates before choosing which
valid transcript is published. For an event `E` with one-candidate probability
`p=Pr[Y in E]`, the strategy “publish an output in `E` whenever one exists” yields

```text
Pr[Y_selected in E] = 1-(1-p)^g.
```

For `0<p<1` and `g>1`, this is strictly greater than `p`. Without independence,
the equality need not hold; the union bound is only `Pr[union_i(Y_i in E)] <= gp`,
and the exact bias depends on the joint distribution. Hashing the selected
candidate cannot remove the bias: a deterministic post-processing function
cannot erase the adversary's selection channel. It can only change which event
is favored.

The current chain computes an epoch seed from the previous epoch's final block
hash. A miner can vary nonce, extra nonce, transaction set, and potentially
withhold a found block. Consequently this seed is **grinding-exposed**. It is
valid as a deterministic PoW parameter seed, but it does not satisfy the
independent-uniform seed assumption used by the committee binomial estimate.

### Commit/reveal does not by itself fix this

Suppose an adversarial final revealer first observes the honest aggregate `h`
and has committed value `a`. It can choose between revealing, producing
`H(h,a)`, and aborting, producing the protocol's fallback output. Unless both
branches are forced to the same unique output with an enforceable availability
mechanism, the adversary again chooses from at least two candidates. Slashing
can price this option; it does not make the distribution cryptographically
unbiasable.

### Acceptable activation routes

One of the following must be implemented and independently reviewed:

1. A unique threshold signature/VRF beacon with authenticated DKG, public share
   verification, threshold unforgeability, uniqueness for one epoch message,
   proactive or epoch key handling, and a liveness proof under share withholding.
2. A VDF-backed beacon whose input availability, delay assumption, verification
   equation, difficulty retargeting, and specialized-hardware advantage are
   explicit.

The chain must verify the complete beacon certificate. Accepting a naked
32-byte `seed` from RPC, config, a leader, or a trait implementation is not a
certificate and must not unlock H-FOC'.

## 2. Committee probability is conditional

With independent work-proportional draws, adversarial work fraction `alpha`,
`n=3f+1`, and an independent seed, the probability of more than `f`
adversarial seats is

```text
P_bad = sum_(i=f+1)^n binom(n,i) alpha^i (1-alpha)^(n-i).
```

This is a conditional model, not a theorem about the current chain. With at
most `g` selectable seeds, a union bound gives

```text
P_bad_grind <= min(1, g P_bad).
```

Correlation between pools, adaptive corruption, work attribution errors, and
repeated seats require separate analysis. No fixed committee size repairs a
biasable election source.

## 3. Circom field/commitment obstruction

Circom normally compiles arithmetic over the BN254 scalar field `F_q`. Hyphen's
current confidential transaction relations use:

- Ristretto255 group elements and scalars in `Z_l`;
- compressed Ristretto encodings;
- BLAKE3 domain-separated hashes;
- Pedersen, CLSAG, and range-proof relations implemented outside BN254.

A Circom signal is an element of `F_q`; it is not automatically a Ristretto
scalar, a 255-bit string, or a compressed point. Mapping a 256-bit digest to one
field element by reduction is not injective: if distinct integers differ by
`q`, they represent the same field element. Therefore the unconstrained rule

```text
signal = digest mod q
```

does not prove equality of the original 256-bit digests.

A sound bridge must instead constrain bit decomposition and range, implement
the exact BLAKE3 compression relation (or commit to a versioned field-friendly
replacement), and constrain Ristretto encoding/decompression and the required
group equations. If a field-friendly in-circuit commitment is introduced, the
chain also needs a binding proof between that commitment and the existing
Ristretto/BLAKE3 consensus object. Merely supplying both as public inputs leaves
them unrelated.

## 4. Shielded H-WES relation required before activation

For public statement `Z` and private witness `W`, a shielded recovery circuit
must constrain at least:

```text
Z = (chain_id, pre_state_root, post_state_root, history_root,
     latest_root, nullifier_root, key_commitment, old_version,
     new_version, action, lease, authorization_context)

W = (expired_record, archive_path, latest_path, owner_secret_or_policy_witness,
     nullifier_path, successor_body, successor_randomness)
```

The circuit relation must prove archive inclusion, latest-only status,
authorization, nullifier non-membership/monotonic update, `new_version =
old_version+1`, the exact lifecycle transition, and the public root transition.
Every hash and commitment in those equations must be the same relation verified
by Rust consensus or connected through a proved binding bridge.

No such circuit, proving-key ceremony, Rust verifier, malformed-proof corpus,
or cross-implementation vector currently exists in this repository. A small
Poseidon/Merkle demonstration would not prove the live chain relation and is
therefore intentionally not presented as H-WES.

## 5. H-SAC circuit and audit evidence

An H-SAC circuit additionally needs a frozen compliance function `F`, chain
inclusion, ownership/provenance, credential-policy membership, scope, auditor,
expiry, and task-output constraints. The leakage theorem determines a lower
bound; it does not instantiate this relation.

“Audited” requires evidence external to implementation authors: named auditor,
scope and commit/circuit hashes, proof-system and setup scope, findings, fixes,
retest status, and a published report. Internal tests, Circom compilation, R1CS
generation, and this document are not an audit. Until that evidence exists,
README and release notes must say **unaudited and inactive**.

---

<!-- hyphen-bilingual-chinese -->

# 密码学激活门槛

状态：强制前置条件，不是已实现功能声明。本文说明为什么当前由 PoW 派生的 seed 不能诚实地称为不可偏置信标，以及当前 Ristretto255/BLAKE3 交易关系不能称为已审计 Circom 电路。

## 1. Seed 偏置是协议性质

假设候选源产生独立同分布输出 `Y_1,...,Y_g`，攻击者在选择发布哪个有效 transcript 前可看到候选。对单候选概率为 `p=Pr[Y in E]` 的事件 `E`，“只要存在落入 `E` 的输出就发布它”的策略得到：

```text
Pr[Y_selected in E] = 1-(1-p)^g.
```

当 `0<p<1` 且 `g>1` 时，该值严格大于 `p`。没有独立性时等式不一定成立；union bound 仅为 `Pr[union_i(Y_i in E)] <= gp`，精确偏置取决于联合分布。对选中候选再次哈希不能消除偏置：确定性后处理无法抹去攻击者的选择通道，只会改变有利事件。

当前链根据前一 epoch 的最终区块哈希计算 epoch seed。矿工可以改变 nonce、extra nonce、交易集合，并可能扣留已找到区块。因此该 seed **暴露于 grinding**。它可作为确定性 PoW 参数 seed，但不满足委员会二项估计所用的独立均匀 seed 假设。

### Commit/reveal 本身不能修复问题

假设恶意的最后 reveal 方先看到诚实聚合值 `h`，且已承诺值 `a`。它可选择 reveal 得到 `H(h,a)`，或中止得到协议 fallback 输出。除非可执行的可用性机制强制两个分支产生同一个唯一输出，否则攻击者仍可从至少两个候选中选择。罚没可以提高行使该选择权的成本，但不能使分布在密码学上不可偏置。

### 可接受的激活路线

必须实现并独立审查以下方案之一：

1. 唯一阈值签名/VRF 信标，包含认证 DKG、公开 share 验证、阈值不可伪造性、同一 epoch 消息的唯一性、主动或逐 epoch 密钥处理，以及 share 被扣留时的活性证明。
2. VDF 支持的信标，明确输入可用性、延迟假设、验证等式、难度调整和专用硬件优势。

链必须验证完整信标证书。从 RPC、配置、leader 或 trait 实现接受裸 32 字节 `seed` 不构成证书，不能解锁 H-FOC'。

## 2. 委员会概率是条件结论

在工作量占比独立抽样、攻击者工作量比例 `alpha`、`n=3f+1` 且 seed 独立的条件下，攻击者获得超过 `f` 个席位的概率为：

```text
P_bad = sum_(i=f+1)^n binom(n,i) alpha^i (1-alpha)^(n-i).
```

这是条件模型，不是当前链的定理。若最多有 `g` 个可选择 seed，union bound 为：

```text
P_bad_grind <= min(1, g P_bad).
```

矿池相关性、自适应腐化、工作量归属错误和重复席位需要单独分析。固定委员会大小无法修复可偏置的选举源。

## 3. Circom field/commitment 障碍

Circom 通常在 BN254 标量域 `F_q` 上编译算术。Hyphen 当前机密交易关系使用 Ristretto255 群元素及 `Z_l` 中的标量、压缩 Ristretto 编码、BLAKE3 域分离哈希，以及在 BN254 之外实现的 Pedersen、CLSAG 和范围证明关系。

Circom signal 是 `F_q` 元素，不会自动成为 Ristretto 标量、255 位字符串或压缩点。通过约简把 256 位 digest 映射到单个域元素不是单射：相差 `q` 的不同整数表示同一个域元素。因此无约束规则 `signal = digest mod q` 不能证明原始 256 位 digest 相等。

可靠桥接必须约束位分解和范围，实现精确 BLAKE3 压缩关系（或承诺一个版本化、域友好的替代物），并约束 Ristretto 编码/解压和所需群等式。如果引入电路内域友好 commitment，链还需要证明它与现有 Ristretto/BLAKE3 共识对象绑定。仅把两者作为 public input 提供并不会建立关系。

## 4. 激活前必须具备 Shielded H-WES 关系

对于公开 statement `Z` 和私有 witness `W`，shielded recovery 电路至少必须约束：

```text
Z = (chain_id, pre_state_root, post_state_root, history_root,
     latest_root, nullifier_root, key_commitment, old_version,
     new_version, action, lease, authorization_context)

W = (expired_record, archive_path, latest_path, owner_secret_or_policy_witness,
     nullifier_path, successor_body, successor_randomness)
```

电路关系必须证明 archive inclusion、latest-only 状态、授权、nullifier 非成员/单调更新、`new_version = old_version+1`、精确生命周期转换和公开根转换。等式中的每个哈希与 commitment 必须和 Rust 共识验证的关系相同，或通过已证明的 binding bridge 连接。

本仓库目前没有这样的电路、proving-key ceremony、Rust verifier、畸形证明语料或跨实现向量。小型 Poseidon/Merkle 演示不能证明真实链关系，因此不会被描述为 H-WES。

## 5. H-SAC 电路与审计证据

H-SAC 电路还需要冻结的合规函数 `F`、链 inclusion、所有权/来源、credential-policy membership、scope、auditor、expiry 和任务输出约束。泄漏定理只给出下界，不会实例化该关系。

“已审计”要求实现作者之外的证据：审计方名称、范围与 commit/circuit 哈希、证明系统与 setup 范围、发现、修复、复测状态和公开报告。内部测试、Circom 编译、R1CS 生成以及本文都不是审计。在具备这些证据前，README 和发布说明必须标注为 **未审计且未激活**。
