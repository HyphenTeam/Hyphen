# Useful-Work Augmented PoW Research Boundary

Status: the bounded AetherCompute lifecycle is active only in the testnet and
mainnet research profiles. It does not alter PoW eligibility, chain weight,
base issuance or transaction ordering. The default proof verifier rejects all
result, fraud and custody proofs, and no token reward transfer is implemented.

## Non-negotiable security rule

Useful work may augment rewards, but it MUST NOT replace the base PoW security
budget. A block remains eligible only when it satisfies ordinary HyphenPoW at
the full consensus difficulty. If there are zero external tasks, the chain's
eligibility rule and measurable PoW cost remain unchanged.

For the first prototype, the safest accounting equation is:

```text
miner_income = consensus_block_reward + transaction_fees + escrowed_task_bounty
chain_weight  = verified_base_PoW_only
```

Task proofs MUST NOT increase chain weight, lower base difficulty, bypass PoW,
or decide fork choice. Any future proposal to change that boundary is a new
consensus design requiring a separate chain profile and audit.

## Explicitly out of scope

Hyphen MUST NOT describe general AI training or inference as mining. Such work
typically has expensive or environment-dependent verification, floating-point
nondeterminism, selectable cheap tasks, fake-demand collusion, volatile demand,
and strong GPU/TPU concentration pressure. External demand disappearing must
not lower consensus security.

## Admissible task class

A candidate task needs all of the following before it can enter even a
non-consensus bounty market:

- deterministic, public input encoding and a unique validity relation;
- a verifier substantially cheaper than producing the result;
- bounded verifier time, memory, proof size, and state access;
- a proof system with published parameters and security assumptions;
- binding to a recent unpredictable chain challenge, task identifier, and
  submitter identity to limit precomputation and proof theft;
- objective expiry and replay rules;
- requester-funded escrow so fake demand cannot mint chain rewards;
- hardware and prover benchmarks across independent implementations; and
- no secret or licensed input that every verifier cannot obtain legally.

Plausible research workloads are proof aggregation, transparent-proof witness
work, deterministic Merkleized data transforms, or tightly specified coding
and scientific computations. Each still needs an individual validity circuit
and economic analysis.

## Research-profile market flow

1. A requester publishes task type, canonical input commitment, verifier
   version, deadline, and an escrowed bounty.
2. Before reward activation, a challenge must derive from an unbiasable value
   that was unknown when the task was funded, plus task ID and worker public
   key. The current v1 execution statement does not yet carry this challenge.
3. A worker computes the result and a succinct proof bound to that challenge.
4. Bounded validation checks the proof and result commitment. Expensive task
   execution never occurs in every full node.
5. A successful claim transfers only the requester's escrowed bounty. It does
   not modify PoW target, block validity, chain weight, or base issuance.

The repository now commits this lifecycle to the unified research-profile
state root. Publication is usable, but settlement stays fail-closed until a
versioned verifier backend and requester-funded escrow transfer are implemented
and activated under a new reviewed chain profile.

## Required experiments

Before proposing activation, publish reproducible results for:

- prover-to-verifier cost ratio, including worst-case invalid proofs;
- proof size and node verification throughput under block saturation;
- challenge grinding, task withholding, duplicate claims, and precomputation;
- requester/miner collusion and fake-demand wash trading;
- task-selection fairness when multiple task types have different hardware
  advantages;
- reward volatility when external demand is zero or concentrated;
- censorship of task claims and expiry/reorg behavior;
- proof-system bugs, parameter compromise, and emergency disable behavior; and
- base-PoW distribution with and without useful-work income.

## Activation gate

Useful-Work reward settlement remains off unless all of these exist:

- a versioned specification and machine-readable vectors;
- at least two independent prover/verifier implementations;
- a deterministic, resource-bounded verifier fuzzed with malformed proofs;
- a formal security/economic model preserving the base security lower bound;
- independent cryptographic and systems review;
- a long-running isolated research network; and
- an activation mechanism that cannot silently change a frozen chain profile.

Until then, README, wallet, pool, and miner interfaces MUST describe this as
research, never as "AI mining" or a current source of chain security.

---

<!-- hyphen-bilingual-chinese -->

# 有用工作增强 PoW 的研究边界

状态：有界 AetherCompute 生命周期仅在 testnet 和 mainnet 研究 profile 中启用。它不改变 PoW 区块资格、链权重、基础发行或交易排序。默认证明验证器拒绝所有结果、欺诈与保管证明，且未实现代币奖励转移。

## 不可妥协的安全规则

有用工作可以增加收入，但绝不能替代基础 PoW 安全预算。区块只有在完整共识难度下满足普通 HyphenPoW 才具备资格。外部任务为零时，链的资格规则与可测 PoW 成本保持不变。

```text
miner_income = consensus_block_reward + transaction_fees + escrowed_task_bounty
chain_weight  = verified_base_PoW_only
```

任务证明不得增加链权重、降低基础难度、绕过 PoW 或决定 fork choice。未来任何改变该边界的提议都属于新的共识设计，需要独立链 profile 和审计。

## 明确排除

Hyphen 不得把通用 AI 训练或推理描述为挖矿。这类工作通常验证昂贵或依赖环境，存在浮点非确定性、可挑选低成本任务、虚假需求共谋、需求波动和强 GPU/TPU 集中压力。外部需求消失不得降低共识安全。

## 可接受任务类别

候选任务即使要进入非共识 bounty 市场，也必须先满足：

- 确定性公开输入编码和唯一有效性关系；
- 验证器成本显著低于结果生产成本；
- 验证时间、内存、证明大小和状态访问有界；
- 证明系统公开参数和安全假设；
- 绑定近期不可预测链 challenge、任务 ID 和提交者身份，以限制预计算与证明盗取；
- 客观的过期与重放规则；
- 请求方出资的 escrow，防止虚假需求铸造链奖励；
- 跨独立实现的硬件与 prover benchmark；
- 不包含所有 verifier 无法合法获得的秘密或授权输入。

可能的研究负载包括证明聚合、透明证明 witness 工作、确定性 Merkle 化数据转换，或严格规定的编码与科学计算。每一类仍需单独的有效性电路和经济分析。

## 研究 Profile 市场流程

1. 请求方发布任务类型、规范输入 commitment、verifier 版本、deadline 和托管 bounty。
2. 奖励激活前，challenge 必须来自任务出资时未知的不可偏置值，并绑定任务 ID 和 worker 公钥。当前 v1 execution statement 尚未携带该 challenge。
3. Worker 计算结果和绑定 challenge 的简洁证明。
4. 有界验证检查证明与结果 commitment。昂贵任务执行绝不在每个全节点中进行。
5. 成功 claim 只转移请求方托管的 bounty，不改变 PoW target、区块有效性、链权重或基础发行。

仓库现已将该生命周期承诺到统一研究 profile 状态根。任务发布可用，但在实现版本化 verifier 后端和请求方出资的 escrow 转移，并通过新链 profile 审查激活前，结算保持 fail-closed。

## 必需实验

提出激活前必须发布可复现结果，覆盖：

- prover/verifier 成本比及最坏非法证明；
- 区块饱和时证明大小和节点验证吞吐量；
- challenge grinding、任务扣留、重复 claim 和预计算；
- 请求方与矿工共谋及虚假需求 wash trading；
- 不同硬件优势任务间的选择公平性；
- 外部需求为零或集中时的奖励波动；
- 任务 claim 审查及过期/reorg 行为；
- 证明系统缺陷、参数泄露和紧急禁用；
- 有无有用工作收入时的基础 PoW 分布。

## 激活门槛

在全部具备以下条件前，有用工作奖励结算保持关闭：

- 版本化规范和机器可读向量；
- 至少两个独立 prover/verifier 实现；
- 经过畸形证明模糊测试的确定性、资源有界 verifier；
- 保持基础安全下界的正式安全/经济模型；
- 独立密码学与系统审查；
- 长期运行的隔离研究网络；
- 不能静默改变冻结链 profile 的激活机制。

在此之前，README、wallet、pool 和 miner 接口必须将其描述为研究，绝不能称为“AI 挖矿”或当前链安全来源。
