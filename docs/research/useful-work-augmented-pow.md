# Useful-Work Augmented PoW Research Boundary

Status: design constraints only. No Useful-Work mechanism is active in Hyphen
consensus, mining, rewards, or transaction ordering.

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

## Proposed non-consensus market flow

1. A requester publishes task type, canonical input commitment, verifier
   version, deadline, and an escrowed bounty.
2. A challenge derives from a block hash that was unknown when the task was
   funded, plus task ID and worker public key.
3. A worker computes the result and a succinct proof bound to that challenge.
4. Bounded validation checks the proof and result commitment. Expensive task
   execution never occurs in every full node.
5. A successful claim transfers only the requester's escrowed bounty. It does
   not modify PoW target, block validity, chain weight, or base issuance.

This flow should first run as an off-chain service anchored by ordinary Hyphen
transactions. Consensus integration is unnecessary until demand, verification
cost, denial-of-service behavior, and centralization are measured.

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

Useful-Work remains off unless all of these exist:

- a versioned specification and machine-readable vectors;
- at least two independent prover/verifier implementations;
- a deterministic, resource-bounded verifier fuzzed with malformed proofs;
- a formal security/economic model preserving the base security lower bound;
- independent cryptographic and systems review;
- a long-running isolated research network; and
- an activation mechanism that cannot silently change devnet v1.

Until then, README, wallet, pool, and miner interfaces MUST describe this as
research, never as "AI mining" or a current source of chain security.

