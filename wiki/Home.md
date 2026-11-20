# Hyphen Wiki

Hyphen is a privacy-focused research blockchain that replaces burned proof-of-work
digests with verifiable mathematical work: single-use Cunningham prime chains, plus
an optional neural-work research profile and a bounded scientific-compute settlement
layer.

> **Status.** Research base chain. No mainnet has launched, no independent consensus
> or cryptographic audit has been completed, and no balance described here carries
> monetary value. Documents state what the code establishes today, not what a future
> profile might establish.

## Start here

| If you are… | Read first |
|---|---|
| Evaluating the design | [Whitepaper](Whitepaper.md) |
| Reviewing consensus changes | [Devnet v2](Consensus-Devnet-V2.md), [Neural Work](Consensus-Neural-Work.md) |
| Operating a node | [Peer networking](Operations-Peer-Network.md), [Deploy on Linux](Operations-Deploy-Linux.md), [Small Host](Operations-Small-Host.md) |
| Building the miner | [Mining Acceleration](Operations-Mining-Acceleration.md) |
| Assessing launch readiness | [Incentivized Testnet](Operations-Incentivized-Testnet.md) |
| Auditing trust boundaries | [Wallet and consensus asset review](Security-Asset-Review.md), [Cryptographic Activation Gates](Security-Cryptographic-Activation-Gates.md), [Peer Policy](Security-Peer-Policy.md) |
| Reading the research record | [Four Core Innovations](Research-Four-Core-Innovations.md) |

## Document map

### Architecture

- [Repository and Compatibility Boundaries](Architecture-Repository-Boundaries.md) — what
  belongs in the base-chain repository, what is a downstream application, and which
  compatibility promises are normative.
- [Mempool Policy](Architecture-Mempool.md) — admission limits, fee/VRE ordering,
  replacement, eviction, expiry, and the `no_std + alloc` boundary.

### Consensus

- [Devnet v2](Consensus-Devnet-V2.md) — active development profile.
- [Neural Work](Consensus-Neural-Work.md) — separate research chain identity; it is not an
  in-place upgrade of the Cunningham-witness rule.
- [Devnet v1](Consensus-Devnet-V1.md) — withdrawn profile retained as historical evidence.

### Operations

- [Connecting Hyphen nodes](Operations-Peer-Network.md) · [中文节点互联指南](Operations-Peer-Network-CN.md)
- [Build and verification](Operations-Verification.md)

- [Deploying a Hyphen node on Linux](Operations-Deploy-Linux.md) — `systemd` runbook for a
  single full node and a private multi-node network.
- [Running on a small host](Operations-Small-Host.md) — measured memory and storage on
  4 vCPU / 2 GiB, the storage cache ceiling, witness-set growth, and what must change
  before mainnet.
- [Mining Acceleration](Operations-Mining-Acceleration.md) — optional CUDA/HIP sieve, ABI,
  verification, and the portable CPU fallback.
- [Incentivized Testnet Readiness](Operations-Incentivized-Testnet.md) — open gates that
  must close before a public incentivized network is defensible.

### Research

- [Four Core Innovations](Research-Four-Core-Innovations.md) — proofs, prior work and the
  implementation charter.
- [AetherCompute](Research-Aether-Compute.md) — fail-closed settlement lifecycle for
  scientific work.
- [Useful-Work Augmented PoW](Research-Useful-Work-Augmented-PoW.md) — the boundary between
  PoUW eligibility and external compute settlement.
- [Neural-Cryptography Challenge](Research-Neural-Cryptography.md) — Alice/Bob challenge and
  its relationship to, but separation from, block eligibility.
- [Non-Custodial Pool Protocol](Research-Non-Custodial-Pool.md) — delegated authority
  reduction without a trustless-pool claim.
- [Private Visible-Domain Fair Ordering](Research-Private-Visible-Fair-Ordering.md) — H-FOC'
  research specification, explicitly not a MEV-free claim.
- [H-WES](Research-H-WES-Theorem-and-Object-Model.md) — expirable authenticated objects and
  recovery lower bounds.
- [H-SAC](Research-H-SAC-Leakage-Lower-Bound.md) — minimum leakage for compliance tasks.

### Security

- [Cryptographic Activation Gates](Security-Cryptographic-Activation-Gates.md) — mandatory
  preconditions for seed unbiasability and circuit audits.
- [Peer Policy](Security-Peer-Policy.md) — what earns a P2P ban and what must never be a
  consensus judgement.

## Source and verification

The code, tests and normative configuration live in
[HyphenTeam/Hyphen](https://github.com/HyphenTeam/Hyphen). Every performance or security
statement in this wiki should be traceable to a test, a vector, or a named open gate. If a
page cannot be traced that way, treat it as a research note, not an operational promise.

---

## 中文摘要

Hyphen 是一条以隐私与可验证数学工作为核心的研究型区块链。当前没有主网上线，也没有完成
独立共识或密码学审计；本 Wiki 中的所有余额、性能与安全表述都不构成价值承诺。

建议阅读顺序：

1. [白皮书](Whitepaper.md)
2. [Devnet v2](Consensus-Devnet-V2.md) 与 [神经工作量证明](Consensus-Neural-Work.md)
3. [节点互联与恢复](Operations-Peer-Network-CN.md) 和 [Linux 节点部署](Operations-Deploy-Linux.md)
4. [小配置主机运行](Operations-Small-Host.md) 与 [跨仓验收](Operations-Verification.md)
5. [密码学激活门槛](Security-Cryptographic-Activation-Gates.md) 与 [对等节点策略](Security-Peer-Policy.md)

代码与测试是唯一事实来源；文档中的每个结论都应能追溯到测试、向量或明确列出的未关闭门槛。
