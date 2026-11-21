# Hyphen protocol and node documentation

Hyphen is a Rust research blockchain for private payments and Wasm applications. On `neural-devnet`, miners evaluate a fixed-point neural network for each nonce. When the BLAKE3 gate passes, they compute the final digest using a 1 MiB scratchpad. Nodes independently verify both thresholds. [Consensus rules](Consensus-Neural-Work.md) · [Block coordinates and recovery](HYN3-Identity-and-Recovery.md)

Hyphen has no live mainnet. Development-network balances have no monetary value. Independent review of the consensus protocol and cryptography is still pending. [Security review](Security-Asset-Review.md)

## Protocol and operations

| Topic | Documentation |
| --- | --- |
| Protocol design | [Whitepaper](Whitepaper.md) · [Neural work](Consensus-Neural-Work.md) |
| Node deployment | [Linux installation](Operations-Deploy-Linux.md) · [Peer configuration and recovery](Operations-Peer-Network.md) · [Memory and storage requirements](Operations-Small-Host.md) |
| Verification | [Build and verification procedures](Operations-Verification.md) · [Wallet and consensus security review](Security-Asset-Review.md) · [HYN3 algorithm audit and measurements](HYN3-Algorithm-Audit.md) |
| Payments and computation | [Offline payments](Offline-Payments.md) · [AetherCompute settlement](Research-Aether-Compute.md) |
| Protocol research | [Research proposals](Research-Four-Core-Innovations.md) · [Cryptographic requirements for activation](Security-Cryptographic-Activation-Gates.md) |

## Project guides

| Project | Coverage |
| --- | --- |
| [HyphenMiner](https://github.com/HyphenTeam/HyphenMiner/wiki) | Miner identity, reward addresses, CPU mining and GPU acceleration |
| [HyphenPool](https://github.com/HyphenTeam/HyphenPool/wiki) | Settlement modes, payout accounting and recovery after a chain reorganization |
| [HyphenWallet](https://github.com/HyphenTeam/HyphenWallet/wiki) | Wallet recovery, payment confirmation, offline receipts and the payout agent |

## 中文导览

Hyphen 是以 Rust 实现的隐私支付与 Wasm 应用研究链。`neural-devnet` 的矿工搜索由 nonce 派生的定点神经网络输入，初筛通过后执行 BLAKE3 scratchpad，节点独立复算两个门槛。

- [神经共识规范](Consensus-Neural-Work.md)给出区块验证、难度与硬件评估方法。
- **节点运维**　[节点互联与恢复](Operations-Peer-Network-CN.md)说明如何连接节点并核对同步状态。[构建与验证](Operations-Verification.md)给出跨项目验证步骤。
- **项目操作指南**　[矿工](https://github.com/HyphenTeam/HyphenMiner/wiki)、[矿池](https://github.com/HyphenTeam/HyphenPool/wiki)和[钱包](https://github.com/HyphenTeam/HyphenWallet/wiki)的文档分别介绍挖矿配置、收益结算和钱包恢复。
