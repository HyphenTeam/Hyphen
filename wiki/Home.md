# Hyphen protocol and node documentation

Hyphen is a research blockchain for private payments. Its standard development network uses Cunningham prime chains as proof of work. A branch may claim each qualifying starting value once. Separate development networks support neural proof of work, contract execution, compute settlement and conditional offline payments. The consensus specification defines the rules for each network. [Consensus profiles](Consensus-Profiles.md)

Hyphen has no live mainnet. Development-network balances have no monetary value. Independent review of the consensus protocol and cryptography is still pending. [Security review](Security-Asset-Review.md)

## Protocol and operations

| Topic | Documentation |
| --- | --- |
| Protocol design | [Whitepaper](Whitepaper.md) · [Consensus profiles](Consensus-Profiles.md) · [Witness inventory and fork weight](Witness-Inventory-Measurements.md) |
| Node deployment | [Linux installation](Operations-Deploy-Linux.md) · [Peer configuration and recovery](Operations-Peer-Network.md) · [Memory and storage requirements](Operations-Small-Host.md) |
| Verification | [Build and verification procedures](Operations-Verification.md) · [Wallet and consensus security review](Security-Asset-Review.md) |
| Payments and computation | [Offline payments](Offline-Payments.md) · [AetherCompute settlement](Research-Aether-Compute.md) |
| Protocol research | [Research proposals](Research-Four-Core-Innovations.md) · [Cryptographic requirements for activation](Security-Cryptographic-Activation-Gates.md) |

## Project guides

| Project | Coverage |
| --- | --- |
| [HyphenMiner](https://github.com/HyphenTeam/HyphenMiner/wiki) | Miner identity, reward addresses, CPU mining and GPU acceleration |
| [HyphenPool](https://github.com/HyphenTeam/HyphenPool/wiki) | Settlement modes, payout accounting and recovery after a chain reorganization |
| [HyphenWallet](https://github.com/HyphenTeam/HyphenWallet/wiki) | Wallet recovery, payment confirmation, offline receipts and the payout agent |

## 中文导览

Hyphen 是面向隐私支付的研究型区块链。标准开发网采用坎宁安素数链作为工作量证明，每个符合条件的起点在同一分支上只能认领一次。神经工作量证明、合约执行、计算任务结算和有条件离线支付各有对应的开发网。主网尚未上线，开发网余额不具备货币价值。协议与密码学实现仍有待独立审计。

- **协议与共识**　[白皮书](Whitepaper.md)介绍协议设计，[共识规范](Consensus-Profiles.md)列出各网络的验证规则，[见证库存与分叉权重](Witness-Inventory-Measurements.md)说明已有见证如何影响分支权重。
- **节点运维**　[节点互联与恢复](Operations-Peer-Network-CN.md)说明如何连接节点并核对同步状态。[构建与验证](Operations-Verification.md)给出跨项目验证步骤。
- **项目操作指南**　[矿工](https://github.com/HyphenTeam/HyphenMiner/wiki)、[矿池](https://github.com/HyphenTeam/HyphenPool/wiki)和[钱包](https://github.com/HyphenTeam/HyphenWallet/wiki)的文档分别介绍挖矿配置、收益结算和钱包恢复。
