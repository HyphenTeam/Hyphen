# Hyphen Repository and Compatibility Boundaries

Status: normative repository policy for development and CI.

## Base-chain scope

The tracked Hyphen repository owns the base-chain protocol and reference node:

- consensus-critical data structures and validation;
- state-transition, storage, replay, and chain identity;
- transaction and cryptographic verification libraries;
- P2P, RPC, Template Provider transport, and explorer interfaces;
- versioned specifications, machine-readable vectors, fuzz targets, and CI.

The root `Cargo.toml` is the authoritative list of base-chain workspace members.
The internal `crates/hyphen-wallet` package is a protocol-facing wallet library,
not the independent Flutter application.

## Independent projects

`HyphenMiner`, `HyphenPool`, and `HyphenWallet` are separate products with
separate source history, lockfiles, releases, threat models, and CI. Local
checkouts may be placed at the Hyphen repository root so compatibility scripts
can find them. Those directories are intentionally ignored by this repository
and MUST NOT become root workspace members or required inputs to base-chain CI.

No successful build or test in an independent project proves base-chain
correctness. No successful base-chain test proves an independent project is
compatible.

## Protocol change sequence

A compatibility-affecting base-chain change MUST proceed in this order:

1. Define the wire/state/consensus change in a versioned specification.
2. State activation and downgrade behavior; consensus changes require a new
   chain profile and chain identity unless the frozen specification explicitly
   permits the change.
3. Publish positive and negative machine-readable vectors.
4. Update and pass the Hyphen reference implementation and base-chain CI.
5. Update each independent project in its own repository and CI.
6. Run cross-project compatibility tests against exact revisions and archive
   the revision map, logs, and vector hashes.

## CI ownership

Hyphen base-chain CI gates formatting, Clippy, workspace tests, fuzz-target
compilation, chain-identity vectors, and a Windows node smoke check. Nightly CI
runs bounded decoder fuzzing on Linux.

Cross-project node/miner/pool/wallet tests are compatibility evidence only.
They require explicit independent checkouts and MUST live in a separate
integration workflow or orchestration repository. They cannot be required by a
clean checkout of the Hyphen base-chain repository.

---

<!-- hyphen-bilingual-chinese -->

# Hyphen 仓库与兼容性边界

状态：开发和 CI 的规范性仓库政策。

## 基础链范围

受版本控制的 Hyphen 仓库负责基础链协议和参考节点：

- 共识关键数据结构与验证；
- 状态转换、存储、重放和链身份；
- 交易与密码学验证库；
- P2P、RPC、Template Provider 传输和浏览器接口；
- 版本化规范、机器可读向量、模糊测试目标和 CI。

根目录 `Cargo.toml` 是基础链工作区成员的权威清单。内部 `crates/hyphen-wallet` 包是面向协议的钱包库，不是独立的 Flutter 应用。

## 独立项目

`HyphenMiner`、`HyphenPool` 和 `HyphenWallet` 是独立产品，分别拥有自己的源码历史、锁文件、发布、威胁模型和 CI。本地检出可放在 Hyphen 仓库根目录下，以便兼容性脚本发现它们。这些目录被本仓库有意忽略，禁止成为根工作区成员或基础链 CI 的必需输入。

独立项目构建或测试成功不能证明基础链正确；基础链测试成功也不能证明独立项目兼容。

三个独立项目通过公开 Git revision `3a7effdc74b59bea1792116327e569e1d9bc9e21` 使用共享协议 crate，不允许依赖本机主链路径。升级必须固定新的公开 revision，并重新执行跨项目向量和兼容性测试。

## 协议变更顺序

影响兼容性的基础链变更必须按以下顺序进行：

1. 在版本化规范中定义线格式、状态或共识变更。
2. 说明激活和降级行为；除非冻结规范明确允许，否则共识变更必须采用新的链 profile 和链身份。
3. 发布正向和负向机器可读向量。
4. 更新 Hyphen 参考实现并使基础链 CI 通过。
5. 在各自仓库和 CI 中更新每个独立项目。
6. 针对精确 revision 运行跨项目兼容性测试，并归档 revision 映射、日志和向量哈希。

## CI 所有权

Hyphen 基础链 CI 负责格式检查、Clippy、工作区测试、模糊测试目标编译、链身份向量和 Windows 节点冒烟测试。夜间 CI 在 Linux 上运行有界解码器模糊测试。

跨项目的 node/miner/pool/wallet 测试只属于兼容性证据。它们要求显式、独立的代码检出，并且必须位于单独的集成工作流或编排仓库中；基础链仓库的干净检出不能依赖这些项目。
