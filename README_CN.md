# Hyphen

[English](README.md)

Hyphen 是一个研究隐私交易与可验证计算工作量的个人区块链项目。本 Rust 工作区包含全节点、共识规则、状态存储和区块浏览器。在标准开发网上，矿工搜索只能使用一次的坎宁安素数链，全节点独立验证每个区块。主网配置仍处于研究阶段，项目尚待独立审计。

## 启动本地节点

使用仓库指定的 Rust 工具链，在仓库根目录运行以下命令。节点将使用独立的数据目录，监听本机的开发网连接。

```sh
cargo run --release --locked -p hyphen-node -- --network devnet --data-dir data/devnet --listen /ip4/127.0.0.1/tcp/48334
```

打开[本地区块浏览器](http://127.0.0.1:8080)查看链状态。连接其他节点时，通过 `--boot-nodes` 指定对方的 TCP 多地址及 Peer ID。双方需要使用相同的网络配置。[节点互联与恢复](wiki/Operations-Peer-Network-CN.md)

## 项目文档

| 主题 | 文档 |
| --- | --- |
| 协议与研究进展 | [白皮书](wiki/Whitepaper.md) · [开发网共识](wiki/Consensus-Devnet-V2.md) |
| 节点运维 | [Linux 部署](wiki/Operations-Deploy-Linux.md) · [对等节点策略](wiki/Security-Peer-Policy.md) |
| 配套软件 | [矿工](https://github.com/HyphenTeam/HyphenMiner) · [矿池](https://github.com/HyphenTeam/HyphenPool) · [钱包](https://github.com/HyphenTeam/HyphenWallet) |

[项目 Wiki](wiki/Home.md)

## 许可证

Hyphen 采用 [PolyForm Strict License 1.0.0](LICENSE)。
