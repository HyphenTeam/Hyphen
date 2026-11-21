# Hyphen

[English](README.md)

Hyphen 是以 Rust 实现的隐私支付与 Wasm 应用研究链。`neural-devnet` 的矿工搜索由 nonce 派生的定点神经网络输入，初筛通过后执行 BLAKE3 scratchpad，节点独立复算两个门槛。

## 启动本地节点

使用仓库指定的 Rust 工具链，在仓库根目录运行以下命令。节点将使用独立的数据目录，监听本机的开发网连接。

```sh
cargo run --release --locked -p hyphen-node -- --network neural-devnet --data-dir data/neural-v3 --listen /ip4/127.0.0.1/tcp/48334
```

打开[本地区块浏览器](http://127.0.0.1:8080)查看链状态。连接其他节点时，通过 `--boot-nodes` 指定对方的 TCP 多地址及 Peer ID。双方需要使用相同的网络配置。[节点互联与恢复](wiki/Operations-Peer-Network-CN.md)

## 项目文档

| 主题 | 文档 |
| --- | --- |
| 协议与研究进展 | [白皮书](wiki/Whitepaper.md) · [开发网共识](wiki/Consensus-Neural-Work.md) |
| 节点运维 | [Linux 部署](wiki/Operations-Deploy-Linux.md) · [对等节点策略](wiki/Security-Peer-Policy.md) |
| 神经开发网的计算任务 | [验证、最终化与容量上限](wiki/Research-Aether-Compute.md#神经开发网的内联-alice-任务) |
| 神经开发网的双离线付款 | [预锁、离线转付及规范链结算](wiki/Offline-Payments.md) |
| Wasm 合约与限价单 | [四种语言的部署、调用与市场交易验收](wiki/Operations-Verification.md#third-party-contract-commands) |
| 配套软件 | [矿工](https://github.com/HyphenTeam/HyphenMiner) · [矿池](https://github.com/HyphenTeam/HyphenPool) · [钱包](https://github.com/HyphenTeam/HyphenWallet) |

[协议与节点文档](https://github.com/HyphenTeam/Hyphen/wiki#中文导览)

## 许可证

Hyphen 采用 [PolyForm Strict License 1.0.0](LICENSE)。
