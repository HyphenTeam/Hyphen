# 连接 Hyphen 节点

[English](Operations-Peer-Network.md)

每个节点都需要独立的数据目录和持久化 Ed25519 身份。在第一个终端按 [README](../README_CN.md) 启动开发网节点，从 `Listening on` 日志复制完整的 `/ip4/127.0.0.1/tcp/48334/p2p/…` 地址。另开一个终端，将下列 `SEED_MULTIADDR` 替换为刚复制的地址。

```sh
cargo run --release --locked -p hyphen-node -- --network neural-devnet --data-dir data/neural-v3-b --listen /ip4/127.0.0.1/tcp/48344 --rpc-bind 127.0.0.1:48343 --template-bind 127.0.0.1:3360 --explorer-bind 127.0.0.1:8082 --boot-nodes SEED_MULTIADDR
```

暂停挖矿后，对照 `http://127.0.0.1:8080/api/info` 和 `http://127.0.0.1:8082/api/info` 的 `height` 与 `tip_hash`。新开发网在矿工产出首块前会停留在创世高度。判断两台节点已同步时，需要同时核对高度和链顶哈希。

## 发现与恢复

跨主机部署时，填写对端可达的 IP 或 DNS 名称，并放行种子节点的 P2P TCP 端口。`--boot-nodes` 接受逗号分隔的 IP、`/dns4`、`/dns6` 和 `/dns` TCP 多地址，每项以 `/p2p/<peer-id>` 结束。Noise 握手使用该 ID 验证种子身份。重启时复用数据目录中的 `p2p_identity.key`。如需自定义位置，使用 `--identity-file`。

节点每 60 秒查询对端链顶并重试配置的种子。DNS 刷新独立于网络事件循环。身份识别、节点发现、同步协议和广播主题都使用所选网络的标识。同网 Kademlia 发现需要对端支持新的协议名。使用兼容种子地址直连时仍沿用 `sync/2` 同步协议。

| 资源 | 上限 |
| --- | --- |
| 已建立连接 | 总计 64，入站最多 48，同一对端最多 2 |
| 正在建立的连接 | 入站 32，出站 16 |
| 历史区块请求 | 同时一个区间，每次最多 16 块 |
| 区块区间响应 | CBOR 编码前的区块数据最多 4 MiB |
| 查询链顶以外的同步响应 | 所有对端共用 4 个名额，包含等待发送的响应 |
| 同步请求超时 | 20 秒 |

遇到历史分歧时，节点可沿父哈希追溯共同祖先，逐块验证候选分支并重算累计工作量，只接入严格更重的分支。脱链交易会重新校验，重新准入的交易可再次广播。排查分叉时核对网络身份、高度、链顶哈希和累计工作量。连续两次换链的实测在一台 Windows 主机上完成，公网多机分区恢复仍待验证。[分叉实测](Operations-Verification.md) · [测试网准入条件](Operations-Incentivized-Testnet.md)

## 验证

在两个安装目录分别运行 `hyphen-node --print-chain-identity`，核对 HYN3 创世和参数摘要。暂停挖矿后核对两节点的高度和链顶，重启其中一个并再次核对。Windows 下运行 `./scripts/devnet-smoke.ps1 -VerifyPeerSync` 可同时验收矿池账本恢复和钱包奖励。
