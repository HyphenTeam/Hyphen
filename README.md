# Hyphen

[简体中文](README_CN.md)

Hyphen is a personal research project in private blockchain transactions and verifiable computational work. This Rust workspace contains the full node, consensus rules, state storage and block explorer. On the standard devnet, miners find single-use Cunningham prime chains and full nodes independently verify each block. Mainnet remains a research profile pending independent review.

## Run a local node

Use the Rust toolchain pinned in this repository. From the repository root, start an isolated devnet node with its own data directory.

```sh
cargo run --release --locked -p hyphen-node -- --network devnet --data-dir data/devnet --listen /ip4/127.0.0.1/tcp/48334
```

Open the [local explorer](http://127.0.0.1:8080) to inspect the chain. To join another node, supply its TCP multiaddress and peer ID with `--boot-nodes`. Both nodes must use the same network profile. [Peer configuration and recovery](wiki/Operations-Peer-Network.md)

## Documentation

| Topic | Reference |
| --- | --- |
| Protocol and research status | [Whitepaper](wiki/Whitepaper.md) · [Consensus profiles](wiki/Consensus-Devnet-V2.md) |
| Node operations | [Linux deployment](wiki/Operations-Deploy-Linux.md) · [Peer policy](wiki/Security-Peer-Policy.md) |
| Related software | [Miner](https://github.com/HyphenTeam/HyphenMiner) · [Pool](https://github.com/HyphenTeam/HyphenPool) · [Wallet](https://github.com/HyphenTeam/HyphenWallet) |

[Project Wiki](wiki/Home.md)

## License

Hyphen is licensed under the [PolyForm Strict License 1.0.0](LICENSE).
