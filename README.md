# Hyphen

[简体中文](README_CN.md)

Hyphen is a Rust research blockchain for private payments and Wasm applications. On `neural-devnet`, miners evaluate a fixed-point neural network for each nonce. When the BLAKE3 gate passes, they compute the final digest using a 1 MiB scratchpad. Nodes independently verify both thresholds.

## Run a local node

Use the Rust toolchain pinned in this repository. From the repository root, start an isolated devnet node with its own data directory.

```sh
cargo run --release --locked -p hyphen-node -- --network neural-devnet --data-dir data/neural-v3 --listen /ip4/127.0.0.1/tcp/48334
```

Open the [local explorer](http://127.0.0.1:8080) to inspect the chain. To join another node, supply its TCP multiaddress and peer ID with `--boot-nodes`. Both nodes must use the same network profile. [Peer configuration and recovery](wiki/Operations-Peer-Network.md)

## Documentation

| Topic | Reference |
| --- | --- |
| Protocol and research status | [Whitepaper](wiki/Whitepaper.md) · [Consensus profiles](wiki/Consensus-Neural-Work.md) |
| Node operations | [Linux deployment](wiki/Operations-Deploy-Linux.md) · [Peer policy](wiki/Security-Peer-Policy.md) |
| Signed neural tasks on neural-devnet | [Task verification, finalization and limits](wiki/Research-Aether-Compute.md) |
| Conditional offline payments on neural-devnet | [Reserve funding, transfer and settlement](wiki/Offline-Payments.md) |
| Wasm contracts and limit orders | [Four toolchains, signed calls and market transactions](wiki/Operations-Verification.md#third-party-contract-commands) |
| Related software | [Miner](https://github.com/HyphenTeam/HyphenMiner) · [Pool](https://github.com/HyphenTeam/HyphenPool) · [Wallet](https://github.com/HyphenTeam/HyphenWallet) |

[Protocol and node documentation](https://github.com/HyphenTeam/Hyphen/wiki)

## License

Hyphen is licensed under the [PolyForm Strict License 1.0.0](LICENSE).
