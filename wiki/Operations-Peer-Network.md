# Connecting Hyphen nodes

[简体中文](Operations-Peer-Network-CN.md)

Each node needs its own data directory and persistent Ed25519 identity. Run the first node with the devnet command in the [README](../README.md). Copy the complete `/ip4/127.0.0.1/tcp/48334/p2p/…` address from its `Listening on` log entry. In a second terminal, substitute that address for `SEED_MULTIADDR` and start a second node.

```sh
cargo run --release --locked -p hyphen-node -- --network devnet --data-dir data/devnet-b --listen /ip4/127.0.0.1/tcp/48344 --rpc-bind 127.0.0.1:48343 --template-bind 127.0.0.1:3360 --explorer-bind 127.0.0.1:8082 --boot-nodes SEED_MULTIADDR
```

Compare `height` and `tip_hash` at `http://127.0.0.1:8080/api/info` and `http://127.0.0.1:8082/api/info` while mining is paused. A fresh devnet stays at genesis until a miner produces a block. Equal heights alone do not establish that two nodes share a tip.

## Discovery and recovery

Across hosts, use a reachable IP or DNS name and allow inbound TCP on the seed's P2P port. `--boot-nodes` accepts comma-separated IP, `/dns4`, `/dns6` and `/dns` TCP multiaddresses ending in `/p2p/<peer-id>`. The ID authenticates the seed through Noise. Preserve `p2p_identity.key` in the data directory across restarts. An operator can select a different key location with `--identity-file`.

The node polls peer tips and retries configured seeds every 60 seconds. DNS refresh runs outside the swarm event loop. Identify, discovery, synchronization and gossip use the selected network's magic. The network-specific Kademlia protocol requires upgraded peers for discovery. Direct connections to compatible `sync/2` seeds retain the existing sync protocol.

| Resource | Limit |
| --- | --- |
| Established connections | 64 total, up to 48 inbound and 2 per peer |
| Pending connections | 32 inbound and 16 outbound |
| Historical block request | One outstanding range, up to 16 blocks |
| Block range response | Up to 4 MiB of block data before CBOR encoding |
| Concurrent non-tip sync responses | Up to 4 across all peers, including responses waiting to be sent |
| Sync request timeout | 20 seconds |

When peers disagree about history, the node can follow parent hashes to a common ancestor. It validates the candidate blocks and recomputes cumulative work before adopting a strictly heavier branch. It rechecks detached transactions and can broadcast those admitted to the mempool again. Compare network identity, height, tip hash and cumulative work when investigating a fork. The recorded two-switch test ran on one Windows host. Public multi-host partition recovery still needs verification. [Fork results](Operations-Verification.md) · [Public testnet criteria](Operations-Incentivized-Testnet.md)

## Verification

The standard-work node updates witness claims and the chain tip in one durable database transaction. On the first startup of an older standard-work database, it rebuilds the witness index from local canonical blocks. Allow time for that one-time scan before checking peer availability.

Run `hyphen-node --network devnet --print-chain-identity` on both installations. To exercise restart recovery, stop the seed, leave the second node running, then restart the seed with its original data directory and port. Compare hashes again after catch-up. A node using `neural-devnet` has a different genesis and network magic. Its Identify handshake should produce an incompatible-network disconnect when pointed at the devnet seed.

For block production, pool ledger recovery and wallet rescans on Windows, check out the three client repositories under the node repository and run `./scripts/devnet-smoke.ps1 -Network devnet`. Select `-Network neural-devnet` to exercise the neural SOLO profile. [Deployment](Operations-Deploy-Linux.md) · [Peer fault accounting](Security-Peer-Policy.md)
