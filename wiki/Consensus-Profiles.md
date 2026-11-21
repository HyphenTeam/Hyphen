# Development network consensus

| Network / magic | Block / state version | Genesis feature mask | Block rule | Target / window / initial threshold | Compute verifier |
|---|---|---|---|---|---|
| `neural-devnet` / HYN3 | 5 / 2 | `0x1f60` | Nonce-derived MLP and BLAKE3 scratchpad | 30 s / 16 intervals / 2^60 | Inline Alice v1, system 3 |

Run `hyphen-node --print-chain-identity` and compare the network magic, consensus digest and genesis hash before connecting a miner, wallet or peer. Start a fresh data directory for HYN3. Previous signed transactions and balances belong to their original genesis. [Identity vector](../test-vectors/chain-identity-neural-v3.json)

Every child block must pass the neural work predicate, miner authorization, time checks and all state transitions. The asset rules bind the coinbase recipient, check parent commitment and nullifier roots, and verify total fees. Contract state and compute settlement contribute to the post-state root. The block-size limit is 2 MiB. [Work predicate and fork weight](Consensus-Neural-Work.md) · [Block transition](../crates/hyphen-consensus/src/chain.rs)

`--export-history`, `--verify-history` and `--replay-history` use the selected genesis. Verification reconstructs historical state in a temporary database. Replay into a fresh directory applies the archive using a single observation time. [Archive implementation](../crates/hyphen-consensus/src/replay.rs)
