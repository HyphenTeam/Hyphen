# Hyphen Frozen Devnet v1 Consensus Profile (Historical)

> Withdrawn on 2026-07-30. V1 generated coinbase outputs with node-local
> randomness, so equal block histories could produce unequal spendable-output
> state. Its identity is retained only as historical evidence and MUST NOT be
> used for a new database. Active development uses [devnet v2](devnet-v2.md).

Status: frozen for reproducible development and adversarial testing. This is
not a production-mainnet specification or a security claim.

Normative words such as MUST and MUST NOT apply to `hyphen-devnet-v1`. The
Rust implementation in this repository is the reference implementation.

## Chain identity

| Field | Frozen value |
| --- | --- |
| Profile | `hyphen-devnet-v1` |
| Network magic | `48594456` (`HYDV`) |
| Block version | `2` |
| Consensus feature mask | `0` |
| Difficulty algorithm | `LwmaV1` |
| Consensus parameters hash | `e9591468e6b53e922b67f6dbecd0dccec4217e95f0f09a21bce7244fbe8e8322` |
| Genesis hash | `4ee146f63ec54ded2ed743e88ee4ff0981598afc0412d4261e17e43a731a1b92` |
| Genesis timestamp | `1767225600000` ms (`2026-01-01T00:00:00Z`) |

The machine-readable vectors are in
`test-vectors/chain-identity-v1.json`. A database stores the genesis hash and
consensus parameters hash and MUST refuse to open under a different identity.

Verify the checked-out implementation with:

```bash
cargo run -p hyphen-node --locked -- --network devnet --print-chain-identity
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
```

## Frozen parameters

| Parameter | Value |
| --- | ---: |
| Target block time | 30 seconds |
| Difficulty window | 30 blocks |
| Initial difficulty | 1,000 |
| Per-step difficulty clamp | previous / 3 through previous * 3 |
| Future timestamp allowance | 60,000 ms |
| Epoch length | 128 blocks |
| Epoch arena | 64 MiB |
| Scratchpad | 256 KiB |
| Page size | 4,096 bytes |
| PoW rounds | 64 |
| Writeback interval | 8 |
| Kernel count | 12 |
| Maximum block size | 2 MiB |
| Ring size | 4 |
| Initial reward | 100,000,000,000,000 atomic units |
| Tail emission | 600,000,000,000 atomic units |
| Fee burn | 5,000 basis points |

The complete ordered parameter commitment is implemented by
`ChainConfig::consensus_params_hash`. A change to any committed field creates a
different chain identity and MUST NOT be deployed as devnet v1.

## Disabled research mechanisms

Uncles, TERA, VRE consensus enforcement, MSE, and MDAD-SPR are disabled. The
code may retain these mechanisms for research profiles, but a devnet v1 node
MUST NOT activate them. Useful-Work is not a consensus feature and is not part
of devnet v1.

## Header and chain rules

For every post-genesis block, the verifier MUST enforce at least:

1. Header version is exactly 2.
2. Height is the current tip height plus one and `prev_hash` is the current
   tip hash.
3. Timestamp is strictly greater than its parent after height 1 and no more
   than 60 seconds ahead of the verifier's adjusted time.
4. Transaction and uncle roots match block contents. Uncle contents MUST be
   empty because the uncle feature is disabled.
5. Miner block authorization is present and valid.
6. PoW satisfies the expected epoch seed and difficulty.
7. Transactions pass size, balance, signature, proof, nullifier, and state
   transition checks before the tip is committed.

At withdrawal, the v1 chain manager accepted only a block extending the active tip. The
state library contains inactive persistent branch metadata, strictly-heavier
cumulative-work reorg planning, atomic one-tip rollback primitives, and a
generic durable coordinator that can resume a static reorg plan or restore the
original branch after a candidate attach failure. No live backend yet performs
fork-specific transaction/state validation, selects a competing branch, or
drives that coordinator. The coordinator model therefore is not active reorg
support.
Consequently complete reorg handling remains a release blocker for an
incentivized public testnet, not a frozen devnet v1 capability.

## Difficulty

`LwmaV1` computes a linear weighted mean over adjacent solve times. Each solve
time is clamped to `[target/10, 6*target]`. The weighted average difficulty is
scaled by target time divided by weighted solve time, then clamped to
`[max(1, previous/3), max(1, previous*3)]`. Calculations use integer arithmetic
in the reference implementation. Reversed timestamp samples cannot force an
adjustment outside the final clamp.

## Miner block authorization

Every accepted block contains a `BlockAuthorization` version 1. The miner's
Ed25519 signature commits to a domain-separated Blake3 digest of:

```text
"Hyphen/NCAP/block-authorization/v1"
authorization_version
network_magic
consensus_params_hash
genesis_hash
full_header_hash
reward_view_public
reward_spend_public
```

The header contains the miner public key. Changing the nonce, extra nonce,
transaction root, reward keys, chain identity, or any other header field after
authorization invalidates the signature. This is a consensus rule, not only a
pool policy.

## Archive, reference verification, and replay

Archive version 1 contains network magic, consensus parameters hash, genesis
hash, and contiguous post-genesis blocks. The lightweight reference verifier
checks archive identity, linkage, timestamps, roots, and miner authorization.
Full replay additionally executes authoritative PoW, transaction, and state
validation into a fresh height-zero database.

```bash
# Export from a stopped or separately copied source database.
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-source \
  --export-history ./devnet-history-v1.bin

# Lightweight verification without writing chain state.
cargo run -p hyphen-node --locked -- \
  --network devnet --verify-history ./devnet-history-v1.bin

# Full replay. The destination must be new and empty.
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-replay \
  --replay-history ./devnet-history-v1.bin
```

Archive files are currently Rust/bincode implementation artifacts, capped at
512 MiB by the CLI. A language-neutral canonical block/archive encoding and
cross-implementation vectors remain required before production consensus.

## Change policy

No in-place activation is allowed on devnet v1. Any consensus change requires:

- a new named profile and network identity;
- a written rationale and threat model;
- updated machine-readable vectors;
- reference-verifier and negative tests;
- successful replay from that profile's genesis; and
- independent review before promotion beyond a research network.
