# Hyphen

A privacy-focused, CPU-first Proof-of-Work blockchain built in Rust.

## Architecture

Hyphen is organised as a Cargo workspace with 11 focused crates:

| Crate | Purpose |
| --- | --- |
| `hyphen-crypto` | Blake3/SHA3 hashing, Ed25519 keys, Pedersen commitments, stealth addresses, Merkle tree, CLSAG ring signatures |
| `hyphen-core` | Block / BlockHeader types, chain configuration, shared error types |
| `hyphen-pow` | **PageWeave** CPU-first PoW — epoch arena, scratchpad, 8 transformation kernels, LWMA difficulty adjustment |
| `hyphen-proof` | Bulletproofs range proofs (64-bit, aggregated) and inner-product argument, batch verification |
| `hyphen-tx` | Shielded UTXO model — notes, transactions, nullifiers, transaction builder |
| `hyphen-economics` | Smooth exponential emission schedule with tail emission, fee calculation and partial burn |
| `hyphen-state` | sled-backed persistent storage — block store, chain state, nullifier set, commitment tree |
| `hyphen-consensus` | Block/transaction validation, chain management, genesis block |
| `hyphen-mempool` | Fee-priority transaction pool with key-image conflict detection |
| `hyphen-network` | libp2p P2P stack — Gossipsub broadcast, Kademlia discovery, Request-Response sync |
| `hyphen-node` | Full-node binary with CLI, mining, P2P networking |

## Key Design Decisions

### PageWeave PoW

PageWeave is a novel CPU-first Proof-of-Work algorithm designed to resist GPU and ASIC acceleration:

- **2 GiB Epoch Arena** — deterministically generated from the epoch seed using keyed Blake3 XOF; rebuilt every 2048 blocks
- **8 MiB Scratchpad** — fits in L3 cache; experiences serial reads and writes with data-dependent addressing
- **8 Transformation Kernels** — DivChain, BitWeave, SparseStep, PrefixScan, MicroSort, VarDecode, HashMix, BranchMaze — selected at runtime based on page content, ensuring full CPU utilisation of branch prediction, out-of-order execution, and cache hierarchy
- **Serial dependency chain** — each round depends on the previous round's output, preventing warp-level GPU parallelism
- **Page graph links** — inter-page dependency edges force random access into the 2 GiB arena
- **Platform portable** — no SIMD or AES-NI required; runs on x86-64, ARM64 and RISC-V

### Privacy Model

Hyphen uses a shielded UTXO model combining:

1. **Pedersen Commitments** — amounts hidden as `v·G + r·H` on the Ristretto group
2. **Stealth Addresses** — ECDH-derived one-time output keys; sender publishes ephemeral key `R`, receiver derives the spending key
3. **CLSAG Ring Signatures** — each input references a ring of decoy outputs; the key image (nullifier) prevents double-spending without revealing the real input
4. **Bulletproofs Range Proofs** — prove every output amount lies in `[0, 2⁶⁴)` with O(log n) proof size; supports aggregation across all outputs in a transaction

### Economics

- **Smooth emission** — exponential decay with half-life of 262 144 blocks; initial reward ≈ 17.59 HYP
- **Tail emission** — permanent floor of 0.3 HYP per block to guarantee long-term mining incentive
- **50 % fee burn** — half of every transaction fee is destroyed; the other half goes to the miner
- **Atomic unit** — 1 HYP = 10¹² atomic units

### Consensus

- **Block time** — 120 s (mainnet), 30 s (testnet)
- **LWMA difficulty adjustment** — Linear Weighted Moving Average over a 60-block window with 6T clamping and 3× max adjustment
- **Ring size** — 16 decoys per input (mainnet)

## Building

```bash
# Debug build (all crates)
cargo build --workspace

# Release build
cargo build --workspace --release

# Run tests
cargo test --workspace

# Run the node (testnet)
cargo run -p hyphen-node -- --network testnet --mine
```

### Prerequisites

- Rust 1.75+ (edition 2021)
- A C compiler for some native dependencies (ring, libsodium bindings if used)
- On Linux: `pkg-config`, `libssl-dev` (for libp2p DNS)

## Running

```bash
# Start a testnet node with mining
hyphen-node --network testnet --data-dir ./testnet_data --mine

# Connect to boot nodes
hyphen-node --network mainnet \
  --boot-nodes "/ip4/1.2.3.4/tcp/9734/p2p/12D3KooW..."

# Custom listen address
hyphen-node --listen "/ip4/0.0.0.0/tcp/9734"
```

## Project Structure

```
Hyphen/
├── Cargo.toml                  # Workspace manifest
├── src/lib.rs                  # Root re-export crate
├── crates/
│   ├── hyphen-crypto/          # Cryptographic primitives
│   │   └── src/
│   │       ├── hash.rs         # Blake3, SHA3
│   │       ├── keys.rs         # Ed25519 key management
│   │       ├── pedersen.rs     # Pedersen commitments
│   │       ├── stealth.rs      # Stealth one-time addresses
│   │       ├── merkle.rs       # Append-only Merkle tree
│   │       └── clsag.rs        # CLSAG ring signatures
│   ├── hyphen-core/            # Core types
│   ├── hyphen-pow/             # PageWeave PoW
│   │   └── src/
│   │       ├── arena.rs        # Epoch arena generation
│   │       ├── scratchpad.rs   # Per-thread scratchpad
│   │       ├── kernels.rs      # 8 transformation kernels
│   │       ├── solver.rs       # Mining solver
│   │       └── difficulty.rs   # LWMA difficulty adjustment
│   ├── hyphen-proof/           # Bulletproofs
│   │   └── src/
│   │       ├── generators.rs   # Vector Pedersen generators
│   │       ├── inner_product.rs# Inner product argument
│   │       ├── range_proof.rs  # Range proofs (single + aggregated)
│   │       └── batch.rs        # Batch verification
│   ├── hyphen-tx/              # Transaction model
│   ├── hyphen-economics/       # Emission + fees
│   ├── hyphen-state/           # sled storage
│   ├── hyphen-consensus/       # Validation + chain
│   ├── hyphen-mempool/         # Transaction pool
│   ├── hyphen-network/         # libp2p P2P
│   └── hyphen-node/            # Binary entry point
└── README.md
```

## License

APGL-3.0
