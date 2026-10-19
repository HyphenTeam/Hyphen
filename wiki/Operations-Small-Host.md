# Running Hyphen on a small host

Target: **4 vCPU, 2 GiB RAM, 40 GB disk**. That is enough for a node, a pool and
a Cloudflare tunnel, and — after the storage fix described below — for a chain
that keeps growing. The numbers here are measured on that stack, not estimated.

## Measured footprint

Devnet run: node, pool and miner, difficulty at the 4096-witness ceiling.

| Process | Resident memory | Notes |
| --- | --- | --- |
| `hyphen-node` | **62–75 MiB** | includes a 64 MiB storage cache |
| `hyphen-pool-server` | 9–13 MiB | ledger is bounded (see below) |
| `cloudflared` | 40–80 MiB | one tunnel, one connection pair |
| `hyphen-miner`, 2 threads | 8 MiB | plus whatever the accelerator holds |

Every process together stays under 200 MiB, so 2 GiB is comfortable. What used
to consume the machine was neither the runtime nor the block size — it was the
witness index.

## What a block costs

| Item | Cost |
| --- | --- |
| Block body | bounded by `max_block_size`, zstd-compressed at rest |
| Undo record | zstd-compressed, proportional to the block's state change |
| Claimed witnesses | 16 bytes each plus storage overhead |
| Transaction / height / output indexes | proportional to the block's contents |

Measured: **37 blocks occupy 3 MB**, about 80 KiB per block including every
index. A 40 GB disk therefore holds on the order of 500 000 blocks, not the
roughly 7 200 the previous witness representation allowed.

## The witness index

PoUW accepts a witness exactly once. The header binds the block's witness list
through `pow_commitment`; the single-use set is a **local** anti-replay index and
no header field, state root or fork-choice weight depends on how it is stored.

It used to be a 256-level sparse Merkle tree keyed by the witness hash: about
245 stored nodes per key, measured at **~15 KiB of disk per witness** and
**45 MiB per block** at ceiling difficulty. That is what filled disks and pushed
node memory past 500 MiB.

It is now one entry per witness — an eight-byte big-endian key, an eight-byte
claiming height — so membership is a point lookup and a block's claims are one
transaction per 128 witnesses.

## Storage cache

`sled` defaults to a **one gigabyte** page cache. The node sets it explicitly:

```bash
hyphen-node ... --db-cache-mb 64     # default; 16 is the floor
```

## Mining on the same host

Do not. Two mining threads produced ~256 seconds of CPU time in a 130-second
window; on four cores that starves the node, the pool and the tunnel, which is
how a healthy origin starts missing tunnel keepalives. `--threads 0` leaves one
core free, but on four cores that is still 75% of the machine.

Mine elsewhere and connect over TCP.

## Bounded-derived data

Nothing a public route can reach grows without a ceiling:

| Structure | Bound |
| --- | --- |
| Mempool entries | 10 000 entries, byte budget derived from that |
| Explorer miner history | 512 blocks per reward key, 4096 keys |
| Explorer index batches | 256 blocks per batch, 8 batches per request |
| Pool share window | trimmed to 4× block difficulty × PPLNS factor |
| Pool payout history | 512 records; reserved and submitted records are never dropped |
| Pool reward events / recent blocks | 512 / 128 |
| Claimed witness index | one entry per witness, 16 bytes of key and value |

## Block size and fee priority

`max_block_size` is part of `consensus_params_hash`, so changing it produces a
new chain identity: a fresh data directory, a rebuilt pool and miner, and a
genesis hash every participant must agree on. Raise it deliberately, never as a
silent edit.

Within a block, space is allocated in two passes: protocol-reserved entries take
up to a quarter of the block, then ordinary transactions are packed in
fee-density order. A transaction that pays more per byte is included before one
that pays less, which is what makes a contract deployment compete for space the
same way a transfer does.

## Recommended layout

- Node, pool and tunnel on the 4 vCPU / 2 GiB box.
- Miner elsewhere.
- `--db-cache-mb 64`, `MemoryMax=1600M` in the node unit so the kernel kills the
  node before it kills the tunnel.
- Cloudflare tunnel as its own service, see
  `deploy/systemd/cloudflared.service.example`.
- Alert on `/healthz` (liveness) and on `df` for the data directory.
