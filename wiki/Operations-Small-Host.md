# Running Hyphen on a small host

Target: **4 vCPU, 2 GiB RAM**. That is enough for a node, a pool and a
Cloudflare tunnel. It is not enough to also mine, and the chain's own storage
model limits how long any node can run there — both points are measured below,
not estimated.

## Measured footprint

All numbers from a devnet run on the same build documented here: node, pool and
tunnel on one machine, two mining threads on a second, difficulty climbing to
about 3300 witnesses per block.

| Process | Resident memory | Notes |
| --- | --- | --- |
| `hyphen-node` | 500–540 MiB | includes a 64 MiB storage cache |
| `hyphen-pool-server` | 10–12 MiB | ledger is bounded (see below) |
| `cloudflared` | 40–80 MiB | one tunnel, one connection pair |
| `hyphen-miner`, 2 threads | 8 MiB | plus whatever the accelerator holds |

Total without mining: **under 650 MiB**. With the OS and page cache that leaves
plenty of the 2 GiB, which is why the node, the pool and the tunnel fit
comfortably.

Do not mine on this host. Two threads of CPU mining already produced ~90 seconds
of CPU time in a 120-second window; adding three or four mining threads on four
cores is what turns a healthy origin into one that misses tunnel keepalives.
`--threads 0` leaves one core free, but on four cores that is still 75% of the
machine.

## Storage cache

`sled`, the storage engine, defaults to a **one gigabyte** page cache. On a 2 GiB
host that single default can decide whether the kernel kills the node. The node
now sets it explicitly:

```bash
hyphen-node ... --db-cache-mb 64     # default
```

16 MiB is the floor: below it every block thrashes the index.

## The real limit: witness storage

PoUW single use is enforced by a 256-level sparse Merkle tree keyed by the
witness hash. Every claimed witness writes its own path, which costs about
**15 KiB on disk per witness**.

Measured on the run above:

| Height | Difficulty | Database size |
| --- | --- | --- |
| 11 | 3294 | 459 MiB |
| 11, after settling | 3294 | 554 MiB |

That is roughly **45 MiB per block** at that difficulty. A 40 GB disk therefore
holds about 900 blocks — hours, not months.

This is a property of the current witness commitment, not of the storage engine,
and it cannot be tuned away. Two decisions follow:

- **For a small host today:** run node, pool and tunnel; keep mining off the
  box; expect the data directory to grow by tens of megabytes per block while a
  miner is connected.
- **Before mainnet:** the witness set needs a commitment whose per-witness cost
  is constant — an append-only Merkle mountain range over witness hashes, with a
  sorted on-disk membership index, gives a logarithmic proof for a few dozen
  bytes per witness. That changes `WitnessSet::root()`, so it is a new chain
  identity and a protocol change, never an in-place edit.

## Write amplification that is fixed

Claiming a block's witnesses used to run one storage transaction **per
witness**, and each transaction flushed. At difficulty 3294 that is 3294 fsyncs
per block: the node stops answering for seconds to minutes, the tunnel times out
and the site shows 1033 while the machine is merely busy.

Claims are now chunked: 128 witnesses per transaction, one flush per chunk. A
block at the ceiling costs 26 flushes instead of 3294, and every node the
witnesses share is written once instead of once per witness.

## Bounded-derived data

Nothing that a public route can reach is allowed to grow without a ceiling:

| Structure | Bound |
| --- | --- |
| Mempool entries | 10 000 entries, byte budget derived from that |
| Explorer miner history | 512 blocks per reward key, 4096 keys |
| Explorer index batches | 256 blocks per batch, 8 batches per request |
| Pool share window | trimmed to 4× block difficulty × PPLNS factor |
| Pool payout history | 512 records; reserved and submitted records are never dropped |
| Pool reward events / recent blocks | 512 / 128 |

## Recommended layout

- Node, pool and tunnel on the 4 vCPU / 2 GiB box.
- Miner elsewhere. The protocol is a TCP connection; distance costs latency, not
  correctness.
- `--db-cache-mb 64`, `MemoryMax=1600M` in the unit so the kernel kills the
  node's children before it kills the tunnel.
- Cloudflare tunnel as its own service, see
  `deploy/systemd/cloudflared.service.example`.
- Alert on `/healthz` (liveness) and on `df` for the data directory.
