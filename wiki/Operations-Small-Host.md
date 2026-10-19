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

## When no block appears

The pool answers "what is the mining loop doing right now" in one read:

```bash
curl -fsS http://127.0.0.1:8081/api/pool/status
```

```json
{
  "status": "ok",
  "uptime_secs": 18,
  "connected_miners": 2,
  "claimed_witnesses": 1727,
  "template_refresh_failures": 0,
  "job": {
    "job_id": "dae57f02ddc98421257c610c78f994cffcf2a2b88e3f2cdf077a4314268e39b1",
    "height": 9, "block_difficulty": 1357, "share_difficulty": 10,
    "transactions": 0, "issued_at": 1792411399, "age_secs": 2
  },
  "shares": {
    "accepted": 18, "rejected": 11,
    "last_rejection": "stale job", "last_rejection_age_secs": 15
  },
  "blocks": { "submitted": 8, "accepted": 8, "rejected": 0 },
  "last_block": {
    "height": 8, "hash": "5df26a4d…", "accepted": true, "age_secs": 2, "detail": ""
  }
}
```

That sample is two miners on one pool, eighteen seconds after start.

| What it shows | What it means |
| --- | --- |
| `connected_miners: 0` | Nothing authenticated. Check the miner's `--pool` host/port and that the pool is listening on the interface the miner reaches — not the node, not the tunnel. |
| `job` is absent | No template has arrived from the node yet. The pool does nothing at all in this state. |
| `job.age_secs` pinned well above the 30 s block target, `blocks.accepted` flat | The pool is still handing out a job the node has already replaced. Look at the node and the path to it (`--node`), not at the miners. |
| `connected_miners > 0`, `shares.accepted` flat | Miners are attached but nothing is landing: share difficulty set beyond what the hardware can reach in a block time. |
| `last_rejection: "stale job"` | A candidate arrived for a job another miner had already turned into a block. Normal in bursts, especially on a devnet ramp where the first blocks are near-instant; a constant stream means miners are racing on a job that should have been replaced. |
| `last_rejection: "witness N was already claimed by another miner on this pool"` | Two miners scanned the same witness lane. Fixed in the current miner: each process takes a private lane derived from `max_chain_origin(chain_length)`. |
| `blocks.submitted > 0`, `blocks.accepted: 0` | The node refused every block. `last_block.detail` carries the node's own reason — read that before touching anything else. |
| `template_refresh_failures` climbing | The node did not serve a template after a block was accepted. The pool retries four times and then waits for the node push; a persistent count is a node problem. |
| `claimed_witnesses` growing without bounds relative to chain length | Witnesses are being credited but not consumed by blocks: the pool is accepting shares for a chain that is not advancing. |

`shares.accepted` counts candidate submissions this pool answered; it is not a
hashrate estimate. `/api/pool/wallet/{wallet}/balance` is still the authority on
what a wallet has earned.

## Recommended layout

- Node, pool and tunnel on the 4 vCPU / 2 GiB box.
- Miner elsewhere.
- `--db-cache-mb 64` and the unit's `MemoryMax=1600M` (already in
  `deploy/systemd/hyphen-node.service`; override with `systemctl edit hyphen-node`
  if your host needs a different ceiling) so the kernel reclaims from the node
  rather than from the tunnel.
- Cloudflare tunnel as its own service, see
  `deploy/systemd/cloudflared.service.example`.
- Alert on `/healthz` (liveness) and on `df` for the data directory.
