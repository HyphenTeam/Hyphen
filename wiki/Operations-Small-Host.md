# Running Hyphen on a small host

The Linux reference deployment has 4 vCPUs, 2 GiB of RAM and a 40 GB disk. Its measurements below cover a devnet node, a pool and a Cloudflare tunnel. Chain history, ledger size and the number of peers affect capacity planning.

## Measured footprint

Devnet run: node, pool and miner, difficulty at the 4096-witness ceiling.

| Process | Resident memory | Notes |
| --- | --- | --- |
| `hyphen-node` | **62–75 MiB** | includes a 64 MiB storage cache |
| `hyphen-pool-server` | 9–13 MiB | observed pool process size during this run |
| `cloudflared` | 40–80 MiB | one tunnel, one connection pair |
| `hyphen-miner`, 2 threads | 8 MiB | plus whatever the accelerator holds |

### Windows working-set comparisons

Each row compares the previous and current algorithm in separate Windows debug processes under the same workload. Values are peak process working sets in MiB. The measurements predate the final P2P changes. The Merkle roots, reorganization paths, wallet spend decisions and witness membership checks agreed.

| Workload | Previous | Current |
| --- | ---: | ---: |
| Merkle root of 1,000,001 streamed leaves | 80.3 | 3.5 |
| Reorganization plan at height 65,536 with a one-block fork | 54.1 | 32.3 |
| Wallet scan with 1,000,000 public key images | 103.8 | 4.5 |
| Miner tracking 1,000,000 claimed witnesses | 30.9 | 8.5 |
| Pool rotating 128 templates with 256 KiB of transaction data and 64 readers | 25.0 | 8.4 |

The wallet buffers 8,192 key images before using a temporary file. The miner spills larger claim sets to a temporary database after 65,536 witnesses. The pool shares each immutable job among its readers. The Linux resident memory and Windows working sets above were measured on different workloads.

上表记录 Windows 调试构建的进程峰值工作集，各行均以同一输入对比前后实现。钱包和矿工用临时磁盘空间保存精确记录，矿池让读取者共享不可变模板。这些基准早于最后的 P2P 调整。实际节点的跨仓验证步骤见[构建与验收](Operations-Verification.md)。

## What a block costs

| Item | Cost |
| --- | --- |
| Block body | bounded by `max_block_size`, zstd-compressed at rest |
| Undo record | zstd-compressed previous commitment tree and protocol snapshots, plus the block's index changes |
| Claimed witnesses | 16 bytes each plus storage overhead |
| Transaction / height / output indexes | proportional to the block's contents |

A 37-block development run occupied 3 MB, about 80 KiB per block including indexes. A separate 1,024-block HYOF run with 1,022 reserve settlements occupied 189,266,577 bytes across files in its stopped node database. Its 2,016,720-byte history archive reproduced the same tip in a fresh database occupying 187,610,140 bytes. The current undo format retains the previous output tree for each block, so disk growth depends on the accumulated outputs as well as the new block. [Checkpoint measurements](Offline-Payments.md)

With `N` cumulative outputs, the snapshot stores the sum of `ceil(N / 2^level)` nodes for levels 0 through 32. At revision `7cf001e`, a snapshot with 499,989 outputs exceeds the reader’s 1,000,000-entry limit. A subsequent local revision derived the collection limit from the 64 MiB encoding limit and the minimum of 34 bytes per tree node. In that revision, a regression test saved and reopened 500,001 outputs and verified the last leaf against the original root. The 64 MiB limit and the cost of storing the preceding tree for each block still constrain long histories. [Snapshot implementation at 7cf001e](https://github.com/HyphenTeam/Hyphen/blob/7cf001ee9c7d04cbba67e3289d01edd5d5b036c5/crates/hyphen-state/src/commitment_tree.rs)

In the archived HYOF history the compressed undo value for one block grew from 1,475 bytes at height 3 to 145,743 bytes at height 1,024. The height-1,023 parent had 2,044 outputs and 75,015,400 bytes of compressed undo values. Across five copies of that parent, median validation, commit and flush time was 58.66 ms. Median rollback and flush time was 4.12 ms. Reopening each rolled-back database reproduced the parent tip and both payment-state roots. [Block measurements](Offline-Payments.md)

## The witness index

PoUW accepts a witness exactly once. The header binds the block's witness list
through `pow_commitment`; the single-use set is a **local** anti-replay index and
no header field, state root or fork-choice weight depends on how it is stored.

It used to be a 256-level sparse Merkle tree keyed by the witness hash: about
245 stored nodes per key, measured at **~15 KiB of disk per witness** and
**45 MiB per block** at ceiling difficulty. That is what filled disks and pushed
node memory past 500 MiB.

It is now one entry per witness — an eight-byte big-endian key, an eight-byte
claiming height. Membership is a point lookup. Canonical block application or rollback updates the witness index in the same durable transaction as the chain tip. On first startup with a pre-upgrade database, the node rebuilds the index from canonical blocks. Startup time depends on the amount of existing history.

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

## Retention and storage budgets

| Structure | Bound |
| --- | --- |
| Mempool entries | 10 000 entries, byte budget derived from that |
| Explorer miner history | 512 blocks per reward key, 4096 keys |
| Explorer index batches | 256 blocks per batch, 8 batches per request |
| Pool settlement history | PROP retains this round's shares. PPLNS keeps the shortest recent suffix reaching 4 × block difficulty × window factor when available. SOLO and the PPS family omit these share lists. |
| Pool payout history | Target of 512 records. Reserved and submitted payouts stay until reconciled. |
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
