# Running Hyphen on a small host

The earlier Linux deployment had 4 vCPUs, 2 GiB of RAM and a 40 GB disk. Its measurements predate HYN2. In a Windows HYN2 smoke run, the peak working sets before restart were 38,092,800 bytes for the node, 10,784,768 for the pool and 7,233,536 for the miner. The sample covered a fresh chain at height 3. The wallet scan peaked at 5,095,424 bytes. Longer histories, larger ledgers and more peers can increase memory use. [Reproduction](Operations-Verification.md)

## Verification cost

A full HYN3 block verification derives the weights, evaluates one nonce and performs up to one 1 MiB BLAKE3 scratchpad calculation. Measure the node, miner and pool separately at the chosen concurrency. [Workload](Operations-Mining-Acceleration.md)

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
| Pool payout history | Target of 512 records. Reserved and submitted payouts stay until reconciled. |
| Pool reward events / recent blocks | 512 / 128 |

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

Use the status response and current tip together to diagnose stalled production.

| What it shows | What it means |
| --- | --- |
| `connected_miners: 0` | Nothing authenticated. Check the miner's `--pool` host/port and that the pool is listening on the interface the miner reaches — not the node, not the tunnel. |
| `job` is absent | No template has arrived from the node yet. The pool does nothing at all in this state. |
| `job.age_secs` pinned well above the 30 s block target, `blocks.accepted` flat | The pool is still handing out a job the node has already replaced. Look at the node and the path to it (`--node`), not at the miners. |
| `connected_miners > 0`, `shares.accepted` flat | HYN3 SOLO counts full block candidates. Check each miner's current job, scoring rate, target and rejection log. |
| `last_rejection: "stale job"` | A candidate arrived for a job another miner had already turned into a block. Normal in bursts, especially on a devnet ramp where the first blocks are near-instant; a constant stream means miners are racing on a job that should have been replaced. |
| `blocks.submitted > 0`, `blocks.accepted: 0` | The node refused every block. `last_block.detail` carries the node's own reason — read that before touching anything else. |
| `template_refresh_failures` climbing | The node did not serve a template after a block was accepted. The pool retries four times and then waits for the node push; a persistent count is a node problem. |

`shares.accepted` counts candidate submissions this pool accepted. Scan the canonical chain with the wallet to verify a SOLO reward and its confirmations.

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
