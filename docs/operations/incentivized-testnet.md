# Incentivized Testnet Readiness and Monitoring

Status: proposed operations gate. The current node is suitable for local
devnet experiments, but not yet for an incentivized public testnet because it
lacks competing-branch fork choice and reorg rollback.

## Entry blockers

Do not attach monetary value or public rewards until the following are
implemented and tested:

- cumulative-work fork choice, competing-branch storage, atomic rollback, and
  forward application for blocks, commitments, nullifiers, mempool, wallet,
  explorer, and pool settlement;
- authenticated and rate-limited public RPC/pool edges;
- automatic pool payout lifecycle or a testnet-only statement that balances
  have no monetary value;
- reproducible builds and signed release artifacts;
- independent consensus, cryptography, wallet, and network review; and
- incident response, vulnerability disclosure, and operator runbooks.

## Phased rollout

| Phase | Scope | Exit evidence |
| --- | --- | --- |
| Local devnet | One host, deterministic identity, smoke/replay/fault tests | Repeatable clean start, mining, export, verify, and replay |
| Private multi-node | At least 5 nodes under 3 independent operators | Partition/reconnect and deep-reorg drills with identical final state |
| Public no-value testnet | Permissionless peers, faucets only | 30 continuous days, published dashboards and incident log |
| Small incentive pilot | Capped rewards and explicit loss limits | 60 continuous days with all thresholds below and no unresolved critical issue |

Durations are minimum observation windows, not proof of security.

## Required metrics

Every release must label metrics by binary version, chain identity, operator,
and region without collecting wallet seeds, IP histories longer than needed, or
transaction metadata beyond the published privacy policy.

| Area | Measurements | Initial alert |
| --- | --- | --- |
| Reorgs | count, depth, replaced work, convergence time | any depth >= 3; any node divergence > 2 target blocks |
| Orphans | blocks mined, accepted, orphaned by miner/pool | 1-hour rate > 5% or 24-hour rate > 2% |
| P2P | peers, churn, dial failures, gossip rejects, duplicate/malformed frames | peer count < 4 for 10 minutes; reject spike 5x baseline |
| PoW | solve-time distribution, reported/observed work, hardware class | median block interval outside 0.7x-1.3x target for 6 hours |
| Concentration | blocks and accepted work by pool/miner/operator | one pool > 35% for 24 hours; top 3 > 70% |
| Sync | initial sync time, CPU, peak RSS, disk growth, bandwidth | regression > 25% release-over-release |
| Pool ledger | accepted/rejected shares, receipt gaps, pending payouts, recovery source | any receipt-chain gap or unexplained balance delta |
| Wallet | scan lag, failed sends, restore/rescan time, mobile crashes | restore mismatch; crash-free sessions < 99.5% |

Thresholds are starting operational limits and should be changed only from
published measurements, never silently.

## Mandatory drills

Run and retain reports for:

1. Network split with unequal work, reconnection, fork choice, and state-root
   convergence.
2. Timestamp reversal/future-time and oscillating-hashrate simulations.
3. Malformed transaction, RPC, P2P, pool, and TP corpora plus bounded fuzzing.
4. Pool primary-ledger truncation, backup recovery, reordered/missing receipts,
   delayed payout, and duplicate settlement injection.
5. Wallet restore from seed on a clean device followed by full rescan and
   balance/history comparison against the original wallet.
6. Node database snapshot restore, archive verification, and full replay into
   a fresh directory.
7. Mobile background/foreground, process kill, storage pressure, network
   switching, and interrupted-send scenarios on supported OS versions.

## Release decision

A pilot release is blocked by any unresolved critical/high finding, consensus
divergence, unexplained supply/accounting mismatch, failed wallet recovery, or
missing raw monitoring data. Parameter changes require a written hypothesis,
before/after dashboards, a new chain identity when consensus-critical, and a
rollback plan.

