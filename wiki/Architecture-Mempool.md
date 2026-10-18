# Mempool Policy

Status: implemented in `hyphen-mempool`. The pool is an admission and ordering
policy, not a validator.

## Trust boundary

Consensus validation happens before a transaction reaches the pool. A caller
constructs `Validated` only after CLSAG, TERA, MD-VRE, balance and range-proof
checks succeed; `ValidatedProtocol` is the equivalent token for a protocol
payload that the canonical state machine accepted at the next height. The pool
uses these tokens to keep the policy boundary explicit, but it cannot re-run the
proof systems itself.

A pool admission is therefore not a consensus endorsement. A block builder must
still validate every selected transaction against the state at the block height.

## Limits

`MempoolConfig::new(entries)` derives a bounded profile:

| Limit | Default |
|---|---|
| Entries (payments + protocol) | `max_entries` |
| Aggregate bytes | `min(max_entries * 8 KiB, 64 MiB)` |
| Protocol entries | 25% of `max_entries`, at least one |
| Protocol bytes | 25% of the byte budget, at least one item |
| Per-item bytes | `MAX_TRANSACTION_SIZE` (2 MiB) |
| Inputs per payment | 1 024 |
| Outputs per payment | 4 096 |
| Replacement bump | 1 000 bps |

A deployment can override these with the `with_*` builders. A node that wants a
relay fee sets `with_minimum_fee(absolute, per_byte)`; the reference node uses
`MIN_RELAY_FEE = 10_000`, `MIN_RELAY_FEE_PER_BYTE = 100` and a 14-day entry TTL.
The bare `Mempool::new` defaults are zero so a devnet can submit zero-fee
transactions. `MempoolConfig::normalized` clamps inconsistent limits (per-item
above aggregate, protocol sub-pool above pool, zero input/output caps) before a
pool is constructed; `validate` reports the same drift when strict checking is
wanted.

## Ordering

Payment priority is the tuple

```text
(fee * 1_000_000 / serialised_bytes, VRE quality, transaction hash)
```

The scaled fee density avoids the truncation that integer division would
introduce for small transactions. VRE quality breaks fee ties in favour of
better ring entropy. The hash makes the order total, so every node chooses the
same eviction victim. Collections are ordered (`BTreeMap`), not hash-seeded.

`get_block_candidates` and `get_block_candidate_blobs` emit payments best-first,
then protocol payloads in hash order. The node applies its canonical transaction
ordering before committing the block.

## Replacement and eviction

A replacement must:

1. displace every payment that shares an input key image,
2. pay at least the displaced total plus the configured bump, and
3. have a fee density no lower than every displaced transaction.

Failure returns `ReplacementFeeTooLow` and leaves the pool untouched.

When the pool is full, admission may evict the lowest-priority payments, but
only if the incoming payment is strictly better than each victim. If it cannot
make room, admission fails with `FeeTooLow` or `Full`. Protocol payloads have
their own entry and byte budget; when the aggregate pool is full they may
displace the worst payment, but they cannot consume the payment fee index.

## Lifecycle

- `insert_at` / `insert_protocol_at` record an arrival timestamp. A node calls
  `prune_expired(now)` periodically; the reference node uses a 14-day TTL.
- `insert` / `insert_protocol` carry no timestamp and never expire. They exist
  for embedders and tests without a clock.
- `purge_confirmed(key_images)` drops every payment that spends an on-chain key
  image, using the key-image index rather than scanning the pool.
- `purge_confirmed_protocol(hashes)` drops protocol payloads included in a block.
- `retain(predicate)` is the revalidation hook after a reorg or a parameter
  change. Protocol payloads have a separate lifecycle and are not passed to the
  payment predicate.
- `retain_protocol(predicate)` applies the same revalidation to WES,
  AetherCompute and WASM payloads.
- `take` returns the removed payment; `remove` and `remove_protocol` discard it.

## `no_std` boundary

The crate is `#![no_std]` with `alloc`. It uses no OS clock, thread, hash-seed or
filesystem API. The default `std` feature only adds the `std::error::Error`
implementation for callers that want it. The transaction dependency currently
uses `std`, so the pool is `no_std + alloc` at the crate boundary, not a claim
that the whole node can link on a hosted-less target.

The PoUW search and verification path in `hyphen-pow::vms` is also `no_std +
alloc`: the prime table is evaluated at compile time and the error type is
implemented manually. `hyphen-pow` keeps its difficulty module behind the `std`
feature because it uses floating-point math, which the node needs and a
consensus-light embedder does not.

## Invariants

- Every payment in `entries` has exactly one `by_priority` entry.
- Every input key image in a payment maps back to that payment's hash.
- `total_bytes` is the sum of payment and protocol payload sizes.
- `total_fees` is the sum of fees of every payment currently in the pool,
  updated on insert, replacement, eviction, purge and clear.
- Removing an entry removes its priority, bytes, and every key image whose map
  value still points at it.
- A failed replacement, eviction plan, or protocol plan performs no mutation.

These invariants are exercised by the unit tests, including multi-victim byte
eviction, protocol eviction, replacement limits, purge indexing, expiry and the
revalidation hook.
