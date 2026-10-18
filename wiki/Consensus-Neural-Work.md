# Hyphen Neural Work Consensus Profile

Status: consensus profile `hyphen-neural-devnet-v1`, 2026-10-19. Research
network; not audited, not value-bearing.

This profile replaces the Cunningham-witness block rule with a one-way neural
work challenge. It is a separate chain identity, never an in-place upgrade:
`network_name`, `network_magic`, `consensus_features` and therefore
`consensus_params_hash` and the genesis hash all differ from devnet v2.

## 1. The challenge

For a block at height `h` with parent hash `p` and miner key `m`:

```text
seed        = BLAKE3("Hyphen/neural-work-seed/v1" ‖ p ‖ h ‖ m)
weights     = ChaCha20(seed, epoch = h ^ 2^63)      // hyphen-neural::work
x           = the block's witness list, input_dim Q32.32 values
y           = A_weights(x)                           // one fixed-point forward pass
score       = mix64-fold(y)                          // 64-bit, uniform
accept      <=> score < threshold
```

`x` must lie in `[-1, 1]` per component (`ONE = 2^32`). `threshold` is the
header's `difficulty` field, and the expected number of trials for a block is
`2^64 / threshold`.

Three properties are load-bearing and each has a regression test:

1. **The seed fixes the network, never the answer.** No function derives an
   accepted `x` from public data; the only way to obtain one is to run forward
   passes. This is what the inverse Alice challenge lacks, which is why that
   circuit cannot settle work.
2. **The seed includes the miner key.** Without it, a solution found by one
   miner is valid for every other miner's block at the same height and could be
   copied out of the mempool. The seed binding makes a solution worthless to
   anyone else.
3. **The header commits to the solution.** `pow_commitment` is
   `BLAKE3("Hyphen/neural-work-commitment/v1" ‖ p ‖ h ‖ threshold ‖ m ‖ x)`, so
   neither the threshold nor the solution can change after the search.

There is no single-use set. The seed changes with every parent, so a solution
cannot be replayed into another block.

## 2. Difficulty

`threshold` is retargeted every `WORK_RETARGET_WINDOW = 16` intervals from the
last 17 headers:

```text
expected = 16 × WORK_TARGET_MS          // 480 000 ms
elapsed  = newest.timestamp - oldest.timestamp   // milliseconds
t'       = clamp(t × elapsed / expected, 1, NEURAL_WORK_MAX_THRESHOLD)
```

Header timestamps are **milliseconds** — the same unit as
`GENESIS_TIMESTAMP_MS` and every operator-facing timestamp in the repository.
An early build of this profile compared that millisecond `elapsed` against a
second-denominated `expected`, read every fast window as six times too slow and
walked the threshold up to `u64::MAX`. At `u64::MAX` the test
`score < threshold` accepts almost every candidate, so the devnet mined at
5 blocks per second with no work at all. `WORK_TARGET_MS` and the regression
test `a_window_of_sub_second_blocks_hardens_instead_of_easing` pin the unit.

The ratio `elapsed / expected` is clamped to `1/4 .. 4` before scaling, so one
timestamp outlier cannot swing the chain, and the result is capped at
`NEURAL_WORK_MAX_THRESHOLD = 2^62`. The cap is not cosmetic: it is what keeps
"hard to find" from degenerating into "free" when hashrate collapses or a
retarget loop misbehaves. `NeuralWorkParams::validate` rejects any profile whose
ceiling exceeds it.

Until a full window exists the profile's `neural_work_initial_threshold`
(default `2^56`) applies. Both thresholds live in `ChainConfig` and are hashed
into `consensus_params_hash` whenever `FEATURE_NEURAL_WORK` is set, so changing
either one mints a new chain identity instead of silently redefining an existing
chain.

Timestamps MUST exceed the median of the last 11 parent headers
(`WORK_MEDIAN_WINDOW`). This is the deterministic half of the timestamp rule; the
"not too far in the future" half compares against the node's NTP-adjusted clock
and is applied by the node before consensus validation.

## 3. Fork choice

The header field is a threshold, so **lower is harder**. Fork-choice weight is
the expected attempt count:

```text
weight(block) = 2^64 / threshold        (u128, floored; 0 for genesis)
cumulative    = Σ weight
```

Summing the raw field, as witness-count profiles do, would rank the easiest
branch as the heaviest and invert the choice. `Blockchain::block_weight` and
`AtomicBlockUpdate::block_weight` carry the rule; the state layer never derives
it from the header.

## 4. Activation state

The node validates the profile end to end: genesis, `next_difficulty`, block
acceptance, reorg weight and the API surface all branch on
`FEATURE_NEURAL_WORK`. A local run of the three components mines this profile:

```text
hyphen-node  --network neural-devnet --rpc-bind 127.0.0.1:49333 \
             --template-bind 127.0.0.1:4350 --explorer-bind 127.0.0.1:9080
hyphen-pool-server --network neural-devnet --node 127.0.0.1:4350 \
             --bind 127.0.0.1:4340 --api-bind 127.0.0.1:9181 --payout-mode solo
hyphen-miner --network neural-devnet --pool 127.0.0.1:4340 --wallet-address hy1...
```

Two protocol properties differ from the witness profile and are enforced by the
clients:

- **No credit shares.** Partial neural work is not verifiable, so the pool sets
  the job's share difficulty to the block threshold and every accepted
  submission is a complete block. PPLNS-style accounting does not apply to this
  profile; use `--payout-mode solo`.
- **One solution per job.** A miner races its own workers; the first solution
  claims the job and the rest stop, because a second solution reaches the pool
  after the template has moved on.

`HyphenWallet` pins all four identities, including
`hyphen-neural-devnet-v1`, so it can read this chain; it also refuses any node
whose `network`, magic, `consensus_params_hash`, genesis hash, block version or
PoUW protocol version does not match a pinned vector.

Current pinned values for this profile:

```text
network              = hyphen-neural-devnet-v1
network_magic        = 48594e4e                     ("HYNN")
consensus_params_hash= 451ca637dafb07604b8dcabebc86c54d72efe590ac5912bb2a2f35ea6d41b6a9
genesis_hash         = 6d3c028ecd7380ba143a62c8b82fa706155da56fb42ec8cf8b30ec4dc989d058
```

Because the retarget parameters are hashed, this identity changed when the
millisecond fix and the threshold ceiling landed. Every chain mined before that
change is a different chain and must be discarded, not migrated.

## 5. Publishing the client changes

`HyphenMiner` and `HyphenPool` consume `hyphen-core`, `hyphen-crypto`,
`hyphen-pow`, `hyphen-neural` and `hyphen-transport` from a pinned public
revision. While the profile is in development they are wired to the local
checkout with path dependencies. Publishing a release requires bumping that
revision to the commit that contains this module, regenerating both lockfiles,
and re-running their CI.

## 6. What the work is not

The network's output is discarded by the puzzle. This is a hash-gated
computation whose per-attempt cost is a forward pass; per unit of security it is
less energy-efficient than a BLAKE3 threshold. It is not "useful work" in the
scientific sense, and this profile does not claim otherwise. Making the output
useful requires a consumer of the result, which is the AetherCompute settlement
layer, not the block rule.
