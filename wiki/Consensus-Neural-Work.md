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
score       = mix64-fold(y)                          // deterministic 64-bit score
accept      <=> score < threshold
```

`x` must lie in `[-1, 1]` per component (`ONE = 2^32`). `threshold` is the
header's `difficulty` field. Under an independent uniform-score model, a trial
succeeds with probability `threshold / 2^64` and the mean trial count is
`2^64 / threshold`. Consensus checks only the score of the submitted input.

Three properties are load-bearing and each has a regression test:

1. **The seed determines the weights.** The reference miner generates candidate
   inputs and evaluates each with a forward pass. A lower bound on the cost of
   alternative solvers remains open.
2. **The seed includes the miner key.** Without it, a solution found by one
   miner is valid for every other miner's block at the same height and could be
   copied directly. Changing the miner key requires evaluating the input under
   different weights and signing the resulting block.
3. **The header commits to the solution.** `pow_commitment` is
   `BLAKE3("Hyphen/neural-work-commitment/v1" ‖ p ‖ h ‖ threshold ‖ m ‖ x)`, so
   neither the threshold nor the solution can change after the search.

Each parent defines a new challenge. Reusing an input requires that it also
satisfy the new threshold test.

## 2. Difficulty

Once 17 parent headers are available, each new block takes its threshold from
the latest 16 intervals. Consecutive windows overlap by 15 intervals.

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

The header field is a threshold, so **lower is harder**. The v1 fork-choice rule uses integer division.

```text
weight(block) = floor((2^64 - 1) / threshold)   // post-genesis; genesis contributes 0
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

`HyphenMiner` and `HyphenPool` pin their shared crates to Git revision
`951ea013f0b61115632f463cea22850cd972df83`. `HyphenWallet/rust` uses the same revision. Each repository
builds with its own lockfile. From the base-chain checkout, run
`./scripts/devnet-smoke.ps1 -Network neural-devnet` to compare the first pool
settlement with the node's block hash and the independent wallet's decoded amount.

## 6. What the work is not

The network's output is discarded by the puzzle. This is a hash-gated
computation whose per-attempt cost is a forward pass; per unit of security it is
less energy-efficient than a BLAKE3 threshold. It is not "useful work" in the
scientific sense, and this profile does not claim otherwise. Making the output
useful requires a consumer of the result, which is the AetherCompute settlement
layer, not the block rule.
