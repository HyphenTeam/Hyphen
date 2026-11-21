# Neural proof of work · 神经工作量证明

`neural-devnet` selects `hyphen-neural-devnet-v3`, magic `HYN3`. Private transfers, conditional offline settlement, Wasm calls and compute settlement use this genesis. A post-genesis block carries one 64-bit nonce. The validator reconstructs its neural output and applies two exclusive digest thresholds. [Chain identity](../test-vectors/chain-identity-neural-v3.json) · [Validation order](../crates/hyphen-consensus/src/neural_work.rs)

## Challenge and integer evaluation

1. Hash the ASCII tag `Hyphen/neural-work-seed/v1`, the 32-byte parent hash, the little-endian child height and the miner's 32-byte public key, in that order, with BLAKE3. This seed fixes one network per parent, height and miner. The same miner can amortize its weight setup across all nonces for that challenge. [Seed transcript](../crates/hyphen-core/src/work.rs)
2. Set `Q = 2^32`. Expand the seed with ChaCha20, counter zero, nonce `LE32(1) || LE64(height XOR 2^63)`. Read 2,112 little-endian 32-bit words. For each word `u`, sample `floor(u × 2a / Q) − a`. The first 1,088 use `a = Q/4` for 1,024 first-layer weights and 64 biases. The remaining 1,024 use `a = Q/8` for the second layer. Its 16 biases are zero. Both matrices are row-major. [Weight generation](../crates/hyphen-neural/src/challenge.rs) · [Stream encoding](../crates/hyphen-neural/src/rng.rs)
3. Interpret the seed as eight little-endian 32-bit words. For component `i` from 0 through 15, mix `word[i mod 8] XOR 0x48595048454e5731 XOR (nonce × 0x9e3779b9 mod 2^64) XOR i` with the SplitMix64 finalizer. Convert its high word `u` to the signed raw input `2u − Q`. This confines each input to `[−Q, Q−2]`. [Candidate and mixer](../crates/hyphen-neural/src/work.rs)
4. Evaluate 16 → 64 → 16. Each product uses `floor(weight × input / Q)` computed with a signed wide intermediate. For an accumulator `s`, the activation returns `sign(s) × Q` when `abs(s) ≥ 3Q`. Otherwise set `r = floor(s²/Q)` and truncate `s × (27Q+r)/(27Q+9r)` toward zero. The first accumulator has magnitude at most `17Q/4` and the second at most `8Q` for profile inputs. These bounds follow by summing the maximum absolute term in each row, including the bias. For the rational segment, `27Q(Q−a) + (9Q−a)floor(a²/Q)` with `a=abs(s)` differs from `(3Q−a)³/Q` by less than `9Q`. Rounding can affect the last raw unit near the clamp. The implementation's exact operation order is normative. [Integer arithmetic](../crates/hyphen-neural/src/fixed.rs) · [Row evaluation](../crates/hyphen-neural/src/mlp.rs)
5. Start with `0x9e3779b97f4a7c15`. For each of the 16 outputs, XOR its two's-complement bit pattern into the accumulator and apply the same mixer. Apply the mixer once more to obtain `score`. The CUDA path computes this scalar per nonce. [Independent evaluator](../scripts/check-neural-work.py)

## BLAKE3 gates

`H` means a 32-byte BLAKE3 digest. `K(key, data)` means keyed BLAKE3 with a public 32-byte key. `low` interprets the first eight digest bytes as a little-endian unsigned integer. A `\0` in the following transcripts denotes one zero byte. The fixed-width integer encoding is little-endian. [Reference evaluator](../crates/hyphen-neural/src/block_work.rs)

```text
gate = H("Hyphen/neural-gate/v3\0" || seed || LE64(nonce) || LE64(score))
require low(gate) < 2^60
s = K(gate, "Hyphen/neural-memory/v3\0")
repeat 32768 times in ascending cell order:
    cell[i] = s
    s = K(gate, s)
repeat 32768 times:
    index = low(s) mod 32768
    s = K(gate, s || cell[index])
final = H("Hyphen/neural-final/v3\0" || gate || s)
require low(final) < T
```

The header commitment hashes `Hyphen/neural-work-commitment/v1 || parent || LE64(height) || LE64(T) || miner_key || LE64(nonce)`. The node checks timestamp, required threshold, witness count and commitment before evaluating the nonce. The pool recomputes the score and both gates. HYN3 accepts a full block candidate as a SOLO share. [Commitment](../crates/hyphen-core/src/work.rs) · [Block authorization](HYN3-Identity-and-Recovery.md)

## Retarget and branch weight

`cargo run --release --locked -p hyphen-consensus --example hyn3_work_audit -- ARCHIVE` checks the frozen vector, seven memory checkpoint strategies and every archived block's PoW with a separate Rust implementation. Pass multiple archive paths to compare several branches. [Protocol audit and timings](HYN3-Algorithm-Audit.md)

To independently recompute the block headers and work from a selected tip back to the HYN3 genesis, run `python scripts/check-neural-work.py --explorer http://127.0.0.1:PORT --tip BLOCK_HASH` with `blake3` and `pycryptodome` installed. Both canonical and previously validated detached blocks expose `neural_work_nonce` as decimal text. The checker reconstructs the serialized header, parent links, expected thresholds, both BLAKE3 predicates, witness commitment and accumulated post-genesis weight. Full-node replay additionally verifies signatures, timestamps, transactions and committed state. [Python checker](../scripts/check-neural-work.py)

Heights 1 through 17 use `T = 2^60`. From height 18 use 16 complete mined intervals ending at the parent. Set `S = 2^96` and `W = Σ floor(S/T_i)` with the threshold of each ending block. Let `d` be the elapsed milliseconds between window endpoints, clamped to `[1, 1920000]` after saturating subtraction. Compute `floor(S × d / (30000 × W))`. Clamp to `[ceil(T_parent/4), min(4 × T_parent, 2^62)]`. At constant threshold and 30-second spacing this estimates the parent threshold up to integer rounding. The lower bound is positive for all valid parents. `W ≤ 2^100`, `30000 W < 2^115` and `S d < 2^117`, so both products fit `u128`. [Integer retarget](../crates/hyphen-consensus/src/neural_work.rs)

Each accepted child contributes `floor((2^64−1)/T)` to cumulative weight. At the initial threshold the contribution is 15. Reorganization requires strictly greater cumulative weight and validation of the attached branch. A tie preserves the existing tip. Each candidate also advances beyond the median of up to 11 parent timestamps and passes the node's future-time and state-transition checks. [Fork choice](../crates/hyphen-consensus/src/chain.rs)

## Recent siblings and fork rewards

The HYN3 explorer marks a previously validated detached block as a *recent sibling* when it shares a parent and positive height `h` with the canonical block, their work commitments differ, and `0 ≤ tip_height − h < 16`. The window uses the HYN3 retarget interval count. Each label compares one block with the canonical block at its height. The graph draws every retained block under its full hash, including multiple headers carrying the same work. Reorganizations and advancing the tip can change the label. [Explorer rule and boundary test](../crates/hyphen-explorer/src/lib.rs)

HYN3 selects a strictly heavier validated branch and credits the canonical reward once. A block carrying any uncle header is rejected. The explorer label contributes zero extra weight and zero payout. Historical Ethereum Ethash permitted up to two included ommers per block, excluded ancestors and previously included ommers, verified their headers, and credited the ommer miner `(8 − depth)/8` of the block subsidy and the including miner `1/32` per ommer. [HYN3 parameters](../crates/hyphen-core/src/config.rs) · [Historical Ethash validation and rewards](https://github.com/ethereum/go-ethereum/blob/v1.10.26/consensus/ethash/consensus.go)

HYN3 work binds the parent, height, miner, threshold and nonce in the commitment. Miner authorization separately binds the completed header and payout keys. Multiple signed headers can reuse a witness. Paying per displayed sibling would make issuance depend on a node's local branch inventory. A payable inclusion rule needs consensus-committed evidence of distinct work, branch-relative duplicate accounting, deterministic rollback and a versioned activation. [Work commitment](../crates/hyphen-core/src/work.rs) · [Block authorization](../crates/hyphen-core/src/authorization.rs)

## Probability, memory and specialized hardware

对高度 1、nonce `125` 的固定向量，参考实现保存 1,048,576 字节的单元摘要，内存阶段及最终摘要共调用 BLAKE3 65,538 次。每 16 个单元保留一个检查点时，保存量为 65,536 字节，调用数增至 308,540。两种计算的 32 字节最终摘要相同。这个构造给出一种可复核的时间与空间折中，尚未给出所有电路的面积、延迟或能耗下界。GPU 验证对照的是 Rust 与 CUDA 的整数结果，当前 CPU 和 CUDA 路径都在主机执行内存阶段。[固定向量](../test-vectors/neural-block-work-v3.json) · [挖矿实测](Operations-Mining-Acceleration.md)

Under independent uniform low words, the first gate passes with probability `1/16` and the conditional final probability is `T/2^64`. The success rate per distinct trial is `T/2^68`. The geometric model at the initial threshold gives 256 neural evaluations and 16 scratchpad evaluations per accepted nonce on average. A valid-block verifier needs one of each plus weight setup. These estimates assume distinct hash inputs and do not establish an optimal mining strategy. [Fixed input windows](../crates/hyphen-consensus/examples/work_cost.rs)

The reference scratchpad contains exactly 1,048,576 digest bytes per finalist. It makes 32,768 sequential fill updates and 32,768 state-dependent reads and updates. A checkable time–space tradeoff is to keep every `k`th fill digest and regenerate a requested cell from its nearest earlier checkpoint. This needs `ceil(32768/k)` saved digests and at most `k−1` extra keyed hashes per lookup. Under uniformly distributed indices and `k` dividing 32,768, the expected extra cost is `(k−1)/2` hashes per lookup. This explicit alternative also rules out a claim that every valid implementation must allocate 1 MiB. Parallel nonces, fixed-point pipelines, on-chip SRAM and custom hash units remain available to hardware designers.

To compare hardware, replay the same ranges with independently verified results, report attempts and finalists per second, and measure whole-system joules, memory, temperature, silicon or device cost and host transfers. For a device with sustained trial rate `r`, modeled block revenue per second is `r × T/2^68 × reward_value`, before stale work, power, depreciation, fees and retargeting. Development-network rewards have no market value. The available CPU and CUDA runs do not determine FPGA/ASIC cost per trial, RandomX-equivalent resistance or long-run profitability. [Measurements](Operations-Verification.md) · [Mining procedure](Operations-Mining-Acceleration.md)

## 固定向量

创世哈希以 `710ad7eb` 开头。高度 1、矿工公钥为 32 个 `0x13` 字节时，从零递增的首个有效 nonce 为 `125`，定点神经评分为 `4366503893791739251`，最终内存评分为 `664485265619752970`。原始神经评分参与第一道摘要的计算。节点对两道摘要均采用严格小于判定。Python 参考程序独立实现整数运算并复核两份完整摘要和工作承诺。安装 `blake3` 与 `pycryptodome` 后可运行 `python scripts/check-neural-work.py`。首个门槛预期筛出十六分之一，专用芯片相对通用硬件的面积、能耗和成本优势仍需同负载测量。[向量](../test-vectors/neural-block-work-v3.json) · [三维坐标与迁移](HYN3-Identity-and-Recovery.md)
