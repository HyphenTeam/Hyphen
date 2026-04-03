# Hyphen

A privacy-focused, CPU-first Proof-of-Work blockchain built in Rust.

Hyphen combines a memory-hard multi-kernel PoW with epoch-mutated constants (EMK), full privacy primitives (CLSAG ring signatures, Bulletproofs range proofs, stealth addresses, multi-dimensional VRE), post-quantum hybrid signatures, NTP-synchronized millisecond timestamps, GHOST-style uncle blocks, MDAD-SPR multi-phase difficulty adjustment with anti-51% dampening, Temporal Epoch-Referenced Anchoring (TERA) for replay resistance, Mining Stability Equalizer (MSE) for revenue smoothing, Gradual Trust Mining (GTM) for Sybil-resistant pool onboarding, and consensus-enforced coinbase validation into a single production-grade blockchain.

## Architecture

Hyphen is organized as a Cargo workspace for the core chain stack plus 2 standalone mining-side applications:

| Crate | Purpose |
| --- | --- |
| `hyphen-crypto` | Blake3 hashing, Ed25519 keys, Pedersen commitments, stealth addresses, Merkle tree, CLSAG ring signatures, WOTS+ post-quantum signatures |
| `hyphen-core` | Block / BlockHeader types, chain configuration, NTP timestamp synchronization, error types |
| `hyphen-pow` | **HyphenPoW** CPU-first PoW — epoch arena, scratchpad, 12 transformation kernels, MDAD-SPR multi-phase difficulty adjustment with anti-51% dampening |
| `hyphen-proof` | Bulletproofs range proofs (64-bit, aggregated up to 16) and inner-product argument, batch verification |
| `hyphen-tx` | Shielded UTXO model — notes, transactions, nullifiers, transaction builder |
| `hyphen-token` | Multi-asset issuance with fixed and mintable policies |
| `hyphen-economics` | Lorentzian Continuous Decay (LCD) emission with tail emission, fee calculation with partial burn |
| `hyphen-state` | sled-backed persistent storage — block store, chain state, nullifier set, commitment tree |
| `hyphen-consensus` | Block/transaction/uncle validation, chain management, genesis block |
| `hyphen-mempool` | Fee-density-priority transaction pool with BTC-style fee market — transactions ordered by fee-per-byte (negative fee density for max-heap extraction), key-image conflict detection preventing double-spend, and bounded pool size with automatic eviction of lowest-fee transactions |
| `hyphen-wallet` | Wallet with ICD key derivation, subaddresses, stealth address scanning |
| `hyphen-network` | libp2p P2P stack — Gossipsub broadcast, Kademlia discovery, Request-Response sync |
| `hyphen-transport` | Template Provider protocol — signed envelope framing, protobuf message types, and `TemplateProvider` trait for node-pool communication |
| `hyphen-vm` | Smart contract VM with gas metering |
| `hyphen-rpc` | Length-prefixed protobuf RPC — chain info, block queries, transaction submission, output index lookups (GET_RANDOM_OUTPUTS for decoy selection, GET_OUTPUT_INFO for pre-flight output verification) |
| `hyphen-node` | Full-node binary with Template Provider server and integrated block explorer; it is the default runtime host for the explorer |
| `hyphen-explorer` | Explorer library crate that provides the HTTP UI/API router consumed by `hyphen-node` |
| `hyphen-pool` | Standalone mining pool server with its own Cargo manifest, crates.io dependency graph, and local compatibility implementation for Hyphen's pool-side protocol, crypto envelope signing, and PoW verification |
| `hyphen-miner` | Standalone CPU miner with its own Cargo manifest, crates.io dependency graph, and local compatibility implementation for Hyphen's miner-side protocol, crypto envelope signing, and PoW evaluation |
| `hyphen-miner-gpu` | Standalone multi-vendor GPU miner via wgpu — supports NVIDIA (Vulkan/DX12), AMD (Vulkan/DX12), Intel (Vulkan/DX12), Apple (Metal), Qualcomm Adreno (Vulkan/GLES), ARM Mali (Vulkan/GLES), and Moore Threads (Vulkan); hybrid CPU/GPU architecture with GPU solver loop and CPU Blake3 finalization; WGSL shader uses `diff_target` field name to avoid reserved-keyword conflicts |
| `hyphen_wallet` | Cross-platform Flutter/Dart wallet app with Rust backend via flutter_rust_bridge — BIP39/44 mnemonic key management, ICD key derivation, WOTS+ post-quantum signatures, stealth address scanning, CLSAG ring-signature transaction building with Bulletproofs range proofs and decoy selection via RPC, multi-wallet management, NFC contactless address sharing, biometric authentication (fingerprint/Face ID), customizable theme colors (6 presets), real-time balance polling, 7-language i18n (EN/ZH/DE/FR/ES/IT/JA) |

## Innovation and Mathematical Foundations

### 1. HyphenPoW — 12-Kernel Memory-Hard Proof-of-Work

HyphenPoW is a novel CPU-first PoW combining a 2 GiB epoch arena, an 8 MiB scratchpad, and **12 dynamically selected compute kernels** per round. No existing PoW algorithm uses runtime kernel selection from a heterogeneous kernel set.

**Algorithm.** For each nonce, the solver runs 1024 rounds. Each round:

1. Reads a page from the epoch arena at a data-dependent address
2. Selects a kernel via $k = (\mathtt{state}[16] \oplus \mathtt{page}[32]) \bmod 12$
3. Executes kernel $k$ on the page data
4. Mixes the kernel output into the state via XOR
5. Follows inter-page links to the next page (data-dependent DAG traversal)
6. Every `writeback_interval` rounds, writes state back into the scratchpad (write-after-read dependency chain)

**12 Heterogeneous Kernels.** Each kernel targets a different CPU execution unit:

| Kernel | Name | Exploit |
| --- | --- | --- |
| K0 | DivChain | 64-iteration integer division chain — penalizes GPU/ASIC without hardware dividers |
| K1 | BitWeave | Rotate/XOR with golden-ratio constant $\phi_{64} = \mathtt{0x9E3779B97F4A7C15}$ |
| K2 | SparseStep | Simulated sparse matrix-vector multiply with indirect reads |
| K3 | PrefixScan | Full Blelloch parallel prefix-sum (up-sweep + down-sweep) on 64 elements |
| K4 | MicroSort | Insertion sort on 32 elements — branch-prediction-heavy |
| K5 | VarDecode | LEB128 variable-length decoding with serial byte-cursor |
| K6 | HashMix | AES S-Box substitution + MixColumns-style GF($2^8$) diffusion |
| K7 | BranchMaze | 8-way data-dependent branching with cursor jumps |
| K8 | AESCascade | Full AES SubBytes→ShiftRows→XOR→MixColumns, 24 rounds, serial across 64 bytes (exploits AES-NI) |
| K9 | FloatEmulate | Fixed-point 32.32 multiply + Newton-Raphson reciprocal |
| K10 | ScatterGather | 2 KiB L1 scratchpad with data-dependent read/write patterns |
| K11 | ModExpChain | 128-bit modular exponentiation (u128 mul+mod) with serial dependency |

**ASIC Resistance Theorem.** Let $\mathcal{K} = \{K_0, \ldots, K_{11}\}$ be the kernel set. For a given nonce, the sequence of kernel invocations $\sigma = (\sigma_1, \ldots, \sigma_{1024})$ where $\sigma_i \in \mathcal{K}$ depends on runtime state. An ASIC optimized for a strict subset $\mathcal{K}' \subset \mathcal{K}$ must emulate the remaining kernels at higher cost. Let $p = |\mathcal{K}'|/|\mathcal{K}|$ be the fraction of kernels with native hardware and $\alpha = T_{\text{emulate}} / T_{\text{native}}$ the cost ratio for emulated kernels. The expected per-hash slowdown is:

$$S = p + (1 - p) \cdot \alpha$$

For $p = 1/6$ (2 of 12 kernels in hardware) and $\alpha = 5$: $S = 1/6 + 5/6 \cdot 5 = 26/6 \approx 4.33\times$. For $p = 1/2$ and $\alpha = 3$: $S = 1/2 + 1/2 \cdot 3 = 2.0\times$. Since the kernels span integer division, AES pipelines, branch prediction, floating-point, and cache hierarchy, no single ASIC architecture can bring $p$ close to 1 without replicating a general-purpose CPU.

**Comparison with existing PoW:**

| | CryptoNight | RandomX | Ethash | HyphenPoW |
|---|---|---|---|---|
| Memory | 2 MiB | 256 MiB | 4+ GiB DAG | 2 GiB arena + 8 MiB scratchpad |
| Instruction diversity | Fixed AES+MUL | Random program/block | Light hash chain | 12 kernels, selected per round |
| Data-dependent branching | No | Limited | No | Yes (BranchMaze, ScatterGather) |
| Epoch-mutated constants | No | Yes (random program) | No | Yes (EMK: S-Box, rotations, multiplicands, permutation, strides) |

### 1a. Epoch Mutation Kernels (EMK)

HyphenPoW kernel constants are not static — they are **re-derived every epoch** from the epoch seed via Blake3 XOF. This renders pre-computed lookup tables and fixed-function ASIC pipelines obsolete at each epoch boundary.

**Derivation.** `EpochKernelParams::derive(epoch_seed)` uses Blake3 in keyed mode with domain `"EMK_epoch_kernel_params_v1"` to generate a deterministic XOF stream that produces:

| Component | Size | Algorithm |
| --- | --- | --- |
| `sbox` | `[u8; 256]` | Fisher-Yates shuffle of the AES S-Box using u16 values from the XOF |
| `rot_offsets` | `[u32; 12]` | Per-kernel rotation offset masked to `[0, 63]` |
| `mix_constants` | `[u64; 12]` | Per-kernel odd multiplicand (`raw \| 1` preserves invertibility) |
| `slot_perm` | `[usize; 8]` | Knuth shuffle of `[0..8]` for cross-lane mixing |
| `stride_salt` | `[u64; 12]` | Per-kernel stride mutator in `[31, 251]` via `31 + (raw % 221)` |

**ASIC amplification.** An ASIC that hard-wires a single epoch's S-Box or multiplicand table faces $S_{\text{total}} = S_{\text{kernel}} \cdot E$ where $E \geq 2$ reflects the cost of reconfiguring hard-wired constants at epoch boundaries.

### 2. Iterative Commitment Derivation (ICD) — Novel Key Derivation

ICD is a novel key derivation scheme that uses Pedersen commitments on the Ristretto255 curve instead of HMAC-based chain codes (BIP32) or HKDF.

**Construction.** Given a parent scalar $s_p$ and a purpose string $\pi$:

$$P_{\text{chain}} = s_p \cdot G + H_s(\pi) \cdot T$$
$$s_{\text{child}} = H_s(\text{compress}(P_{\text{chain}}))$$

where $T = H_p(\texttt{"Hyphen\_ICD\_twist\_generator\_v1"})$ is a nothing-up-my-sleeve twist generator with unknown discrete logarithm relative to $G$, $H_s$ is a domain-separated blake3 hash-to-scalar, and $H_p$ is hash-to-point.

**Security Claim.** Under the Decisional Diffie-Hellman (DDH) assumption on Ristretto255:

*Given $(G, T, s_c \cdot G)$ where $s_c$ is a child key, no PPT adversary can distinguish whether $s_c$ was derived from $s_p$ via ICD or sampled uniformly at random.*

**Proof sketch.** The chain point $P_{\text{chain}} = s_p \cdot G + H_s(\pi) \cdot T$ is a Pedersen commitment to $s_p$ with blinding factor $H_s(\pi)$. By the hiding property of Pedersen commitments (which follows from DDH on the group), $P_{\text{chain}}$ reveals nothing about $s_p$. The child key $s_c = H_s(\text{compress}(P_{\text{chain}}))$ is then a hash of this commitment. Since blake3 is modeled as a random oracle, $s_c$ is pseudorandom given $P_{\text{chain}}$, which is itself pseudorandom given $(G, T)$ and the DDH assumption.

**Subaddress derivation.** Extend ICD with account index $a$ and subaddress index $i$:

$$P_{\text{sub}} = s_p \cdot G + H_s(a \| i) \cdot T$$
$$s_{\text{sub}} = H_s(\text{compress}(P_{\text{sub}}))$$

This generates unlimited unlinkable subaddresses from a single master key.

### 3. Anti-51% Difficulty Dampening (integrated into MDAD-SPR)

Beyond the standard LWMA difficulty adjustment, Hyphen includes a secondary check that prevents a high-hashrate attacker from rapidly reducing difficulty.

**Detection.** Let $\{t_i\}_{i=1}^{N}$ be the timestamps of the last $N$ blocks. Define the observed span $\Delta = t_N - t_1$ and the expected span $E = (N-1) \cdot T_{\text{target}}$ where $T_{\text{target}}$ is the target block time.

If $\Delta < E / 4$ (blocks arriving at < 25% of expected pace), the dampening mechanism activates and forces difficulty upward by the clamp multiplier:

$$D_{\text{next}} = D_{\text{prev}} \cdot C_{\text{up}}$$

where $C_{\text{up}} = 3$ (configurable).

**Rationale.** A 51% attacker who temporarily controls > 50% hashrate will produce blocks faster than expected. Without dampening, the attacker could:
1. Mine rapidly, allow difficulty to drop
2. Release hashrate, leaving honest miners with artificially low difficulty
3. Re-attack at lower cost

The dampening ensures difficulty cannot drop during periods of anomalously fast block production.

### 4. GHOST-Style Uncle Blocks with Privacy

Hyphen combines Ethereum-style uncle (ommer) block inclusion with a full privacy-coin architecture. No existing privacy coin supports uncle blocks.

**Uncle reward** for an uncle at depth $d$ from the including block:

$$R_{\text{uncle}}(d) = R_{\text{base}} \cdot \frac{(\text{max\_depth} + 1 - d) \cdot n_u}{\text{max\_depth} \cdot d_u}$$

where $n_u / d_u = 7/8$ are configurable.

**Nephew reward** for the block that includes $u$ uncles:

$$R_{\text{nephew}}(u) = R_{\text{base}} \cdot \frac{n_n \cdot u}{d_n}$$

where $n_n / d_n = 1/32$ are configurable.

**Parameters:** max 2 uncles per block, max uncle depth 7.

### 5. NTP-Synchronized Consensus Time

All timestamps in Hyphen are millisecond-precision UTC obtained from NTP servers, not the local system clock.

**Protocol:**
1. Query 11 NTP servers (Google, Cloudflare, Apple, NIST, Tencent, Aliyun, etc.)
2. Require a quorum of $\geq 3$ responses
3. Compute the median offset
4. Reject outliers $> 2$ seconds from the median
5. Average the filtered set to obtain the correction offset
6. Apply offset to all `ntp_adjusted_timestamp_ms()` calls

**Adaptive polling:** 30s interval when clock is trusted, 5s when untrusted, 10s default.

**Consensus integration:** Blocks with timestamps more than `timestamp_future_limit_ms` (120s mainnet, 60s testnet) ahead of the node's NTP-adjusted clock are rejected.

### 6. MDAD-SPR — Multi-Dimensional Adaptive Difficulty with Statistical Phase Recognition

Hyphen replaces the standard LWMA difficulty adjustment with **MDAD-SPR**, a novel multi-phase algorithm that detects and responds to distinct network regimes (stable mining, flash crash, sustained attack, recovery).

**Phase Detection.** Let $\{t_i, D_i\}_{i=1}^{N}$ be the recent block timestamps and difficulties. Define:

- **Solve-time ratio:** $r = \text{median}(\Delta t) / T_{\text{target}}$
- **Coefficient of variation:** $\text{cv} = \sigma(\Delta t) / \mu(\Delta t)$
- **Hashrate gradient:** $g = (H_{\text{recent}} - H_{\text{old}}) / H_{\text{old}}$

The algorithm classifies the current network phase based on these three metrics:

| Phase | Detection Condition | Response |
| --- | --- | --- |
| Stable | $r \in [0.8, 1.2]$ and $\text{cv} < 0.5$ | Standard LWMA with dampening |
| FlashCrash | $r > 2.0$ or $g < -0.3$ | Aggressive downward correction with emergency floor |
| SustainedAttack | $r < 0.5$ and $\text{cv} < 0.3$ | Upward ramp with anti-51% clamp |
| Recovery | Transitioning between phases | Blended EMA with momentum tracking |

**Anti-oscillation.** After a phase transition, MDAD-SPR applies exponential smoothing with a configurable inertia factor $\alpha$, preventing the difficulty from ping-ponging between regimes.

**Anti-manipulation.** Timestamp outliers beyond $3\sigma$ from the window median are clamped before the difficulty calculation, preventing timestamp injection attacks.

**Formal guarantee.** Under MDAD-SPR, the expected block time converges to $T_{\text{target}}$ within $O(N)$ blocks after any hashrate perturbation, with bounded overshoot:

$$|D_{\text{next}} / D_{\text{ideal}} - 1| \leq C_{\text{clamp}}^{-1}$$

where $C_{\text{clamp}} = 3$ and $D_{\text{ideal}}$ is the difficulty that would produce exactly $T_{\text{target}}$ at the current hashrate.

### 7. Post-Quantum Hybrid Signatures

Hyphen ships with dual-signature post-quantum readiness at the protocol level.

**WOTS+ parameters:** $w = 16$, 67 chains (64 message + 3 checksum), blake3-based chain function:

$$C_i^{(j)} = H(\texttt{"Hyphen\_WOTS\_chain"} \| \text{addr\_seed} \| i \| j \| C_i^{(j-1)})$$

**Hybrid signature:** A `HybridSignature` contains both an Ed25519 signature and a WOTS+ signature. Verification requires **both** to pass. Even if Curve25519 is broken by quantum computers, the WOTS+ signature (hash-based, quantum-resistant) remains secure.

**Signature size:** $67 \times 32 + 32 = 2{,}176$ bytes (WOTS+) + 64 bytes (Ed25519) = **2,240 bytes** total.

### 8. Unified Blake3 Cryptographic Stack

Every cryptographic hash operation in Hyphen uses blake3 with domain separation:

- `blake3_hash` — standard 256-bit digest
- `blake3_keyed` — keyed hash (MAC)
- `hash_to_scalar` — blake3 XOF → 512-bit → reduce mod $\ell$
- `hash_to_point` — blake3 XOF → 512-bit → `RistrettoPoint::from_uniform_bytes`

All domain separations use `b"Hyphen_..."` prefixes. No SHA-256 or Keccak anywhere in the codebase. Blake3 provides ~6x faster hashing than SHA-256/Keccak on modern CPUs with native XOF mode.

### 9. Quantum-Resistant BIP39 Passphrase Transform

Hyphen hardens the BIP39 mnemonic-to-seed derivation with a post-quantum password transform. Instead of using the raw user password as the BIP39 passphrase, the password is first passed through WOTS+ hash chains:

1. Derive a WOTS+ secret key from the password via domain-separated BLAKE3: $\text{seed} = H(\texttt{"Hyphen\_PQ\_seed"} \| \text{password})$
2. Compute the full WOTS+ public key (67 chains, $w = 16$, 15 hash steps each = 1,005 blake3 invocations)
3. Hash the concatenated public key to produce the hardened passphrase: $\text{passphrase} = H(\texttt{"Hyphen\_PQ\_passphrase"} \| H(\text{pubkey}) \| \text{addr\_seed})$

**Security property:** Even if an attacker can reverse PBKDF2-HMAC-SHA512 (the BIP39 KDF), they would still need to invert the WOTS+ hash chain to recover the original password. WOTS+ is provably secure against quantum adversaries under the second-preimage resistance of blake3.

### 10. Temporal Epoch-Referenced Anchoring (TERA)

TERA binds every transaction input to a specific epoch window, preventing replay attacks and stale-transaction injection.

**Construction.** Each `TxInput` carries three 32-byte TERA fields:

$$\texttt{epoch\_context} = \text{Blake3\_keyed}(\texttt{"TERA\_v1\_context\_\_Hyphen\_2025\_ctx"},\; \text{epoch\_seed})$$

$$\texttt{temporal\_nonce} = H_s(\texttt{"TERA\_nonce"} \| \text{spend\_sk} \| \texttt{epoch\_context})$$

$$\texttt{causal\_binding} = \text{Blake3}(\texttt{"TERA\_causal"} \| \text{spend\_sk} \| \text{note\_hash} \| \texttt{epoch\_context})$$

**Validation.** The validator maintains a list of valid epoch contexts covering $\pm T$ epochs from the chain tip, where $T = \texttt{tera\_epoch\_tolerance}$ (mainnet: 2, testnet: 4). A transaction whose `epoch_context` does not appear in this list is rejected with `TeraEpochMismatch`.

**Replay resistance.** A transaction signed for epoch $e$ cannot be replayed after $e + T$ epochs have passed, because its `epoch_context` will no longer be in the valid set.

### 11. Mining Stability Equalizer (MSE)

MSE adjusts the block reward based on the ratio of actual-to-target difficulty, creating a negative-feedback loop that smooths miner revenue across hashrate fluctuations.

**Formula.** Let $D_{\text{ratio}} = D_{\text{actual}} / D_{\text{target}}$. The MSE multiplier is:

$$\mu = \text{clamp}\!\left(1 + \gamma \cdot (D_{\text{ratio}} - 1),\; 0.80,\; 1.20\right)$$

where $\gamma = 0.10$ (`mse_gamma = 100` in basis points). The effective block reward is:

$$R_{\text{eff}}(h) = R_{\text{lcd}}(h) \cdot \mu$$

| Condition | $\mu$ range | Effect |
| --- | --- | --- |
| $D_{\text{actual}} > D_{\text{target}}$ | $\mu > 1$ (up to 1.20) | Reward increases — compensates higher security cost |
| $D_{\text{actual}} = D_{\text{target}}$ | $\mu = 1$ | Neutral — base LCD reward |
| $D_{\text{actual}} < D_{\text{target}}$ | $\mu < 1$ (down to 0.80) | Reward decreases — prevents overpayment |

This creates an economic equilibrium: miners migrate toward the network when rewards are high and away when rewards are low, stabilizing both hashrate and miner revenue.

### 12. Gradual Trust Mining (GTM)

GTM prevents Sybil-based difficulty manipulation at the pool level by exponentially ramping a new miner's share difficulty from `d_init` to `d_target` over a warmup window.

**Warmup formula:**

$$d(n) = d_{\text{init}} + (d_{\text{target}} - d_{\text{init}}) \cdot \left(1 - e^{-5n/W}\right)$$

where $W = 100$ (`GTM_WARMUP_SHARES`) and $d_{\text{init}} = 100$ (`VARDIFF_INITIAL`).

**Convergence:**
- At $n = 0$: $d \approx d_{\text{init}} = 100$
- At $n = 20$: $d \approx 0.63 \cdot d_{\text{target}}$ (practical operating difficulty)
- At $n = W = 100$: $d \approx 0.993 \cdot d_{\text{target}}$ (within 1% of target)

**Sybil resistance:** A Sybil attacker opening $k$ parallel connections is constrained to `GTM_MAX_CONNECTIONS_PER_IP = 32` connections per IP. Each connection starts at $d_{\text{init}}$ regardless of claimed hashrate, so the attacker must invest $k \cdot W$ shares of real work before reaching full difficulty on all connections.

### 13. Consensus-Enforced Coinbase Validation

Hyphen validates coinbase transactions at the consensus level with five structural rules:

1. **No inputs** — coinbase must have zero `TxInput` entries
2. **Single output** — exactly one commitment output
3. **Zero fee** — coinbase fee must be 0
4. **Extra field** — minimum 8 bytes (encodes block height)
5. **Range proof** — valid Bulletproof on the output commitment

Additionally, `accept_block` verifies that `block.header.reward` exactly matches `lcd_base_reward(height, cfg)`, preventing miners from claiming inflated rewards.

## Privacy Model

Hyphen uses a shielded UTXO model combining:

1. **Pedersen Commitments** — amounts hidden as $C = v \cdot H + r \cdot G$ where $H = H_p(\texttt{"Hyphen\_pedersen\_value\_generator\_v1"})$
2. **Stealth Addresses** — ECDH-derived one-time output keys with output-index binding and blake3-based amount encryption
3. **CLSAG Ring Signatures** — compact linkable ring signatures over Ristretto255 with key image and commitment key image; the transaction builder performs self-verification of each CLSAG signature immediately after signing (pre-submission integrity check)
4. **Bulletproofs Range Proofs** — prove $v \in [0, 2^{64})$ with $O(\log n)$ proof size; aggregation up to 16 outputs
5. **View Tag** — single-byte tag $\tau = H(\texttt{"Hyphen\_view\_tag"} \| ss)[0]$ enabling 256× scanning speedup by filtering non-owned outputs without full ECDH
6. **Deterministic Commitment Blinding** — blinding factor $r = H_s(\texttt{"Hyphen\_commitment\_blind"} \| ss)$ derived deterministically from the shared secret, ensuring sender and receiver always compute the same commitment (no blinding mismatch)
7. **Pre-Flight Output Verification** — before building a transaction, the wallet fetches output data from the chain via GET_OUTPUT_INFO RPC and verifies each selected input's public key and commitment against the locally cached values, preventing stale-output and index-mismatch errors
8. **Spent Output Tracking** — after a successful transaction send, the wallet receives spent global indices from the builder and immediately removes them from the local UTXO cache, preventing double-spend attempts on already-consumed outputs

### Verifiable Ring Entropy (VRE) — Novel Consensus Innovation

Hyphen is the first blockchain to enforce **ring signature quality at the consensus level**.

In all existing ring-signature-based privacy coins (Monero, etc.), the decoy selection algorithm is purely client-side — the network cannot verify whether decoys were chosen well. This creates a critical blind spot:

- A malicious wallet can choose **all decoys from the same block**, trivially identifying the real input
- Statistical analysis of decoy age distributions can narrow the anonymity set
- The network has **no way to reject** transactions with poor decoy quality

**Hyphen's VRE** solves this with four consensus-enforced rules:

**VRE-1: Minimum Height Span.** Given ring member block heights $\{h_1, \ldots, h_n\}$:

$$\max(h_i) - \min(h_i) \geq S_{\min}$$

where $S_{\min} = 100$ (mainnet), $S_{\min} = 20$ (testnet). This ensures ring members span a significant time range, preventing temporal clustering attacks.

**VRE-2: Minimum Distinct Height Fraction.** Let $D = |\{h_1, \ldots, h_n\}|$ be the count of distinct heights in the ring:

$$D \geq \lceil 3n/4 \rceil$$

For ring size 16, at least 12 members must come from distinct block heights. This prevents mass decoy reuse from popular blocks.

**VRE-3: Age Band Diversity.** Each ring member's age $a_i = \max(h) - h_i$ is assigned to a band $b_i = \lfloor a_i / w \rfloor$ where $w = \texttt{vre\_age\_band\_width}$ (mainnet: 2048, testnet: 128). The number of distinct bands must satisfy:

$$|\{b_1, \ldots, b_n\}| \geq B_{\min}$$

where $B_{\min} = \texttt{vre\_min\_age\_bands}$ (mainnet: 3, testnet: 2). This forces ring members to span multiple temporal regions, defeating age-clustering deanonymization.

**VRE-4: Global Index Span.** Let $g_{\min}, g_{\max}$ be the minimum and maximum global output indices in the ring, and $N$ the total output set size:

$$\frac{(g_{\max} - g_{\min}) \cdot 10000}{N} \geq \tau$$

where $\tau = \texttt{vre\_min\_index\_span\_bps}$ (mainnet: 500 = 5%, testnet: 300 = 3%). This ensures ring members are drawn from a broad range of the output set, preventing index-clustering attacks.

**Security Improvement.** Under the four VRE rules, the effective anonymity set is provably bounded below. Without VRE, a transaction with all decoys from height $h$ has effective anonymity $\leq 1$. With VRE-1 through VRE-4, the minimum effective anonymity is:

$$A_{\text{eff}} \geq \lceil 3n/4 \rceil = 12 \text{ (for } n=16\text{)}$$

and decoys are guaranteed to span multiple age bands and a minimum fraction of the global output space.

**No existing privacy coin provides consensus-level guarantees on ring anonymity quality.**

#### Adaptive VRE — Early-Chain Scaling

The full-strength VRE parameters (e.g., `vre_age_band_width = 2048`) would require thousands of blocks before transactions could be constructed. Hyphen solves this with **adaptive VRE**: the consensus layer and wallet jointly scale parameters proportionally to the current chain height so that all four VRE rules are always satisfiable once the **activation height** is reached.

- **VRE activation height:** mainnet = 128, testnet = 32. Before the activation height, only coinbase (mining reward) transactions exist; no user transfers are accepted.
- **Effective band width:** $w_{\text{eff}} = \min\bigl(w,\; \lfloor h / B_{\min} \rfloor\bigr)$ — shrinks the band width so that the required number of distinct age bands always fits within the available height range.
- **Effective min ring span:** $S_{\text{eff}} = \min(S_{\min},\; h - 1)$ — caps the span requirement at what the chain can actually provide.
- **Progressive index span (logistic ramp):** $\tau_{\text{eff}} = \min\!\Bigl(\tau \cdot \frac{n^2}{n^2 + k^2},\; \frac{(N-1) \cdot 10000}{N}\Bigr)$ where $k = \texttt{ring\_size} \times 64$. Unlike a simple cap, this logistic sigmoid provides smooth 0 → target growth: 50% at $n = k$ outputs, 80% at $n = 2k$, converging to full enforcement as the output set matures.

As the chain grows, all effective parameters converge to their full paper-specified values. At mainnet height 6144 ($= 2048 \times 3$), $w_{\text{eff}}$ reaches 2048 and full-strength VRE is in effect.

#### Security Hardening

Hyphen implements defence-in-depth across all transaction acceptance paths:

- **P2P gossip validation.** Every transaction received via gossipsub undergoes full consensus validation (CLSAG + TERA + MD-VRE + balance + range proof + nullifier check) before it enters the mempool. A malicious peer cannot inject invalid transactions into any honest node's pool.
- **Validated mempool insert.** The mempool API requires a `Validated` proof token, ensuring that no code path can insert an unvalidated transaction. The token also carries a **VRE quality score** (0–10,000) — see below.
- **Genesis config immutability.** On first startup the node's consensus-critical parameters are hashed (blake3) and persisted. On every subsequent startup the stored hash is compared to the current config; a mismatch aborts with a clear error, preventing accidental or malicious rule changes.
- **VRE quality scoring.** Each validated transaction receives a composite quality score based on four equally-weighted factors: height span excess, height uniqueness, age-band diversity, and index spread. The mempool uses this score as a secondary priority after fee density (via `neg_vre_quality` in the `Priority` ordering), so transactions with superior ring construction are prioritised for block inclusion.
- **Decoy distribution audit.** The wallet divides the output index space into 10 equal bands and verifies that no more than half the node-returned decoys fall in the same band. A node that returns clustered outputs to deanonymize the sender will be detected and the transaction refused.
- **Adaptive VRE flag.** The wallet reports a `vre_used_adaptive: bool` field to the Flutter UI. When adaptive parameters were used, the user sees an informational banner explaining that ring entropy will improve as the chain matures.

更多细节与逐文件变更说明，请参阅： [docs/HARDENING_CHANGES.md](docs/HARDENING_CHANGES.md)

### Encrypted Wallet Storage

Wallet files containing master seed and key material are protected by password-based encryption:

1. **KDF:** 100,000-round iterative blake3 hash with random 32-byte salt
2. **Stream cipher:** blake3 keyed XOF in streaming mode
3. **MAC:** blake3 keyed hash over ciphertext (encrypt-then-MAC)
4. **Format:** `[salt:32] [mac:32] [ciphertext:N]`

Wrong passwords are detected via MAC verification before any decryption attempt.

### Memory-Safe Key Management

- `DerivedKeys` auto-zeroizes secret scalars on drop via custom `Drop` implementation
- `MasterKey` derives `Zeroize` with drop semantics
- `OwnedNote` omits `Debug` to prevent accidental logging of spend keys
- `ViewKey` and `SpendKey` derive `Zeroize` with drop semantics

## Economics

### Lorentzian Continuous Decay (LCD) Emission

Hyphen uses a novel **Lorentzian Continuous Decay** emission model instead of discrete halvings:

$$R(h) = R_{\text{tail}} + (R_0 - R_{\text{tail}}) \cdot \frac{c^2}{h^2 + c^2}$$

| Parameter | Value |
| --- | --- |
| Initial reward ($R_0$) | 100 HPN per block |
| Tail emission ($R_{\text{tail}}$) | 0.6 HPN per block (perpetual) |
| Decay constant ($c$) | 1,048,576 blocks ($2^{20}$, ≈ 2 years at 60s/block) |
| Midpoint ($h = c$) | ≈ 50.3 HPN per block |
| Total finite supply | ≈ 164 million HPN |
| Tail emission rate | ≈ 315,000 HPN / year |
| Fee burn | 50% destroyed, 50% to miner |
| Atomic unit | 1 HPN = $10^{12}$ atomic units |

**Properties:**
- Smooth, continuous, infinitely differentiable — no discrete halving events
- $R(0) = R_0 = 100$ HPN (full initial reward at genesis)
- $R(c) \approx (R_0 + R_{\text{tail}}) / 2 \approx 50.3$ HPN (midpoint at ~2 years)
- $R(\infty) \to R_{\text{tail}} = 0.6$ HPN (perpetual tail emission for miner incentive)
- Total supply converges to approximately $(R_0 - R_{\text{tail}}) \cdot c \cdot \pi / 2 \approx 164\text{M}$ HPN

## Consensus Parameters

| Parameter | Mainnet | Testnet |
| --- | --- | --- |
| Block time | 60 s | 30 s |
| Difficulty window | 60 blocks | 30 blocks |
| Difficulty clamp | 3× up/down | 3× up/down |
| Max uncles | 2 | 2 |
| Max uncle depth | 7 | 7 |
| Ring size | 16 | 4 |
| VRE activation height | 128 | 32 |
| Min ring span (VRE-1) | 100 blocks | 20 blocks |
| Min distinct heights (VRE-2) | ⌈3n/4⌉ | ⌈3n/4⌉ |
| Min age bands (VRE-3) | 3 | 2 |
| Age band width (VRE-3) | 2048 blocks | 128 blocks |
| Min index span (VRE-4) | 500 bps (5%) | 300 bps (3%) |
| TERA epoch tolerance | ±2 epochs | ±4 epochs |
| MSE γ | 100 bps (0.10) | 100 bps (0.10) |
| MSE floor | 8000 bps (0.80×) | 8000 bps (0.80×) |
| MSE ceiling | 12000 bps (1.20×) | 12000 bps (1.20×) |
| Epoch length | 2048 blocks | 2048 blocks |
| Timestamp future limit | 120,000 ms | 60,000 ms |
| Arena size | 2 GiB | 64 MiB |
| Scratchpad size | 8 MiB | 256 KiB |
| PoW rounds | 1024 | 64 |
| Max block size | 2 MiB | 2 MiB |

### Network Ports

| Port | Purpose |
| --- | --- |
| 18333 | Mainnet P2P and RPC |
| 20333 | Mainnet node discovery (UDP) |
| 38333 | Testnet P2P and RPC |
| 20334 | Testnet node discovery (UDP) |
| 3350 | Template Provider (node → pool) |
| 3340 | Pool protocol (pool → miner) |
| 3333 | Stratum V1 JSON-RPC |
| 8080 | Integrated block explorer HTTP |

Default seed/RPC domain: `bytesnap.tech`

## Standalone Mining Architecture

Hyphen uses a strict node/pool/miner split. The mining side is intentionally not part of the root workspace and does not inherit `workspace.dependencies` from the main chain codebase.

```
Node (Template Provider :3350, Explorer :8080, P2P :18333/:38333)
  ↕  TP protocol (length-prefixed protobuf over TCP)
Standalone Pool Server (:3340)
  ↕  Pool protocol (length-prefixed protobuf over TCP)
Standalone Miner(s) — CPU (hyphen-miner) and/or GPU (hyphen-miner-gpu)
```

The mining protocol includes hashrate-based initial difficulty negotiation: miners report their thread count and estimated hashrate during login, and the pool computes an appropriate starting share difficulty.

The node owns the blockchain and mempool. The pool pulls templates from the node, constructs miner jobs, verifies shares locally, and only submits a full block back to the node when a share reaches block difficulty. The miner only speaks the pool protocol and never links against the node/core workspace crates.

### TP Message Demultiplexer

The pool's Template Provider client uses a single TCP connection to the node for both request-response (get_template, submit_block) and subscription push (template updates). A background demultiplexer task reads all incoming envelopes and routes them by message type:

- `TP_TEMPLATE (101)` pushed by the node after subscription → forwarded to the subscription channel
- `TP_SUBMIT_RESULT (103)`, `TP_DECLARE_JOB_RESULT (105)` → matched to the pending request-response oneshot sender

This eliminates race conditions where a pushed template could be mistakenly consumed as a submit_block response (or vice versa), which would produce "expected type X, got Y" errors.

After a miner submits a share that meets block difficulty, the pool submits the block to the node and immediately requests a fresh template to distribute to all connected miners, ensuring they mine at the correct height.

The standalone mining programs live in `hyphen-pool/` and `hyphen-miner/`. Each one carries its own manifest, its own crates.io dependency set, and its own local implementation for block/header compatibility, envelope signing, difficulty targeting, arena generation, and HyphenPoW evaluation.

## Building

### Prerequisites

- Rust 1.75+ (edition 2021)
- A C/C++ toolchain for native dependencies
- On Windows: MSVC Build Tools are recommended
- On Linux: `build-essential`, `pkg-config`, and a recent GCC/Clang toolchain are recommended

### Verified build commands

All commands below are valid against the current repository layout.

```bash
# Core workspace (chain, node, wallet backend crates, consensus, RPC, etc.)
cargo build --manifest-path Cargo.toml --workspace --release

# Optional test pass for the workspace
cargo test --manifest-path Cargo.toml --workspace

# Workspace lint pass
cargo clippy --manifest-path Cargo.toml --workspace -- -W clippy::all

# Explorer library crate
cargo build --manifest-path Cargo.toml -p hyphen-explorer --lib --release
cargo clippy --manifest-path Cargo.toml -p hyphen-explorer --all-targets -- -W clippy::all

# Standalone pool
cargo build --manifest-path hyphen-pool/Cargo.toml --release
cargo clippy --manifest-path hyphen-pool/Cargo.toml -- -W clippy::all

# Standalone miner
cargo build --manifest-path hyphen-miner/Cargo.toml --release
cargo clippy --manifest-path hyphen-miner/Cargo.toml -- -W clippy::all

# Standalone GPU miner (requires Vulkan/DX12/Metal SDK)
cargo build --manifest-path hyphen-miner-gpu/Cargo.toml --release
cargo clippy --manifest-path hyphen-miner-gpu/Cargo.toml -- -W clippy::all
```

## Operational Overview

Hyphen runs as three processes for a full mining deployment (the block explorer is built into the node):

1. `hyphen-node` — the full node, P2P participant, chain database owner, Template Provider server, and integrated HTTP block explorer (port 8080)
2. `hyphen-pool-server` — the mining pool that talks to the node's Template Provider
3. `hyphen-miner` — the CPU miner that talks to the pool
4. `hyphen-miner-gpu` — (optional) the GPU miner that talks to the pool using the same protocol as the CPU miner

### Integrated Explorer

The block explorer is now **provided by the `hyphen-explorer` library crate and hosted by `hyphen-node` by default**. When the node starts, it automatically serves the explorer UI and API on `--explorer_bind` (default `0.0.0.0:8080`).

Navigate to `http://<node-ip>:8080/` while the node is running to browse the chain in real time.

`hyphen-explorer` no longer owns a separate `main.rs` entrypoint. The explorer runtime, database ownership, bind lifecycle, and shutdown semantics all stay inside `hyphen-node`, while the reusable HTTP router and handlers live in the `hyphen-explorer` library.

## CLI Reference

### Full node: `hyphen-node`

```text
Usage: hyphen-node.exe [OPTIONS]

Options:
  --data-dir <DATA_DIR>            [default: hyphen_data]
  --network <NETWORK>              [default: testnet]
  --listen <LISTEN>                P2P listen multiaddr (defaults to /ip4/0.0.0.0/tcp/<port> from chain config)
  --boot-nodes <BOOT_NODES>       [default: ""]
  --template-bind <TEMPLATE_BIND> [default: 0.0.0.0:3350]
  --explorer_bind <EXPLORER_BIND> [default: 0.0.0.0:8080]
```

Field meaning:

- `--data-dir`: sled chain database directory used by the full node
- `--network`: `mainnet` or `testnet`; any value other than `mainnet` falls back to testnet in the current code
- `--listen`: libp2p multiaddr for inbound P2P traffic; defaults to the port from chain config (mainnet: 18333, testnet: 38333)
- `--boot-nodes`: comma-separated multiaddrs containing `/p2p/<peer_id>`
- `--template-bind`: TCP address for the Template Provider interface consumed by the pool
- `--explorer_bind`: HTTP bind address for the integrated block explorer

### Pool: `hyphen-pool-server`

Verified from `cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- --help`:

```text
Usage: hyphen-pool-server.exe [OPTIONS] [COMMAND]

Commands:
  keygen

Options:
  --node <NODE>                              [default: 127.0.0.1:3350]
  --bind <BIND>                              [default: 0.0.0.0:3340]
  --stratum-bind <STRATUM_BIND>              [default: 0.0.0.0:3333]
  --api-bind <API_BIND>                      [default: 0.0.0.0:8081]
  --share-difficulty <SHARE_DIFFICULTY>      [default: 100]
  --network <NETWORK>                        [default: testnet]
  --pool-id <POOL_ID>                        [default: hyphen-pool/0.1]
  --key-file <KEY_FILE>                      [default: ""]
  --standalone
  --data-dir <DATA_DIR>                      [default: data]
  --pool-state-dir <POOL_STATE_DIR>          [default: pool_state]
  --no-stratum
  --no-api
  --payout-mode <PAYOUT_MODE>                [default: solo] [possible values: solo, prop, pps, pplns, pps+, fpps]
  --pool-fee-bps <POOL_FEE_BPS>
  --pplns-window-factor <PPLNS_WINDOW_FACTOR> [default: 2]
  --pool-wallet <POOL_WALLET>                [default: ""]
```

Field meaning:

- `--node`: Template Provider endpoint exposed by `hyphen-node`
- `--bind`: protobuf miner protocol listener
- `--stratum-bind`: Stratum V1 JSON-RPC listener
- `--api-bind`: HTTP listener for the pool accounting API consumed by wallets and external dashboards
- `--share-difficulty`: per-share difficulty target for miner submissions
- `--network`: `mainnet` or `testnet`; any non-`mainnet` value falls back to testnet in current code
- `--pool-id`: pool identity string sent to miners
- `--key-file`: 32-byte raw Ed25519 secret key file for the pool signing identity
- `--standalone`: run an internal chain provider inside the pool instead of connecting to a node
- `--data-dir`: chain state path used only when `--standalone` is enabled
- `--pool-state-dir`: persistence directory for miner ledger, pending balances, recent settlements, and payout accounting
- `--no-stratum`: disable the Stratum JSON-RPC interface
- `--no-api`: disable the pool accounting HTTP API
- `--payout-mode`: pool settlement model; supports `solo`, `prop`, `pps`, `pplns`, `pps+`, and `fpps`
- `--pool-fee-bps`: explicit pool fee override in basis points; when omitted, `SOLO` defaults to `0` and all shared-reward modes default to `100` (1%)
- `--pplns-window-factor`: PPLNS window size, measured as a multiple of current block difficulty
- `--pool-wallet`: block reward destination for pool-mined blocks — accepts either a `hy1...` Hyphen address (base58-decoded, checksum-verified, spend public key extracted) or 64 hex chars representing a raw 32-byte public key

### Pool Payout Semantics And Wallet Visibility

Hyphen now distinguishes between two kinds of mining rewards in the wallet UI:

- On-chain mining rewards: rewards already recorded on-chain for the miner payout key; this is what the explorer endpoint `/api/miner/{pubkey}/rewards` reports
- Pool pending balance: internal pool ledger balance that has been earned but not yet paid on-chain; this is exposed by the pool API endpoint `/api/pool/wallet/{wallet}/balance`

Payout mode behavior:

- `SOLO`: the mined block pays directly to the miner payout wallet, so the reward becomes visible through the explorer as soon as the block exists on-chain
- `PROP`, `PPS`, `PPLNS`, `PPS+`, `FPPS`: the mined block pays to the configured pool wallet, and each miner accrues an internal pending balance in `pool_state`; the wallet shows that pending amount through the pool API until the operator performs the real payout transaction on-chain

This distinction is intentional and production-correct: displaying a pending balance does not mean the funds are already spendable on-chain. Spendable wallet balance only increases after the pool actually sends a settlement transaction to the miner wallet.

The wallet UI now renders mining activity from both sides of that model:

- Explorer-backed confirmed activity from `/api/miner/{pubkey}/rewards` and `/api/miner/{pubkey}/blocks?limit=<n>`
- Pool-ledger reward activity from `/api/pool/wallet/{wallet}/balance`, including recent reward events emitted when the pool settles a found block into miner ledgers

Same-address handling is explicit. If the configured pool wallet and a miner wallet resolve to the same spend public key:

- In `SOLO`, that is still treated as the miner's own direct on-chain block reward
- In shared-reward modes, the wallet does not misclassify the pool operator's coinbase receipt as the miner's already-settled personal reward; it is surfaced separately as a pool coinbase receipt while the miner's actual entitlement continues to come from the pool ledger

This prevents the double-counting bug where a pool operator using the same address for pool collection and mining payout would otherwise appear to receive the same block reward twice.

Pool API contract:

- Health: `GET /healthz`
- Pool metadata: `GET /api/pool/info`
- Wallet aggregate ledger summary: `GET /api/pool/wallet/{wallet}/balance`

The wallet balance response now also carries production-facing settlement metadata:

- `is_pool_wallet`: whether the queried wallet is the configured pool coinbase destination
- `direct_coinbase_mode`: whether the current payout mode sends found blocks directly to the miner instead of the pool wallet
- `recent_blocks`: recent block settlements with recipient and direct-coinbase flags
- `recent_reward_events`: wallet-scoped reward credits generated by pool accounting

The `{wallet}` path segment accepts either a `hy1...` address or a 64-character hex public key. The response aggregates all miner identities that settle into the same payout wallet.

### Mainnet Deployment Notes

For a production shared-reward pool (`PROP`, `PPS`, `PPLNS`, `PPS+`, `FPPS`), all of the following must be aligned:

1. Start `hyphen-pool-server` with `--payout-mode`, `--pool-wallet`, and optionally `--pool-fee-bps`, `--pplns-window-factor`, `--api-bind`, and `--pool-state-dir`.
2. Keep the pool accounting API reachable from user wallets, reverse proxies, or your public edge. If you do not want public exposure, terminate it behind your own authenticated gateway, but the wallet still needs an HTTP path to query pending balances.
3. Configure the Hyphen wallet's `Pool API Endpoint` setting to the pool API origin. If left empty, the wallet auto-derives it from the RPC host and uses port `8081`.
4. Run an actual payout process that converts internal pending balances into on-chain settlement transactions. Without this operational step, miners will correctly see pending balances in the wallet, but those balances will not become spendable funds.
5. Preserve `pool_state/` backups. In non-`SOLO` modes it is the source of truth for miner pending balances, recent block settlements, and payout accounting history.

### Production Difficulty And Reject Control

The miner/pool path now keeps difficulty negotiation live during the whole session instead of only at login:

- The miner sends its estimated hashrate at login so the pool can choose a better starting share difficulty immediately after connect
- The miner reports hashrate every 5 seconds and sends keepalives every 15 seconds
- The pool may retarget share difficulty both after accepted-share VarDiff observations and after explicit hashrate reports
- Whenever the pool changes difficulty, it now sends both `MSG_SET_DIFFICULTY` and a fresh clean `MSG_JOB` so miners stop hashing stale work at the old share target
- Miner worker threads now interrupt batches on either job changes or difficulty-generation changes, which reduces startup-period rejects and post-retarget stale shares

Operational guidance:

- Do not treat high accepted-share counts as proof that reject spikes are harmless; startup rejects usually indicate stale-difficulty lag or oversized work batches
- Keep `--batch-size` conservative enough that miners can react to retargets quickly on your hardware; the default `100000` is a throughput/latency compromise, not a universally optimal constant
- Keep the pool reachable from miners continuously. Real-time difficulty updates depend on the live TCP session staying healthy, not on intermittent reconnects

### Miner: `hyphen-miner`

Verified from `cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- --help`:

```text
Usage: hyphen-miner.exe [OPTIONS] [COMMAND]

Commands:
  keygen

Options:
  --pool <POOL>                              [default: 127.0.0.1:3340]
  --threads <THREADS>                        [default: 0]
  --network <NETWORK>                        [default: testnet]
  --key-file <KEY_FILE>                      [default: ""]
  --user-agent <USER_AGENT>                  [default: hyphen-miner/0.1]
  --batch-size <BATCH_SIZE>                  [default: 100000]
  --wallet-address <WALLET_ADDRESS>          [default: ""]
```

Field meaning:

- `--pool`: pool protobuf endpoint
- `--threads`: worker thread count; `0` means auto-detect logical CPUs
- `--network`: `mainnet` or `testnet`; any non-`mainnet` value falls back to testnet in current code
- `--key-file`: 32-byte raw Ed25519 secret key file for the miner identity
- `--user-agent`: user-agent string sent in login
- `--batch-size`: amount of nonce work processed before yielding progress/state updates
- `--wallet-address`: accepts a `hy1...` Hyphen address (BIP44, checksum-verified, spend public key extracted) or 64 hex chars representing a raw 32-byte public key; if omitted, the miner's signing public key is used instead

Current runtime behavior relevant to production tuning:

- the miner keeps a persistent pool connection open, rather than treating pool contact as one-time job fetch
- the miner measures local hashrate continuously and reports it upstream every 5 seconds
- the pool can push difficulty changes mid-session, and the miner now aborts the active nonce batch when that happens
- the mining loop also wakes faster when no job is available, which shortens the cold-start period after reconnect

### GPU Miner: `hyphen-miner-gpu`

```text
Usage: hyphen-miner-gpu.exe [OPTIONS] [COMMAND]

Commands:
  keygen
  list-gpus

Options:
  --pool <POOL>                              [default: 127.0.0.1:3340]
  --network <NETWORK>                        [default: testnet]
  --key-file <KEY_FILE>                      [default: ""]
  --user-agent <USER_AGENT>                  [default: hyphen-gpu-miner/0.1]
  --gpu-device <GPU_DEVICE>
  --backend <BACKEND>                        [default: auto]
  --batch-size <BATCH_SIZE>
  --wallet-address <WALLET_ADDRESS>          [default: ""]
```

Field meaning:

- `--gpu-device`: 0-based adapter index from `list-gpus` output; omit for automatic selection (prefers discrete GPUs)
- `--backend`: preferred graphics API — `vulkan` (NVIDIA/AMD/Intel/Moore Threads on Linux/Windows/Android), `dx12` (Windows), `metal` (macOS/iOS), `gl` (OpenGL ES fallback), `auto` (try all)
- `--batch-size`: nonces per GPU dispatch; if omitted, auto-calculated from VRAM capacity

**Supported GPU vendors and backends:**

| Vendor | Vulkan | DX12 | Metal | OpenGL ES |
| --- | --- | --- | --- | --- |
| NVIDIA (GeForce/Quadro/Tesla) | Yes | Yes (Windows) | — | — |
| AMD (Radeon/RX) | Yes | Yes (Windows) | — | — |
| Intel (Arc/Iris/UHD) | Yes | Yes (Windows) | — | Yes |
| Apple (M1/M2/M3/M4) | — | — | Yes | — |
| Qualcomm Adreno (Android) | Yes | — | — | Yes |
| ARM Mali (Android) | Yes | — | — | Yes |
| Moore Threads (MTT S-series) | Yes | — | — | — |

**Architecture:** The GPU miner uses a hybrid CPU/GPU architecture:
1. Arena generation and scratchpad seeding run on the CPU (Blake3 XOF)
2. The PageWeave 12-kernel solver loop runs on the GPU via WGSL compute shaders
3. Blake3 keyed-hash finalization and target comparison run on the CPU after GPU readback

This design ensures CPU mining remains more efficient than GPU mining for the same silicon budget — the GPU handles only the parallelizable solver loop while the CPU handles the sequential Blake3 finalization that cannot be efficiently parallelized in WGSL.

### Explorer library: `hyphen-explorer`

`hyphen-explorer` is a library crate, not an end-user binary. It exports the explorer router and server bootstrap used by `hyphen-node`.

Current integration contract:

- `hyphen-node` owns the sled database and blockchain handle
- `hyphen-node` binds the explorer HTTP listener through `--explorer_bind`
- `hyphen-explorer` provides the reusable UI/API implementation as Rust library code

## Key Generation

### Recommended method: built-in keygen subcommands

Pool key generation:

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- keygen --output pool.key
```

Miner key generation:

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- keygen --output miner.key
```

GPU miner key generation:

```bash
cargo run --manifest-path hyphen-miner-gpu/Cargo.toml --bin hyphen-miner-gpu -- keygen --output miner-gpu.key
```

Those commands print the corresponding public key in hex. Save that output if you want to reuse the key as a payout destination or identify the process later.

### File format requirement

Both `pool.key` and `miner.key` must contain **exactly 32 raw bytes**. They are not PEM files, not hex text files, and not JSON.

## Wallet Address / Reward Address Rules

This is the part that must be correct for miners and operators.

### What `--wallet-address` and `--pool-wallet` actually expect

They accept **either** of the following formats:

**Format A: `hy1...` Hyphen address** (recommended)

- A standard Hyphen wallet address starting with `hy1`
- Base58-encoded payload: `version[1] | view_public[32] | spend_public[32] | blake3_checksum[4]`
- The pool/miner verifies the blake3 checksum and extracts the 32-byte spend public key automatically
- This is the same address format displayed by the Hyphen wallet app

Example:

```text
hy1<base58-encoded 69-byte payload>
```

**Format B: 64-character hex** (raw public key)

- A **32-byte public key** encoded as **64 lowercase or uppercase hex characters**
- With **no `0x` prefix**
- With **no spaces, commas, or quotes inside the value**

Example:

```text
6f8d7c4d1b2a...<total 64 hex chars>...99aabbccddeeff00
```

### What is not valid

The following are not valid values for `--wallet-address` or `--pool-wallet`:

- a mnemonic phrase
- a password
- a path like `wallet.dat`
- a 32-byte secret key
- a hex string that is not exactly 64 hex characters long
- a `hy1` address with an invalid checksum

### Current payout behavior in code

- If the miner omits `--wallet-address`, the miner uses its own signing public key as `payout_pubkey`
- If the pool omits `--pool-wallet`, the pool uses its own signing public key as the block reward destination

### Operational recommendation

For production, explicitly set both:

- `--pool-wallet` on the pool
- `--wallet-address` on each miner

That avoids accidental reward routing to ephemeral or infrastructure-only signing keys.

## Verified Startup Recipes

### A. Testnet full node only

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

### B. Mainnet full node only

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network mainnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

### C. Testnet node with explicit boot nodes

`--boot-nodes` must be a comma-separated string of full libp2p multiaddrs that include `/p2p/<peer_id>`, for example:

```text
/ip4/203.0.113.10/tcp/18333/p2p/12D3KooWExamplePeerA,/ip4/203.0.113.11/tcp/18333/p2p/12D3KooWExamplePeerB
```

Then run:

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "/ip4/203.0.113.10/tcp/18333/p2p/12D3KooWExamplePeerA,/ip4/203.0.113.11/tcp/18333/p2p/12D3KooWExamplePeerB" \
  --template-bind 0.0.0.0:3350
```

### D. Pool connected to a node

Recommended testnet command (using a `hy1...` wallet address from the Hyphen wallet app):

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet hy1YourWalletAddressFromTheApp
```

Or using 64-hex-character raw public key:

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

If you want the pool reward address to follow the pool signing key instead, remove `--pool-wallet`.

### E. Pool standalone mode

This mode does **not** use a full node. It runs the pool with its own internal chain state.

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --standalone \
  --data-dir pool_data \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Use standalone mode only when that is specifically what you want. For real node-backed mining, do not add `--standalone`.

### F. Miner connected to the pool

Recommended testnet command with an explicit payout wallet (using a `hy1...` address):

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address hy1YourWalletAddressFromTheApp
```

Or using 64-hex-character raw public key:

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

### G. Mainnet production-style release commands

Build:

```bash
cargo build --manifest-path Cargo.toml --workspace --release
cargo build --manifest-path Cargo.toml -p hyphen-explorer --lib --release
cargo build --manifest-path hyphen-pool/Cargo.toml --release
cargo build --manifest-path hyphen-miner/Cargo.toml --release
cargo build --manifest-path hyphen-miner-gpu/Cargo.toml --release
```

Run node:

```bash
./target/release/hyphen-node \
  --data-dir hyphen_data \
  --network mainnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

Run pool:

```bash
./hyphen-pool/target/release/hyphen-pool-server \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network mainnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Run miner:

```bash
./hyphen-miner/target/release/hyphen-miner \
  --pool 127.0.0.1:3340 \
  --threads 16 \
  --network mainnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

## Explorer Usage

### Supported and correct launch flow

1. Start `hyphen-node` with the target `--data-dir` and `--network`.
2. Keep the default integrated explorer enabled, or override the HTTP listener with `--explorer_bind`.
3. Open the browser at the node's explorer bind address.

### Testnet explorer command

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --template-bind 0.0.0.0:3350 \
  --explorer_bind 127.0.0.1:8080
```

Then open:

```text
http://127.0.0.1:8080/
```

### Mainnet explorer command

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network mainnet \
  --template-bind 0.0.0.0:3350 \
  --explorer_bind 0.0.0.0:8080
```

### What the explorer serves

- `/` — browser UI
- `/api/info` — chain tip, supply, reward, epoch info
- `/api/updates?since=<height>` — lightweight polling endpoint for live home-page refresh when a new tip arrives
- `/api/blocks?page=0&limit=20` — recent block list
- `/api/block/<height_or_hash>` — full block details
- `/api/tx/<tx_hash>` — transaction location
- `/api/miner/<pubkey>/rewards` — cached aggregate confirmed mining rewards for one miner payout public key
- `/api/miner/<pubkey>/blocks?limit=<n>` — recent mined blocks for one miner payout public key
- `/api/search?q=<term>` — block/tx search

The integrated explorer home page now polls `/api/updates` automatically while it is displaying the newest block page, so newly found blocks appear without a manual refresh. Miner reward lookups are no longer computed by full chain rescans on every request; they are served from an incremental in-memory index refreshed from chain tip progress.

### Explorer correctness requirements

To get correct explorer output:

- `--data-dir` must point at the node database you want the node to own
- `--network` must match the chain you intend to serve
- `--explorer_bind` must be reachable from the browser you use

If any of those are wrong, the browser will show the wrong chain, fail to connect, or expose the explorer on the wrong interface.

## End-to-End Local Testnet Flow

This is the most useful exact sequence for local validation.

### Step 1: generate keys

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- keygen --output pool.key
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- keygen --output miner.key
```

### Step 2: start the node

```bash
cargo run --manifest-path Cargo.toml -p hyphen-node -- \
  --data-dir hyphen_data \
  --network testnet \
  --boot-nodes "" \
  --template-bind 0.0.0.0:3350
```

### Step 3: start the pool

Replace the sample pool wallet with a real `hy1...` address from the Hyphen wallet app, or a 64-hex-character public key.

```bash
cargo run --manifest-path hyphen-pool/Cargo.toml --bin hyphen-pool-server -- \
  --node 127.0.0.1:3350 \
  --bind 0.0.0.0:3340 \
  --stratum-bind 0.0.0.0:3333 \
  --share-difficulty 100 \
  --network testnet \
  --pool-id hyphen-pool/0.1 \
  --key-file ./pool.key \
  --pool-wallet hy1YourWalletAddressFromTheApp
```

### Step 4: start the miner

Replace the sample wallet address with the real miner payout `hy1...` address or a 64-hex public key.

```bash
cargo run --manifest-path hyphen-miner/Cargo.toml --bin hyphen-miner -- \
  --pool 127.0.0.1:3340 \
  --threads 0 \
  --network testnet \
  --key-file ./miner.key \
  --user-agent hyphen-miner/0.1 \
  --batch-size 100000 \
  --wallet-address hy1YourWalletAddressFromTheApp
```

### Step 5: open the integrated explorer

Open `http://127.0.0.1:8080/` while the node from step 2 is still running.

## Operational Notes

### Node startup contract

- the node exposes Template Provider on `--template-bind`
- the pool connects to that endpoint using `--node`
- miners connect to the pool using `--pool`

### Thread behavior

- `--threads 0` on the miner means auto-detect available parallelism
- for deterministic benchmarking, set an explicit thread count

### Network selection behavior

The current binaries all treat `mainnet` specially and otherwise fall back to testnet. For operational safety, pass `mainnet` or `testnet` explicitly every time.

### Key persistence behavior

If `--key-file` is omitted:

- the pool generates an ephemeral signing key for that process run
- the miner generates an ephemeral signing key for that process run

That is acceptable for quick testing and unacceptable for stable production identity.

## Troubleshooting

### Explorer says it cannot open the database

Cause: the node is still holding the sled database, or you pointed to the wrong directory.

Fix:

1. stop the node cleanly
2. verify the explorer `--data-dir` matches the node `--data-dir`
3. restart the explorer

### Miner starts but rewards go to the wrong place

Cause: `--wallet-address` was omitted or wrong.

Fix:

1. verify the payout wallet is a valid `hy1...` address or a 64-hex-character public key
2. restart the miner with the correct `--wallet-address`

### Pool starts but block rewards go to the wrong place

Cause: `--pool-wallet` was omitted or wrong.

Fix:

1. verify the value is either a valid `hy1...` address from your wallet or a 64-hex-character public key
2. restart the pool with the correct `--pool-wallet`

### Pool cannot connect to the node

Cause: the node is not running, `--template-bind` is different, or `--node` points to the wrong address.

Fix:

1. confirm the node log says Template Provider is listening on the expected address
2. use the exact same address in the pool `--node` argument

### Boot nodes do not work

Cause: `--boot-nodes` must include full libp2p multiaddrs with `/p2p/<peer_id>`.

Fix: use a comma-separated string of complete peer multiaddrs, not bare IP:port values.

## Project Structure

```
Hyphen/
├── Cargo.toml
├── src/lib.rs
├── crates/
│   ├── hyphen-crypto/      # Ring signatures, stealth addresses, PQ sigs
│   ├── hyphen-core/        # Block types, config, NTP timestamps
│   ├── hyphen-pow/         # HyphenPoW (12 kernels, arena, difficulty)
│   ├── hyphen-proof/       # Bulletproofs range proofs
│   ├── hyphen-tx/          # Shielded UTXO transactions
│   ├── hyphen-token/       # Multi-asset issuance
│   ├── hyphen-economics/   # Emission + fees
│   ├── hyphen-state/       # Persistent storage
│   ├── hyphen-consensus/   # Validation + chain + uncles
│   ├── hyphen-mempool/     # Transaction pool
│   ├── hyphen-wallet/      # Wallet + ICD derivation
│   ├── hyphen-network/     # libp2p P2P
│   ├── hyphen-transport/   # Template Provider protocol (node-pool)
│   ├── hyphen-vm/          # Smart contract VM
│   ├── hyphen-rpc/         # JSON-RPC
│   └── hyphen-node/        # Full node binary
│   ├── hyphen-explorer/    # Explorer library crate consumed by hyphen-node
```

## Hyphen Wallet App

The `hyphen_wallet/` directory contains a cross-platform Flutter wallet app with a Rust backend connected via `flutter_rust_bridge`.

### Features

- **Primary desktop/mobile targets** — maintained first for Windows, Android, Linux, and macOS; iOS/web remain secondary targets
- **Light / Full node mode** — choose light node (remote RPC via bytesnap.tech) or full node (local chain sync with integrated explorer) during wallet setup; changeable in Settings
- **Quantum-resistant BIP39 passphrase** — wallet password is transformed through WOTS+ hash chains (67 chains × 15 steps) before use as BIP39 passphrase, providing post-quantum hardening of mnemonic derivation
- **Multi-wallet management** — create, import, rename, switch, and delete multiple wallets within a single app instance
- **7-language i18n** — English, Chinese (中文), German (Deutsch), French (Français), Spanish (Español), Italian (Italiano), Japanese (日本語)
- **Quantum-resistant security** — WOTS+ hybrid signatures, blake3-XOF stream encryption with encrypt-then-MAC wallet storage, blake3-based 100k-round KDF
- **ICD key derivation** — Pedersen commitment-based BIP44-compatible key tree on Ristretto255
- **Stealth addresses** — one-time output keys with view tag scanning
- **Private transfers** — full shielded transaction pipeline: blockchain output scanning via RPC, CLSAG ring-signature construction with decoy outputs fetched from the node's output index (GET_RANDOM_OUTPUTS), pre-flight output verification via GET_OUTPUT_INFO, CLSAG self-verification after signing, Bulletproofs range proofs, bincode serialization, and transaction submission to the mempool; greedy input selection with automatic change output generation; spent output tracking with automatic UTXO cache invalidation after successful sends
- **NFC contactless** — share wallet address via NFC tap on Android (full NFC) and iOS (NDEF/TAG reader session with entitlements); uses `nfc_manager` 3.5.0 with Kotlin 2.2 compatibility workaround
- **Biometric authentication** — fingerprint and Face ID lock/unlock via `local_auth` 2.3.0; Android uses `FlutterFragmentActivity` for BiometricPrompt API compatibility; biometric-gated mnemonic reveal and transaction confirmation
- **Network switching** — toggle between mainnet and testnet with automatic address re-derivation
- **Mining payout address** — displays the wallet's `hy1...` address for use as `--pool-wallet` or `--wallet-address` in mining configuration; one-tap copy to clipboard
- **Receive QR code** — generates a scannable QR code of the wallet's `hy1...` address on the Receive screen, rendered with rounded eye/data module styling via `qr_flutter`
- **Light node connection status** — Settings screen shows real-time TCP connectivity to the configured RPC endpoint, with ability to switch between available nodes or add custom endpoints
- **Secure mnemonic backup** — 24-word BIP39 mnemonic with reveal/hide and clipboard support
- **Wise-style Material Design 3 UI** — light green palette (#9FE870 bright green, #163300 forest green), Inter font, rounded surfaces, animated balance hero card, bottom NavigationBar with 4 destinations, action pills, pool info strips
- **Customizable theme color** — six preset color themes (Wise Green, Ocean Blue, Royal Purple, Sunset Orange, Rose Pink, Slate Gray) selectable from Settings; choice persists across sessions via encrypted storage; MaterialApp ColorScheme, buttons, navigation bar, segmented controls, and snackbars all follow the selected preset
- **Real-time balance updates** — wallet balance auto-refreshes every 10 seconds via timer-based polling of pool and explorer APIs; pull-to-refresh on the home screen triggers an immediate on-demand refresh; `Consumer<WalletService>` reactive rebuild ensures the balance hero card, mining breakdown, and activity feed reflect the latest data without manual navigation
- **3D animated UI** — perspective-tilt card interactions and floating orb animations on key screens

### Building the wallet

```bash
cd hyphen_wallet
flutter pub get

# Generate flutter_rust_bridge Dart bindings after any Rust API change.
flutter_rust_bridge_codegen generate

# Static validation used in this repository.
flutter analyze

# Run on the current host platform.
flutter run
```

Primary platform entrypoints currently maintained in-tree:

- Windows: `flutter run -d windows` or `flutter build windows`
- Android: `flutter run -d android` or `flutter build apk`
- Linux: `flutter run -d linux` or `flutter build linux`
- macOS: `flutter run -d macos` or `flutter build macos`

Platform notes:

- The Flutter app depends on generated bindings under `hyphen_wallet/lib/src/rust/`; if they are missing, run `flutter_rust_bridge_codegen generate` from `hyphen_wallet/`.
- Android release signing is intentionally not committed to the repository. Configure your own release keystore before shipping Play-distributed builds.
- Linux builds require GTK3 development packages on the build host.
- macOS binaries must be built and signed on macOS.

Repository validation commands executed for the current update:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo check --manifest-path hyphen-miner-gpu/Cargo.toml
cd hyphen_wallet && flutter analyze
```

Current validation status for this update:

- `cargo test --workspace`: passed
- `flutter analyze`: passed
- `cargo clippy --workspace --all-targets`: passed
- `cargo check` (hyphen-miner-gpu): passed

### Generating app icons

Place `Hyphen.png` in `assets/images/` and run:

```bash
dart run flutter_launcher_icons
```

## License

AGPL-3.0
