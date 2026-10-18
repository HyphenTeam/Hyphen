# Hyphen

[中文说明](README_CN.md)

Hyphen is an experimental privacy-oriented base chain whose block work is a
search for verifiable mathematical witnesses, written in Rust. The protocol
identifier is `PoUW v3`: single-use Cunningham-chain witnesses, not digest
grinding. This repository contains the node, consensus and state
transition code, transaction validation, networking, RPC, cryptographic
libraries, executable research models, and consensus test vectors.

This repository does not contain the Hyphen Miner, Hyphen Pool, or Hyphen Wallet
products. They are independent Git repositories with independent lockfiles, CI,
releases, and security boundaries; this checkout may carry them alongside as
`HyphenMiner/`, `HyphenPool/`, and `HyphenWallet/`, and `.gitignore` keeps them out
of this repository's history. `scripts/devnet-smoke.ps1` builds and runs all three
when they are present, and refuses with a clear message when they are not. A
protocol change can require coordinated updates, but it does not make those
repositories part of this one.

## Read this first

Hyphen is not a launched mainnet and has not had an independent consensus or
cryptographic audit. `mainnet` is a research profile. The current devnet can be
built and tested, but that is not evidence that real assets are safe.

The design rationale, threat model, mechanism status and known limitations are
written up in the [whitepaper](docs/whitepaper.md). Read it before quoting any
claim from this repository.

The four named research mechanisms are executable reference models, not active
devnet consensus:

| Mechanism | Code and vectors | What is actually established | Missing before activation |
| --- | --- | --- | --- |
| H-WES recoverable state expiry | Public profile integrated on research chains | Atomic five-root state, signed public creation, bounded deterministic expiry and reorg rollback | Shielded recovery/consume circuit, incentives, benchmarks, audit |
| H-BFM parallel block fusion | Present | Unique order, missing-parent rejection, preverified DA-set enforcement and atomic first-winner conflict receipts for one agreed finite DAG | DAG set agreement/certificate acquisition, incentives and liveness proof |
| H-FOC' fair finality | Present, inactive | Durable PREPARE/COMMIT locks, timeout certificates, lock-carrying view change, dual-committee handoff, receipt obligations and typed P2P receipt transport | Unbiasable beacon, live pacemaker/leader, finalized committee source, block-execution integration, WAN benchmarks, audit |
| H-SAC selective audit disclosure | Present, inactive | One-output amount opening, scoped Schnorr ownership proof, and a leakage lower bound | Frozen compliance relation, confidential delivery, chain-provenance ZK circuit, proving/verifying integration, independent circuit audit |

AetherCompute task publication and the deterministic WASM ledger are integrated
with research-chain block execution, RPC/P2P ingress, mempool templates, state
roots and reorg rollback. Scientific result settlement remains fail-closed
until an exact audited proof verifier is installed. See the
[AetherCompute boundary](docs/research/aether-compute.md).

Block version 5 activates PoUW v3. A block claims `difficulty` distinct
Cunningham-chain witnesses of the epoch's chain length; a witness is a value `n`
whose chain `n, 2n+1, 4n+3, …` is prime at every link and fits in 64 bits.
Primality is decided by Miller-Rabin with the seven-base set that Jaeschke,
Sorenson and Webster proved exact for every `n < 2^64`, so verification is a
handful of integer operations per link and carries no probabilistic error bound.

Witnesses are **single-use**: the chain records every claimed witness in a sparse
Merkle set, and a block is rejected if any witness it claims was claimed before.
That is the whole anti-replay argument of the workload, and it is why header
filters are not used at all:

- A header-derived filter (`H(header ‖ n) < T`) is broken by pooling. A solver
  who builds `m / p` chains satisfies *every* future header, because the filter
  is evaluated per header while the pool persists, so each further block costs a
  handful of hashes.
- Residue binding (`n ≡ r(header) mod 2^b`) fails the same way: covering every
  residue class costs `2^b · m / density` candidate tests, while one honest block
  costs `m · 2^b / density`. One block of work buys a permanent table.

Single-use witnesses make a precomputed pool spendable exactly once, so total
work is conserved and precomputation degenerates into mining in advance with no
advantage. `n` in the paragraph above is not a nonce: the miner searches the
number space for chains, and the block commits the list through
`pow_commitment = BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)`. The
commitment is parent-relative on purpose — a set root would depend on the whole
claimed set, so a miner building on a non-canonical branch would need that
branch's set state to produce a valid commitment.

`difficulty` is the number of witnesses a block must claim, and cumulative
difficulty is the fork-choice weight. `pouw_chain_length` is epoch-invariant and
is the coarse knob: each extra link multiplies the expected search cost by
roughly `ln(n) / 2`.

Honest framing: this is verifiable mathematical search. A verifier pays `L`
primality tests where a solver pays the full search, every accepted witness is
independently checkable number-theoretic data rather than a burned digest, and
the accumulated witness set is a publishable dataset. It is not a claim about
artificial intelligence, quantum computing or externally funded science; those
belong to the AetherCompute settlement layer, which remains fail-closed.

This block-level deterministic kernel is separate from user-funded
AetherCompute result settlement. Settlement remains fail-closed until an exact
audited circuit and verifier key are activated. The current PoUW does not
justify claims of a SNARK, useful external dataset processing, succinct
verification, or audited mainnet economic security. The search rule makes
verifier cost bounded and measurable, but this revision still lacks a published
analysis of ASIC advantage, deterministic-race centralization, fork rate, and
adversarial scheduling. It is a research computational-work protocol, not a
production-ready PoUW claim.

The Explorer at `http://127.0.0.1:8080` uses a Rust-compiled WebAssembly
renderer. It shows blocks, private-transaction inclusion records,
AetherCompute commitments and deployed WASM applications. Scientific object
locators, credentials and transaction payloads are not returned to the
browser. The application convention is a bounded `hyphen.app` JSON custom
section with ABI version, category (`defi`, `game`, or `utility`), name and
version. Classified applications must export `hyphen_query` and
`hyphen_execute`; queries are consensus-enforced read-only. The page, its
script, its module and every `/api/…` route are served by Courierust's own
HTTP/1.1 + HTTP/2 server — no web framework sits between the state and the
socket, and every answer carries the same media type, `nosniff`,
`no-referrer` and content-security policy. Rebuild the checked in browser
module after renderer changes with:

```powershell
.\scripts\build-explorer-wasm.ps1
```

Consensus and storage serialization uses RustBinary 0.1.8 with the
schema-guided compact profile: fields in declaration order with no field names
and no type tags, canonical little-endian varints, length-prefixed containers
and trailing bytes rejected. Every call sets byte and collection limits, so one
value has exactly one accepted encoding. The profile lives in the `hyphen-wire`
crate; the node, pool, miner and wallet take it from there instead of
re-implementing it, and ordered sets travel through `CanonicalSet`, which
rejects duplicate or descending elements on decode. Consensus maps use ordered
containers because the binary codec preserves map iteration order. PoUW changed
the block version, consensus parameters and genesis hashes, and the compact
profile changed them again. Normative identities are in
`test-vectors/chain-identity-v6.json`; `chain-identity-v1.json` and
`chain-identity-v5.json` are kept as historical records of superseded
identities. Old databases are rejected before state
mutation. Both the identity and the genesis block are computed inside `hyphen-core` from
`ChainConfig` alone, so there is exactly one implementation: `ChainIdentity::of`
and `build_genesis_block`. The miner, the pool and the wallet each pin the same
published revision of these crates in their own lockfile, so none of them links a
local checkout and each can build from a clean clone; both also compare the
derived identity against the canonical vector in a unit test, which fails the
moment they drift. A copied constant without that test pins a client to a chain
that no longer exists, and the handshake then fails on the first byte.
RustBinary has not been independently audited for Hyphen.

### Dependency policy

The workspace keeps no dependency mirror and no `[patch.crates-io]` override.
Every dependency is a crates.io release pinned by the committed lockfile, and
the default answer to "do we need this crate" is no: the hex codec, the base58
codec, the SNTP client and the NTP-adjusted clock live in `hyphen-crypto` and
`hyphen-core`, because a consensus crate should not import a supply chain for
forty lines of byte shuffling. The crates the chain does take from outside the
repository are the ones that answer a question the repository should not answer
itself — the bounded binary codec (`rustbinary`, frozen in `hyphen-wire`), the
DNSSEC-validating resolver for seed names (`recurse-x`), the calendar behind
operator-facing timestamps (`tzcraft`), the HTTP/1.1 + HTTP/2 stack that
serves the explorer, the pool's accounting API and both ends of the payout link
(`courierust`, which has no dependencies of its own and replaced axum, tower and
hyper in this workspace), and the peer block list that enforces the ban policy
(`libp2p-allow-block-list`, which the umbrella `libp2p` crate does not re-export
as a feature).

The miner carries no proxy engine: `--via-proxy` performs the SOCKS5 or HTTP
`CONNECT` handshake itself, so whatever proxy the operator runs — including a
`corduit` service with its `socks5` or `http` inbound — stays an external
process that the miner dials rather than a library it links.

The contract VM is Wasmi 2.0, a pure-Rust interpreter with built-in fuel
metering, rather than a JIT runtime. That choice is deliberate:

- execution is deterministic across hosts, so contract fuel consumption is a
  reproducible consensus value and there is no code generator in the consensus
  path;
- the dependency graph drops from 368 crates to 267, and with it the whole
  Cranelift, `bindgen`, CMake, `libclang` and native-toolchain surface;
- Wasmi has been independently audited twice, including by Runtime Verification
  for the Stellar Development Foundation.

The workspace enables Wasmi's `auto-dispatch` feature explicitly. Without it the
engine always selects its tail-call backend; at `opt-level` 0 or 1 LLVM cannot
turn those dispatches into sibling calls, so every executed instruction grows the
host stack and a long-running contract aborts the process. `auto-dispatch` picks
the loop backend exactly when sibling-call optimization is unavailable, and
`MAX_CONTRACT_RECURSION_DEPTH` bounds the remaining depth. Both are pinned by the
contract tests in `crates/hyphen-vm/tests`.

`proc-macro-error2` 2.0.1, which Wasmer pulled in transitively, is gone from
the graph entirely. Upstream never published a fix for its
`pub extern crate proc_macro;` visibility bug, so removing the runtime that
needed it was the only correct resolution.

Contract gas units changed with the runtime: instruction fuel is now charged by
the Wasmi model rather than one point per Wasmer operation. Host-side charges
(`GAS_STORAGE_READ`, `GAS_HASH`, `GAS_LOG`, ...) are unchanged. Any contract
budget tuned against PoUW v1 gas numbers must be re-measured.

### PoUW v3: verifiable mathematical search

`hyphen-pow::vms` implements the active workload:

```text
witness n  <=>  n, 2n+1, 4n+3, ... (length L) are all prime and all < 2^64
```

The block claims `difficulty` distinct witnesses of the epoch's chain length.
Deterministic primality is not assumed, it is proven: Miller-Rabin with the
seven-base set that Jaeschke, Sorenson and Webster proved exact for every
`n < 2^64`. No probabilistic error bound enters consensus and no big-integer
dependency is needed. A verifier pays `L` primality tests (microseconds) where a
solver pays the full search (seconds to minutes), every accepted witness is
independently checkable number-theoretic data rather than a burned digest, and
the accumulated witness set is a publishable dataset.

Binding a witness to a header with a derived filter or residue class is unsound,
and the reason is worth stating precisely, because the intuitive design is the
broken one. A solver who builds a pool of `m / p` chains satisfies *every*
future header: the filter is evaluated once per header while the pool persists,
so the marginal cost of each further block collapses to a handful of hashes.
Residue binding of width `b` fails identically, because the cost of covering
every residue class equals the cost of one honest block. Witnesses must
therefore be **single-use**: `hyphen-state::WitnessSet` records claimed
witnesses in a sparse Merkle set, a precomputed pool can be spent exactly once,
total work is conserved, and precomputation degrades into mining in advance with
no advantage at all.

`pow_commitment` chains each block to its parent:
`BLAKE3(domain ‖ parent_commitment ‖ height ‖ witnesses)`. The commitment is
parent-relative on purpose — a set root depends on the whole claimed set, so a
miner building on a non-canonical branch would need that branch's set state to
produce a valid commitment. Single-use membership stays a node-local oracle over
that branch's own claimed set, and a reorg releases the detached block's
witnesses so the reverted branch can be re-attached unchanged.

## Neural-cryptography challenge (research contract)

The repository also ships the Alice/Bob neural challenge: an on-chain contract
that publishes a random two-layer perceptron `A` and a target `y* = A(x*)`, and a
fully specified prover that searches for a preimage `x`. Verification is one
fixed-point forward pass; the search is Levenberg–Marquardt over Q32.32 integers.
The design, the soundness argument for using the inverse problem rather than
"learn Alice's weights", the measured cost envelope, the contract ABI and its open
obligations are in [docs/research/neural-cryptography.md](docs/research/neural-cryptography.md).

Three things it is not:

- it is not the block proof-of-work, and it does not add chain weight;
- it is not a ten-minute mining clock — an on-chain verifier must regenerate the
  weights, so the width axis saturates long before that; the measured envelope is
  published rather than asserted;
- it is not a claim about AI usefulness. It is a deterministic inverse problem with
  a cheap, exact verifier.

The prover is a normal Rust binary, no node required:

```bash
cargo run --release -p hyphen-neural --bin bob-miner -- solve \
  --seed <64-hex> --epoch 1 --hidden 512
```

## What this borrows from Kaspa, and what it does not

Kaspa is the reference point for a mature, high-throughput PoW chain, and several
of its engineering decisions are worth copying. Hyphen borrows the ones that are
about process, not consensus:

- **A separated template provider.** The node produces block templates, the pool
  turns them into share work, and the miner only searches. Hyphen's `hyphen-transport`
  template protocol follows the same split, with the node as the only source of
  truth for headers and transaction sets.
- **Explicit share accounting.** Pool modes (solo, prop, pplns, pps, pps+, fpps)
  are named, fee-basis-points are explicit, and settlement is persisted before it
  is reported. The pool never guesses a balance.
- **Identity pinning per network.** Network magic, consensus-parameter hash and
  genesis hash are published vectors; node, miner and pool derive them, the wallet
  pins them with a drift test.
- **Release discipline.** Reproducible builds, checksummed artifacts, a pinned
  toolchain, nightly fuzzing and a strict dependency policy.

It does not borrow Kaspa's consensus. Kaspa orders a block DAG with GHOSTDAG's
blue set; Hyphen's H-BFM fuses a finite braid under a total rank and is explicitly
not a GHOSTDAG or PHANTOM implementation. Kaspa's kHeavyHash is a digest-grinding
ASIC workload; Hyphen's PoUW v3 is single-use Cunningham-witness search, and the
neural challenge is a research contract on top, not a replacement for either.
Copying Kaspa's hashing or its DAG ordering would have produced a worse copy of a
chain that already exists.

A concrete audit of issue classes reported against `rusty-kaspa`, checked against
this tree rather than dismissed by analogy:

| Kaspa issue class | Status here |
| --- | --- |
| Header built with a hardcoded pre-upgrade block version | Not applicable. One compile-time `FROZEN_BLOCK_VERSION = 5`, hashed into `consensus_params_hash` and used by genesis, the validator, authorization, replay and the node. There is no runtime switch to get wrong; changing it is a new chain identity. |
| Difficulty weighting that mis-scores parents or decays over depth | Cumulative difficulty is an exact `u128` sum of `header.difficulty`, which the validator requires to equal the integer-only LWMA controller's expectation for the current window (`chain.rs`: `expected_difficulty`). No floats on the consensus path, no per-round weighting term. The window is read from the canonical height index under the current tip, and a block with an inconsistent parent set or height is rejected before it is scored. |
| Ordering that is not a total order, or a tie-break that is not unique | `rank(b) = (logical_round, lane, block_hash)` over certified identifiers; the ready set is a `BTreeSet<Rank>` and the minimum is unique. |
| Trusting an imported UTXO/pruning-point snapshot before validating it | No snapshot import surface exists. Sync is block-only (`GetBlocks`/`GetBlock`), so state is always rebuilt by execution. |
| Adversarial peers that degrade a node without consequence | Undecodable envelopes, payloads or sync responses beyond the structural budget are scored; three strikes in ten minutes bans the peer for an hour and drops the live connection. Contextual failures are deliberately not scored. See [docs/security/peer-policy.md](docs/security/peer-policy.md). |

## Run a node

Install Rust 1.97.0 and a host C/C++ toolchain, then build with the committed
lockfile:

```bash
cargo build --release --locked -p hyphen-node
```

Print the chain identity before opening an existing database:

```bash
./target/release/hyphen-node --network devnet --print-chain-identity
```

The current devnet v2 identity is:

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=521f6cdc47f4424c1ea7b9f4d6770cf114f620cdff62958060f8c6953cb69de8
genesis_hash=5f7c144f0ef27880259b2429e46ef175685da679916fcc6b80c45f457465e32d
```

Start a local node:

```bash
./target/release/hyphen-node \
  --network devnet \
  --data-dir ./data/devnet-node \
  --listen /ip4/127.0.0.1/tcp/48334 \
  --rpc-bind 127.0.0.1:48333 \
  --template-bind 127.0.0.1:3350 \
  --explorer-bind 127.0.0.1:8080
```

The explorer is HTTP. RPC, P2P, and the template protocol are binary protocols;
opening those ports in a browser is not a valid health check. Use `--help` as
the authoritative CLI reference.

## What the base chain verifies

A block is accepted only after its chain identity, parent, height, timestamp,
difficulty, scientific PoUW commitment, transaction encodings, signatures, range proofs,
nullifiers, fees, roots, reward, and miner authorization pass validation. State
updates are committed atomically. The backend can validate and execute a
planned branch switch with rollback, but complete live reorg handling still
needs P2P branch intake, automatic branch selection, and reconciliation of all
dependent services.

Inbound peers are scored only on faults the node can prove locally: an envelope
or payload that does not decode, or a sync response that exceeds its structural
budget. Three such faults inside ten minutes block the peer for an hour; the block
list closes live connections and refuses reconnects. A well-formed block that
fails contextual validation is not counted, because the node validates against
its current tip and catch-up sync would otherwise ban honest relays. The policy,
including its in-memory limitation and the absence of any snapshot-import surface,
is specified in [docs/security/peer-policy.md](docs/security/peer-policy.md).

There is no switchable block version to disagree with: `FROZEN_BLOCK_VERSION` is
the only version in the build, it is hashed into the consensus-parameter
identity, and genesis construction, header validation, authorization and replay
all read that same constant. A profile change is a new build and a new identity
vector, not a runtime toggle that a header builder can silently miss.

Canonical transaction ordering is a research-profile rule. It makes a declared
set mutation-detectable and removes arrival order as a tie-breaker. It does not
force a miner to include a transaction and therefore does not eliminate
censorship or MEV.

## Mathematical core and proof ledger

This section states only the properties represented by the current reference
code. Full protocol claims require the open obligations listed after each
result.

### Common notation and assumptions

Let `H_d(x) = BLAKE3(d || 0x00 || x)` be a domain-separated 256-bit hash. The
arguments below assume collision resistance and second-preimage resistance of
`H_d`. `Sig` is assumed EUF-CMA secure. `G` is the prime-order Ristretto255 base
point, scalars are in `Z_l`, and discrete logarithms in the group are assumed
hard. These are computational assumptions, not unconditional proofs.

### H-WES: rejecting stale state restoration

For a key `x`, let the authenticated latest-version map at height `t` contain

```text
V_t[x] = (version, status, archive_index, value_hash, head_hash).
```

The archive is append-only and committed by an MMR root `A_t`. A restoration
witness contains an archived record `r`, an MMR inclusion path for `r`, and a
membership path proving `V_t[x]`. Validation requires:

```text
r.key = x
H_record(encode(r)) = V_t[x].head_hash
r.version = V_t[x].version
V_t[x].status = Expired
r.value_hash = V_t[x].value_hash
MMRVerify(A_t, V_t[x].archive_index, H_record(encode(r)), pi_archive) = 1
MapVerify(root(V_t), x, V_t[x], pi_latest) = 1.
```

**Proposition (stale-version rejection).** If the latest map is binding and the
record hash is collision resistant, an adversary cannot restore a record
`r_old` with version lower than the committed version except with negligible
probability.

**Proof.** A successful witness must satisfy both authenticated paths. The map
path fixes one tuple `V_t[x]`; binding prevents a second tuple at the same root
and key. Equality of versions then requires
`r_old.version = V_t[x].version`, contradicting that `r_old` is older. If the
adversary substitutes record fields while preserving `record_hash`, it produces
a second preimage or collision for `H_record`. Therefore success reduces to
breaking one of the assumptions. The MMR alone is insufficient: it proves only
that a record was appended, not that it is latest. That is why both proofs are
mandatory.

The unqualified claim that append-only recovery is impossible would itself be
false: a prover can send the complete archive in one round and let the verifier
recompute its commitment and scan every suffix record. The actual lower bound
needs a succinctness condition. In a membership-only authenticated-array model,
if `m` cells follow the candidate and a verifier opens only `q<m`, an unqueried
cell can contain either an unrelated record or a newer version of the same key.
With perfect completeness and miss probability at most `epsilon`, its expected
number of authenticated queries `Q` must satisfy

```text
E[Q] >= (1-epsilon)m.
```

With two-sided error at most `epsilon`, the corresponding bound is
`E[Q] >= (1-2epsilon)m` for `epsilon < 1/2`.

Secure recovery must therefore pay for authenticated latest state, continuing
witness/index maintenance, or linear suffix data/prover work. H-WES chooses a
fixed-size latest root with provider-held tree/body data and on-demand
`O(log K + log N)` proofs; it does not evade this lower bound.

Lifecycle is defined per incarnation `(x,v)`:

```text
Live(x,v) -> Expired(x,v) -> Recovered(x,v; successor=v+1)
                              \-> Consumed(x,v).
```

Recovery atomically appends a terminal event and creates `Live(x,v+1)`;
consumption has no successor. Authorization binds the action, height, new lease,
and pre-state root. The reference model now tests terminal receipts,
action-bound authorization, and no resurrection after consumption.

For spendable objects, the nullifier set is monotone:
`N_t subseteq N_(t+1)`. If a nullifier `z` was inserted at height `i`, then
`z in N_i` and hence `z in N_t` for every `t >= i`. A restoration transition
that rejects membership in `N_t` cannot revive an already-spent object. The
reference profile deliberately excludes shielded notes until ownership,
latest-state, and non-membership are constrained by a circuit soundly bound to
the chain's Ristretto255/BLAKE3 commitments.

The persistent SMT stores only non-default nodes. For namespace `ns`, leaf
`(k,v)` is `H_leaf(ns,k,v)` and every internal node commits to namespace, depth,
left child, and right child. A 256-sibling membership or non-membership proof
reconstructs exactly one root. Two different openings for one `(ns,k,root)`
imply a first level at which equal parent hashes have different ordered child
pairs, reducing binding to a collision in the domain-separated node/leaf hash.
All changed leaves, ancestors, and the root are committed by one optimistic
sled transaction and flushed before success is returned.

The proof store commits each bounded blob by content hash and each chunk by
`H_chunk(object,index,count,len,bytes)`, then commits chunk leaves in a Merkle
root. A valid chunk proof binds position, count, length, object identity, and
bytes. Full reconstruction checks the complete blob hash. P2P sync serves typed
SMT proofs, blob metadata, and chunk proofs under strict response limits.

An availability certificate means that `2f+1` distinct committee seats signed
after validating the complete blob and exact chain/epoch/retention context. At
least `f+1` signers are honest under the seat fault bound, so honest signers had
the blob at signing time. It does **not** prove that any copy remains available
later; durable retention still needs an enforceable provider/slashing or
erasure-coded availability protocol.

The research-chain public H-WES profile now commits all five roots atomically,
expires at most 1024 objects per block in canonical order, and rolls state back
with reorgs. Open obligations are provider incentives and repair, state-rent
policy, a complete shielded recovery/consume relation, benchmarks, and
independent review.

### H-BFM: a necessary fusion mechanism, not a novelty claim

Let `G_e = (B_e, E_e)` be a finite acyclic braid for epoch `e`. At each step,
take the currently zero-indegree blocks and choose the minimum under the total
rank

```text
rank(b) = (logical_round(b), lane(b), block_hash(b)),
```

as implemented by `rank` in
[crates/hyphen-consensus/src/fusion.rs](crates/hyphen-consensus/src/fusion.rs);
the third component is the certified opaque block identifier, so ties inside a
round are broken by lane and then by hash.

Append that block to the fused order and delete its outgoing edges.

**Lemma (unique canonical order).** For a fixed finite DAG and a total `rank`,
the algorithm terminates and returns exactly one topological order.

**Proof.** Every non-empty finite DAG has at least one zero-indegree vertex.
Because `rank` is total, the eligible set has one unique minimum. Removing that
vertex preserves acyclicity. Induction on `|B_e|` gives a unique choice at every
step and termination after exactly `|B_e|` steps. Every edge's source is
removed before its destination becomes eligible, so the result is topological.

This lemma does not prove that two nodes possess the same `G_e`. Agreement on
the braid, missing-data behavior, conflicting state accesses, and rewards are
separate consensus problems and remain open.

The research candidate is instead fairness over a deliberately finite visible
domain. Consensus admits only

```text
M(tx) = (txid, fee_class, encoded_len, public_conflict_tag).
```

For signed receive sequences from `n=3f+1` work seats and `q=2f+1`, define
`x <_E y` when at least `q` seats report `x` before `y`. Opposite edges cannot
both exist because `2q=4f+2>n`, but longer strong-majority cycles can exist.
The implementation therefore emits strongly connected components as fair
batches. Hidden amounts, parties, and semantics never enter the ordering
function and receive no fairness claim.

For an inclusion receipt and proposal certificate, both signer sets have size
`q=2f+1` in `n=3f+1`, hence intersect in at least `f+1` seats. The durable
`HonestReceiptVoter` records the transaction obligation and flushes it before
returning a seat-bound signature. Therefore the intersection contains an honest
seat that refuses an order omitting that transaction. This proves omission
resistance only when the same active committee and honest-voter APIs are
mandatory. P2P transports typed vote/quorum receipts, but the node does not
activate them because no finalized committee profile is wired in.

### H-FOC: quorum safety, not unconditional 100 ms finality

For a committee of `n = 3f + 1` seats, a certificate contains `q = 2f + 1`
valid signatures over one chain-bound ordering statement. For any two quorum
sets `Q1` and `Q2`,

```text
|Q1 intersect Q2| >= |Q1| + |Q2| - n
                  = 2(2f + 1) - (3f + 1)
                  = f + 1.
```

At most `f` seats are Byzantine, so the intersection contains an honest seat.
If honest voters sign at most one order root for the same `(chain, epoch, view,
slot, parent_frontier)`, two conflicting certificates require that honest seat
to equivocate. Thus two conflicting certificates cannot both exist unless the
fault bound, signature assumption, or honest-voter rule is broken.

This is a safety argument only. A 100 ms path additionally needs a synchronous
period with network delay `Delta`, signature aggregation and verification,
proposal dissemination, and scheduling all fitting the budget. In an
asynchronous network, deterministic bounded-time consensus is impossible; the
repository therefore makes no global 100 ms finality claim.

Seats are sampled with replacement from finalized prior-epoch work. Under an
independent unbiasable-seed model and adversarial work fraction `alpha`, capture
probability is

```text
P_bad = sum_(i=f+1)^n C(n,i) alpha^i (1-alpha)^(n-i).
```

Grinding over `g` candidate seeds raises the union-bound estimate to at most
`min(1,gP_bad)`. Fixed-committee intersection does not by itself prove
cross-epoch safety. The inactive H-FOC' state machine now implements durable
PREPARE/COMMIT locks, timeout votes carrying the highest prepare QC,
lock-preserving view-change proposal checks, and old/new committee handoff QCs
bound to one finalized checkpoint. Safety tests include crash/restart
anti-equivocation and handoff context replay rejection. It still has no live
pacemaker, leader election, committee beacon, or block-execution path.

The current chain seed is `BLAKE3(last epoch block hash)` and is grindable. It
must not be substituted into the independent-seed probability model as if it
were unbiasable. Acceptable activation routes and the Circom field-bridge
obstruction are stated in
[`cryptographic-activation-gates.md`](docs/security/cryptographic-activation-gates.md).

### H-SAC: amount opening and scoped ownership

An output commitment is

```text
C = vG + rH,
```

where `v` is the amount, `r` is a blinding scalar, and `H` is a generator whose
discrete-log relation to `G` is unknown. A disclosure reveals `(v, r)` for one
output and verifies `C = vG + rH`. Binding follows from discrete-log hardness:
two distinct openings imply

```text
(v - v')G = (r' - r)H,
```

which reveals the discrete-log relation between `G` and `H` when
`r != r'`. Hiding is provided by uniformly random `r` in the usual Pedersen
model.

Ownership uses a Schnorr proof. For one-time public key `P = xG`, the prover
samples `k`, sets `R = kG`, computes
`c = H_challenge(context, R, P)`, and returns `s = k + cx`. Verification checks
`sG = R + cP`. The context binds chain ID, transaction ID, output index, global
index, auditor public key, scope hash, validity interval, nonce, commitment,
public key, amount, and blinding. Under the forking-lemma model, two accepting
transcripts with the same `R` and different challenges extract
`x = (s-s')/(c-c')`; forging therefore reduces to discrete log plus the random
oracle assumption.

The package is not encrypted and proves neither full transaction provenance nor
source-of-funds legality. Confidential transport and the larger provenance
circuit are still required.

For private state `X`, prior public chain information `P`, compliance output
`Y=F(X,P)`, and adversarial view `V`, zero-error correctness implies

```text
I(X;V | P) >= H(Y | P).
```

With error `epsilon` and output range size `M`, Fano's inequality gives

```text
I(X;V | P) >= H(Y|P)-h_2(epsilon)-epsilon log_2(M-1).
```

A transcript simulatable from `(P,Y)` is task-optimal in the computational
sense. The current v0 package reveals the amount and blinding, so it is not
optimal for a task that needs only one compliance bit. Its exact plaintext
fields are now exposed through `DISCLOSED_FIELDS_V0`.

Full statements and boundaries are in the [H-WES lower bound and object
model](docs/research/h-wes-theorem-and-object-model.md), [private visible-domain
fair ordering and H-FOC'](docs/research/private-visible-fair-ordering.md),
[H-SAC leakage lower bound](docs/research/h-sac-leakage-lower-bound.md), and the
[research ledger](docs/research/four-core-innovations.md).

No shielded H-WES or H-SAC Circom circuit is claimed. The live transaction
relations use Ristretto255 and BLAKE3 while ordinary Circom artifacts operate
over BN254; a sound bit-level/group bridge or a versioned commitment migration
is required. No independent circuit audit has been commissioned or supplied.

## Verification

Run the same base-chain gates used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
cargo audit --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
cargo audit --file crates/hyphen-fuzz/Cargo.lock --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119
```

Nightly CI runs bounded transaction, RPC, P2P, and canonical-codec decoder
fuzzing. Passing these
checks establishes reproducibility for the tested revision; it is not a formal
proof or an external security review.

The two audit exceptions are optional `hickory-proto` dependencies retained in
libp2p's lock graph. Hyphen disables libp2p default features, DNS, and mDNS, so
those crates are not in the built runtime graph. Any new non-ignored RustSec
vulnerability fails CI. Informational unmaintained/unsound transitive warnings
remain tracked and are not presented as resolved.

Because libp2p's DNS transport stays out, `/dns4`, `/dns6` and `/dns` boot nodes
are resolved by the node itself through `hyphen-network`'s seed resolver, which
is built on RecurseX: a resolver that walks the delegation tree from the root
servers and validates DNSSEC, with the HyphenTeam crates as its only
dependencies. An operator who must route DNS through their own infrastructure
names upstreams instead:

```powershell
# Iterative, DNSSEC-validating (the default)
.\target\release\hyphen-node.exe --network mainnet `
    --boot-nodes /dns4/seed.example.org/tcp/48334/p2p/12D3Koo... --data-dir node

# Through an encrypted upstream; the `#name` fragment is the TLS identity
.\target\release\hyphen-node.exe --network mainnet `
    --dns-upstream tls://1.1.1.1:853#cloudflare-dns.com `
    --dns-upstream https://dns.google/dns-query#dns.google `
    --boot-nodes /dns4/seed.example.org/tcp/48334/p2p/12D3Koo... --data-dir node
```

A seed whose host does not resolve is a startup error naming the host, never a
silently dropped peer, and an isolated node re-resolves on its bootstrap retry
tick so a rotated seed record does not strand it until restart. Wall-clock
values that operators read — the genesis instant, sync logs — are rendered in
RFC 3339 by `tzcraft`; the chain's own bytes keep the frozen millisecond
encoding.

## CI and automated releases

`CI` runs on pushes and pull requests. A successful `CI` run on `main` triggers
the `Release` workflow. It rebuilds `hyphen-node` on Linux, Windows, and macOS,
packages the executable with build metadata and available debug information,
publishes SHA-256 files, and creates a GitHub prerelease tied to the exact commit.
Pull requests never receive release permissions.

Automated releases are reproducible development artifacts, not a declaration
of mainnet readiness. Verify the checksum and the embedded commit before use.

## Repository boundaries

Wire formats and chain identity are compatibility contracts. Change them in
this order: update the specification, update canonical vectors, update and test
the base chain, then update each independent client against the exact base-chain
commit. See
[`docs/architecture/repository-boundaries.md`](docs/architecture/repository-boundaries.md).

## Security

Do not publish mnemonics, identity keys, payout tokens, or private vulnerability
details. See [SECURITY.md](SECURITY.md) for reporting instructions and the
current support boundary.

## License

Hyphen is licensed under the PolyForm Strict License 1.0.0. See
[LICENSE](LICENSE) for the complete terms.
