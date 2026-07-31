# Hyphen

[中文说明](README_CN.md)

Hyphen is an experimental privacy-oriented, CPU-first proof-of-work base chain
written in Rust. This repository contains the node, consensus and state
transition code, transaction validation, networking, RPC, cryptographic
libraries, executable research models, and consensus test vectors.

It does not contain the Hyphen Miner, Hyphen Pool, or Hyphen Wallet products.
Those are independent repositories with independent lockfiles, CI, releases,
and security boundaries. A protocol change can require coordinated updates,
but it does not make those repositories part of this one.

## Read this first

Hyphen is not a launched mainnet and has not had an independent consensus or
cryptographic audit. `mainnet` is a research profile. The current devnet can be
built and tested, but that is not evidence that real assets are safe.

The four named research mechanisms are executable reference models, not active
devnet consensus:

| Mechanism | Code and vectors | What is actually established | Missing before activation |
| --- | --- | --- | --- |
| H-WES recoverable state expiry | Public profile integrated on research chains | Atomic five-root state, signed public creation, bounded deterministic expiry and reorg rollback | Shielded recovery/consume circuit, incentives, benchmarks, audit |
| H-BFM parallel block fusion | Present | Unique deterministic order for one agreed finite DAG | DAG set agreement, availability, conflict semantics, incentive and liveness proof |
| H-FOC' fair finality | Present, inactive | Durable PREPARE/COMMIT locks, timeout certificates, lock-carrying view change, dual-committee handoff, receipt obligations and typed P2P receipt transport | Unbiasable beacon, live pacemaker/leader, finalized committee source, block-execution integration, WAN benchmarks, audit |
| H-SAC selective audit disclosure | Present, inactive | One-output amount opening, scoped Schnorr ownership proof, and a leakage lower bound | Frozen compliance relation, confidential delivery, chain-provenance ZK circuit, proving/verifying integration, independent circuit audit |

AetherCompute task publication and the deterministic WASM ledger are integrated
with research-chain block execution, RPC/P2P ingress, mempool templates, state
roots and reorg rollback. Scientific result settlement remains fail-closed
until an exact audited proof verifier is installed. See the
[AetherCompute boundary](docs/research/aether-compute.md).

Consensus and storage serialization uses RustBinary 0.1.2 with the explicit
fixed-width little-endian legacy profile. Every call sets byte and collection
limits and rejects trailing bytes. Consensus maps use ordered containers because
the binary codec preserves map iteration order. Published devnet v2 chain
identity vectors remain unchanged. RustBinary has not been independently audited
for Hyphen.

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
consensus_params_hash=bb0c74b93362b8265d65af5dd48796084448e6b3022c39825476ce1b84439902
genesis_hash=854adc605062fb872dcd20a535dca1ec25d4af58689f1be50e6c26df0c841295
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
difficulty, proof of work, transaction encodings, signatures, range proofs,
nullifiers, fees, roots, reward, and miner authorization pass validation. State
updates are committed atomically. The backend can validate and execute a
planned branch switch with rollback, but complete live reorg handling still
needs P2P branch intake, automatic branch selection, and reconciliation of all
dependent services.

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
rank(b) = (parent_frontier_hash(b), producer_key(b), block_hash(b)).
```

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
those crates are not in the built runtime graph; boot nodes must currently use
IP multiaddresses. Any new non-ignored RustSec vulnerability fails CI.
Informational unmaintained/unsound transitive warnings remain tracked and are
not presented as resolved.

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
