# Cryptographic activation gates

Status: mandatory preconditions, not implemented-feature claims. This document
records why the current PoW-derived seed and the current Ristretto255/BLAKE3
transaction relations cannot honestly be called an unbiasable beacon or an
audited Circom circuit.

## 1. Seed bias is a protocol property

Let a candidate source produce independent, identically distributed outputs
`Y_1,...,Y_g`, and let an adversary see the candidates before choosing which
valid transcript is published. For an event `E` with one-candidate probability
`p=Pr[Y in E]`, the strategy “publish an output in `E` whenever one exists” yields

```text
Pr[Y_selected in E] = 1-(1-p)^g.
```

For `0<p<1` and `g>1`, this is strictly greater than `p`. Without independence,
the equality need not hold; the union bound is only `Pr[union_i(Y_i in E)] <= gp`,
and the exact bias depends on the joint distribution. Hashing the selected
candidate cannot remove the bias: a deterministic post-processing function
cannot erase the adversary's selection channel. It can only change which event
is favored.

The current chain computes an epoch seed from the previous epoch's final block
hash. A miner can vary nonce, extra nonce, transaction set, and potentially
withhold a found block. Consequently this seed is **grinding-exposed**. It is
valid as a deterministic PoW parameter seed, but it does not satisfy the
independent-uniform seed assumption used by the committee binomial estimate.

### Commit/reveal does not by itself fix this

Suppose an adversarial final revealer first observes the honest aggregate `h`
and has committed value `a`. It can choose between revealing, producing
`H(h,a)`, and aborting, producing the protocol's fallback output. Unless both
branches are forced to the same unique output with an enforceable availability
mechanism, the adversary again chooses from at least two candidates. Slashing
can price this option; it does not make the distribution cryptographically
unbiasable.

### Acceptable activation routes

One of the following must be implemented and independently reviewed:

1. A unique threshold signature/VRF beacon with authenticated DKG, public share
   verification, threshold unforgeability, uniqueness for one epoch message,
   proactive or epoch key handling, and a liveness proof under share withholding.
2. A VDF-backed beacon whose input availability, delay assumption, verification
   equation, difficulty retargeting, and specialized-hardware advantage are
   explicit.

The chain must verify the complete beacon certificate. Accepting a naked
32-byte `seed` from RPC, config, a leader, or a trait implementation is not a
certificate and must not unlock H-FOC'.

## 2. Committee probability is conditional

With independent work-proportional draws, adversarial work fraction `alpha`,
`n=3f+1`, and an independent seed, the probability of more than `f`
adversarial seats is

```text
P_bad = sum_(i=f+1)^n binom(n,i) alpha^i (1-alpha)^(n-i).
```

This is a conditional model, not a theorem about the current chain. With at
most `g` selectable seeds, a union bound gives

```text
P_bad_grind <= min(1, g P_bad).
```

Correlation between pools, adaptive corruption, work attribution errors, and
repeated seats require separate analysis. No fixed committee size repairs a
biasable election source.

## 3. Circom field/commitment obstruction

Circom normally compiles arithmetic over the BN254 scalar field `F_q`. Hyphen's
current confidential transaction relations use:

- Ristretto255 group elements and scalars in `Z_l`;
- compressed Ristretto encodings;
- BLAKE3 domain-separated hashes;
- Pedersen, CLSAG, and range-proof relations implemented outside BN254.

A Circom signal is an element of `F_q`; it is not automatically a Ristretto
scalar, a 255-bit string, or a compressed point. Mapping a 256-bit digest to one
field element by reduction is not injective: if distinct integers differ by
`q`, they represent the same field element. Therefore the unconstrained rule

```text
signal = digest mod q
```

does not prove equality of the original 256-bit digests.

A sound bridge must instead constrain bit decomposition and range, implement
the exact BLAKE3 compression relation (or commit to a versioned field-friendly
replacement), and constrain Ristretto encoding/decompression and the required
group equations. If a field-friendly in-circuit commitment is introduced, the
chain also needs a binding proof between that commitment and the existing
Ristretto/BLAKE3 consensus object. Merely supplying both as public inputs leaves
them unrelated.

## 4. Shielded H-WES relation required before activation

For public statement `Z` and private witness `W`, a shielded recovery circuit
must constrain at least:

```text
Z = (chain_id, pre_state_root, post_state_root, history_root,
     latest_root, nullifier_root, key_commitment, old_version,
     new_version, action, lease, authorization_context)

W = (expired_record, archive_path, latest_path, owner_secret_or_policy_witness,
     nullifier_path, successor_body, successor_randomness)
```

The circuit relation must prove archive inclusion, latest-only status,
authorization, nullifier non-membership/monotonic update, `new_version =
old_version+1`, the exact lifecycle transition, and the public root transition.
Every hash and commitment in those equations must be the same relation verified
by Rust consensus or connected through a proved binding bridge.

No such circuit, proving-key ceremony, Rust verifier, malformed-proof corpus,
or cross-implementation vector currently exists in this repository. A small
Poseidon/Merkle demonstration would not prove the live chain relation and is
therefore intentionally not presented as H-WES.

## 5. H-SAC circuit and audit evidence

An H-SAC circuit additionally needs a frozen compliance function `F`, chain
inclusion, ownership/provenance, credential-policy membership, scope, auditor,
expiry, and task-output constraints. The leakage theorem determines a lower
bound; it does not instantiate this relation.

“Audited” requires evidence external to implementation authors: named auditor,
scope and commit/circuit hashes, proof-system and setup scope, findings, fixes,
retest status, and a published report. Internal tests, Circom compilation, R1CS
generation, and this document are not an audit. Until that evidence exists,
README and release notes must say **unaudited and inactive**.
