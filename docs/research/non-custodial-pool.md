# Hyphen Non-Custodial Pool Protocol

Status: experimental protocol v3. It reduces delegated block authority, but
does not yet provide a complete trustless shared-pool system.

## Objective

Hyphen separates two powers that conventional pools often combine:

```text
shared reward variance reduction
AND
miner-held final block authorization
```

The pool can account for shares, operate VarDiff, relay templates, and provide
PPLNS/PPS/FPPS calculations. It cannot produce a consensus-valid block for a
miner unless that miner authorizes the exact solved header and reward keys.

This document calls the node-to-pool Template Provider protocol TP v2 and the
pool-to-miner protobuf protocol Pool v3. Legacy Stratum V1 is a local share-only
adapter; it cannot carry the frozen block authorization and is forbidden on
mainnet mode.

## Roles and trust boundaries

- The node validates consensus and supplies a chain-bound base template.
- The pool authenticates miners, maintains share difficulty, relays work, and
  records settlement events.
- The miner owns an Ed25519 protocol identity and a separate `hy1...` payout
  address. It validates each job before spending work.
- The chain accepts only blocks with a valid miner block authorization.

Pool and miner identity keys are raw 32-byte protocol secrets. They are not
wallet seeds and do not replace wallet backup.

## Protocol flow

1. TP v2 binds signed requests and templates to network magic, consensus
   parameters hash, and genesis hash.
2. Pool v3 login sends the miner identity, payout view/spend public keys,
   thread count, and the same chain identity.
3. The pool personalizes the header with the miner public key and advertises
   exact reward keys, transaction blobs, transaction root, difficulty, epoch
   seed, arena size, and page size.
4. The miner recomputes the transaction root and rejects chain, header,
   difficulty, arena, miner-key, or reward-key mismatches. A shared mode may
   redirect coinbase to the pool wallet only when the miner explicitly starts
   with `--allow-shared-reward-recipient`.
5. The miner evaluates PoW. Ordinary shares carry no reusable block
   authorization. A full-block solution carries `BlockAuthorization` signed by
   the miner over the full solved header, chain identity, and reward keys.
6. The pool recomputes PoW and verifies miner authorization before relaying a
   full block to the node.
7. Every accepted share result has a pool-signed envelope and a hash-chain
   receipt committing to pool identity, miner identity, sequence, previous
   receipt, exact submission hash, and exact result hash. The miner recomputes
   the receipt and keeps a bounded queue of unanswered submissions.

## Implemented properties

| Property | Current enforcement |
| --- | --- |
| Share identity binding | Signed envelopes and per-session sender checks |
| Replay resistance | Signed envelope nonce/freshness checks and a 4,096-entry submission-nonce window |
| Miner-specific work | Header commits the miner public key |
| Template integrity after receipt | Miner recomputes the transaction root and validates all advertised metadata |
| Reward redirection resistance | Miner checks payout keys; consensus authorization commits exact reward keys |
| Pool cannot finish a block alone | Consensus requires the miner's authorization over the solved header |
| Share omission/substitution detection | Miner-verified, sequence-linked share receipts |
| Publicly inspectable local accounting | Wallet-scoped HTTP summaries and persisted settlement history |
| Ledger crash recovery | Atomic next-file replacement plus last committed backup recovery |

These properties mean a pool cannot take an already authorized solution and
change its transactions, reward address, chain, or miner identity. They do not
mean the pool has no remaining control.

## Attack analysis and open work

| Attack | Status | Remaining work |
| --- | --- | --- |
| Share stealing | Mitigated for identity substitution and payload replay | Test hostile proxies, reconnect races, and same-identity key compromise |
| Template hijacking | Post-delivery mutation is detected | Pool currently chooses the transaction list it sends; miner-originated job declaration is not exposed through Pool v3 |
| Pool censorship / MEV | Not solved | Add miner-selected transaction sets or direct miner-to-TP job declaration with bounded validation and fallback nodes |
| Block withholding by miner | Not solved | Economic detection/penalties require a formal model and cannot prove a private solution existed |
| Block withholding by pool | Not solved | Miner needs a safe direct submission path or encrypted/adaptor relay design after finding a block |
| Clandestine pools | Not solved | Non-transferability against deliberate off-protocol work sale needs a separate cryptographic construction and impossibility analysis |
| Payout griefing | Receipts expose accepted-share omission or mutation | Shared balances still depend on the operator to create on-chain payouts |
| Ledger forgery | Local snapshot recovery and miner receipts improve auditability | Publish append-only checkpoints, inclusion proofs, independent mirrors, and reconciliation tooling |
| Pool hopping | PPLNS uses a work-weighted trailing window | Strategy simulation and parameter calibration are still required; PROP/PPS economics remain operator-dependent |

The present shared modes (`prop`, `pps`, `pplns`, `pps+`, `fpps`) produce
internal `pending_payout_atomic` entries. No automatic transaction builder,
broadcaster, confirmation tracker, reserve proof, or solvency guarantee exists.
Those entries MUST NOT be represented as wallet funds or completed payments.

## Next protocol milestone

A Pool v4 proposal should be evaluated before implementation and should include:

1. Miner-declared transaction sets with deterministic size/fee policy and TP
   validation, without allowing unbounded parsing or memory use.
2. Direct full-block fallback submission that does not expose a transferable
   solution before miner authorization is fixed.
3. Periodic Merkle commitments to accepted share receipts and settlement
   events, with miner inclusion proofs and independent archival mirrors.
4. A specified payout transaction state machine: constructed, signed,
   broadcast, confirmed, reorged, retried, and reconciled.
5. Simulation and fault injection for withholding, delayed replies, reordered
   receipts, disk corruption, pool hopping, and adversarial VarDiff changes.

Activation requires a standalone specification, test vectors, a reference
verifier, cryptographic review, and evidence that each claimed property follows
from the protocol rather than from operator policy.

## Novelty discipline

The miner-bound authorization plus auditable share-receipt chain is
project-specific work, not proof of academic novelty or patent freedom. A
novelty claim requires a documented prior-art search and independent review
against at least decentralized pool protocols, job-declaration protocols,
blind/adaptor signatures, non-outsourceable puzzles, and payment-channel or
commitment-ledger systems. Standard cryptographic primitives should remain in
reviewed libraries; reimplementing them merely to look different would reduce
security.

