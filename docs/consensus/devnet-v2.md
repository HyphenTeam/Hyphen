# Hyphen Devnet v2 Consensus Profile

Status: active development profile, 2026-07-30. It is not a production or
value-bearing network.

Devnet v2 inherits the numeric parameter table and disabled research-feature
set from the historical [devnet v1 profile](devnet-v1.md), with these normative
changes:

1. `network_name` is `hyphen-devnet-v2`.
2. `STATE_TRANSITION_VERSION` is `2` and is committed by
   `ChainConfig::consensus_params_hash`.
3. A post-genesis coinbase output and its range proof MUST be derived
   deterministically from the domain-separated block hash, reward public keys,
   amount, height and commitment blinding. Ordinary wallet sends continue to
   use operating-system randomness.
4. A v1 database MUST be rejected by the consensus-parameter and genesis-hash
   checks. There is no in-place database migration.
5. H-WES, H-BFM, H-FOC and H-SAC remain inactive research mechanisms.

The exact network magic, parameter hash and genesis hash are normative only in
`test-vectors/chain-identity-v2.json`. The block and authorization wire versions
remain unchanged because this revision changes state-transition semantics, not
their encoding.

The state library contains atomic one-block commit/rollback, immutable branch
body storage, persistent reorg journals and a real `Blockchain` reorg backend.
The backend recomputes plan work, holds an exclusive transition lock, validates
each candidate against its fork state, restores the old branch on failure and
resumes a journal during database open. Automatic P2P competing-branch intake,
fork-choice triggering and mempool/wallet/explorer/pool reconciliation are not
implemented, so complete live reorg handling remains a release blocker.
