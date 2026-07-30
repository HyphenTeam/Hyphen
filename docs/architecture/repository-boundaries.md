# Hyphen Repository and Compatibility Boundaries

Status: normative repository policy for development and CI.

## Base-chain scope

The tracked Hyphen repository owns the base-chain protocol and reference node:

- consensus-critical data structures and validation;
- state-transition, storage, replay, and chain identity;
- transaction and cryptographic verification libraries;
- P2P, RPC, Template Provider transport, and explorer interfaces;
- versioned specifications, machine-readable vectors, fuzz targets, and CI.

The root `Cargo.toml` is the authoritative list of base-chain workspace members.
The internal `crates/hyphen-wallet` package is a protocol-facing wallet library,
not the independent Flutter application.

## Independent projects

`HyphenMiner`, `HyphenPool`, and `HyphenWallet` are separate products with
separate source history, lockfiles, releases, threat models, and CI. Local
checkouts may be placed at the Hyphen repository root so compatibility scripts
can find them. Those directories are intentionally ignored by this repository
and MUST NOT become root workspace members or required inputs to base-chain CI.

No successful build or test in an independent project proves base-chain
correctness. No successful base-chain test proves an independent project is
compatible.

## Protocol change sequence

A compatibility-affecting base-chain change MUST proceed in this order:

1. Define the wire/state/consensus change in a versioned specification.
2. State activation and downgrade behavior; consensus changes require a new
   chain profile and chain identity unless the frozen specification explicitly
   permits the change.
3. Publish positive and negative machine-readable vectors.
4. Update and pass the Hyphen reference implementation and base-chain CI.
5. Update each independent project in its own repository and CI.
6. Run cross-project compatibility tests against exact revisions and archive
   the revision map, logs, and vector hashes.

## CI ownership

Hyphen base-chain CI gates formatting, Clippy, workspace tests, fuzz-target
compilation, chain-identity vectors, and a Windows node smoke check. Nightly CI
runs bounded decoder fuzzing on Linux.

Cross-project node/miner/pool/wallet tests are compatibility evidence only.
They require explicit independent checkouts and MUST live in a separate
integration workflow or orchestration repository. They cannot be required by a
clean checkout of the Hyphen base-chain repository.
