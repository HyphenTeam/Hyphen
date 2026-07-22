# Security Policy

Hyphen is experimental research software. It has not completed an independent
cryptographic or consensus audit, has no production mainnet, and must not be
used to custody or advertise material real-world value.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

https://github.com/HyphenTeam/Hyphen/security/advisories/new

Do not publish an exploitable report in a public issue. Include the affected
revision, component, reproduction steps or proof of concept, impact, and any
suggested mitigation. Remove wallet seeds, private keys, personal data, and
third-party credentials from the report.

If private vulnerability reporting is unavailable, contact the repository
maintainers through a private channel listed on the GitHub organization before
sharing technical details. A public issue may ask the maintainers to enable a
private channel, but must not contain the vulnerability.

No response-time service level is promised for this research repository. Do
not test attacks against systems or users you do not own or have permission to
assess.

## Bug bounty status

There is currently no funded bug bounty and no reward is promised. A future
bounty must publish scope, eligibility, safe-harbor terms, severity rules,
reward ranges, duplicate policy, prohibited testing, and a payment process
before researchers are asked to rely on it.

## Audit scope before any value-bearing launch

Independent reviewers must cover at least:

- consensus parameters, genesis, block/transaction validation, PoW,
  difficulty, fork choice, reorg, state rollback, and archive replay;
- CLSAG, commitments, range proofs, derivation, address encoding, key images,
  randomness, domain separation, and side-channel/key-zeroization behavior;
- transaction, RPC, P2P, Template Provider, pool, explorer, and wallet parsing
  boundaries, including resource-exhaustion limits;
- wallet seed generation, encrypted storage, backup, recovery, rescan, signing,
  mobile lifecycle, and external signer protocol;
- Pool v3 miner authorization, share receipts, VarDiff, all payout formulas,
  persistence recovery, withholding, hopping, and automated on-chain payout;
- reproducible builds, dependency provenance, release signing, secrets,
  deployment hardening, monitoring, and incident response.

Audit reports, exact reviewed commits, remediations, and retest results must be
public. An audit is not complete while critical or high findings remain open.

## Launch blockers

Production or value-bearing promotion is prohibited until:

- competing-branch fork choice and reorg rollback are implemented and tested;
- frozen specifications and cross-implementation vectors exist;
- independent cryptography, consensus, wallet, network, and pool reviews pass;
- a public testnet meets `docs/operations/incentivized-testnet.md`;
- wallet recovery and pool ledger/payout fault drills pass;
- shared-pool balances settle through audited, confirmed on-chain payments;
- a funded vulnerability program and incident-response team exist; and
- release artifacts are reproducible, signed, and accompanied by provenance
  and an SBOM.

Passing unit tests or starting a binary does not remove these blockers.

