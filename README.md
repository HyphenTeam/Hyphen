# Hyphen

English | [中文](README_CN.md)

Hyphen is an experimental privacy-oriented, CPU-first Proof-of-Work blockchain
written in Rust. The formal scope of this repository is the Hyphen base chain:
the full node, consensus, state, cryptography, transactions, P2P/RPC, protocol
support libraries, and test vectors.

`HyphenMiner/`, `HyphenPool/`, and `HyphenWallet/` are independent projects.
They may be checked out at the repository root for compatibility testing, but
they are ignored by Git, are not root Cargo workspace members, and are not
dependencies of the base-chain CI. A base-chain protocol change must first
update versioned specifications and test vectors; each independent project then
upgrades and runs its own compatibility suite. See
[Repository and compatibility boundaries](docs/architecture/repository-boundaries.md).

> **Security status, 2026-07-30:** the base-chain devnet v2 profile, unit tests,
> decoder fuzz-target compilation, and chain-identity checks can be verified
> independently. End-to-end compatibility with the three external projects is
> a separate integration test. The project has not had an independent
> cryptographic/consensus audit, does not implement automatic end-to-end reorg
> handling across the network and dependent subsystems,
> has no long-running public testnet, and has no funded bug bounty. Do not send
> real assets or treat an external client's availability as evidence of
> base-chain production safety.

## How to use this document

If blockchain software is new to you, follow this order: read the capability
table and system model, pass the automated devnet smoke test, run node/pool/
miner manually, then study wallet recovery, replay, and adversarial tests. The
non-custodial pool and Useful-Work sections are research boundaries, not
production promises. `mainnet` currently means the `mainnet-research` profile,
not a launched value-bearing network.

The four new base-chain research directions are recoverable state expiry with
witness-carrying execution, deterministic fusion of parallel block braids,
fast ordering certificates under explicit network assumptions, and
user-controlled selective audit proofs. Their notation, impossibility
boundaries, theorem ledger, and implementation order are defined in the
[four-core-innovation research charter](docs/research/four-core-innovations.md).
None is active in devnet v2.

Choose a path before proceeding:

| Goal | Start here | Completion signal |
| --- | --- | --- |
| Verify that it runs | Local devnet | Smoke JSON says `passed`; preserve commit and logs |
| Learn node/pool/miner operation | Manual local devnet | Explain every port, observe a share, and distinguish it from on-chain reward |
| Develop or submit a PR | Tests and adversarial coverage | Base-chain workspace and fuzz checks exit zero; each independent client passes its own CI and optional compatibility suite |
| Research pool decentralization | Non-custodial pool semantics | Evaluate each attack separately; a signature alone is not the claim |
| Research useful work | Useful-Work boundary | Base PoW remains the independent security floor |
| Operate a testnet or audit | Incentivized testnet and external validation | Every launch blocker is closed with public evidence |

The normative/supporting documents have separate roles: the [devnet v2 profile](docs/consensus/devnet-v2.md), [pool threat model](docs/research/non-custodial-pool.md), [Useful-Work boundary](docs/research/useful-work-augmented-pow.md), [testnet runbook](docs/operations/incentivized-testnet.md), and [security policy](SECURITY.md). This README teaches operation but does not replace them.

## Capability status

| Capability | Status | Important boundary |
| --- | --- | --- |
| Devnet v2 deterministic state transition | Implemented | Deterministic post-genesis coinbase derivation is consensus-bound; research mechanisms remain disabled |
| Independent miner, pool, and wallet compatibility | Requires v2 upgrade and retest | These projects are outside the base-chain workspace and root CI; no v2 end-to-end pass is claimed here |
| Export, reference verification, replay | Implemented | Full replay requires a fresh destination database |
| Pool v3 miner authorization | Experimental | A pool cannot mutate an authorized header, transaction root, reward keys, or chain identity |
| Shared pool payouts | Incomplete | PROP/PPS/PPLNS/PPS+/FPPS balances are internal accounting, not wallet funds |
| Fork choice and reorg | **Backend implemented; end-to-end automation incomplete** | The real backend recomputes work, revalidates fork state, switches atomically, restores on failure, and resumes after reopen; P2P branch intake, automatic selection, and subsystem reconciliation remain missing |
| Privacy transactions and ZKP | Library implementation | CLSAG, commitments, and range proofs require external cryptographic review |
| WASM contracts | Isolated library | No contract transaction, consensus execution, state root, receipt, or RPC activation exists |
| Flutter wallet | Experimental | Software signing only; no vendor device app or physical hardware-wallet adapter |
| Useful-Work | Research specification only | It is off, is not AI mining, and cannot replace the base PoW security budget |

## System model and terminology

```text
wallet --RPC--> node --validate--> mempool --P2P--> other nodes
                 |--Explorer HTTP
                 +--TP v2 template--> pool <--Pool v3 jobs/shares/receipts--> miner
                                      |<--miner-authorized full block---------|
```

A node decides whether blocks satisfy consensus. A miner searches nonces and,
under Pool v3, validates and authorizes a solved block. A pool aggregates
shares and reduces payout variance; an ordinary share is accounting evidence,
not a block or wallet payment. Chain identity combines network magic,
consensus-parameter hash, and genesis hash. Replay sends archived blocks back
through validation. The chain manager can durably execute a validated static
multi-block reorg plan, revalidate each attachment against its fork state,
restore the original branch after candidate failure, and resume after database
reopen. Network ingestion and automatic selection of competing branches, plus
mempool, wallet, explorer, and pool reconciliation, are not implemented; this
is therefore not complete live reorg handling.

Wallet mnemonics control assets. Miner, pool, and P2P identity key files only
authenticate their respective protocols and cannot recover wallet funds.

The listeners are different protocols and are not interchangeable:

| Interface | Consumer | HTTP/browser? | Purpose |
| --- | --- | --- | --- |
| P2P | Nodes | No | libp2p discovery, gossip, and sync |
| Protobuf RPC | Wallet/client | No | Length-framed protobuf, not HTTP JSON-RPC |
| Explorer | Human/monitor | Yes | Read-only `/api/info` and explorer HTTP |
| TP v2 | Node/pool | No | Signed templates, job declaration, block submission |
| Pool v3 | Pool/miner | No | Login, jobs, shares, authorization, receipts |
| Pool accounting | Miner/operator | Yes | Health and internal ledger, not proof of on-chain funds |

A blank browser page on RPC, TP, or Pool v3 does not mean the service is broken.

## Run a local devnet on Windows

Install Git, stable Rust, and the Visual Studio C++ Build Tools. Clone the
repository and record the exact revision being tested:

```powershell
git clone https://github.com/HyphenTeam/Hyphen.git
Set-Location .\Hyphen
git rev-parse HEAD
git status --short --branch
```

Include that commit in bug reports. For an existing checkout, enter its actual
path; do not copy a developer-specific absolute path or blindly pull over local
changes.

Run commands from the repository root unless a `cd` says otherwise. In
PowerShell, a trailing backtick continues a command and must have no following
space; in Bash use `\`. Replace `<placeholders>` instead of typing the angle
brackets. Check `$LASTEXITCODE` on PowerShell or `$?` on Bash immediately after
native commands; zero is success and nonzero requires investigation of the
first error, not only the final line. Then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1
```

With previously built artifacts and a complete dependency cache:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1 `
  -SkipBuild -Offline -TimeoutSeconds 120
```

The script is an optional cross-project compatibility harness. When matching
devnet-v2 revisions of the independent pool and miner are present, it builds and
starts a fresh node, a node-connected SOLO pool, and a one-thread Pool v3 miner.
It waits until the accounting API reports `valid_shares > 0`, prints JSON
evidence, and stops all three processes in a `finally` block. Logs remain under
`target/devnet-smoke-<timestamp>/`. This repository does not currently claim a
v2 end-to-end pass; record it only after upgrading and testing those independent
projects at identified revisions.

A passing result looks like:

```json
{
  "status": "passed",
  "network": "hyphen-devnet-v2",
  "pool_health": "ok",
  "valid_shares": 3,
  "invalid_shares": 0,
  "direct_coinbase_mode": true
}
```

The script uses ports `49633`, `49634`, `49640`, `49650`, `49680`, and
`49681`. Stop any service already using those ports before running it.

This proves process startup, matching identities, job flow, and at least one
accepted share. It does not prove a full block, payout, reorg behavior,
cryptographic safety, or long-term reliability.

Preserve reproducible evidence rather than reporting only “works for me”:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$revision = (git rev-parse --short=12 HEAD).Trim()
$evidence = ".\evidence\$stamp-$revision"
New-Item -ItemType Directory -Force $evidence | Out-Null
git status --short --branch | Tee-Object "$evidence\git-status.txt"
rustc --version | Tee-Object "$evidence\toolchain.txt"
cargo --version | Tee-Object -Append "$evidence\toolchain.txt"
powershell -ExecutionPolicy Bypass -File .\scripts\devnet-smoke.ps1 *>&1 |
  Tee-Object "$evidence\devnet-smoke.log"
$smokeExit = $LASTEXITCODE
if ($smokeExit -ne 0) { throw "devnet smoke failed: exit $smokeExit" }
Get-FileHash .\test-vectors\chain-identity-v2.json |
  Format-List | Out-File "$evidence\chain-vector.sha256.txt"
```

Never publish mnemonic words, passwords, `*.key` files, or private vulnerability
details. A useful report includes exact commit, OS, CPU/RAM, reproduction, and
the earliest relevant error from the smoke `run_dir`.

The smoke script force-stops child processes so a failed run cannot leave
background services behind. Its `run_dir` is diagnostic evidence, not a
consistent node backup; a height briefly reported in JSON may be newer than
the last disk flush. For a non-empty export/verify/replay exercise, use the
manual flow, stop the node with `Ctrl+C`, wait for `Shutdown complete.`, and
then export that stopped data directory.

## Build

Prerequisites are stable Rust/Cargo and the host C/C++ toolchain required by
Rust dependencies. Flutter and platform SDKs are needed only for the GUI
wallet.

Reserve roughly 10 GiB for sources, dependencies, and debug artifacts.
Devnet/testnet mining uses a 64 MiB arena; the research mainnet profile uses a
roughly 2 GiB arena per miner process. Linux needs the usual compiler,
`pkg-config`, and native crypto/build dependencies; macOS needs Xcode Command
Line Tools.

```bash
cargo build --release --locked -p hyphen-node
cargo build --release --locked --manifest-path HyphenPool/Cargo.toml
cargo build --release --locked --manifest-path HyphenMiner/Cargo.toml
```

The independent pool and miner have their own lockfiles and target directories.
On Windows, the binaries are:

```text
target/release/hyphen-node.exe
HyphenPool/target/release/hyphen-pool-server.exe
HyphenMiner/target/release/hyphen-miner.exe
```

Use each binary's `--help` output as the canonical CLI reference.

## Stop, back up, and restart

Stop node, pool, and miner with `Ctrl+C`. Ensure all three have exited before
moving a database. Prefer a recoverable backup over deletion when resetting an
experiment:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force .\data\backups | Out-Null
if (Test-Path .\data\devnet-node) {
  Move-Item .\data\devnet-node ".\data\backups\devnet-node-$stamp"
}
```

The next start creates a fresh directory. Never share data directories across
devnet, testnet, and mainnet-research, use a non-fresh replay destination, or
delete the only wallet/recovery evidence. After updating source, print chain
identity first; an identity change requires a new database and an explained
profile/specification change.

## Manual local devnet

The following public fixed-seed address is for local devnet tests only. Anyone
can derive its keys. Never send it real value.

```text
hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD
```

Reproduce it with:

```bash
cargo run -p hyphen-wallet --example dev_address --locked
```

Start these commands in separate terminals.

1. Node:

```bash
target/debug/hyphen-node \
  --network devnet \
  --data-dir ./data/devnet-node \
  --listen /ip4/127.0.0.1/tcp/48334 \
  --rpc-bind 127.0.0.1:48333 \
  --template-bind 127.0.0.1:3350 \
  --explorer-bind 127.0.0.1:8080
```

Open `http://127.0.0.1:8080` or query
`http://127.0.0.1:8080/api/info`. At genesis, `network` is
`hyphen-devnet-v2`, height is 0, and `tip_hash` matches the identity below.

2. Persistent pool identity and SOLO pool:

```bash
mkdir -p keys
HyphenPool/target/debug/hyphen-pool-server keygen --output ./keys/devnet-pool.key

HyphenPool/target/debug/hyphen-pool-server \
  --network devnet \
  --node 127.0.0.1:3350 \
  --key-file ./keys/devnet-pool.key \
  --bind 127.0.0.1:3340 \
  --api-bind 127.0.0.1:8081 \
  --share-difficulty 1 \
  --payout-mode solo \
  --pool-state-dir ./data/devnet-pool
```

Difficulty 1 is only for a quick local test.

3. Persistent miner identity and miner:

```bash
HyphenMiner/target/debug/hyphen-miner keygen --output ./keys/devnet-miner.key

HyphenMiner/target/debug/hyphen-miner \
  --network devnet \
  --pool 127.0.0.1:3340 \
  --key-file ./keys/devnet-miner.key \
  --wallet-address hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD \
  --threads 1 \
  --batch-size 1000
```

`--threads 0` uses all available logical CPUs. Worker threads in one miner
share an epoch arena. Devnet/testnet uses 64 MiB; the research mainnet profile
uses 2 GiB per mining process plus normal overhead.

Check the pool:

```text
GET http://127.0.0.1:8081/healthz
GET http://127.0.0.1:8081/api/pool/wallet/<hy1-address>/balance
```

Stop each component with Ctrl+C. Never share a data directory between
mainnet, testnet, and devnet.

The smoke/manual success condition is intentionally narrow: matching protocol
identity and at least one accepted share. It does not prove a full block was
found, a shared balance was paid, reorg works, or the cryptography is safe.

Shared payout modes are research-only. A PPLNS pool needs `--payout-mode
pplns`, a network-correct `--pool-wallet`, and its accounting parameters. A
miner must explicitly pass `--allow-shared-reward-recipient`. The opt-in does
not let a pool mutate an authorized header, but shared balances still require
an external payout process; no automatic on-chain settlement exists.
Non-SOLO mainnet-research mode also refuses to start without
`--acknowledge-manual-payouts`. That flag only acknowledges the external payout
risk; it does not fund, prove solvent, or automate the pool.

## Frozen chain identity

| Profile | Magic | Consensus parameters hash | Genesis hash |
| --- | --- | --- | --- |
| `devnet-v2` | `48594456` | `bb0c74b93362b8265d65af5dd48796084448e6b3022c39825476ce1b84439902` | `854adc605062fb872dcd20a535dca1ec25d4af58689f1be50e6c26df0c841295` |
| `testnet-research` | `48595453` | `462678e5ddc913b99ae7fe3ccc72a114c125273e7f559f2e67fa9f56ca8c6ec4` | `37201e26dacd35d361a83e79cb7f52d5c6bb1b139180434b889543fc08e2efaf` |
| `mainnet-research` | `4859504e` | `4f21a74c3c32111bcc0c45fc907d77227a51ae17189d7945489898bf08e8e56e` | `9e7f8e3810a15ccf8f93e887630906c377ad14a7bde0f2783d15f0ca7120f06a` |

Verify the checked-out code rather than trusting this table:

```bash
cargo run -p hyphen-node --locked -- --network devnet --print-chain-identity
cargo run -p hyphen-node --locked -- --network testnet --print-chain-identity
cargo run -p hyphen-node --locked -- --network mainnet --print-chain-identity
```

Machine-readable vectors are in `test-vectors/chain-identity-v2.json`. The
normative profile and activation policy are in
[docs/consensus/devnet-v2.md](docs/consensus/devnet-v2.md). Devnet v2 fixes a
genesis timestamp, block version 2, state-transition version 2, parameter
commitment, deterministic coinbase derivation, genesis block, and integer
`LwmaV1`; H-WES, H-BFM, H-FOC, H-SAC, uncles, TERA, VRE enforcement, MSE, and
MDAD-SPR are off.

Devnet v1 is historical and withdrawn because randomized coinbase construction
could make identical block histories produce different state. Do not open a v1
database with v2 software and do not rewrite its stored identity. Preserve any
needed evidence, then start v2 with a fresh data directory. The historical
profile and vector remain under `docs/consensus/devnet-v1.md` and
`test-vectors/chain-identity-v1.json` solely to document the superseded chain.

## History export and replay

Stop the writer or use a consistent copy of the source database.

```bash
cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-node \
  --export-history ./data/devnet-history-v1.bin

cargo run -p hyphen-node --locked -- \
  --network devnet --verify-history ./data/devnet-history-v1.bin

cargo run -p hyphen-node --locked -- \
  --network devnet --data-dir ./data/devnet-replay \
  --replay-history ./data/devnet-history-v1.bin
```

The reference verifier checks identity, contiguous linkage, timestamps, roots,
and miner authorization. Full replay also performs authoritative PoW,
transaction, and state validation. The destination must be fresh at height 0.
Archive v1 is currently a Rust/bincode artifact with a 512 MiB CLI limit;
production consensus still needs language-neutral canonical encoding and
cross-implementation vectors.

## Tests and adversarial coverage

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo check --manifest-path crates/hyphen-fuzz/Cargo.toml --bins --locked
cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked
```

These are the required base-chain checks. `HyphenPool`, `HyphenMiner`, and
`HyphenWallet` run their own CI; when those independent checkouts are present,
their tests and `scripts/devnet-smoke.ps1` are optional compatibility evidence,
not root CI dependencies. Add `--offline` when the complete dependency cache is
present. On 2026-07-30, the base-chain workspace reported 156 passed, 0 failed,
and 0 ignored tests; strict Clippy passed, and all three fuzz targets compiled
with the locked fuzz dependency graph. The maximum aggregated range-proof test
took about 84 seconds in debug mode.

Interpret results by level:

| Level | Pass condition | First failure action | Does not prove |
| --- | --- | --- | --- |
| Build/check | Exit zero and no `error:` | Start at the first compiler error; verify toolchain and lockfile | Runtime interoperability or safety |
| Unit/integration | Expected tests are `ok`, only registered ignores, exit zero | Rerun the exact failing test and preserve backtrace | Attacks not encoded by the test |
| Devnet smoke | `passed`, correct identity, accepted share > 0 | Inspect earliest node/pool/miner stderr in `run_dir` | Full block, payout, reorg, audit |
| Sustained fuzz | Budget ends without crash/hang/OOM; corpus retained | Save/minimize the input and add a regression | Unreached states or formal safety |
| Multi-node fault drill | Every declared invariant and raw series retained | Stop incentives and preserve disk/log snapshots | Cryptographic correctness |

Warnings remain technical debt even with exit zero. Deprecated APIs, unused
security checks, future incompatibilities, and ignored tests must be assigned;
“tests pass” is not equivalent to “zero issues.”

Known toolchain debt on Rust 1.97.0: `proc-macro-error2 2.0.1`, pulled only by
`wasmer-derive 7.2.0`, triggers future-incompatibility E0365. It is an upstream
dependency warning, not suppressed source lint. Upgrade Wasmer or the fixed
macro dependency before a Rust release turns that warning into an error.

### Requirement-to-evidence matrix

Run commands from the repository root and require exit code zero. Manual or
external rows cannot be marked complete by a unit test.

| Requirement | Reproducible evidence | Current blocker |
| --- | --- | --- |
| Freeze devnet consensus | `cargo test -p hyphen-core frozen_devnet_disables_research_consensus_features --locked`; `cargo test -p hyphen-consensus published_chain_identity_vectors_match_the_implementation --locked`; history verify/replay | A language-neutral encoding and second reference verifier are still missing |
| Transaction/RPC/P2P and attack testing | The three fuzz targets plus focused LWMA, anonymity, ledger, and recovery commands below | Stateful network sequences, long statistical runs, and real payout faults remain open |
| Independent review and bounty | Exact-commit scope, reports, remediation, and retest under [SECURITY.md](SECURITY.md) | None has occurred; value-bearing promotion is blocked |
| Small incentivized testnet | Devnet smoke first, then drills and metrics in [incentivized-testnet.md](docs/operations/incentivized-testnet.md) | Automatic branch intake/selection, subsystem reconciliation, and multi-node fault evidence are missing, so no value-bearing testnet may start |
| Standalone, non-combinatorial novelty | Per-claim prior-art chart, formal property, ablation, raw data, reproduction, and independent implementation | Current work is candidate research, not a novelty or patent-freedom guarantee |
| Non-delegable final block authority | `cargo test -p hyphen-core authorization --locked`; miner receipt tests | Solved-header/chain/reward binding exists; miner templates and direct submission do not |
| Pool-control resistance and auditable settlement | Pool `protocol::tests` and `accounting::tests` | Cannot force payment or eliminate censorship, withholding, or clandestine pools |

| Surface | Automated coverage |
| --- | --- |
| Transaction | Bounded decode, oversize/trailing rejection, deterministic malformed corpus, libFuzzer target |
| RPC | Malformed protobuf corpus, payload round trip, libFuzzer target |
| P2P | Envelope/tx/block bounds, unknown input handling, malformed corpus, libFuzzer target |
| Time/difficulty | Reversed timestamp samples, solve-time and per-step clamps, hashrate simulations |
| Anonymity-set bias | Clustered decoys compared with age/index-stratified decoys |
| Pool protocol | Sender substitution, payload tampering, share submission/result/order receipt binding |
| Pool ledger | Primary truncation recovery, duplicate-settlement idempotency, and PPLNS trailing-window behavior |
| Wallet recovery | Same-seed key recovery, rescan requirement, encrypted-file corruption rejection |
| Archive | Wrong chain, height gap, transaction-root mutation, authorization mutation |

Focused commands include:

```bash
cargo test -p hyphen-tx adversarial_decode_tests --locked
cargo test -p hyphen-rpc adversarial_decode_tests --locked
cargo test -p hyphen-network protocol::tests --locked
cargo test -p hyphen-pow frozen_lwma_clamps_timestamp_reversal_attack --locked
cargo test -p hyphen-consensus anonymity_set_bias_experiment --locked
cargo test --manifest-path HyphenPool/Cargo.toml protocol::tests --locked
cargo test --manifest-path HyphenPool/Cargo.toml recovers_last_committed_ledger --locked
cargo test -p hyphen-wallet seed_recovery_restores_keys_but_requires_rescan --locked
```

Passing tests prove only their encoded properties. Stateful RPC/P2P sequence
fuzzing, multi-node partition/eclipsing/reorg simulation, cross-platform PoW
vectors, long-running anonymity experiments, payout-transaction fault
injection, and killed-process mobile recovery remain open work.

Run sustained fuzzing on Linux/WSL:

```bash
rustup toolchain install nightly-2026-07-22
cargo +nightly-2026-07-22 install cargo-fuzz --version 0.13.2 --locked
cd crates/hyphen-fuzz
cargo +nightly-2026-07-22 fuzz run transaction_decode -- -max_total_time=300
cargo +nightly-2026-07-22 fuzz run rpc_decode -- -max_total_time=300
cargo +nightly-2026-07-22 fuzz run p2p_decode -- -max_total_time=300
```

The scheduled `Nightly fuzz smoke` workflow runs each target for 60 seconds. A
five-minute manual run is still only a smoke test. Preserve corpus, minimized
crashes, and coverage trends, and add dedicated Pool v3, TP v2, and wallet-file
targets.

## Flutter wallet tutorial

`HyphenWallet/` is the Flutter GUI and its Rust backend;
`crates/hyphen-wallet` is the workspace core library. The GUI currently offers
testnet/mainnet, not devnet, so it cannot directly attach to the devnet smoke
network above.

The current `pubspec.yaml` requires Dart `^3.12.0-210.2.beta`. Install a
compatible Flutter SDK and platform toolchain, then:

```bash
cd HyphenWallet
flutter doctor
flutter pub get
# Only after changing rust/src/api:
flutter_rust_bridge_codegen generate
flutter analyze
flutter run -d windows  # or android, linux, macos
```

Create a test wallet, record and verify its 24 words offline, select testnet,
and copy the complete `hy1...` receive address. Use that address as the miner's
`--wallet-address`. A pool's shared reward address is separately supplied as
`--pool-wallet`. Sending needs a reachable RPC node, spendable test outputs,
sufficient decoys, and valid fees; this repository does not provide a trusted
public faucet or production network.

For a private connection test, start a node with `--network testnet
--rpc-bind 127.0.0.1:38333` and point the wallet to host `127.0.0.1`, port
`38333`. An isolated genesis node has no useful history, funds, or anonymity
set, so this checks connectivity/UI only.

Recovery must be rehearsed on a second test device/profile: restore the same
24 words and passphrase rules, verify the exact address, rescan from height 0,
and compare history/balance. Also exercise wrong passwords, a wrong word,
corrupt storage, and interrupted scanning. Never delete the only wallet copy
for a first drill.

## Non-custodial pool semantics

TP v2 is node-to-pool. Pool v3 is pool-to-miner. Pool v3 personalizes the
header with the miner key; the miner validates transaction root, chain
identity, difficulty, epoch parameters, and exact reward view/spend keys. A
full block requires the miner's signature over the solved header, chain
identity, and reward keys. Accepted shares receive miner-verifiable hash-chain
receipts committing to the exact submission and result.

This prevents the pool from mutating an already authorized block or redirecting
its reward. It does **not** yet eliminate pool power:

- the pool still selects the transaction set it sends, so censorship and MEV
  control are not solved;
- the pool can refuse to relay a full block;
- a miner can withhold a block;
- deliberate off-protocol work sale to a clandestine pool is not prevented;
- shared modes have no automatic on-chain payout, reserve proof, or solvency
  guarantee; and
- receipts reveal omission/reordering/substitution but cannot force payment.

Each attack needs a separate acceptance result; “messages are signed” is not a
substitute for the whole threat model.

| Attack/control surface | Current defense and evidence | Still missing |
| --- | --- | --- |
| Share stealing | Sender, exact submission, result, and receipt position are bound; identity-substitution and miner-recomputation tests exist | Interception, replay, concurrency, and multi-connection tests |
| Block withholding | Nodes require miner authorization for a full block | Miner direct submission when a pool refuses relay; bilateral withholding treatment |
| Template hijacking | Miner recomputes the transaction root and signs the solved header, chain, and reward keys; mutation tests exist | Miner-created/negotiated templates; the pool still influences censorship, MEV, and signalling |
| Clandestine pool | No sufficient protocol defense | Explicit model and measurable negative result for off-protocol work sale; voluntary collusion cannot honestly be claimed impossible |
| Payout griefing | Signed receipt chain, persistent ledger, truncation recovery, idempotent settlement | Public availability, solvency proof, timeouts, and automatic on-chain payout |
| Pool hopping | PPLNS uses a trailing target-work window with a boundary test | Multi-strategy/cross-pool simulation and long-run fairness across payout modes |

A pool may provide VarDiff, node service, and template broadcast, but those
services must not grant final authorization. Pool-side scheduling and selective
template delivery also remain control surfaces for Pool v4 and field metrics.

Read the threat model and Pool v4 requirements in
[docs/research/non-custodial-pool.md](docs/research/non-custodial-pool.md).
Legacy Stratum V1 is disabled by default, cannot carry frozen block
authorization, and is rejected in mainnet mode.

The acceptance target is stronger than “the miner signs”: header/chain/reward
mutation must invalidate authorization; miners need an independent template
path and direct block submission; share theft and replay need network tests;
accounting needs public availability, solvency, and automatic idempotent
payouts; withholding and clandestine work sale need an explicit protocol or
economic treatment. Only the first mutation-binding subset exists today.

## Useful-Work boundary

Hyphen does not implement AI mining. Useful-Work is inactive. Any prototype
must preserve:

```text
chain_weight = verified base HyphenPoW only
miner_income = base reward + fees + requester-escrowed task bounty
```

Zero external demand must not lower PoW difficulty or security cost. Tasks need
deterministic public inputs, a unique validity relation, resource-bounded cheap
verification, unpredictable challenge binding, and requester-funded escrow.
Nodes should verify succinct proofs, not execute expensive tasks. See
[docs/research/useful-work-augmented-pow.md](docs/research/useful-work-augmented-pow.md).

| Failure mode | Mandatory gate |
| --- | --- |
| Verification costs as much as work | Nodes verify bounded short proofs; public benchmarks show a substantial cost gap |
| Precomputation | Bind instances to an unpredictable chain challenge, expiry height, task ID, and submitter |
| Cherry-picking cheap tasks | Auditable allocation/pricing plus heterogeneous-task fairness experiments |
| Requester/miner fake-demand collusion | Requester escrow funds every bounty; no extra issuance or chain weight |
| External demand falls to zero | Base HyphenPoW independently continues to determine chain weight and the security floor |
| GPU/TPU concentration | Useful work remains an add-on market with public CPU/GPU/accelerator revenue and concentration measurements |

Deterministically verifiable proof aggregation, public Merkleized transforms,
or constrained encoding/scientific jobs are plausible research classes. General
model training and floating-point/private-environment inference are not.

## How innovation is accepted

Combining privacy, PoW, pools, WASM, and Useful-Work is not an independent
innovation claim. Each candidate must state a standalone problem, threat model,
formal property, closest prior art, and an ablation showing what fails when the
mechanism is removed.

| Candidate | Evidence present | Evidence still required |
| --- | --- | --- |
| NCAP / Pool v3 | Domain-separated miner authorization, chain/reward/header binding, receipt-chain tests | Claim chart against BetterHash, Stratum V2, P2Pool and DATUM; miner templates; direct submission; formal model; independent implementation/review |
| Auditable pool ledger | Signed receipt chain, truncation recovery, idempotent settlement tests | Public data availability, inclusion/non-inclusion proofs, reserve proof, automatic payout, large-scale fault injection |
| Useful-Work Augmented PoW | Versioned research boundary and disabled activation | Prototype, validity proofs, anti-precomputation/collusion model, hardware/economic experiments, external review |

Before activation, require a versioned specification, literature/patent/deployed
protocol search, minimal prototype, ablation and comparative measurements,
public vectors/raw data/scripts, a second interoperable implementation, and
independent cryptographic/systems review. Standard audited primitives should
be reused; rewriting cryptography merely to look original is a security defect.

## Comparison with established systems

This table compares design dimensions, not superiority. Bitcoin, Monero,
Zcash, and Ethereum have far more production history and external review.

| Dimension | Hyphen today | Bitcoin | Monero | Zcash | Ethereum PoS |
| --- | --- | --- | --- | --- | --- |
| Consensus | Experimental PoW; frozen devnet | SHA-256 PoW | RandomX PoW | PoW | PoS |
| Privacy | Shielded libraries, unaudited | Transparent base layer | Privacy by default | Transparent and shielded pools | Public L1 state |
| Hardware tendency | CPU-first hypothesis, no field data | ASIC-dominated | General-purpose CPU-oriented | ASIC mining ecosystem | Staked validators |
| Pool control | Miner final authorization; pool still supplies tx set | Operators commonly supply templates | Traditional pools or P2Pool | Pool-specific | Not a PoW pool model |
| Reorg maturity | **Incomplete** | Production mature | Production mature | Production mature | Production fork choice/finality |
| Contracts | VM library only, inactive | Limited scripting | Not a general contract L1 | Payment/privacy focused | Production general contracts |
| Evidence | Research/devnet, unaudited | Long production history | Long production history | Long production/crypto review | Long production history |

Mining protocols require a separate comparison: traditional Stratum V1 is
usually operator-template/private-ledger; BetterHash and Stratum V2 Job
Negotiation move template construction/negotiation toward miners; P2Pool adds a
public decentralized sharechain; DATUM is another relevant decentralized
template direction. Hyphen Pool v3 currently adds solved-header/reward binding
and local signed receipts, but lacks miner-created templates, direct submission,
public ledger availability, and forced payment. Those systems must be included
in any novelty claim rather than comparing only against Stratum V1.

Project-specific naming or combining modules does not prove novelty, patent
freedom, or safety. A responsible innovation claim needs a prior-art search,
formal properties, comparative experiments, reproducible vectors, and
independent review. Reviewed standard primitives should be reused rather than
rewritten merely to appear different.

Primary review entry points: [Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf),
[Bitcoin Core](https://github.com/bitcoin/bitcoin),
[Monero Research Lab](https://www.getmonero.org/resources/research-lab/),
[RandomX](https://github.com/tevador/RandomX),
[Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf),
[Ethereum consensus specifications](https://github.com/ethereum/consensus-specs),
[Stratum V2](https://stratumprotocol.org/specification/),
[BetterHash](https://arxiv.org/abs/1803.03846),
[P2Pool](https://github.com/p2pool/p2pool), and
[DATUM Gateway](https://github.com/OCEAN-xyz/datum_gateway). Archive the cited
version/commit, date, hardware, configuration, and raw measurements with any
formal comparison.

### Reproducible cross-chain experiments

The tables above compare documented properties, not performance. A fair
experiment freezes hardware, implementation commits, history size, topology,
bandwidth/latency, cache policy, and observation window before execution.

| Question | Minimum metrics | Hyphen evidence today |
| --- | --- | --- |
| Initial sync | Wall/CPU time, peak RSS, disk I/O, downloaded bytes | No long public history for a fair comparison |
| Propagation/reorg | p50/p95/p99 propagation, orphan rate, depth, convergence | Backend tests exist, but there is no multi-node field evidence; no superiority claim is valid |
| PoW decentralization | Entity-adjusted shares, Top-3, HHI, hardware/region | CPU-first is a hypothesis, not field evidence |
| Privacy | Effective anonymity, age/index bias, link rate, confidence interval | Small bias experiment only |
| Pool control | Template origin, direct-submit rate, censorship, receipt gaps, payout delay | Authorization prototype; templates/direct submit/payment remain open |
| Wallet recovery | Success rate, rescan time/resources, incorrect history/balance | Unit tests only; real mobile drills remain open |

Each experiment artifact should contain a protocol README, pinned versions,
hardware/config, raw CSV/JSON, logs, analysis scripts, and hashes. Do not compare
different history sizes, rank a small devnet's TPS against production chains,
or hide tail latency and failed runs. Until measured, the correct result is
“unknown,” not “Hyphen is faster/more private/more decentralized.”

## Incentivized testnet and external validation

An incentivized testnet is blocked even though competing-branch body storage,
strict heavier-work plan validation, fork-state revalidation, atomic reorg, old
branch restoration, and reopen recovery now have backend tests. P2P intake and
automatic fork-choice triggering are still missing, and reorg reconciliation
does not yet cover the mempool, wallet, explorer, or pool settlement.

Before promotion, monitor reorg depth/convergence, orphan rate, P2P churn and
rejects, solve-time/PoW distribution, pool concentration, sync CPU/RSS/disk/
bandwidth, receipt gaps, payout state, and mobile wallet recovery/crashes. The
phased rollout, initial alerts, and mandatory drills are in
[docs/operations/incentivized-testnet.md](docs/operations/incentivized-testnet.md).

Independent review and a bounty cannot be simulated by local code. No external
audit or funded bounty has occurred. Private reports should use GitHub private
vulnerability reporting. [SECURITY.md](SECURITY.md) defines review scope and
launch blockers. Audit reports must identify the exact commit, findings,
remediation, and retest; unresolved critical/high findings block launch.

The required order is: freeze the reviewed revision/threat model; commission
separate consensus/network, cryptography/privacy, wallet/key-management, and
pool/economic-ledger reviews; obtain reviewer retest after remediation; only
then open a funded bounty with scope, response targets, and safe harbor.
Internal unit tests or informal review do not substitute for independence.

## Wallet recovery

Pool/miner identity key files are not wallet seeds. A same-seed restore must
reproduce addresses and then rescan from height 0; cached balance is not chain
truth. Run the current drills with:

```bash
cargo test -p hyphen-wallet seed_recovery_restores_keys_but_requires_rescan --locked
cargo test -p hyphen-wallet encrypted_wallet_rejects_single_byte_corruption --locked
```

Production also requires cross-implementation derivation vectors, clean-device
restore, full-history comparison, interrupted mobile lifecycle tests, and
independent review of encrypted storage and its password derivation.

## Ports and exposure

| Service | Devnet | Testnet | Mainnet research | Guidance |
| --- | ---: | ---: | ---: | --- |
| P2P | `48334` | `38334` | `18334` | Public nodes may expose it |
| Protobuf RPC | `48333` | `38333` | `18333` | Loopback/private only; no built-in TLS/auth |
| Template Provider | `3350` | `3350` | `3350` | Private node-to-pool link |
| Explorer HTTP | `8080` | `8080` | `8080` | Loopback or authenticated reverse proxy |
| Pool v3 | `3340` | `3340` | `3340` | Expose only to intended miners |
| Legacy Stratum V1 | `3333` | `3333` | Forbidden | Disabled compatibility test adapter |
| Pool accounting HTTP | `8081` | `8081` | `8081` | Private; permissive CORS and no authentication |

Signed envelopes provide integrity and identity, not confidentiality, access
control, or transport encryption. Do not directly expose RPC, TP, explorer, or
accounting services to the Internet.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `crates/hyphen-core` | Blocks, frozen configuration, timestamps, miner authorization |
| `crates/hyphen-crypto` | Blake3, Ed25519, commitments, stealth, CLSAG, Merkle, WOTS+ |
| `crates/hyphen-proof` | Range and inner-product proofs |
| `crates/hyphen-pow` | Epoch arena, kernels, solver, difficulty |
| `crates/hyphen-tx` | Shielded UTXO transactions and builder |
| `crates/hyphen-state` | Sled block/tip/nullifier/commitment state |
| `crates/hyphen-consensus` | Genesis, validation, append, archive, replay |
| `crates/hyphen-network` | libp2p discovery, gossip, sync |
| `crates/hyphen-rpc` | Protobuf RPC |
| `crates/hyphen-transport` | Node-to-pool TP v2 |
| `crates/hyphen-explorer` | Embedded explorer and HTTP API |
| `crates/hyphen-wallet` | Core wallet and external signer protocol |
| `crates/hyphen-vm` | Deterministic WASM library, inactive in consensus |
| `crates/hyphen-fuzz` | Transaction/RPC/P2P fuzz targets |
| `HyphenPool` | Independent pool Cargo workspace |
| `HyphenMiner` | Independent CPU-miner Cargo workspace |
| `HyphenWallet` | Flutter app and Rust backend |

## Troubleshooting

- **Genesis/consensus mismatch:** the data directory belongs to another network,
  profile, or old dynamic-genesis revision. Preserve it and use a fresh directory.
- **PowerShell treats an option as a command:** a continuation backtick is
  missing or has trailing whitespace. Retry as one line first.
- **Cargo appears idle:** initial Wasmer/cryptography compilation and the
  largest aggregate-proof test can be slow. Check CPU/disk activity before
  starting another build.
- **Browser cannot open `38333/48333`:** that is protobuf RPC, not HTTP. Use the
  explorer on `8080`; wallets connect through their node settings.
- **Pool cannot reach node:** match node `--template-bind` with pool `--node`,
  then inspect firewall and logs.
- **Miner login rejected:** node, pool, and miner need the same network and
  revision. Pool is v3; TP is v2.
- **Wallet rejected:** mainnet address version is `0x01`; testnet/devnet is
  `0x02`. All render with `hy1`, so prefix alone is insufficient.
- **Accepted share but no wallet funds:** an ordinary share is not a block.
  Shared pending balance is also not paid until an on-chain payout confirms.
- **Only stale jobs:** a new tip or an already-submitted full block invalidates
  old work. Persistent staleness indicates template refresh or time issues.
- **NTP warnings offline:** local devnet can continue; a public network needs a
  trustworthy time source and alerts.
- **Cannot deploy WASM through RPC:** contract consensus activation is not
  implemented.

## From runnable to releasable

Complete these gates in order; failure at one gate blocks every later one:

- [ ] Publish exact revision, frozen profile, identity, and machine-readable vectors.
- [ ] Pass base-chain workspace and fuzz checks; independently record each external project's CI and compatibility results; assign warnings and ignores.
- [ ] Pass automated and manual node-pool-miner flows; distinguish shares, blocks, pool balances, and on-chain funds.
- [ ] Export real generated history and obtain matching lightweight verification and fresh-state replay; add language-neutral encoding and a second implementation.
- [ ] Connect the tested fork-state revalidation and crash-recoverable multi-block reorg backend to bounded P2P branch intake and automatic fork choice; reconcile mempool/wallet/explorer/pool state and pass partition, eclipse, timestamp/difficulty, and deep-reorg drills.
- [ ] Add miner templates/direct submission plus public ledger availability, solvency evidence, and automatic idempotent on-chain pool payouts; test every named pool attack separately.
- [ ] Rehearse clean-device wallet creation, backup, corruption/interruption, height-zero rescan, and history/balance comparison on target platforms.
- [ ] Run a valueless multi-operator testnet before capped incentives; publish raw reorg, orphan, P2P, PoW/pool concentration, sync-resource, and mobile-failure data.
- [ ] Complete independent consensus, cryptography, wallet, and pool audits; remediate/retest Critical/High issues; fund and launch the bounty.
- [ ] Finish production specification/genesis ceremony, reproducible signed builds, SBOM, license/notices, monitoring, backup, recovery, and incident response.

Until the final gate, this remains experimental research/devnet software and
must not be promoted as a store for substantial real value.

## License

Cargo metadata declares `AGPL-3.0`. The repository root still lacks the full
matching license text; add it and review third-party notices before distributing
release artifacts.
