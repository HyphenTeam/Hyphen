# Mining on the neural development network

The CPU miner evaluates each nonce and computes the scratchpad when the BLAKE3 digest of the seed, nonce and neural score passes the first gate. The CUDA plugin evaluates batches of neural scores. The host checks both digest thresholds and reproduces the winning neural score before signing. Each accepted SOLO submission is a full block candidate. [Protocol](Consensus-Neural-Work.md)

Build the node, pool and miner with `cargo build --release --locked` in their respective repositories. Start all three with `--network neural-devnet`. Use `--no-accelerator --threads 1` for the CPU path or `--accelerator-dir DIRECTORY` for a CUDA plugin. The miner logs the backend used for each winning solution. A device error retries the affected window on the CPU.

On Windows, `python scripts/measure-mining.py --seconds 70 --accelerator-dir DIRECTORY` starts a fresh node and SOLO pool per backend. It checks reported heights against the miner log and records valid and invalid shares, executable digests, the CUDA plugin digest and sampled GPU board power under `target/mining-measurement-*/`. CPU and CUDA start from separate genesis databases and retarget independently. Use an external whole-system meter and fixed challenge windows for energy comparisons. [Measurement script](../scripts/measure-mining.py)

`cargo run --release --locked -p hyphen-consensus --example work_cost` measures 16 deterministic windows of 1,024 nonces. The CSV records the number of memory evaluations, accepted nonces and time spent independently verifying all winners.

## HYN3 short run

Windows 10 build 19045, Core i7-11850H, RTX A4000 Laptop GPU, driver 596.71. Each backend ran with one host mining thread and started from genesis. The miner’s search median covers completed solutions. The board sensor was sampled 138 times per run. The CPU run overlapped other local work. [Sampling implementation](../scripts/measure-mining.py)

| Backend | Seconds | Valid / invalid shares | Completed search median | GPU board mean | GPU board energy |
|---|---:|---:|---:|---:|---:|
| CPU | 70.03 | 21 / 0 | 99.227 ms | 27.17 W | 1,893 J |
| CUDA scores, host scratchpad | 70.06 | 23 / 0 | 66.829 ms | 19.61 W | 1,371 J |

Both runs crossed the first retarget. Their tips had different cumulative weights and different challenge histories. Board readings exclude host CPU energy and other system loads. Estimating comparative energy per trial requires repeated fixed ranges and a whole-system meter.

## Matched nonce windows and live SOLO runs, 2026-11-21

Across 16 matched windows the one-thread Rust path searched 2,504 nonce/s and CUDA scoring with host gates searched 3,048 nonce/s. All 131,072 scores and all 507 winners matched. The CUDA scoring call alone averaged 92,162 scores/s. [Setup, timing boundaries and Rust reproduction](HYN3-Algorithm-Audit.md)

Two additional live runs used separate fresh HYN3 databases, a local node and SOLO pool, one mining thread and the same development miner key. Every accepted height had a solution logged by the selected backend. The CUDA log showed no device fallback. Board samples came from `nvidia-smi` at roughly one-second intervals. Energy below integrates adjacent board readings by timestamp.

| Backend | Mining seconds | Valid / invalid shares | Last height | GPU samples | GPU temperature | GPU mean power | GPU board energy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CPU | 180.26 | 22 / 0 | 22 | 179 | 55–57 °C | 30.30 W | 5,464 J |
| CUDA scoring, host gates | 180.08 | 22 / 0 | 22 | 179 | 50–57 °C | 23.29 W | 4,193 J |

The CPU run also recorded GPU board power from the shared laptop. The forks retargeted separately and local workloads varied. These observations cover three minutes per backend. A sustained thermal qualification and whole-machine energy per matched attempt still require separate measurements. Raw logs, board samples and binary digests are under `target/audit-local/live-e213fc7f-e84a-4fe8-b757-90e034a8af71/`.
