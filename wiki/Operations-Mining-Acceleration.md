# Mining Acceleration

Status: optional device sieve, active in `HyphenMiner`. The CPU path is the
canonical implementation on every architecture.

## What is accelerated

PoUW v3 requires Cunningham chains: for a witness `n`, every element of
`n, 2n+1, 4n+3, …` up to the chain length must be prime. The miner first runs a
small-prime sieve over a window of candidates. That sieve is the only part
offloaded to a device. It is exact, cheap, and massively parallel; it rejects
the overwhelming majority of candidates before any Miller-Rabin work.

A device plugin does **not** decide whether a witness is acceptable. It returns
the candidates that survive the small-prime sieve. The Rust worker then runs:

1. the same deterministic Miller-Rabin test the consensus validator uses,
2. the local single-use check against witnesses already submitted by this miner,
3. the existing block-authorization and pool-protocol path.

A broken, stale, or malicious plugin can therefore waste work, but it cannot
make the miner accept a composite chain or bypass single-use enforcement.

## Backends

| Platform | Build | Runtime |
|---|---|---|
| Linux x86_64/aarch64, NVIDIA | `-DHYPHEN_ENABLE_CUDA=ON` | CUDA plugin |
| Linux x86_64, AMD | `-DHYPHEN_ENABLE_HIP=ON` | HIP plugin |
| Windows x86_64, NVIDIA | `-DHYPHEN_ENABLE_CUDA=ON` | CUDA plugin |
| Windows x86_64, AMD | `-DHYPHEN_ENABLE_HIP=ON` | HIP plugin |
| macOS | not built | portable CPU |
| Android arm64/armv7 | not built | portable CPU |
| RISC-V | not built | portable CPU |

macOS Metal, Android Adreno matrix cores/HPM, and other NPU or DSP backends are
not wired into the miner. Those platforms use the CPU search; no acceleration
claim is made for them. The miner deliberately does not ship a plugin that
implements a retired workload: a device result is only meaningful if it matches
the current consensus predicate.

## Build

```powershell
cmake -S native -B native/build -DHYPHEN_ENABLE_CUDA=ON
cmake --build native/build --config Release
```

or, with ROCm/HIP:

```powershell
cmake -S native -B native/build -DHYPHEN_ENABLE_HIP=ON
cmake --build native/build --config Release
```

Plugins are written to `accelerators/`. The loader searches, in order:

1. `--accelerator-dir`,
2. `HYPHEN_ACCELERATOR_DIR`,
3. `accelerators/` next to the executable (including `Release/`),
4. `accelerators/` in the current directory,
5. the source-tree `accelerators/` directory.

`HYPHEN_CUDA_ARCHITECTURES` defaults to `native`. `HYPHEN_HIP_ARCHITECTURES` is
empty by default, so hipcc chooses; set an explicit list for a binary
distributed to other machines.

## Verify before mining

```powershell
cargo run --release -- accelerator-check --batch 2000000 --offset 1000001 `
    --stride 32 --length 6
```

The check scans the same window with the device and the CPU sieve and fails on
any mismatch. It also rejects values outside the requested window and counts
the survivors that pass full chain validation. Use `--no-accelerator` to force
the CPU path for a baseline, and `--accelerator-dir` to test a specific build.

## Failure behavior

- No plugin, no capable device, or an ABI mismatch: the miner logs the reason
  and uses the CPU path.
- A device call fails once: the worker sets an atomic failure flag, logs the
  device error, and every worker falls back to CPU. It does not retry a broken
  plugin in a loop.
- A survivor buffer overflows: the miner keeps the candidates it received and
  moves the cursor past the scanned window; it never resubmits the same window.
- The initial window starts below the small-prime bound, so it is scanned on
  CPU. This avoids the only case where an element can equal a sieve prime.

## CPU portability

The CPU path uses `u64` arithmetic and the seven-base Miller-Rabin set proven
for every `n < 2^64`. It has no architecture-specific intrinsics, no big-integer
dependency, and no endianness assumption. It builds for x86, x86_64, armv7,
aarch64, and riscv64 with the same source.

Hashing is BLAKE3 throughout the miner and pool protocol; SHA-256 is not used.
