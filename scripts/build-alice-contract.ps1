# Builds the Alice neural-challenge contract for wasm32 and prints its hash.
# The chain executes exactly this module in `crates/hyphen-vm/tests/alice_contract.rs`.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$contractDir = Join-Path $root 'contracts/alice-neural'

Push-Location $contractDir
try {
    # Windows PowerShell turns native stderr into a terminating error under
    # `$ErrorActionPreference = 'Stop'`, so the native calls run allowed to
    # write to stderr and are checked through their exit codes instead.
    $strict = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & rustup target add wasm32-unknown-unknown 2>&1 | Out-Null
    $targetExit = $LASTEXITCODE
    & cargo build --release --locked 2>&1 | Out-Host
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = $strict
    if ($targetExit -ne 0) {
        throw "wasm32 target installation failed with exit code $targetExit"
    }
    if ($buildExit -ne 0) {
        throw "contract build failed with exit code $buildExit"
    }
} finally {
    Pop-Location
}

$artifact = Join-Path $contractDir 'target/wasm32-unknown-unknown/release/alice_neural_contract.wasm'
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
    throw "expected contract artifact at $artifact"
}

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$b3sum = Get-Command b3sum -ErrorAction SilentlyContinue
if ($b3sum) {
    $hashOutput = & $b3sum.Source --no-names -- $artifact 2>&1
    $hashExit = $LASTEXITCODE
} else {
    $hashOutput = & cargo run --quiet --manifest-path (Join-Path $root 'Cargo.toml') `
        -p hyphen-crypto --example blake3-file -- $artifact 2>&1
    $hashExit = $LASTEXITCODE
}
$ErrorActionPreference = $previousPreference
if ($hashExit -ne 0) {
    throw "BLAKE3 hashing failed with exit code $hashExit`n$($hashOutput | Out-String)"
}
$hash = ($hashOutput | Where-Object { "$_".Trim() } | Select-Object -Last 1).ToString().Trim()
if ($hash -notmatch '^[0-9a-f]{64}$') {
    throw "unexpected BLAKE3 output: $hash"
}

$size = (Get-Item -LiteralPath $artifact).Length
Write-Host "alice-neural contract: $artifact"
Write-Host "  size:   $size bytes"
Write-Host "  blake3: $hash"
