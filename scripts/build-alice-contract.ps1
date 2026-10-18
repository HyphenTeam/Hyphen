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

$hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
$size = (Get-Item -LiteralPath $artifact).Length
Write-Host "alice-neural contract: $artifact"
Write-Host "  size:   $size bytes"
Write-Host "  sha256: $hash"
