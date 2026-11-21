param([string]$Clang = 'clang')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Push-Location $root
$previous = $env:HYPHEN_CONTRACT_TOOLCHAINS
try {
    $output = New-Item -ItemType Directory -Force -Path 'target/contract-toolchains'
    foreach ($contract in 'collection','limit-orders') {
        & rustc --edition=2024 --target wasm32-unknown-unknown --crate-type cdylib --crate-name ($contract.Replace('-','_')) `
            -C opt-level=z -C lto=fat -C panic=abort -C strip=debuginfo -C link-arg=--max-memory=4194304 `
            "contracts/$contract/lib.rs" -o "$($output.FullName)/$contract.wasm"
        if ($LASTEXITCODE) { throw "Could not compile the Rust $contract contract" }
    }
    foreach ($language in 'c','cpp','s') {
        $source = "crates/hyphen-vm/tests/toolchains/storage.$language"
        $flags = @()
        if ($language -eq 'cpp') {
            $flags = @('-std=c++20', '-fno-exceptions', '-fno-rtti')
        }
        & $Clang --target=wasm32-unknown-unknown -O2 -nostdlib -Icontracts/include @flags $source `
            '-Wl,--no-entry,--import-undefined,--export-memory,--max-memory=4194304,--export=hyphen_execute,--export=hyphen_query' `
            -o "$($output.FullName)/$language.wasm"
        if ($LASTEXITCODE) { throw "Could not compile $source" }
    }
    $env:HYPHEN_CONTRACT_TOOLCHAINS = $output.FullName
    & cargo test --locked --release -p hyphen-consensus compiled_contract_toolchains -- --ignored
    if ($LASTEXITCODE) { throw 'Compiled contract validation failed' }
} finally {
    $env:HYPHEN_CONTRACT_TOOLCHAINS = $previous
    Pop-Location
}
