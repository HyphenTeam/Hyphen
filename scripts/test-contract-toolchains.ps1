param([string]$Clang = 'clang')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Push-Location $root
$previous = $env:HYPHEN_CONTRACT_TOOLCHAINS
try {
    $output = New-Item -ItemType Directory -Force -Path 'target/contract-toolchains'
    foreach ($language in 'c','s') {
        $source = "crates/hyphen-vm/tests/toolchains/storage.$language"
        & $Clang --target=wasm32-unknown-unknown -O2 -nostdlib -Icontracts/include $source `
            '-Wl,--no-entry,--import-undefined,--export-memory,--max-memory=4194304,--export=hyphen_execute,--export=hyphen_query' `
            -o "$($output.FullName)/$language.wasm"
        if ($LASTEXITCODE) { throw "Could not compile $source" }
    }
    $env:HYPHEN_CONTRACT_TOOLCHAINS = $output.FullName
    & cargo test --locked -p hyphen-consensus compiled_contract_toolchains -- --ignored
    if ($LASTEXITCODE) { throw 'Compiled contract validation failed' }
} finally {
    $env:HYPHEN_CONTRACT_TOOLCHAINS = $previous
    Pop-Location
}
