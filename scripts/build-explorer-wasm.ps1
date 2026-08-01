$ErrorActionPreference = 'Stop'

$workspace = Split-Path -Parent $PSScriptRoot
$artifact = Join-Path $workspace 'target\wasm32-unknown-unknown\release\hyphen_explorer_web.wasm'
$destination = Join-Path $workspace 'crates\hyphen-explorer\src\hyphen_explorer_web.wasm'

Push-Location $workspace
try {
    cargo build --offline --release -p hyphen-explorer-web --target wasm32-unknown-unknown
    Copy-Item -LiteralPath $artifact -Destination $destination -Force
    Write-Host "Explorer WASM updated: $destination"
} finally {
    Pop-Location
}
