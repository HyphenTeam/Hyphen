param(
    [switch]$SkipBuild,
    [switch]$Offline,
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

function Invoke-Cargo {
    param([string[]]$CargoArgs)

    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo failed with exit code ${LASTEXITCODE}: cargo $($CargoArgs -join ' ')"
    }
}

if (-not $SkipBuild) {
    $common = @('build', '--locked')
    if ($Offline) {
        $common += '--offline'
    }
    Invoke-Cargo ($common + @('-p', 'hyphen-node'))
    Invoke-Cargo ($common + @('--manifest-path', 'HyphenPool/Cargo.toml'))
    Invoke-Cargo ($common + @('--manifest-path', 'HyphenMiner/Cargo.toml'))
}

$runDir = Join-Path $repoRoot ('target\devnet-smoke-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$nodeExe = (Resolve-Path 'target\debug\hyphen-node.exe').Path
$poolExe = (Resolve-Path 'HyphenPool\target\debug\hyphen-pool-server.exe').Path
$minerExe = (Resolve-Path 'HyphenMiner\target\debug\hyphen-miner.exe').Path

# This address comes from a published fixed seed and is for local devnet only.
$devAddress = 'hy12fsCeNkXNT8BTTMLVD38QsY7h8rkafxMhX96Z2juRjHc73RWHrQqPGEczfatT6ZLNDMDsG4PHwyj6TYv6j78vUqTtJEYrD'
$node = $null
$pool = $null
$miner = $null

function Wait-Http {
    param(
        [string]$Uri,
        [System.Diagnostics.Process]$Process,
        [string]$Name
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        if ($Process.HasExited) {
            throw "$Name exited with code $($Process.ExitCode)"
        }
        try {
            return Invoke-RestMethod -Uri $Uri -TimeoutSec 2
        }
        catch {
            # Service startup is expected to race the first requests.
        }
    }
    throw "$Name did not become ready within $TimeoutSeconds seconds"
}

try {
    $nodeArgs = @(
        '--network', 'devnet',
        '--data-dir', (Join-Path $runDir 'node'),
        '--listen', '/ip4/127.0.0.1/tcp/49634',
        '--rpc-bind', '127.0.0.1:49633',
        '--template-bind', '127.0.0.1:49650',
        '--explorer-bind', '127.0.0.1:49680'
    )
    $node = Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs `
        -RedirectStandardOutput (Join-Path $runDir 'node.stdout.log') `
        -RedirectStandardError (Join-Path $runDir 'node.stderr.log') `
        -PassThru -WindowStyle Hidden
    $nodeInfo = Wait-Http 'http://127.0.0.1:49680/api/info' $node 'node'

    $poolArgs = @(
        '--network', 'devnet',
        '--node', '127.0.0.1:49650',
        '--bind', '127.0.0.1:49640',
        '--api-bind', '127.0.0.1:49681',
        '--share-difficulty', '1',
        '--payout-mode', 'solo',
        '--pool-state-dir', (Join-Path $runDir 'pool')
    )
    $pool = Start-Process -FilePath $poolExe -ArgumentList $poolArgs `
        -RedirectStandardOutput (Join-Path $runDir 'pool.stdout.log') `
        -RedirectStandardError (Join-Path $runDir 'pool.stderr.log') `
        -PassThru -WindowStyle Hidden
    $poolHealth = Wait-Http 'http://127.0.0.1:49681/healthz' $pool 'pool'

    $minerArgs = @(
        '--network', 'devnet',
        '--pool', '127.0.0.1:49640',
        '--threads', '1',
        '--batch-size', '1000',
        '--wallet-address', $devAddress
    )
    $miner = Start-Process -FilePath $minerExe -ArgumentList $minerArgs `
        -RedirectStandardOutput (Join-Path $runDir 'miner.stdout.log') `
        -RedirectStandardError (Join-Path $runDir 'miner.stderr.log') `
        -PassThru -WindowStyle Hidden

    $balanceUri = "http://127.0.0.1:49681/api/pool/wallet/$devAddress/balance"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $balance = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        foreach ($entry in @(@('miner', $miner), @('pool', $pool), @('node', $node))) {
            if ($entry[1].HasExited) {
                throw "$($entry[0]) exited with code $($entry[1].ExitCode)"
            }
        }
        try {
            $balance = Invoke-RestMethod -Uri $balanceUri -TimeoutSec 2
            if ([uint64]$balance.valid_shares -gt 0) {
                break
            }
        }
        catch {
            # Keep polling until the miner registers and submits work.
        }
    }

    if ($null -eq $balance -or [uint64]$balance.valid_shares -eq 0) {
        throw "no accepted share observed within $TimeoutSeconds seconds"
    }

    # Quiesce block production before reading the final node state. This also
    # gives sled's periodic flusher time to persist an accepted difficulty-1
    # block before the node is terminated by the test harness.
    foreach ($process in @($miner, $pool)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 2

    # A difficulty-1 share may trigger synchronous full-block validation. The
    # Explorer can briefly exceed a single two-second request while that work
    # holds the storage path, so use the same bounded readiness retry as startup.
    $nodeInfo = Wait-Http 'http://127.0.0.1:49680/api/info' $node 'node'
    [pscustomobject]@{
        status = 'passed'
        run_dir = $runDir
        network = $nodeInfo.network
        node_height = $nodeInfo.height
        node_tip = $nodeInfo.tip_hash
        pool_health = $poolHealth.status
        valid_shares = $balance.valid_shares
        invalid_shares = $balance.invalid_shares
        direct_coinbase_mode = $balance.direct_coinbase_mode
    } | ConvertTo-Json -Depth 4
}
finally {
    foreach ($process in @($miner, $pool, $node)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
        }
    }
}
