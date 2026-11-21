param(
    [switch]$SkipBuild,
    [switch]$Offline,
    [switch]$Release,
    [switch]$VerifyPeerSync,
    [ValidateSet('neural-devnet')]
    [string]$Network = 'neural-devnet',
    [ValidateRange(1, 100)]
    [int]$TargetHeight = 1,
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

$externalProjects = @(
    'HyphenPool\Cargo.toml',
    'HyphenMiner\Cargo.toml',
    'HyphenWallet\rust\Cargo.toml'
)
foreach ($manifest in $externalProjects) {
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "Compatibility smoke requires the independent project manifest '$manifest'. Check out HyphenPool, HyphenMiner and HyphenWallet at the repository root."
    }
}

function Invoke-Cargo {
    param([string[]]$CargoArgs)

    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo failed with exit code ${LASTEXITCODE}: cargo $($CargoArgs -join ' ')"
    }
}

if (-not $SkipBuild) {
    $common = @('build', '--locked')
    if ($Release) { $common += '--release' }
    if ($Offline) {
        $common += '--offline'
    }
    Invoke-Cargo ($common + @('-p', 'hyphen-node'))
    Invoke-Cargo ($common + @('--manifest-path', 'HyphenPool/Cargo.toml'))
    Invoke-Cargo ($common + @('--manifest-path', 'HyphenMiner/Cargo.toml'))
}

$runDir = Join-Path $repoRoot ("target\$Network-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$profile = if ($Release) { 'release' } else { 'debug' }
$nodeExe = (Resolve-Path "target\$profile\hyphen-node.exe").Path
$poolExe = (Resolve-Path "HyphenPool\target\$profile\hyphen-pool-server.exe").Path
$minerExe = (Resolve-Path "HyphenMiner\target\$profile\hyphen-miner.exe").Path

# This address comes from a published fixed seed and is for local devnet only.
$devAddress = 'hy12X1dKMPZ9KRTa4CaZ1MFGHPqCGFnjwVZAPQPKcYq5fpUPkdKn6VVomB1oRK8r7bW8s7uR9iYUQtpSdSfifsCg1P3WKdxD3'
$node = $null
$pool = $null
$miner = $null
$peer = $null

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

function Get-PeakWorkingSet([Diagnostics.Process[]]$Processes) {
    $bytes = @{}
    foreach ($process in $Processes) {
        $process.Refresh()
        $bytes[$process.ProcessName] = $process.PeakWorkingSet64
    }
    $bytes
}

try {
    $nodeArgs = @(
        '--network', $Network,
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
    if ([uint64]$nodeInfo.height -ne 0) { throw 'Expected a new chain at genesis' }

    $poolArgs = @(
        '--network', $Network,
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
        '--network', $Network,
        '--pool', '127.0.0.1:49640',
        '--threads', '1',
        '--batch-size', '1000',
        '--wallet-address', $devAddress
    )
    $miner = Start-Process -FilePath $minerExe -ArgumentList $minerArgs `
        -RedirectStandardOutput (Join-Path $runDir 'miner.stdout.log') `
        -RedirectStandardError (Join-Path $runDir 'miner.stderr.log') `
        -PassThru -WindowStyle Hidden

    $balanceUri = "http://127.0.0.1:49681/api/pool/wallet/$devAddress/balance?limit=128"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $balance = $null
    $memorySamples = [Collections.Generic.List[object]]::new()
    $nextHeight = 1
    $lastReadError = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 500
        foreach ($entry in @(@('miner', $miner), @('pool', $pool), @('node', $node))) {
            if ($entry[1].HasExited) {
                throw "$($entry[0]) exited with code $($entry[1].ExitCode)"
            }
        }
        try {
            $nodeInfo = Invoke-RestMethod -Uri 'http://127.0.0.1:49680/api/info' -TimeoutSec 2
            $balance = Invoke-RestMethod -Uri $balanceUri -TimeoutSec 2
            $lastReadError = $null
        }
        catch {
            $lastReadError = "$($_.Exception.Message) $($_.ErrorDetails)"
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 400) {
                throw "Invalid smoke request. $lastReadError. Logs in $runDir"
            }
            continue
        }
        $height = [uint64]$nodeInfo.height
        if ($height -ge $nextHeight) {
            $memorySamples.Add([pscustomobject]@{
                height = $height
                peak_working_set_bytes = Get-PeakWorkingSet @($node, $pool, $miner)
            })
            while ($nextHeight -le $height) { $nextHeight *= 2 }
        }
        if ([uint64]$balance.total_blocks_found -ge $TargetHeight -and $height -ge $TargetHeight) {
            break
        }
    }

    if ($null -eq $balance -or [uint64]$balance.valid_shares -eq 0 -or
        [uint64]$balance.total_blocks_found -lt $TargetHeight -or [uint64]$nodeInfo.height -lt $TargetHeight) {
        throw "Target $TargetHeight timed out after ${TimeoutSeconds}s. Last node height $($nodeInfo.height). Last HTTP error '$lastReadError'. Logs in $runDir"
    }
    $firstReward = @($balance.recent_reward_events | Where-Object { $_.height -eq 1 -and $_.direct_coinbase })
    if ($firstReward.Count -ne 1) { throw 'Missing or duplicate pool settlement for the first reward' }

    # Quiesce block production before reading the final node state. This also
    # gives sled's periodic flusher time to persist an accepted difficulty-1
    # block before the node is terminated by the test harness.
    $peakWorkingSetBytes = Get-PeakWorkingSet @($node, $pool, $miner)
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
    if ([uint64]$nodeInfo.height -lt 1) { throw 'Node did not accept a post-genesis block' }
    if ($VerifyPeerSync) {
        $identity = Select-String -Path (Join-Path $runDir 'node.stdout.log') -Pattern 'local peer ID: ([A-Za-z0-9]+)' | Select-Object -First 1
        if (-not $identity) { throw 'Node did not log its persistent peer ID' }
        $peerId = $identity.Matches[0].Groups[1].Value
        $peerArgs = @('--network', $Network, '--data-dir', (Join-Path $runDir 'peer'),
            '--listen', '/ip4/127.0.0.1/tcp/49734', '--rpc-bind', '127.0.0.1:49733',
            '--template-bind', '127.0.0.1:49750', '--explorer-bind', '127.0.0.1:49780')
        $seededArgs = $peerArgs + @('--boot-nodes', "/ip4/127.0.0.1/tcp/49634/p2p/$peerId")
        $peer = Start-Process -FilePath $nodeExe -ArgumentList $seededArgs `
            -RedirectStandardOutput (Join-Path $runDir 'peer.stdout.log') `
            -RedirectStandardError (Join-Path $runDir 'peer.stderr.log') -PassThru -WindowStyle Hidden
        $peerUri = 'http://127.0.0.1:49780/api/info'
        $peerInfo = Wait-Http $peerUri $peer 'peer'
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while ($peerInfo.tip_hash -ne $nodeInfo.tip_hash) {
            if ($peer.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw "Peer failed to reach $($nodeInfo.tip_hash)" }
            Start-Sleep -Milliseconds 500
            try { $peerInfo = Invoke-RestMethod -Uri $peerUri -TimeoutSec 2 } catch { continue }
        }
        if ($peerInfo.network -ne $nodeInfo.network -or $peerInfo.height -ne $nodeInfo.height) { throw 'Peer chain identity or height differs' }
        Stop-Process -Id $peer.Id -Force
        $peer.WaitForExit()
        $peer = Start-Process -FilePath $nodeExe -ArgumentList $peerArgs `
            -RedirectStandardOutput (Join-Path $runDir 'peer-restarted.stdout.log') `
            -RedirectStandardError (Join-Path $runDir 'peer-restarted.stderr.log') -PassThru -WindowStyle Hidden
        $restored = Wait-Http $peerUri $peer 'restarted peer'
        if ($restored.height -ne $nodeInfo.height -or $restored.tip_hash -ne $nodeInfo.tip_hash) {
            throw 'Restarted peer did not recover the canonical tip from storage'
        }
    }
    # Open the same on-disk ledger in a new process with the miner stopped.
    $pool = Start-Process -FilePath $poolExe -ArgumentList $poolArgs `
        -RedirectStandardOutput (Join-Path $runDir 'pool-restarted.stdout.log') `
        -RedirectStandardError (Join-Path $runDir 'pool-restarted.stderr.log') `
        -PassThru -WindowStyle Hidden
    $reopened = Wait-Http $balanceUri $pool 'restarted pool'
    $persisted = @($reopened.recent_reward_events | Where-Object { $_.height -eq 1 -and $_.direct_coinbase })
    if ($persisted.Count -ne 1 -or $persisted[0].block_hash_hex -ne $firstReward[0].block_hash_hex -or
        [string]$persisted[0].amount_atomic -ne [string]$firstReward[0].amount_atomic) {
        throw 'First reward changed after reopening the pool ledger'
    }
    $walletTest = @('test', '--locked', '--manifest-path', 'HyphenWallet/rust/Cargo.toml', '--test', 'devnet_reward')
    if ($Release) { $walletTest += '--release' }
    if ($Offline) { $walletTest += '--offline' }
    $previousReward = $env:HYPHEN_SMOKE_REWARD_ATOMIC
    $previousHash = $env:HYPHEN_SMOKE_BLOCK_HASH
    try {
        $env:HYPHEN_SMOKE_REWARD_ATOMIC = $firstReward[0].amount_atomic
        $env:HYPHEN_SMOKE_BLOCK_HASH = $firstReward[0].block_hash_hex
        $artifacts = & cargo @walletTest --no-run --message-format=json
        if ($LASTEXITCODE -ne 0) { throw 'Could not build wallet scan tests' }
        $walletBinary = $artifacts | ForEach-Object { ConvertFrom-Json $_ } | Where-Object {
            $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'devnet_reward' -and $_.executable
        } | Select-Object -ExpandProperty executable -Last 1
        if (-not $walletBinary) { throw 'Wallet scan test executable missing' }
        $walletInfo = [Diagnostics.ProcessStartInfo]::new($walletBinary, '--ignored --nocapture')
        $walletInfo.UseShellExecute = $false
        $wallet = [Diagnostics.Process]::Start($walletInfo)
        try {
            $walletPeak = 0L
            while (-not $wallet.HasExited) {
                $wallet.Refresh()
                try { $walletPeak = [Math]::Max($walletPeak, $wallet.PeakWorkingSet64) }
                catch { if (-not $wallet.HasExited) { throw } }
                [void]$wallet.WaitForExit(10)
            }
            if ($wallet.ExitCode -ne 0) { throw "Wallet scan test failed with exit code $($wallet.ExitCode)" }
        } finally {
            $wallet.Dispose()
        }
    } finally {
        $env:HYPHEN_SMOKE_REWARD_ATOMIC = $previousReward
        $env:HYPHEN_SMOKE_BLOCK_HASH = $previousHash
    }
    $result = [pscustomobject]@{
        status = 'passed'
        run_dir = $runDir
        network = $nodeInfo.network
        node_height = $nodeInfo.height
        node_tip = $nodeInfo.tip_hash
        pool_health = $poolHealth.status
        valid_shares = $balance.valid_shares
        invalid_shares = $balance.invalid_shares
        direct_coinbase_mode = $balance.direct_coinbase_mode
        first_reward_atomic = $firstReward[0].amount_atomic
        first_block_hash = $firstReward[0].block_hash_hex
        pool_restart_verified = $true
        peer_sync_verified = $VerifyPeerSync.IsPresent
        target_height = $TargetHeight
        peak_working_set_bytes_before_restart = $peakWorkingSetBytes
        memory_samples = $memorySamples
        wallet_scan_sampled_peak_working_set_bytes = if ($walletPeak -gt 0) { $walletPeak } else { $null }
    } | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText((Join-Path $runDir 'result.json'), $result)
    $result
}
finally {
    foreach ($process in @($miner, $pool, $peer, $node)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
        }
    }
}
