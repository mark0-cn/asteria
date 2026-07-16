[CmdletBinding()]
param(
    [string] $LocalnetRoot,
    [switch] $RequireHealthy,
    [ValidateRange(1, 60)]
    [int] $LivenessWindowSeconds = 5
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")

if ([string]::IsNullOrWhiteSpace($LocalnetRoot)) {
    $LocalnetRoot = Get-DefaultLocalnetRoot
}
$LocalnetRoot = Resolve-LocalnetPath -Path $LocalnetRoot
$specs = @(Get-LocalnetNodeSpecs -LocalnetRoot $LocalnetRoot)
$rows = @()
$rpcResults = @{}
$healthy = $true

foreach ($spec in $specs) {
    $appRecordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind app -Node $spec.Node
    $cometRecordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind comet -Node $spec.Node
    $appRunning = $null -ne (Get-RecordedProcess -RecordPath $appRecordPath)
    $cometRunning = $null -ne (Get-RecordedProcess -RecordPath $cometRecordPath)
    $appHealthy = $false
    $height = 0
    $catchingUp = $null
    $peers = 0
    $validatorCount = 0

    if ($appRunning) {
        $appHealthDeadline = [DateTime]::UtcNow.AddSeconds($LivenessWindowSeconds)
        while (-not $appHealthy -and [DateTime]::UtcNow -lt $appHealthDeadline) {
            try {
                $appHealth = Invoke-RestMethod -Uri "http://127.0.0.1:$($spec.HttpPort)/health" -Method Get -TimeoutSec 4
                $appHealthy = $appHealth.status -eq "ok" -and
                    [bool] $appHealth.initialized -and
                    [bool] $appHealth.comet_reachable
            }
            catch {
                $appHealthy = $false
            }
            if (-not $appHealthy) {
                Start-Sleep -Milliseconds 250
            }
        }
    }
    if ($cometRunning) {
        try {
            $status = Get-CometRpcResult -RpcPort $spec.RpcPort -Path "status"
            $netInfo = Get-CometRpcResult -RpcPort $spec.RpcPort -Path "net_info"
            $validators = Get-CometRpcResult -RpcPort $spec.RpcPort -Path "validators?per_page=100"
            $height = [long] $status.sync_info.latest_block_height
            $catchingUp = [bool] $status.sync_info.catching_up
            $peers = [int] $netInfo.n_peers
            $validatorCount = @($validators.validators).Count
            $rpcResults[$spec.Node] = $status
        }
        catch {
        }
    }

    $nodeHealthy = $appRunning -and $cometRunning -and $appHealthy -and
        $height -ge 1 -and $catchingUp -eq $false -and $peers -eq 3 -and $validatorCount -eq 4
    $healthy = $healthy -and $nodeHealthy
    $rows += [PSCustomObject]@{
        Node = $spec.Name
        App = if ($appRunning -and $appHealthy) { "up" } else { "down" }
        Comet = if ($cometRunning) { "up" } else { "down" }
        Height = $height
        CatchingUp = $catchingUp
        Peers = $peers
        Validators = $validatorCount
        Rpc = "127.0.0.1:$($spec.RpcPort)"
    }
}

$hashes = @()
$commonHeight = 0
$initialMaximumHeight = $null
$heightAdvanced = $false
if ($healthy -and $rpcResults.Count -eq 4) {
    $initialHeights = @($rpcResults.Values | ForEach-Object { [long] $_.sync_info.latest_block_height })
    $initialMaximumHeight = ($initialHeights | Measure-Object -Maximum).Maximum
    Start-Sleep -Seconds $LivenessWindowSeconds

    $secondRpcResults = @{}
    foreach ($spec in $specs) {
        try {
            $status = Get-CometRpcResult -RpcPort $spec.RpcPort -Path "status"
            $secondRpcResults[$spec.Node] = $status
            $rows[$spec.Node].Height = [long] $status.sync_info.latest_block_height
            $rows[$spec.Node].CatchingUp = [bool] $status.sync_info.catching_up
        }
        catch {
            $healthy = $false
        }
    }
    if ($secondRpcResults.Count -eq 4) {
        $rpcResults = $secondRpcResults
        $secondHeights = @($rpcResults.Values | ForEach-Object { [long] $_.sync_info.latest_block_height })
        $commonHeight = ($secondHeights | Measure-Object -Minimum).Minimum
        $heightAdvanced = $commonHeight -gt $initialMaximumHeight
        $healthy = $healthy -and $heightAdvanced
    }
    else {
        $healthy = $false
    }
}

if ($rpcResults.Count -eq 4) {
    $heights = @($rpcResults.Values | ForEach-Object { [long] $_.sync_info.latest_block_height })
    $commonHeight = ($heights | Measure-Object -Minimum).Minimum
    if ($commonHeight -ge 1) {
        foreach ($spec in $specs) {
            try {
                $block = Get-CometRpcResult -RpcPort $spec.RpcPort -Path "block?height=$commonHeight"
                $hashes += [string] $block.block.header.app_hash
            }
            catch {
                $healthy = $false
            }
        }
        if ($hashes.Count -ne 4 -or @($hashes | Select-Object -Unique).Count -ne 1) {
            $healthy = $false
        }
    }
}

Write-Host ($rows | Format-Table -AutoSize | Out-String)
if ($null -ne $initialMaximumHeight) {
    Write-Host "Height advanced beyond initial maximum: $initialMaximumHeight -> $commonHeight ($heightAdvanced)"
}
if ($hashes.Count -eq 4) {
    Write-Host "Common height: $commonHeight"
    Write-Host "Committed app hash: $($hashes[0])"
    Write-Host "App hash agreement: $(@($hashes | Select-Object -Unique).Count -eq 1)"
}
Write-Host "Four-validator localnet healthy: $healthy"

if ($RequireHealthy -and -not $healthy) {
    throw "The four-validator Asteria localnet is not healthy."
}

$rows
