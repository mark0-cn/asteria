[CmdletBinding()]
param(
    [string] $LocalnetRoot,
    [string] $CometBinary,
    [ValidatePattern('^[A-Za-z0-9._-]{1,50}$')]
    [string] $ChainId,
    [ValidatePattern('^ed25519:[0-9a-f]{64}$')]
    [string] $Authority,
    [ValidateSet("debug", "release")]
    [string] $Profile = "debug",
    [ValidateRange(10, 600)]
    [int] $StartupTimeoutSeconds = 120,
    [switch] $SkipBuild
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")

if ([string]::IsNullOrWhiteSpace($LocalnetRoot)) {
    $LocalnetRoot = Get-DefaultLocalnetRoot
}
if ([string]::IsNullOrWhiteSpace($CometBinary)) {
    $CometBinary = Get-DefaultCometBinary
}
$LocalnetRoot = Resolve-LocalnetPath -Path $LocalnetRoot
$CometBinary = Assert-CometBinary -CometBinary $CometBinary
$repoRoot = Get-AsteriaRepositoryRoot
$specs = @(Get-LocalnetNodeSpecs -LocalnetRoot $LocalnetRoot)

$active = @()
foreach ($kind in @("app", "comet")) {
    foreach ($spec in $specs) {
        $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind $kind -Node $spec.Node
        $process = Get-RecordedProcess -RecordPath $recordPath
        if ($null -ne $process) {
            $active += "$kind-$($spec.Name) PID $($process.Id)"
        }
        elseif (Test-Path -LiteralPath $recordPath -PathType Leaf) {
            Remove-Item -LiteralPath $recordPath -Force
        }
    }
}
if ($active.Count -gt 0) {
    throw "Localnet already has recorded processes: $($active -join ', '). Run Stop-Localnet.ps1 before starting it again."
}

$ports = @()
foreach ($spec in $specs) {
    $ports += $spec.AbciPort, $spec.HttpPort, $spec.P2pPort, $spec.RpcPort, $spec.MetricsPort
}
foreach ($port in $ports) {
    if (-not (Test-TcpPortAvailable -Port $port)) {
        throw "TCP port 127.0.0.1:$port is already in use. Stop the owning process or choose a separate machine."
    }
}

$cargo = (Get-Command cargo -ErrorAction Stop).Source
$cargoArguments = @(
    "build", "--locked",
    "--bin", "asteria-node",
    "--bin", "asteria-private-keygen"
)
if ($Profile -eq "release") {
    $cargoArguments += "--release"
}
Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        Invoke-CheckedCommand -FilePath $cargo -ArgumentList $cargoArguments
    }
    $metadataOutput = @(& $cargo metadata --no-deps --format-version 1)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
try {
    $cargoMetadata = ($metadataOutput -join [Environment]::NewLine) | ConvertFrom-Json
}
catch {
    throw "Unable to parse cargo metadata: $($_.Exception.Message)"
}

$appBinary = Join-Path ([string] $cargoMetadata.target_directory) "$Profile\asteria-node.exe"
if (-not (Test-Path -LiteralPath $appBinary -PathType Leaf)) {
    throw "Asteria node binary was not found at '$appBinary'. Run without -SkipBuild first."
}
$privateKeygenBinary = Join-Path ([string] $cargoMetadata.target_directory) "$Profile\asteria-private-keygen.exe"
if (-not (Test-Path -LiteralPath $privateKeygenBinary -PathType Leaf)) {
    throw "Private-order keygen binary was not found at '$privateKeygenBinary'. Run without -SkipBuild first."
}

$initializeArguments = @{
    LocalnetRoot = $LocalnetRoot
    CometBinary = $CometBinary
    PrivateKeygenBinary = $privateKeygenBinary
}
if ($PSBoundParameters.ContainsKey("ChainId")) {
    $initializeArguments.ChainId = $ChainId
}
if ($PSBoundParameters.ContainsKey("Authority")) {
    $initializeArguments.Authority = $Authority
}
& (Join-Path $PSScriptRoot "Initialize-Localnet.ps1") @initializeArguments

$runDirectory = Join-Path $LocalnetRoot "run"
$logDirectory = Join-Path $LocalnetRoot "logs"
New-Item -ItemType Directory -Force -Path $runDirectory, $logDirectory | Out-Null
$logStamp = [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)

try {
    foreach ($spec in $specs) {
        $privateKeySharePath = Get-PrivateOrderSharePath -LocalnetRoot $LocalnetRoot -Node $spec.Node
        if (-not (Test-Path -LiteralPath $privateKeySharePath -PathType Leaf)) {
            throw "Private-order key share file was not found for $($spec.Name)."
        }
        $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind app -Node $spec.Node
        $prefix = Join-Path $logDirectory "$logStamp-app-$($spec.Name)"
        [void] (Start-RecordedProcess `
            -FilePath $appBinary `
            -ArgumentList @(
                "--abci-bind", "127.0.0.1:$($spec.AbciPort)",
                "--http-bind", "127.0.0.1:$($spec.HttpPort)",
                "--data", $spec.AppData,
                "--comet-rpc", "http://127.0.0.1:$($spec.RpcPort)"
            ) `
            -WorkingDirectory $repoRoot `
            -StandardOutputPath "$prefix.out.log" `
            -StandardErrorPath "$prefix.err.log" `
            -RecordPath $recordPath `
            -Kind app `
            -Node $spec.Node `
            -ProcessEnvironment @{
                ASTERIA_PRIVATE_VALIDATOR_ID = [string] ($spec.Node + 1)
                ASTERIA_PRIVATE_KEY_SHARE_FILE = $privateKeySharePath
            })
    }
    foreach ($spec in $specs) {
        Wait-TcpPort -Port $spec.HttpPort -Deadline $deadline -Description "$($spec.Name) HTTP API"
    }

    $genesisPath = Join-Path $specs[0].CometHome "config\genesis.json"
    $genesisHash = (Get-FileHash -LiteralPath $genesisPath -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach ($spec in $specs) {
        $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind comet -Node $spec.Node
        $prefix = Join-Path $logDirectory "$logStamp-comet-$($spec.Name)"
        [void] (Start-RecordedProcess `
            -FilePath $CometBinary `
            -ArgumentList @(
                "start",
                "--home", $spec.CometHome,
                "--genesis_hash", $genesisHash,
                "--proxy_app", "tcp://127.0.0.1:$($spec.AbciPort)",
                "--rpc.laddr", "tcp://127.0.0.1:$($spec.RpcPort)",
                "--p2p.laddr", "tcp://127.0.0.1:$($spec.P2pPort)",
                "--p2p.external-address", "127.0.0.1:$($spec.P2pPort)",
                "--p2p.pex=false"
            ) `
            -WorkingDirectory $repoRoot `
            -StandardOutputPath "$prefix.out.log" `
            -StandardErrorPath "$prefix.err.log" `
            -RecordPath $recordPath `
            -Kind comet `
            -Node $spec.Node)
    }
    foreach ($spec in $specs) {
        Wait-TcpPort -Port $spec.RpcPort -Deadline $deadline -Description "$($spec.Name) CometBFT RPC"
    }

    $baselineHeight = $null
    while ([DateTime]::UtcNow -lt $deadline -and $null -eq $baselineHeight) {
        try {
            $baselineStatuses = @($specs | ForEach-Object {
                Get-CometRpcResult -RpcPort $_.RpcPort -Path "status"
            })
            if ($baselineStatuses.Count -eq 4) {
                $baselineHeight = (@($baselineStatuses | ForEach-Object {
                    [long] $_.sync_info.latest_block_height
                }) | Measure-Object -Maximum).Maximum
            }
        }
        catch {
            $baselineHeight = $null
        }
        if ($null -eq $baselineHeight) {
            Start-Sleep -Milliseconds 500
        }
    }
    if ($null -eq $baselineHeight) {
        throw "Timed out reading the initial height from all four validators."
    }

    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline -and -not $ready) {
        try {
            $snapshots = @($specs | ForEach-Object {
                [PSCustomObject]@{
                    Status = Get-CometRpcResult -RpcPort $_.RpcPort -Path "status"
                    NetInfo = Get-CometRpcResult -RpcPort $_.RpcPort -Path "net_info"
                    Validators = Get-CometRpcResult -RpcPort $_.RpcPort -Path "validators?per_page=100"
                }
            })
            $heights = @($snapshots | ForEach-Object { [long] $_.Status.sync_info.latest_block_height })
            $commonHeight = ($heights | Measure-Object -Minimum).Minimum
            $notReady = @($snapshots | Where-Object {
                [bool] $_.Status.sync_info.catching_up -or
                [int] $_.NetInfo.n_peers -ne 3 -or
                @($_.Validators.validators).Count -ne 4
            })
            $ready = $snapshots.Count -eq 4 -and
                $commonHeight -ge 2 -and
                $commonHeight -gt $baselineHeight -and
                $notReady.Count -eq 0
        }
        catch {
            $ready = $false
        }
        if (-not $ready) {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        throw "Timed out waiting for all four validators to commit blocks."
    }

    & (Join-Path $PSScriptRoot "Get-LocalnetStatus.ps1") -LocalnetRoot $LocalnetRoot -RequireHealthy | Out-Null
    Write-Host "Four-validator Asteria localnet is running."
    Write-Host "RPC endpoints:  http://127.0.0.1:26657, :26757, :26857, :26957"
    Write-Host "HTTP endpoints: http://127.0.0.1:8080, :8081, :8082, :8083"
    Write-Host "Stop with: powershell -File deploy\comet\windows\Stop-Localnet.ps1"
}
catch {
    $startupError = $_
    & (Join-Path $PSScriptRoot "Stop-Localnet.ps1") -LocalnetRoot $LocalnetRoot
    throw $startupError
}
