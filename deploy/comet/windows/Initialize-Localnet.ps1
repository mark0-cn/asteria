[CmdletBinding()]
param(
    [string] $LocalnetRoot,
    [string] $CometBinary,
    [string] $PrivateKeygenBinary,
    [ValidatePattern('^[A-Za-z0-9._-]{1,50}$')]
    [string] $ChainId = "asteria-localnet-1",
    [ValidatePattern('^ed25519:[0-9a-f]{64}$')]
    [string] $Authority = "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
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
$specs = @(Get-LocalnetNodeSpecs -LocalnetRoot $LocalnetRoot)
$cometRoot = Join-Path $LocalnetRoot "comet"
$bootstrapHome = Join-Path $LocalnetRoot "bootstrap"
$privateConfigRoot = Get-PrivateOrderConfigRoot -LocalnetRoot $LocalnetRoot
$appStatePath = Join-Path (Get-AsteriaRepositoryRoot) "deploy\comet\genesis-app-state.json"

if ([string]::IsNullOrWhiteSpace($PrivateKeygenBinary)) {
    $cargo = (Get-Command cargo -ErrorAction Stop).Source
    Push-Location (Get-AsteriaRepositoryRoot)
    try {
        $metadata = (@(& $cargo metadata --no-deps --format-version 1) -join [Environment]::NewLine) | ConvertFrom-Json
        $PrivateKeygenBinary = Join-Path ([string] $metadata.target_directory) "debug\asteria-private-keygen.exe"
        if (-not (Test-Path -LiteralPath $PrivateKeygenBinary -PathType Leaf)) {
            Invoke-CheckedCommand -FilePath $cargo -ArgumentList @(
                "build", "--locked", "--bin", "asteria-private-keygen"
            )
        }
    }
    finally {
        Pop-Location
    }
}
$PrivateKeygenBinary = Resolve-LocalnetPath -Path $PrivateKeygenBinary
if (-not (Test-Path -LiteralPath $PrivateKeygenBinary -PathType Leaf)) {
    throw "Private-order keygen binary was not found at '$PrivateKeygenBinary'."
}

function Test-CompleteCometHome {
    param([Parameter(Mandatory = $true)][string] $CometHome)
    $required = @(
        "config\config.toml",
        "config\genesis.json",
        "config\node_key.json",
        "config\priv_validator_key.json",
        "data\priv_validator_state.json"
    )
    return (@($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $CometHome $_) -PathType Leaf) }).Count -eq 0)
}

function Test-NonemptyDirectory {
    param([Parameter(Mandatory = $true)][string] $Path)
    return ((Test-Path -LiteralPath $Path -PathType Container) -and
        (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0))
}

function Test-PrivateOrderConfiguration {
    param(
        [Parameter(Mandatory = $true)][string] $ConfigRoot,
        [Parameter(Mandatory = $true)][string] $GenesisPath
    )

    if (-not (Test-Path -LiteralPath $ConfigRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $GenesisPath -PathType Leaf)) {
        return $false
    }
    $validationOutput = @(& $PrivateKeygenBinary --output-dir $ConfigRoot --epoch 1 --chain-id $ChainId 2>&1)
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    try {
        $genesis = Get-Content -LiteralPath $GenesisPath -Raw | ConvertFrom-Json
        $publicKeys = Get-Content -LiteralPath (Join-Path $ConfigRoot "public-key-set.json") -Raw | ConvertFrom-Json
        if ([long] $genesis.app_state.app_protocol_version -ne $script:AsteriaAppProtocolVersion) {
            return $false
        }
        if ([string] $genesis.consensus_params.abci.vote_extensions_enable_height -ne "1") {
            return $false
        }
        if ($null -eq $genesis.app_state.private_order_key_set -or
            $genesis.app_state.private_order_key_set.key_id -ne $publicKeys.key_id) {
            return $false
        }
        foreach ($node in 0..3) {
            $validatorKeyPath = Join-Path $cometRoot "node$node\config\priv_validator_key.json"
            if (-not (Test-Path -LiteralPath $validatorKeyPath -PathType Leaf)) {
                return $false
            }
            $address = ([string] (Get-Content -LiteralPath $validatorKeyPath -Raw | ConvertFrom-Json).address).ToLowerInvariant()
            if ([int] $genesis.app_state.private_validator_bindings.$address -ne ($node + 1)) {
                return $false
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Assert-NoActiveLocalnetProcesses {
    foreach ($kind in @("app", "comet")) {
        foreach ($spec in $specs) {
            $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind $kind -Node $spec.Node
            $process = Get-RecordedProcess -RecordPath $recordPath
            if ($null -ne $process) {
                throw "Refusing to rebuild while $kind-$($spec.Name) PID $($process.Id) is running. Stop the localnet first."
            }
        }
    }
}

function Remove-ManagedLocalnetPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $resolvedRoot = [IO.Path]::GetFullPath($LocalnetRoot).TrimEnd('\')
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith("$resolvedRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unmanaged path '$resolved'."
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

function Set-TomlSetting {
    param(
        [Parameter(Mandatory = $true)][string] $Content,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $TomlValue
    )
    $pattern = "^(\s*)$([regex]::Escape($Name))\s*=.*$"
    $regex = New-Object Text.RegularExpressions.Regex(
        $pattern,
        [Text.RegularExpressions.RegexOptions]::Multiline
    )
    if (-not $regex.IsMatch($Content)) {
        throw "CometBFT config does not contain expected setting '$Name'."
    }
    return $regex.Replace(
        $Content,
        { param($match) "$($match.Groups[1].Value)$Name = $TomlValue" },
        1
    )
}

New-Item -ItemType Directory -Force -Path $LocalnetRoot | Out-Null
$completeHomes = @($specs | Where-Object { Test-CompleteCometHome -CometHome $_.CometHome })
$nonemptyHomes = @($specs | Where-Object { Test-NonemptyDirectory -Path $_.CometHome })
$compatibleExistingNetwork = $false

if ($completeHomes.Count -eq 4 -and $nonemptyHomes.Count -eq 4) {
    $existingGenesisPath = Join-Path $cometRoot "node0\config\genesis.json"
    $existingGenesis = Get-Content -LiteralPath $existingGenesisPath -Raw | ConvertFrom-Json
    if ($existingGenesis.chain_id -ne $ChainId) {
        throw "Existing genesis chain ID '$($existingGenesis.chain_id)' does not match requested '$ChainId'."
    }
    if ($existingGenesis.app_state.authority -ne $Authority) {
        throw "Existing genesis authority '$($existingGenesis.app_state.authority)' does not match requested '$Authority'."
    }
    $compatibleExistingNetwork = Test-PrivateOrderConfiguration `
        -ConfigRoot $privateConfigRoot `
        -GenesisPath $existingGenesisPath
    if ($compatibleExistingNetwork) {
        $hasCommittedBlocks = @($specs | Where-Object {
            $validatorState = Get-Content -LiteralPath (Join-Path $_.CometHome "data\priv_validator_state.json") -Raw | ConvertFrom-Json
            [long] $validatorState.height -gt 0
        }).Count -gt 0
        $completeApps = @($specs | Where-Object { Test-Path -LiteralPath $_.AppData -PathType Leaf })
        if ($hasCommittedBlocks -and $completeApps.Count -ne 4) {
            $compatibleExistingNetwork = $false
        }
    }
}

$managedStateExists = $nonemptyHomes.Count -gt 0 -or
    (Test-Path -LiteralPath (Join-Path $LocalnetRoot "apps")) -or
    (Test-Path -LiteralPath (Join-Path $LocalnetRoot "secrets")) -or
    (Test-Path -LiteralPath (Join-Path $LocalnetRoot "manifest.json"))

if ($managedStateExists -and -not $compatibleExistingNetwork) {
    Assert-NoActiveLocalnetProcesses
    Write-Warning "Existing localnet state predates or does not match private-order threshold provisioning; rebuilding managed state."
    Enable-PrivateOrderConfigRemoval -LocalnetRoot $LocalnetRoot
    foreach ($managedPath in @(
        $cometRoot,
        (Join-Path $LocalnetRoot "apps"),
        (Join-Path $LocalnetRoot "secrets"),
        (Join-Path $LocalnetRoot "run"),
        (Join-Path $LocalnetRoot "logs"),
        (Join-Path $LocalnetRoot "bootstrap"),
        (Join-Path $LocalnetRoot "manifest.json")
    )) {
        Remove-ManagedLocalnetPath -Path $managedPath
    }
    $completeHomes = @()
    $nonemptyHomes = @()
}

if ($nonemptyHomes.Count -eq 0) {
    $stagingRoot = Join-Path $LocalnetRoot ".comet-init-$([Guid]::NewGuid().ToString('N'))"
    $privateConfigParent = Split-Path -Parent $privateConfigRoot
    New-Item -ItemType Directory -Force -Path $privateConfigParent | Out-Null
    Protect-PrivateOrderDirectory -Path $privateConfigParent
    $keyStagingRoot = Join-Path $privateConfigParent ".private-order-init-$([Guid]::NewGuid().ToString('N'))"
    try {
        Invoke-CheckedCommand -FilePath $PrivateKeygenBinary -ArgumentList @(
            "--output-dir", $keyStagingRoot,
            "--epoch", "1",
            "--chain-id", $ChainId
        )
        Write-Host "Generating four CometBFT v0.38.23 validator homes..."
        Invoke-CheckedCommand -FilePath $CometBinary -ArgumentList @(
            "testnet",
            "--home", $bootstrapHome,
            "--v", "4",
            "--o", $stagingRoot,
            "--populate-persistent-peers=false"
        )

        for ($node = 0; $node -lt 4; $node++) {
            $stagedHome = Join-Path $stagingRoot "node$node"
            if (-not (Test-CompleteCometHome -CometHome $stagedHome)) {
                throw "CometBFT generated an incomplete validator home for node$node."
            }
        }

        $referenceGenesisPath = Join-Path $stagingRoot "node0\config\genesis.json"
        $genesis = Get-Content -LiteralPath $referenceGenesisPath -Raw | ConvertFrom-Json
        $appState = Get-Content -LiteralPath $appStatePath -Raw | ConvertFrom-Json
        $publicKeySet = Get-Content -LiteralPath (Join-Path $keyStagingRoot "public-key-set.json") -Raw | ConvertFrom-Json
        $validatorBindings = [ordered]@{}
        for ($node = 0; $node -lt 4; $node++) {
            $validatorKey = Get-Content -LiteralPath (Join-Path $stagingRoot "node$node\config\priv_validator_key.json") -Raw | ConvertFrom-Json
            $validatorBindings[([string] $validatorKey.address).ToLowerInvariant()] = $node + 1
        }
        $appState.authority = $Authority
        if ($appState.PSObject.Properties.Name -contains "private_order_key_set") {
            $appState.private_order_key_set = $publicKeySet
        }
        else {
            $appState | Add-Member -NotePropertyName private_order_key_set -NotePropertyValue $publicKeySet
        }
        if ($appState.PSObject.Properties.Name -contains "private_validator_bindings") {
            $appState.private_validator_bindings = $validatorBindings
        }
        else {
            $appState | Add-Member -NotePropertyName private_validator_bindings -NotePropertyValue $validatorBindings
        }
        $genesis.chain_id = $ChainId
        if (-not ($genesis.consensus_params.PSObject.Properties.Name -contains "abci")) {
            $genesis.consensus_params | Add-Member -NotePropertyName abci -NotePropertyValue ([PSCustomObject]@{})
        }
        if ($genesis.consensus_params.abci.PSObject.Properties.Name -contains "vote_extensions_enable_height") {
            $genesis.consensus_params.abci.vote_extensions_enable_height = "1"
        }
        else {
            $genesis.consensus_params.abci | Add-Member -NotePropertyName vote_extensions_enable_height -NotePropertyValue "1"
        }
        if ($genesis.PSObject.Properties.Name -contains "app_state") {
            $genesis.app_state = $appState
        }
        else {
            $genesis | Add-Member -NotePropertyName app_state -NotePropertyValue $appState
        }
        Write-Utf8NoBom -Path $referenceGenesisPath -Content ($genesis | ConvertTo-Json -Depth 100)
        for ($node = 1; $node -lt 4; $node++) {
            [IO.File]::Copy(
                $referenceGenesisPath,
                (Join-Path $stagingRoot "node$node\config\genesis.json"),
                $true
            )
        }

        if (Test-Path -LiteralPath $cometRoot -PathType Container) {
            [IO.Directory]::Delete($cometRoot, $false)
        }
        [IO.Directory]::Move($stagingRoot, $cometRoot)
        [IO.Directory]::Move($keyStagingRoot, $privateConfigRoot)
    }
    catch {
        $initializationError = $_
        if (Test-Path -LiteralPath $stagingRoot -PathType Container) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
        if (Test-Path -LiteralPath $keyStagingRoot -PathType Container) {
            Remove-Item -LiteralPath $keyStagingRoot -Recurse -Force
        }
        throw $initializationError
    }
}
elseif (-not $compatibleExistingNetwork) {
    throw "Private-order localnet initialization reached an inconsistent state."
}

Invoke-CheckedCommand -FilePath $PrivateKeygenBinary -ArgumentList @(
    "--output-dir", $privateConfigRoot,
    "--epoch", "1",
    "--chain-id", $ChainId
)
Protect-PrivateOrderConfig -Path $privateConfigRoot

$nodeIds = @()
foreach ($spec in $specs) {
    $nodeIdOutput = @(& $CometBinary show-node-id --home $spec.CometHome 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read node ID for $($spec.Name): $($nodeIdOutput -join [Environment]::NewLine)"
    }
    $nodeId = ($nodeIdOutput | Select-Object -Last 1).ToString().Trim()
    if ($nodeId -notmatch '^[0-9a-f]{40}$') {
        throw "Invalid CometBFT node ID '$nodeId' for $($spec.Name)."
    }
    $nodeIds += $nodeId
}
if (@($nodeIds | Select-Object -Unique).Count -ne 4) {
    throw "The localnet must have four unique CometBFT node IDs."
}

foreach ($spec in $specs) {
    $persistentPeers = @()
    foreach ($peer in $specs) {
        if ($peer.Node -ne $spec.Node) {
            $persistentPeers += "$($nodeIds[$peer.Node])@127.0.0.1:$($peer.P2pPort)"
        }
    }

    $configPath = Join-Path $spec.CometHome "config\config.toml"
    $config = Get-Content -LiteralPath $configPath -Raw
    $config = Set-TomlSetting -Content $config -Name "persistent_peers" -TomlValue ('"' + ($persistentPeers -join ',') + '"')
    $config = Set-TomlSetting -Content $config -Name "pex" -TomlValue "false"
    $config = Set-TomlSetting -Content $config -Name "timeout_commit" -TomlValue '"1s"'
    $config = Set-TomlSetting -Content $config -Name "prometheus" -TomlValue "true"
    $config = Set-TomlSetting -Content $config -Name "prometheus_listen_addr" -TomlValue ('"127.0.0.1:' + $spec.MetricsPort + '"')
    Write-Utf8NoBom -Path $configPath -Content $config

    $appDirectory = Split-Path -Parent $spec.AppData
    New-Item -ItemType Directory -Force -Path $appDirectory | Out-Null
}

$referenceGenesisPath = Join-Path $specs[0].CometHome "config\genesis.json"
$referenceHash = (Get-FileHash -LiteralPath $referenceGenesisPath -Algorithm SHA256).Hash.ToLowerInvariant()
$referenceGenesis = Get-Content -LiteralPath $referenceGenesisPath -Raw | ConvertFrom-Json
if ($referenceGenesis.chain_id -ne $ChainId) {
    throw "Existing genesis chain ID '$($referenceGenesis.chain_id)' does not match requested '$ChainId'."
}
if ($referenceGenesis.app_state.authority -ne $Authority) {
    throw "Existing genesis authority '$($referenceGenesis.app_state.authority)' does not match requested '$Authority'."
}
if ([string] $referenceGenesis.consensus_params.abci.vote_extensions_enable_height -ne "1") {
    throw "Genesis must enable vote extensions at height 1."
}
$publicKeySet = Get-Content -LiteralPath (Get-PrivateOrderPublicKeyPath -LocalnetRoot $LocalnetRoot) -Raw | ConvertFrom-Json
if ($referenceGenesis.app_state.private_order_key_set.key_id -ne $publicKeySet.key_id) {
    throw "Genesis private-order key set does not match the provisioned public key set."
}
$validators = @($referenceGenesis.validators)
$validatorAddresses = @($validators | ForEach-Object { ([string] $_.address).ToLowerInvariant() })
if ($validators.Count -ne 4 -or @($validatorAddresses | Select-Object -Unique).Count -ne 4) {
    throw "Genesis must contain exactly four unique validators."
}

foreach ($spec in $specs) {
    $genesisPath = Join-Path $spec.CometHome "config\genesis.json"
    $hash = (Get-FileHash -LiteralPath $genesisPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $referenceHash) {
        throw "Genesis mismatch for $($spec.Name)."
    }
    $validatorKey = Get-Content -LiteralPath (Join-Path $spec.CometHome "config\priv_validator_key.json") -Raw | ConvertFrom-Json
    $validatorAddress = ([string] $validatorKey.address).ToLowerInvariant()
    if ($validatorAddresses -notcontains $validatorAddress) {
        throw "$($spec.Name)'s validator key is absent from genesis."
    }
    if ([int] $referenceGenesis.app_state.private_validator_bindings.$validatorAddress -ne ($spec.Node + 1)) {
        throw "$($spec.Name)'s Comet validator address is not bound to private validator ID $($spec.Node + 1)."
    }
    $config = Get-Content -LiteralPath (Join-Path $spec.CometHome "config\config.toml") -Raw
    $peerCount = ([regex]::Match($config, '(?m)^persistent_peers\s*=\s*"([^"]+)"$').Groups[1].Value -split ',').Count
    if ($peerCount -ne 3) {
        throw "$($spec.Name) must have exactly three persistent peers."
    }
}

$manifest = [ordered]@{
    app_protocol_version = $script:AsteriaAppProtocolVersion
    chain_id = $ChainId
    authority = $Authority
    cometbft_version = "v0.38.23"
    genesis_sha256 = $referenceHash
    nodes = @($specs | ForEach-Object {
        [ordered]@{
            name = $_.Name
            node_id = $nodeIds[$_.Node]
            validator_address = ([string] (Get-Content -LiteralPath (Join-Path $_.CometHome "config\priv_validator_key.json") -Raw | ConvertFrom-Json).address).ToLowerInvariant()
            abci = "127.0.0.1:$($_.AbciPort)"
            http = "http://127.0.0.1:$($_.HttpPort)"
            p2p = "127.0.0.1:$($_.P2pPort)"
            rpc = "http://127.0.0.1:$($_.RpcPort)"
            metrics = "http://127.0.0.1:$($_.MetricsPort)"
        }
    })
}
Write-Utf8NoBom -Path (Join-Path $LocalnetRoot "manifest.json") -Content ($manifest | ConvertTo-Json -Depth 10)

Write-Host "Asteria localnet '$ChainId' is initialized with four validators."
Write-Host "Genesis SHA-256: $referenceHash"
Write-Host "Persistent data: $LocalnetRoot"
