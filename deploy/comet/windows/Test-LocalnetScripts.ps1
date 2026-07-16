[CmdletBinding()]
param(
    [switch] $IncludeRuntime,
    [string] $CometBinary
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")

function Assert-LocalnetTest {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw "Regression test failed: $Message"
    }
}

function Start-TestSleeper {
    param(
        [Parameter(Mandatory = $true)][string] $Root,
        [Parameter(Mandatory = $true)][string] $RecordPath,
        [Parameter(Mandatory = $true)][int] $Node,
        [string] $PidFile,
        [string] $EnvironmentProbeFile,
        [hashtable] $ProcessEnvironment = @{}
    )

    $logRoot = Join-Path $Root "logs"
    New-Item -ItemType Directory -Force -Path $logRoot, (Split-Path -Parent $RecordPath) | Out-Null
    $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $command = "Start-Sleep -Seconds 60"
    if (-not [string]::IsNullOrWhiteSpace($PidFile)) {
        $escapedPidFile = $PidFile.Replace("'", "''")
        $command = "[IO.File]::WriteAllText('$escapedPidFile', `$PID.ToString()); Start-Sleep -Seconds 60"
    }
    if (-not [string]::IsNullOrWhiteSpace($EnvironmentProbeFile)) {
        $escapedProbeFile = $EnvironmentProbeFile.Replace("'", "''")
        $command = "[IO.File]::WriteAllText('$escapedProbeFile', [Environment]::GetEnvironmentVariable('ASTERIA_PRIVATE_KEY_SHARE_FILE')); Start-Sleep -Seconds 60"
    }
    return (Start-RecordedProcess `
        -FilePath $powershell `
        -ArgumentList @("-NoProfile", "-Command", $command) `
        -WorkingDirectory $Root `
        -StandardOutputPath (Join-Path $logRoot "app-node$Node.out.log") `
        -StandardErrorPath (Join-Path $logRoot "app-node$Node.err.log") `
        -RecordPath $RecordPath `
        -Kind app `
        -Node $Node `
        -ProcessEnvironment $ProcessEnvironment)
}

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase "asteria-localnet-script-tests-$([Guid]::NewGuid().ToString('N'))"
$trackedProcesses = @()
$runtimeRoot = $null
$runtimeCleanupRoot = $null
$oldCargoTargetDirectory = $env:CARGO_TARGET_DIR
$testsSucceeded = $false

New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
try {
    $repositoryRoot = Get-AsteriaRepositoryRoot
    $composeText = Get-Content -LiteralPath (Join-Path $repositoryRoot "docker-compose.blockchain.yml") -Raw
    $linuxInitText = Get-Content -LiteralPath (Join-Path $repositoryRoot "deploy\comet\init-testnet.sh") -Raw
    $windowsInitText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Initialize-Localnet.ps1") -Raw
    $windowsStartText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Start-Localnet.ps1") -Raw
    $windowsCommonText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "Localnet.Common.ps1") -Raw
    $nodeText = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\node.rs") -Raw
    $consensusText = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\consensus.rs") -Raw
    $engineText = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\engine.rs") -Raw
    $storeText = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\store.rs") -Raw
    $stateCommitmentText = Get-Content -LiteralPath (Join-Path $repositoryRoot "src\state_commitment.rs") -Raw
    $genesisAppState = Get-Content -LiteralPath (Join-Path $repositoryRoot "deploy\comet\genesis-app-state.json") -Raw | ConvertFrom-Json
    $protocolVersionMatch = [regex]::Match($consensusText, 'pub const APP_PROTOCOL_VERSION: u64 = (\d+);')
    Assert-LocalnetTest -Condition $protocolVersionMatch.Success -Message "Rust app protocol version constant is missing"
    $appProtocolVersion = [int] $protocolVersionMatch.Groups[1].Value
    Assert-LocalnetTest -Condition ([int] $genesisAppState.app_protocol_version -eq $appProtocolVersion) -Message "genesis app protocol version differs from Rust"
    Assert-LocalnetTest -Condition ($windowsCommonText -match "AsteriaAppProtocolVersion = $appProtocolVersion") -Message "Windows app protocol version differs from Rust"
    Assert-LocalnetTest -Condition ($linuxInitText -match "APP_PROTOCOL_VERSION=$appProtocolVersion") -Message "Linux app protocol version differs from Rust"
    Assert-LocalnetTest -Condition ($engineText -match "(?s)fn default_protocol_version\(\) -> u16 \{\s*$appProtocolVersion\s*\}") -Message "engine state protocol version differs from consensus"
    $storeVersionMatches = [regex]::Matches($storeText, 'TableDefinition::new\("[^"]+_v(\d+)"\)')
    Assert-LocalnetTest -Condition ($storeVersionMatches.Count -eq 4) -Message "redb physical table definitions are missing"
    Assert-LocalnetTest -Condition (@($storeVersionMatches | Where-Object { [int] $_.Groups[1].Value -ne $appProtocolVersion }).Count -eq 0) -Message "redb physical table domain differs from the app protocol version"
    Assert-LocalnetTest -Condition ($stateCommitmentText -match "ASTERIA_STATE_ENTITY_KEY_V$appProtocolVersion") -Message "state entity key domain differs from the app protocol version"
    Assert-LocalnetTest -Condition (($composeText | Select-String -Pattern 'ASTERIA_PRIVATE_VALIDATOR_ID:' -AllMatches).Matches.Count -eq 4) -Message "Docker Compose does not bind four private validator IDs"
    Assert-LocalnetTest -Condition (($composeText | Select-String -Pattern 'ASTERIA_PRIVATE_KEY_SHARE_FILE:' -AllMatches).Matches.Count -eq 4) -Message "Docker Compose does not bind four private key share files"
    Assert-LocalnetTest -Condition ([regex]::Matches($composeText, 'private-order-share[0-3]:/private:ro').Count -eq 4) -Message "Docker Compose does not mount one isolated private share volume per app"
    Assert-LocalnetTest -Condition ([regex]::Matches($composeText, '(?m)^\s{2}private-order-share[0-3]:\s*$').Count -eq 4) -Message "Docker Compose does not declare four private share volumes"
    Assert-LocalnetTest -Condition ($composeText -notmatch 'private-order-config') -Message "Docker Compose still uses a shared private-order volume"
    Assert-LocalnetTest -Condition ([regex]::Matches($composeText, '127\.0\.0\.1:\d+:\d+').Count -eq 16) -Message "Docker Compose host ports are not all bound to loopback"
    Assert-LocalnetTest -Condition ($composeText -notmatch 'ASTERIA_PRIVATE_KEY_SHARE(?!_FILE)') -Message "Docker Compose still injects a raw private key share"
    Assert-LocalnetTest -Condition ($windowsStartText -match 'ASTERIA_PRIVATE_KEY_SHARE_FILE' -and $windowsStartText -notmatch 'ASTERIA_PRIVATE_KEY_SHARE(?!_FILE)') -Message "Windows startup does not exclusively use private key share files"
    Assert-LocalnetTest -Condition ($nodeText -match 'ASTERIA_PRIVATE_KEY_SHARE_FILE' -and $nodeText -notmatch 'ASTERIA_PRIVATE_KEY_SHARE(?!_FILE)') -Message "Asteria node accepts a raw private key share instead of requiring a file"
    Assert-LocalnetTest -Condition ($linuxInitText -match 'vote_extensions_enable_height\s*=\s*"1"') -Message "Linux genesis initialization does not enable vote extensions at height 1"
    Assert-LocalnetTest -Condition ($windowsInitText -match 'vote_extensions_enable_height') -Message "Windows genesis initialization does not enable vote extensions"
    Assert-LocalnetTest -Condition ($linuxInitText -match 'private_validator_bindings' -and $windowsInitText -match 'private_validator_bindings') -Message "validator address bindings are not provisioned on both platforms"
    Assert-LocalnetTest -Condition ($windowsInitText -match 'Protect-PrivateOrderDirectory -Path \$privateConfigParent' -and $windowsInitText -match '\$keyStagingRoot = Join-Path \$privateConfigParent') -Message "Windows key generation is not staged under a pre-protected parent directory"

    $atomicPath = Join-Path $testRoot "atomic.json"
    Write-Utf8NoBomAtomic -Path $atomicPath -Content '{"generation":1}'
    Write-Utf8NoBomAtomic -Path $atomicPath -Content '{"generation":2}'
    $atomicValue = Get-Content -LiteralPath $atomicPath -Raw | ConvertFrom-Json
    Assert-LocalnetTest -Condition ($atomicValue.generation -eq 2) -Message "atomic record replacement did not publish the second generation"

    $sourceComet = Get-DefaultCometBinary
    $sourceGo = Join-Path (Get-AsteriaRepositoryRoot) ".tools\go\bin\go.exe"
    if ((Test-Path -LiteralPath $sourceComet -PathType Leaf) -and
        (Test-Path -LiteralPath $sourceGo -PathType Leaf)) {
        $customTools = Join-Path $testRoot "custom-tools"
        $customComet = Join-Path $customTools "bin\cometbft.exe"
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $customComet) | Out-Null
        New-Item -ItemType HardLink -Path $customComet -Target $sourceComet | Out-Null
        & (Join-Path $PSScriptRoot "Install-CometBft.ps1") -ToolsRoot $customTools -GoBinary $sourceGo
    }

    $recordFailureRoot = Join-Path $testRoot "record-failure"
    $recordFailureRun = Join-Path $recordFailureRoot "run"
    $recordFailurePath = Join-Path $recordFailureRun "app-node0.json"
    New-Item -ItemType Directory -Force -Path $recordFailurePath | Out-Null
    $recordFailureObserved = $false
    $failedRecordPid = 0
    try {
        [void] (Start-TestSleeper -Root $recordFailureRoot -RecordPath $recordFailurePath -Node 0)
    }
    catch {
        $recordFailureObserved = $_.Exception.Message -match "newly started process was terminated"
        if ($_.Exception.Message -match 'PID (\d+)') {
            $failedRecordPid = [int] $Matches[1]
        }
    }
    Start-Sleep -Milliseconds 250
    Assert-LocalnetTest -Condition ($failedRecordPid -gt 0) -Message "record publication failure did not identify the child PID"
    $leakedProcess = Get-Process -Id $failedRecordPid -ErrorAction SilentlyContinue
    Assert-LocalnetTest -Condition $recordFailureObserved -Message "record publication failure was not reported as a terminated child"
    Assert-LocalnetTest -Condition ($null -eq $leakedProcess) -Message "record publication failure leaked PID $failedRecordPid"

    $corruptStopRoot = Join-Path $testRoot "corrupt-stop"
    $corruptRun = Join-Path $corruptStopRoot "run"
    New-Item -ItemType Directory -Force -Path $corruptRun | Out-Null
    $app0Record = Get-ProcessRecordPath -LocalnetRoot $corruptStopRoot -Kind app -Node 0
    $app1Record = Get-ProcessRecordPath -LocalnetRoot $corruptStopRoot -Kind app -Node 1
    $app0 = Start-TestSleeper -Root $corruptStopRoot -RecordPath $app0Record -Node 0
    $app1 = Start-TestSleeper -Root $corruptStopRoot -RecordPath $app1Record -Node 1
    $trackedProcesses += $app0, $app1
    $corruptRecord = Get-ProcessRecordPath -LocalnetRoot $corruptStopRoot -Kind comet -Node 3
    Write-Utf8NoBom -Path $corruptRecord -Content '{invalid-json'

    $stopReportedCorruption = $false
    try {
        & (Join-Path $PSScriptRoot "Stop-Localnet.ps1") -LocalnetRoot $corruptStopRoot
    }
    catch {
        $stopReportedCorruption = $_.Exception.Message -match "Invalid localnet process record"
    }
    $app0.Refresh()
    $app1.Refresh()
    Assert-LocalnetTest -Condition $stopReportedCorruption -Message "Stop-Localnet did not report the corrupt record"
    Assert-LocalnetTest -Condition ($app0.HasExited -and $app1.HasExited) -Message "a corrupt record prevented other recorded processes from stopping"
    Assert-LocalnetTest -Condition (Test-Path -LiteralPath $corruptRecord -PathType Leaf) -Message "Stop-Localnet removed a corrupt record that still requires operator inspection"

    $environmentRoot = Join-Path $testRoot "private-environment"
    $environmentRecord = Get-ProcessRecordPath -LocalnetRoot $environmentRoot -Kind app -Node 2
    $environmentProbe = Join-Path $environmentRoot "private-environment.txt"
    $probeShare = "a" * 64
    $probeSharePath = Join-Path $environmentRoot "node2.key-share"
    New-Item -ItemType Directory -Force -Path $environmentRoot | Out-Null
    [IO.File]::WriteAllText($probeSharePath, $probeShare)
    $previousParentShareFile = $env:ASTERIA_PRIVATE_KEY_SHARE_FILE
    $env:ASTERIA_PRIVATE_KEY_SHARE_FILE = "parent-path"
    try {
        $environmentProcess = Start-TestSleeper `
            -Root $environmentRoot `
            -RecordPath $environmentRecord `
            -Node 2 `
            -EnvironmentProbeFile $environmentProbe `
            -ProcessEnvironment @{
                ASTERIA_PRIVATE_VALIDATOR_ID = "3"
                ASTERIA_PRIVATE_KEY_SHARE_FILE = $probeSharePath
            }
        $trackedProcesses += $environmentProcess
        $probeDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path -LiteralPath $environmentProbe -PathType Leaf) -and [DateTime]::UtcNow -lt $probeDeadline) {
            Start-Sleep -Milliseconds 100
        }
        Assert-LocalnetTest -Condition (Test-Path -LiteralPath $environmentProbe -PathType Leaf) -Message "private share file environment probe was not written"
        Assert-LocalnetTest -Condition ((Get-Content -LiteralPath $environmentProbe -Raw) -eq $probeSharePath) -Message "private share file path was not injected into the child environment"
        Assert-LocalnetTest -Condition ($env:ASTERIA_PRIVATE_KEY_SHARE_FILE -eq "parent-path") -Message "private child environment leaked into the parent process"
        Assert-LocalnetTest -Condition ((Get-Content -LiteralPath $environmentRecord -Raw) -notmatch $probeShare) -Message "private share was written to a PID record"
        $environmentLogs = @(Get-ChildItem -LiteralPath (Join-Path $environmentRoot "logs") -File)
        Assert-LocalnetTest -Condition (-not ($environmentLogs | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match $probeShare })) -Message "private share was written to a process log"
    }
    finally {
        $env:ASTERIA_PRIVATE_KEY_SHARE_FILE = $previousParentShareFile
    }

    $rawShareRejected = $false
    try {
        [void] (Start-TestSleeper `
            -Root $environmentRoot `
            -RecordPath (Get-ProcessRecordPath -LocalnetRoot $environmentRoot -Kind app -Node 3) `
            -Node 3 `
            -ProcessEnvironment @{ ASTERIA_PRIVATE_KEY_SHARE = $probeShare })
    }
    catch {
        $rawShareRejected = $_.Exception.Message -match "refuses unsupported private environment variable"
    }
    Assert-LocalnetTest -Condition $rawShareRejected -Message "Start-RecordedProcess accepted a raw private key share"

    if ($IncludeRuntime) {
        if ([string]::IsNullOrWhiteSpace($CometBinary)) {
            $CometBinary = Get-DefaultCometBinary
        }
        $CometBinary = Assert-CometBinary -CometBinary $CometBinary
        $cargo = (Get-Command cargo -ErrorAction Stop).Source
        Push-Location (Get-AsteriaRepositoryRoot)
        try {
            $metadata = (@(& $cargo metadata --no-deps --format-version 1) -join [Environment]::NewLine) | ConvertFrom-Json
        }
        finally {
            Pop-Location
        }
        $sourceBinary = Join-Path ([string] $metadata.target_directory) "debug\asteria-node.exe"
        if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
            throw "Runtime regression requires '$sourceBinary'; run cargo build --bin asteria-node first."
        }
        $sourceKeygen = Join-Path ([string] $metadata.target_directory) "debug\asteria-private-keygen.exe"
        if (-not (Test-Path -LiteralPath $sourceKeygen -PathType Leaf)) {
            throw "Runtime regression requires '$sourceKeygen'; run cargo build --bin asteria-private-keygen first."
        }

        $customTarget = Join-Path $testRoot "custom-cargo-target"
        $customDebug = Join-Path $customTarget "debug"
        New-Item -ItemType Directory -Force -Path $customDebug | Out-Null
        [IO.File]::Copy($sourceBinary, (Join-Path $customDebug "asteria-node.exe"), $true)
        [IO.File]::Copy($sourceKeygen, (Join-Path $customDebug "asteria-private-keygen.exe"), $true)
        $env:CARGO_TARGET_DIR = $customTarget
        $runtimeRoot = Join-Path $testRoot "runtime"
        $runtimeCleanupRoot = $runtimeRoot
        $chainId = "asteria-script-test-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"

        & (Join-Path $PSScriptRoot "Start-Localnet.ps1") `
            -LocalnetRoot $runtimeRoot `
            -CometBinary $CometBinary `
            -ChainId $chainId `
            -SkipBuild `
            -StartupTimeoutSeconds 180
        $rows = @(& (Join-Path $PSScriptRoot "Get-LocalnetStatus.ps1") `
            -LocalnetRoot $runtimeRoot `
            -RequireHealthy `
            -LivenessWindowSeconds 3)
        Assert-LocalnetTest -Condition ($rows.Count -eq 4) -Message "runtime status did not return four healthy nodes"
        $manifest = Get-Content -LiteralPath (Join-Path $runtimeRoot "manifest.json") -Raw | ConvertFrom-Json
        Assert-LocalnetTest -Condition ($manifest.chain_id -eq $chainId) -Message "custom chain ID was not forwarded through Start-Localnet"
        $stagingDirectories = @(Get-ChildItem -LiteralPath $runtimeRoot -Directory -Filter ".comet-init-*" -ErrorAction SilentlyContinue)
        Assert-LocalnetTest -Condition ($stagingDirectories.Count -eq 0) -Message "fresh initialization left a staging directory"
        $genesis = Get-Content -LiteralPath (Join-Path $runtimeRoot "comet\node0\config\genesis.json") -Raw | ConvertFrom-Json
        Assert-LocalnetTest -Condition ([string] $genesis.consensus_params.abci.vote_extensions_enable_height -eq "1") -Message "runtime genesis did not enable vote extensions at height 1"
        Assert-LocalnetTest -Condition ($null -ne $genesis.app_state.private_order_key_set) -Message "runtime genesis omitted the private-order key set"
        foreach ($node in 0..3) {
            $validatorAddress = ([string] (Get-Content -LiteralPath (Join-Path $runtimeRoot "comet\node$node\config\priv_validator_key.json") -Raw | ConvertFrom-Json).address).ToLowerInvariant()
            Assert-LocalnetTest -Condition ([int] $genesis.app_state.private_validator_bindings.$validatorAddress -eq ($node + 1)) -Message "runtime genesis contains an incorrect validator/private-share binding for node$node"
        }
        $privateConfigRoot = Get-PrivateOrderConfigRoot -LocalnetRoot $runtimeRoot
        $privateAcl = Get-Acl -LiteralPath $privateConfigRoot
        Assert-LocalnetTest -Condition $privateAcl.AreAccessRulesProtected -Message "private-order config directory still inherits ACLs"
        $secretValues = @(0..3 | ForEach-Object {
            (Get-Content -LiteralPath (Get-PrivateOrderSharePath -LocalnetRoot $runtimeRoot -Node $_) -Raw).Trim()
        })
        $publicKeyHashBefore = (Get-FileHash -LiteralPath (Get-PrivateOrderPublicKeyPath -LocalnetRoot $runtimeRoot) -Algorithm SHA256).Hash
        $shareHashesBefore = @(0..3 | ForEach-Object {
            (Get-FileHash -LiteralPath (Get-PrivateOrderSharePath -LocalnetRoot $runtimeRoot -Node $_) -Algorithm SHA256).Hash
        })
        $leakFiles = @(
            (Join-Path $runtimeRoot "manifest.json")
        ) + @(Get-ChildItem -LiteralPath (Join-Path $runtimeRoot "run") -File | ForEach-Object FullName) +
            @(Get-ChildItem -LiteralPath (Join-Path $runtimeRoot "logs") -File | ForEach-Object FullName)
        foreach ($leakFile in $leakFiles) {
            $leakText = [string] (Get-Content -LiteralPath $leakFile -Raw)
            if ($null -eq $leakText) {
                $leakText = ""
            }
            foreach ($secretValue in $secretValues) {
                Assert-LocalnetTest -Condition (-not $leakText.Contains($secretValue)) -Message "private key share leaked into $leakFile"
            }
        }

        & (Join-Path $PSScriptRoot "Stop-Localnet.ps1") -LocalnetRoot $runtimeRoot
        & (Join-Path $PSScriptRoot "Start-Localnet.ps1") `
            -LocalnetRoot $runtimeRoot `
            -CometBinary $CometBinary `
            -ChainId $chainId `
            -SkipBuild `
            -StartupTimeoutSeconds 180
        & (Join-Path $PSScriptRoot "Stop-Localnet.ps1") -LocalnetRoot $runtimeRoot
        Assert-LocalnetTest -Condition ((Get-FileHash -LiteralPath (Get-PrivateOrderPublicKeyPath -LocalnetRoot $runtimeRoot) -Algorithm SHA256).Hash -eq $publicKeyHashBefore) -Message "restart regenerated the private-order public key set"
        foreach ($node in 0..3) {
            Assert-LocalnetTest -Condition ((Get-FileHash -LiteralPath (Get-PrivateOrderSharePath -LocalnetRoot $runtimeRoot -Node $node) -Algorithm SHA256).Hash -eq $shareHashesBefore[$node]) -Message "restart regenerated node$node private key share"
        }
        $runtimeRoot = $null
    }

    $testsSucceeded = $true
    Write-Host "All localnet PowerShell regression tests passed."
}
finally {
    $env:CARGO_TARGET_DIR = $oldCargoTargetDirectory
    if ($null -ne $runtimeRoot) {
        try {
            & (Join-Path $PSScriptRoot "Stop-Localnet.ps1") -LocalnetRoot $runtimeRoot
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    foreach ($process in $trackedProcesses) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
        }
    }
    if ($testsSucceeded -and
        $testRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $testRoot -PathType Container)) {
        if ($null -ne $runtimeCleanupRoot) {
            Enable-PrivateOrderConfigRemoval -LocalnetRoot $runtimeCleanupRoot
        }
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
    elseif (-not $testsSucceeded) {
        Write-Warning "Regression test artifacts were preserved at $testRoot"
    }
}
