[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")
. (Join-Path $PSScriptRoot "Localnet.Backup.Common.ps1")

function Assert-BackupTest {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )
    if (-not $Condition) {
        throw "Backup/restore regression failed: $Message"
    }
}

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase "asteria-backup-tests-$([Guid]::NewGuid().ToString('N'))"
$sourceRoot = Join-Path $testRoot "source"
$restoreRoot = Join-Path $testRoot "restored"
$archivePath = Join-Path $testRoot "localnet.zip"
$keysArchivePath = Join-Path $testRoot "localnet-with-validator-keys.zip"
$corruptArchivePath = Join-Path $testRoot "corrupt.zip"
$largeManifestArchivePath = Join-Path $testRoot "large-manifest.zip"
$oversizedEntryArchivePath = Join-Path $testRoot "oversized-entry.zip"
$succeeded = $false

try {
    foreach ($unsafePath in @(
            "../escape",
            "apps/./node0/chain.redb",
            "apps/node0/chain.redb:alternate",
            "apps/node0/NUL.txt",
            "apps/node0/trailing."
        )) {
        $unsafePathRejected = $false
        try {
            [void] (Assert-BackupRelativeEntry -RelativePath $unsafePath)
        }
        catch {
            $unsafePathRejected = $_.Exception.Message -match "Unsafe backup archive entry path"
        }
        Assert-BackupTest -Condition $unsafePathRejected -Message "archive path '$unsafePath' was accepted"
    }
    Assert-BackupTest -Condition ((Assert-BackupRelativeEntry -RelativePath "apps/node0/chain.redb") -eq "apps/node0/chain.redb") -Message "a valid archive path was rejected"

    New-Item -ItemType Directory -Force -Path (Join-Path $sourceRoot "secrets\private-order") | Out-Null
    $genesisText = '{"chain_id":"asteria-backup-regression","app_state":{"private_order_key_set":{"key_id":"test"}}}'
    foreach ($node in 0..3) {
        $appDirectory = Join-Path $sourceRoot "apps\node$node"
        $cometConfig = Join-Path $sourceRoot "comet\node$node\config"
        $cometData = Join-Path $sourceRoot "comet\node$node\data"
        New-Item -ItemType Directory -Force -Path $appDirectory, $cometConfig, $cometData | Out-Null
        Write-Utf8NoBom -Path (Join-Path $appDirectory "chain.redb") -Content "application-state-$node"
        Write-Utf8NoBom -Path (Join-Path $cometConfig "genesis.json") -Content $genesisText
        Write-Utf8NoBom -Path (Join-Path $cometConfig "config.toml") -Content 'persistent_peers = "test"'
        Write-Utf8NoBom -Path (Join-Path $cometConfig "node_key.json") -Content ("node-key-$node")
        Write-Utf8NoBom -Path (Join-Path $cometConfig "priv_validator_key.json") -Content ("validator-key-$node")
        Write-Utf8NoBom -Path (Join-Path $cometData "priv_validator_state.json") -Content '{"height":"10"}'
        Write-Utf8NoBom -Path (Join-Path $sourceRoot "secrets\private-order\node$node.key-share") -Content ("share-$node")
    }
    Write-Utf8NoBom -Path (Join-Path $sourceRoot "secrets\private-order\public-key-set.json") -Content '{"key_id":"test","threshold":3,"validator_count":4,"epoch":1,"validators":[1,2,3,4]}'
    Write-Utf8NoBom -Path (Join-Path $sourceRoot "secrets\private-order\dkg-session.json") -Content '{"ceremony_id":"test","kind":"initial","epoch":1}'
    $genesisHash = (Get-FileHash -LiteralPath (Join-Path $sourceRoot "comet\node0\config\genesis.json") -Algorithm SHA256).Hash.ToLowerInvariant()
    $localnetManifest = [ordered]@{
        app_protocol_version = $script:AsteriaAppProtocolVersion
        chain_id = "asteria-backup-regression"
        authority = "ed25519:$('0' * 64)"
        cometbft_version = "v0.38.23"
        genesis_sha256 = $genesisHash
        nodes = @(0..3 | ForEach-Object { [ordered]@{ name = "node$_" } })
    }
    Write-Utf8NoBom -Path (Join-Path $sourceRoot "manifest.json") -Content ($localnetManifest | ConvertTo-Json -Depth 10)

    $runDirectory = Join-Path $sourceRoot "run"
    New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
    $staleRecord = [ordered]@{
        kind = "app"
        node = 0
        pid = 2147483647
        executable = "C:\missing-asteria-node.exe"
        start_time_filetime_utc = 1
        stdout = "C:\missing.out.log"
        stderr = "C:\missing.err.log"
    }
    $staleRecordPath = Join-Path $runDirectory "app-node0.json"
    Write-Utf8NoBom -Path $staleRecordPath -Content ($staleRecord | ConvertTo-Json)
    $staleRecordRejected = $false
    try {
        & (Join-Path $PSScriptRoot "Backup-Localnet.ps1") -LocalnetRoot $sourceRoot -OutputPath (Join-Path $testRoot "stale.zip")
    }
    catch {
        $staleRecordRejected = $_.Exception.Message -match "stale process record"
    }
    Assert-BackupTest -Condition $staleRecordRejected -Message "backup accepted an unresolved stale process record"
    Remove-Item -LiteralPath $staleRecordPath -Force

    & (Join-Path $PSScriptRoot "Backup-Localnet.ps1") -LocalnetRoot $sourceRoot -OutputPath $archivePath
    Assert-BackupTest -Condition (Test-Path -LiteralPath $archivePath -PathType Leaf) -Message "backup archive was not published"
    Assert-BackupTest -Condition (Test-Path -LiteralPath "$archivePath.sha256" -PathType Leaf) -Message "archive checksum sidecar was not published"
    & (Join-Path $PSScriptRoot "Backup-Localnet.ps1") -LocalnetRoot $sourceRoot -OutputPath $archivePath -Force
    Assert-BackupTest -Condition (Test-Path -LiteralPath "$archivePath.sha256" -PathType Leaf) -Message "forced backup replacement removed checksum sidecar"
    $verified = Read-BackupManifestFromArchive -ArchivePath $archivePath
    Assert-BackupArchiveContent -VerifiedArchive $verified
    Assert-BackupTest -Condition (-not [bool] $verified.Manifest.includes_private_order_shares) -Message "default backup claims to include private shares"
    $archivedPaths = @($verified.Manifest.files | ForEach-Object { [string] $_.path })
    foreach ($share in @(0..3 | ForEach-Object { "secrets/private-order/node$_.key-share" })) {
        Assert-BackupTest -Condition ($archivedPaths -notcontains $share) -Message "default backup leaked $share"
    }
    Assert-BackupTest -Condition (-not [bool] $verified.Manifest.includes_validator_keys) -Message "default backup claims to include validator keys"
    foreach ($key in @(0..3 | ForEach-Object { "comet/node$_/config/node_key.json"; "comet/node$_/config/priv_validator_key.json" })) {
        Assert-BackupTest -Condition ($archivedPaths -notcontains $key) -Message "default backup leaked $key"
    }

    & (Join-Path $PSScriptRoot "Backup-Localnet.ps1") -LocalnetRoot $sourceRoot -OutputPath $keysArchivePath -IncludeValidatorKeys -Force
    $keysVerified = Read-BackupManifestFromArchive -ArchivePath $keysArchivePath
    Assert-BackupArchiveContent -VerifiedArchive $keysVerified
    Assert-BackupTest -Condition ([bool] $keysVerified.Manifest.includes_validator_keys) -Message "explicit validator-key backup did not record its secret contents"
    Assert-BackupTest -Condition (@($keysVerified.Manifest.files | Where-Object { $_.path -like "comet/node*/config/*_key.json" }).Count -eq 8) -Message "explicit validator-key backup omitted a validator key"

    & (Join-Path $PSScriptRoot "Restore-Localnet.ps1") -ArchivePath $archivePath -ExpectedChainId "asteria-backup-regression" -VerifyOnly
    & (Join-Path $PSScriptRoot "Restore-Localnet.ps1") -ArchivePath $archivePath -LocalnetRoot $restoreRoot
    foreach ($node in 0..3) {
        $sourceHash = (Get-FileHash -LiteralPath (Join-Path $sourceRoot "apps\node$node\chain.redb") -Algorithm SHA256).Hash
        $restoredHash = (Get-FileHash -LiteralPath (Join-Path $restoreRoot "apps\node$node\chain.redb") -Algorithm SHA256).Hash
        Assert-BackupTest -Condition ($sourceHash -eq $restoredHash) -Message "node$node application database changed during restore"
        Assert-BackupTest -Condition (-not (Test-Path -LiteralPath (Join-Path $restoreRoot "secrets\private-order\node$node.key-share"))) -Message "restore manufactured a missing private share"
    }

    [IO.File]::Copy($archivePath, $corruptArchivePath, $false)
    $stream = $null
    $zip = $null
    try {
        $stream = [IO.File]::Open($corruptArchivePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Update, $false)
        $entry = $zip.GetEntry("apps/node0/chain.redb")
        $entry.Delete()
        $replacement = $zip.CreateEntry("apps/node0/chain.redb", [IO.Compression.CompressionLevel]::Optimal)
        $writer = New-Object IO.StreamWriter($replacement.Open(), [Text.Encoding]::UTF8)
        try {
            $writer.Write("tampered-state")
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $trustedOriginalHash = ((Get-Content -LiteralPath "$archivePath.sha256" -Raw).Trim() -split '\s+')[0]
    Write-Utf8NoBom -Path "$corruptArchivePath.sha256" -Content "$trustedOriginalHash  $(Split-Path -Leaf $corruptArchivePath)`n"
    $externalChecksumRejected = $false
    try {
        & (Join-Path $PSScriptRoot "Restore-Localnet.ps1") -ArchivePath $corruptArchivePath -VerifyOnly
    }
    catch {
        $externalChecksumRejected = $_.Exception.Message -match "does not match the trusted checksum"
    }
    Assert-BackupTest -Condition $externalChecksumRejected -Message "restore accepted an archive that differed from its external checksum"

    $corruptHash = (Get-FileHash -LiteralPath $corruptArchivePath -Algorithm SHA256).Hash
    $tamperingRejected = $false
    try {
        & (Join-Path $PSScriptRoot "Restore-Localnet.ps1") -ArchivePath $corruptArchivePath -ExpectedArchiveSha256 $corruptHash -VerifyOnly
    }
    catch {
        $tamperingRejected = $_.Exception.Message -match "failed its size or SHA-256 check"
    }
    Assert-BackupTest -Condition $tamperingRejected -Message "restore accepted a tampered application database"

    $stream = $null
    $zip = $null
    try {
        $stream = [IO.File]::Open($largeManifestArchivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        $entry = $zip.CreateEntry("backup-manifest.json", [IO.Compression.CompressionLevel]::Optimal)
        $writer = New-Object IO.StreamWriter($entry.Open(), [Text.Encoding]::ASCII)
        try {
            $writer.Write(('x' * 8388609))
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $largeManifestRejected = $false
    try {
        [void] (Read-BackupManifestFromArchive -ArchivePath $largeManifestArchivePath)
    }
    catch {
        $largeManifestRejected = $_.Exception.Message -match "8 MiB"
    }
    Assert-BackupTest -Condition $largeManifestRejected -Message "backup parser accepted an oversized manifest"

    $stream = $null
    $zip = $null
    try {
        $stream = [IO.File]::Open($oversizedEntryArchivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        $payloadEntry = $zip.CreateEntry("payload.bin", [IO.Compression.CompressionLevel]::Optimal)
        $payloadStream = $payloadEntry.Open()
        try {
            $payloadStream.Write((New-Object byte[] 9), 0, 9)
        }
        finally {
            $payloadStream.Dispose()
        }
        $manifestEntry = $zip.CreateEntry("backup-manifest.json", [IO.Compression.CompressionLevel]::Optimal)
        $manifestWriter = New-Object IO.StreamWriter($manifestEntry.Open(), [Text.Encoding]::UTF8)
        try {
            $manifestWriter.Write((@{
                        schema_version = 1
                        files = @(@{
                                path = "payload.bin"
                                bytes = 9
                                sha256 = "0" * 64
                            })
                    } | ConvertTo-Json -Depth 5))
        }
        finally {
            $manifestWriter.Dispose()
        }
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
    $oversizedEntryRejected = $false
    try {
        [void] (Read-BackupManifestFromArchive -ArchivePath $oversizedEntryArchivePath -MaxFileBytes 8)
    }
    catch {
        $oversizedEntryRejected = $_.Exception.Message -match "per-file maximum"
    }
    Assert-BackupTest -Condition $oversizedEntryRejected -Message "backup parser accepted an entry above the per-file limit"

    $succeeded = $true
    Write-Host "All localnet backup/restore regression tests passed."
}
finally {
    if ($succeeded -and
        $testRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $testRoot -PathType Container)) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
    elseif (-not $succeeded) {
        Write-Warning "Backup/restore regression artifacts were preserved at $testRoot"
    }
}
