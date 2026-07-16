[CmdletBinding()]
param(
    [string] $LocalnetRoot,
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,
    [switch] $IncludeValidatorKeys,
    [switch] $IncludePrivateOrderShares,
    [switch] $Force
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")
. (Join-Path $PSScriptRoot "Localnet.Backup.Common.ps1")

if ([string]::IsNullOrWhiteSpace($LocalnetRoot)) {
    $LocalnetRoot = Get-DefaultLocalnetRoot
}
$LocalnetRoot = Resolve-LocalnetPath -Path $LocalnetRoot
$output = Get-BackupAbsolutePath -Path $OutputPath
$outputParent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $outputParent | Out-Null
}
$output = Assert-BackupOutputPath -Path $output
$sidecar = Assert-BackupOutputPath -Path "$output.sha256"
if (Test-BackupPathWithin -Path $output -Root $LocalnetRoot -AllowRoot) {
    throw "Backup archive must be outside the live localnet root '$LocalnetRoot'."
}
$outputExistedBefore = Test-Path -LiteralPath $output -PathType Leaf
if ($outputExistedBefore -and -not $Force) {
    throw "Backup destination '$output' already exists. Pass -Force to replace it."
}
if ($IncludePrivateOrderShares -and -not $Force) {
    throw "Including private threshold shares requires -Force as an explicit acknowledgement that the archive contains signing secrets."
}
if ($IncludeValidatorKeys -and -not $Force) {
    throw "Including Comet validator keys requires -Force as an explicit acknowledgement that the archive contains signing secrets."
}

$entries = @(Get-LocalnetBackupSourceEntries -LocalnetRoot $LocalnetRoot -IncludeValidatorKeys:$IncludeValidatorKeys -IncludePrivateOrderShares:$IncludePrivateOrderShares)
$stagingRoot = Join-Path ([IO.Path]::GetTempPath()) "asteria-backup-$([Guid]::NewGuid().ToString('N'))"
$archiveTemp = "$output.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
$sidecarTemp = "$output.sha256.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
$oldArchivePath = $null
$oldSidecarPath = $null
$archivePublished = $false
$sidecarPublished = $false
$published = $false
try {
    New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
    Assert-BackupNoReparseAncestors -Path $stagingRoot | Out-Null
    if ($IncludePrivateOrderShares -or $IncludeValidatorKeys) {
        Protect-PrivateOrderDirectory -Path $stagingRoot
    }
    foreach ($entry in $entries) {
        Assert-BackupRelativeEntry $entry.Relative | Out-Null
        $destination = Join-Path $stagingRoot ($entry.Relative.Replace('/', '\'))
        if (-not (Test-BackupPathWithin -Path $destination -Root $stagingRoot)) {
            throw "Backup entry '$($entry.Relative)' escapes staging root."
        }
        Copy-BackupSourceFile -Source $entry.Source -Destination $destination
    }

    $records = @(Get-BackupFileRecords -StagingRoot $stagingRoot)
    $recordNames = @($records | ForEach-Object { [string] $_.path })
    if ($recordNames -notcontains "manifest.json") {
        throw "Backup staging did not contain manifest.json."
    }
    $manifestJson = Get-Content -LiteralPath (Join-Path $stagingRoot "manifest.json") -Raw | ConvertFrom-Json
    $backupManifest = [ordered]@{
        schema_version = 1
        created_at_utc = [DateTime]::UtcNow.ToString("o")
        chain_id = [string] $manifestJson.chain_id
        app_protocol_version = [int] $manifestJson.app_protocol_version
        genesis_sha256 = ([string] $manifestJson.genesis_sha256).ToLowerInvariant()
        includes_validator_keys = [bool] $IncludeValidatorKeys
        includes_private_order_shares = [bool] $IncludePrivateOrderShares
        files = $records
    }
    Write-Utf8NoBom -Path (Join-Path $stagingRoot "backup-manifest.json") -Content ($backupManifest | ConvertTo-Json -Depth 20)
    Write-BackupZipArchive -StagingRoot $stagingRoot -ArchivePath $archiveTemp

    # Re-open and verify the finished archive before it becomes visible as the
    # operator's backup. This catches truncated writes and malformed ZIP data.
    $verified = Read-BackupManifestFromArchive -ArchivePath $archiveTemp
    Assert-BackupArchiveContent -VerifiedArchive $verified
    if ([string] $verified.Manifest.chain_id -ne [string] $manifestJson.chain_id -or
        [string] $verified.Manifest.genesis_sha256 -ne ([string] $manifestJson.genesis_sha256).ToLowerInvariant()) {
        throw "Backup archive metadata does not match the live localnet manifest."
    }

    if (Test-Path -LiteralPath $output -PathType Leaf) {
        $oldArchivePath = "$output.previous-$([Guid]::NewGuid().ToString('N'))"
        [IO.File]::Replace($archiveTemp, $output, $oldArchivePath, $true)
        $archivePublished = $true
    }
    else {
        [IO.File]::Move($archiveTemp, $output)
        $archivePublished = $true
    }
    $archiveHash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Utf8NoBom -Path $sidecarTemp -Content "$archiveHash  $(Split-Path -Leaf $output)`n"
    if (Test-Path -LiteralPath $sidecar -PathType Leaf) {
        $oldSidecarPath = "$sidecar.previous-$([Guid]::NewGuid().ToString('N'))"
        [IO.File]::Replace($sidecarTemp, $sidecar, $oldSidecarPath, $true)
        $sidecarPublished = $true
    }
    else {
        [IO.File]::Move($sidecarTemp, $sidecar)
        $sidecarPublished = $true
    }
    $published = $true
    if ($null -ne $oldArchivePath -and (Test-Path -LiteralPath $oldArchivePath -PathType Leaf)) {
        Remove-Item -LiteralPath $oldArchivePath -Force
    }
    if ($null -ne $oldSidecarPath -and (Test-Path -LiteralPath $oldSidecarPath -PathType Leaf)) {
        Remove-Item -LiteralPath $oldSidecarPath -Force
    }
    Write-Host "Created verified Asteria localnet backup: $output"
    Write-Host "Archive SHA-256: $archiveHash"
    if ($IncludePrivateOrderShares) {
        Write-Warning "This archive contains all four private threshold shares. Encrypt and access-control it before moving it off-host."
    }
    else {
        Write-Host "Private threshold shares were excluded. Preserve the exact same epoch's share files separately; a newly generated DKG/keyset cannot restore this genesis."
    }
    if (-not $IncludeValidatorKeys) {
        Write-Host "Comet validator keys were excluded; preserve the exact node_key and priv_validator_key files separately for validator identity continuity."
    }
}
finally {
    if (-not $published) {
        try {
            if ($sidecarPublished -and $null -ne $oldSidecarPath -and (Test-Path -LiteralPath $oldSidecarPath -PathType Leaf)) {
                if (Test-Path -LiteralPath "$output.sha256" -PathType Leaf) {
                    Remove-Item -LiteralPath "$output.sha256" -Force
                }
                [IO.File]::Move($oldSidecarPath, "$output.sha256")
            }
            elseif ($sidecarPublished -and $null -eq $oldSidecarPath -and (Test-Path -LiteralPath "$output.sha256" -PathType Leaf)) {
                Remove-Item -LiteralPath "$output.sha256" -Force
            }
            if ($archivePublished -and $null -ne $oldArchivePath -and (Test-Path -LiteralPath $oldArchivePath -PathType Leaf)) {
                if (Test-Path -LiteralPath $output -PathType Leaf) {
                    Remove-Item -LiteralPath $output -Force
                }
                [IO.File]::Move($oldArchivePath, $output)
            }
            elseif ($archivePublished -and $null -eq $oldArchivePath -and (Test-Path -LiteralPath $output -PathType Leaf)) {
                Remove-Item -LiteralPath $output -Force
            }
        }
        catch {
            Write-Warning "Backup publication rollback failed: $($_.Exception.Message)"
        }
    }
    foreach ($oldPath in @($oldArchivePath, $oldSidecarPath)) {
        if ($null -ne $oldPath -and (Test-Path -LiteralPath $oldPath -PathType Leaf)) {
            Remove-Item -LiteralPath $oldPath -Force
        }
    }
    if (Test-Path -LiteralPath $stagingRoot -PathType Container) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $archiveTemp -PathType Leaf) {
        Remove-Item -LiteralPath $archiveTemp -Force
    }
    if (Test-Path -LiteralPath $sidecarTemp -PathType Leaf) {
        Remove-Item -LiteralPath $sidecarTemp -Force
    }
    if (-not $published -and $archivePublished) {
        Write-Warning "Backup failed after publication began; inspect '$output' before using it."
    }
}
