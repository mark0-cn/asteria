[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ArchivePath,
    [string] $ChecksumPath,
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedArchiveSha256,
    [string] $LocalnetRoot,
    [ValidatePattern('^[A-Za-z0-9._-]{1,50}$')]
    [string] $ExpectedChainId,
    [switch] $VerifyOnly,
    [switch] $Force,
    [ValidateRange(1048576, 1099511627776)]
    [long] $MaxBytes = 107374182400,
    [ValidateRange(1048576, 1099511627776)]
    [long] $MaxFileBytes = 17179869184
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")
. (Join-Path $PSScriptRoot "Localnet.Backup.Common.ps1")

$archive = Get-BackupAbsolutePath -Path $ArchivePath
$archive = Assert-BackupRegularPath -Path $archive -Type Leaf
$actualArchiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [string]::IsNullOrWhiteSpace($ExpectedArchiveSha256)) {
    $expectedArchiveHash = $ExpectedArchiveSha256.ToLowerInvariant()
}
else {
    if ([string]::IsNullOrWhiteSpace($ChecksumPath)) {
        $ChecksumPath = "$archive.sha256"
    }
    $resolvedChecksum = Get-BackupAbsolutePath -Path $ChecksumPath
    Assert-BackupRegularPath -Path $resolvedChecksum -Type Leaf | Out-Null
    $checksumText = (Get-Content -LiteralPath $resolvedChecksum -Raw).Trim()
    if ($checksumText -notmatch '^([0-9A-Fa-f]{64})\s+([^\r\n]+)$') {
        throw "Checksum file '$resolvedChecksum' must contain one SHA-256 and filename line."
    }
    $expectedArchiveHash = $Matches[1].ToLowerInvariant()
    $checksumFileName = $Matches[2].Trim()
    if ($checksumFileName -cne (Split-Path -Leaf $archive)) {
        throw "Checksum file names '$checksumFileName' but restore requested '$(Split-Path -Leaf $archive)'."
    }
}
if ($actualArchiveHash -ne $expectedArchiveHash) {
    throw "Backup archive SHA-256 does not match the trusted checksum."
}
$verified = Read-BackupManifestFromArchive -ArchivePath $archive -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes
Assert-BackupArchiveContent -VerifiedArchive $verified -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes

$manifest = $verified.Manifest
if ([int] $manifest.app_protocol_version -ne $script:AsteriaAppProtocolVersion) {
    throw "Backup app protocol $($manifest.app_protocol_version) does not match this binary/deployment protocol $script:AsteriaAppProtocolVersion."
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedChainId) -and
    [string] $manifest.chain_id -ne $ExpectedChainId) {
    throw "Backup chain ID '$($manifest.chain_id)' does not match expected '$ExpectedChainId'."
}

$declaredPaths = @($manifest.files | ForEach-Object { [string] $_.path })
foreach ($required in @(
        "manifest.json",
        "secrets/private-order/public-key-set.json",
        "secrets/private-order/dkg-session.json",
        "apps/node0/chain.redb",
        "apps/node1/chain.redb",
        "apps/node2/chain.redb",
        "apps/node3/chain.redb",
        "comet/node0/config/genesis.json",
        "comet/node1/config/genesis.json",
        "comet/node2/config/genesis.json",
        "comet/node3/config/genesis.json")) {
    if ($declaredPaths -notcontains $required) {
        throw "Backup is incomplete; required entry '$required' is missing."
    }
}
$sharePaths = @(0..3 | ForEach-Object { "secrets/private-order/node$_.key-share" })
$declaredShares = @($declaredPaths | Where-Object { $sharePaths -contains $_ })
if ([bool] $manifest.includes_private_order_shares -and $declaredShares.Count -ne 4) {
    throw "Backup claims to include private shares but does not contain all four share files."
}
if (-not [bool] $manifest.includes_private_order_shares -and $declaredShares.Count -ne 0) {
    throw "Backup contains private shares but its manifest does not mark them as included."
}
$validatorKeyPaths = @(0..3 | ForEach-Object {
    "comet/node$_/config/node_key.json"
    "comet/node$_/config/priv_validator_key.json"
})
$declaredValidatorKeys = @($declaredPaths | Where-Object { $validatorKeyPaths -contains $_ })
if ([bool] $manifest.includes_validator_keys -and $declaredValidatorKeys.Count -ne 8) {
    throw "Backup claims to include validator keys but does not contain all eight key files."
}
if (-not [bool] $manifest.includes_validator_keys -and $declaredValidatorKeys.Count -ne 0) {
    throw "Backup contains validator keys but its manifest does not mark them as included."
}
$unsafeOperationalFiles = @($declaredPaths | Where-Object {
    $_ -like "run/*" -or $_ -like "logs/*" -or $_ -like ".tools/*"
})
if ($unsafeOperationalFiles.Count -gt 0) {
    throw "Backup contains runtime/log/tool files that are not accepted for restore: $($unsafeOperationalFiles -join ', ')"
}

if ($VerifyOnly) {
    Write-Host "Verified Asteria localnet backup: $archive"
    Write-Host "Chain ID: $($manifest.chain_id)"
    Write-Host "Protocol: $($manifest.app_protocol_version)"
    Write-Host "Genesis SHA-256: $($manifest.genesis_sha256)"
    Write-Host "Contains private threshold shares: $([bool] $manifest.includes_private_order_shares)"
    Write-Host "Archive SHA-256: $actualArchiveHash"
    return
}

if ([string]::IsNullOrWhiteSpace($LocalnetRoot)) {
    $LocalnetRoot = Get-DefaultLocalnetRoot
}
$target = Resolve-LocalnetPath -Path $LocalnetRoot
$targetLeaf = Split-Path -Leaf $target
Assert-BackupRelativeEntry -RelativePath $targetLeaf | Out-Null
$targetParent = Split-Path -Parent $target
if ([string]::IsNullOrWhiteSpace($targetParent)) {
    throw "Restore target '$target' has no parent directory."
}
if ([IO.Path]::GetFullPath($target).TrimEnd('\') -ieq [IO.Path]::GetPathRoot($target).TrimEnd('\')) {
    throw "Refusing to restore directly into a filesystem root."
}
New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
Assert-BackupNoReparseAncestors -Path $targetParent | Out-Null
if (Test-BackupPathWithin -Path $archive -Root $target -AllowRoot) {
    throw "Restore archive must be outside the target localnet root."
}

if (Test-Path -LiteralPath $target) {
    Assert-BackupRegularPath -Path $target -Type Container | Out-Null
    Assert-LocalnetStoppedForBackup -LocalnetRoot $target
    [void] @(Get-LocalnetBackupSourceEntries -LocalnetRoot $target)
    if (-not $Force) {
        throw "Restore target '$target' already exists. Pass -Force only after confirming it is stopped and disposable."
    }
}

$staging = Join-Path $targetParent ".asteria-restore-$([Guid]::NewGuid().ToString('N'))"
$oldTarget = $null
$movedOldTarget = $false
try {
    New-Item -ItemType Directory -Force -Path $staging | Out-Null
    Assert-BackupNoReparseAncestors -Path $staging | Out-Null
    Expand-VerifiedBackupArchive -VerifiedArchive $verified -DestinationRoot $staging -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes

    # Validate the extracted tree using the same source checks used for a new
    # backup. This verifies genesis equality, app files, and required secrets
    # before the directory is made live.
    $restoredEntries = @(Get-LocalnetBackupSourceEntries -LocalnetRoot $staging -IncludeValidatorKeys:$([bool] $manifest.includes_validator_keys) -IncludePrivateOrderShares:$([bool] $manifest.includes_private_order_shares))
    if ($restoredEntries.Count -lt 12) {
        throw "Restored localnet tree did not contain the expected managed files."
    }
    if ([string] $manifest.chain_id -ne [string] ((Get-Content -LiteralPath (Join-Path $staging "manifest.json") -Raw | ConvertFrom-Json).chain_id)) {
        throw "Restored manifest chain ID changed during extraction."
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $actualArchiveHash) {
        throw "Backup archive changed while it was being verified or extracted."
    }

    if (Test-Path -LiteralPath $target) {
        $oldTarget = "$target.previous-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
        [IO.Directory]::Move($target, $oldTarget)
        $movedOldTarget = $true
    }
    [IO.Directory]::Move($staging, $target)
    Write-Host "Restored verified Asteria localnet '$($manifest.chain_id)' to $target"
    if ($movedOldTarget) {
        Write-Warning "The previous target was preserved at '$oldTarget'. Remove it only after validating a restart."
    }
    if (-not [bool] $manifest.includes_private_order_shares) {
        Write-Warning "Private threshold shares were not in the archive. Restore the exact same epoch's four share files from a separate secret backup before startup; generating a new DKG/keyset will not match genesis."
    }
}
catch {
    if ($movedOldTarget -and -not (Test-Path -LiteralPath $target) -and (Test-Path -LiteralPath $oldTarget)) {
        [IO.Directory]::Move($oldTarget, $target)
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
