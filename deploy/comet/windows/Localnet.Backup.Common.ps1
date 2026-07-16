Set-StrictMode -Version Latest

# Backup archives are deliberately implemented here instead of using
# Compress-Archive. Compress-Archive silently skips hidden files on Windows,
# while CometBFT stores important files under hidden/temp paths on some hosts.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Keep archive limits explicit and bounded independently.  The total limit is
# useful against a collection of large files; the per-file limit prevents one
# highly-compressed entry from exhausting a restore volume before the total is
# reached.
$script:AsteriaBackupMaxArchiveEntries = 200000
$script:AsteriaBackupMaxManifestBytes = 8 * 1024 * 1024
$script:AsteriaBackupMaxFileBytes = [long] (16 * 1024 * 1024 * 1024)

function Assert-BackupLimitArguments {
    param(
        [Parameter(Mandatory = $true)]
        [long] $MaxBytes,
        [Parameter(Mandatory = $true)]
        [long] $MaxFileBytes
    )

    if ($MaxBytes -le 0 -or $MaxFileBytes -le 0) {
        throw "Backup size limits must be positive."
    }
}

function Assert-BackupNoReparseAncestors {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $current = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Backup refuses a reparse-point path or ancestor: '$($current.FullName)'."
        }
        if ($current -is [IO.DirectoryInfo]) {
            $parent = $current.Parent
        }
        else {
            $parent = $current.Directory
        }
        if ($null -eq $parent -or $parent.FullName -ieq $current.FullName) {
            break
        }
        $current = $parent
    }
    return $resolved
}

function Assert-BackupOutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $leaf = Split-Path -Leaf $resolved
    Assert-BackupRelativeEntry -RelativePath $leaf | Out-Null
    $parent = Split-Path -Parent $resolved
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "Backup output path '$resolved' has no parent directory."
    }
    Assert-BackupNoReparseAncestors -Path $parent | Out-Null
    if (Test-Path -LiteralPath $resolved) {
        $item = Get-Item -LiteralPath $resolved -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Backup output path must not be a reparse point: '$resolved'."
        }
        if ($item.PSIsContainer) {
            throw "Backup output path must be a regular file: '$resolved'."
        }
    }
    return $resolved
}

function Get-BackupAbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [string] $BasePath = (Get-AsteriaRepositoryRoot)
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Backup path must not be empty."
    }
    if ([IO.Path]::IsPathRooted($Path)) {
        $resolved = [IO.Path]::GetFullPath($Path)
    }
    else {
        $resolved = [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
    }
    # Archive/checksum paths are ordinary files, never NTFS alternate data
    # streams or device names.  Validate the leaf even when it does not exist.
    Assert-BackupRelativeEntry -RelativePath (Split-Path -Leaf $resolved) | Out-Null
    return $resolved
}

function Test-BackupPathWithin {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [string] $Root,
        [switch] $AllowRoot
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($AllowRoot -and $resolvedPath -ieq $resolvedRoot) {
        return $true
    }
    return $resolvedPath.StartsWith("$resolvedRoot\", [StringComparison]::OrdinalIgnoreCase)
}

function Assert-BackupRegularPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Leaf", "Container")]
        [string] $Type
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType $Type)) {
        throw "Required backup path was not found: '$resolved'."
    }
    Assert-BackupNoReparseAncestors -Path $resolved | Out-Null
    return $resolved
}

function Assert-LocalnetStoppedForBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot
    )

    $specs = @(Get-LocalnetNodeSpecs -LocalnetRoot $LocalnetRoot)
    foreach ($kind in @("app", "comet")) {
        foreach ($spec in $specs) {
            $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind $kind -Node $spec.Node
            if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
                continue
            }
            $record = Read-ProcessRecord -RecordPath $recordPath
            if ($null -eq $record) {
                throw "Cannot back up while process record '$recordPath' is invalid. Run Stop-Localnet.ps1 and inspect it."
            }
            $process = Get-RecordedProcess -RecordPath $recordPath
            if ($null -ne $process) {
                throw "Cannot back up while $kind node$($spec.Node) is running (PID $($process.Id)). Run Stop-Localnet.ps1 first."
            }
            throw "Cannot back up while stale process record '$recordPath' exists. Run Stop-Localnet.ps1 and inspect it."
        }
    }
}

function Get-BackupRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root,
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$pathFull' is outside backup root '$Root'."
    }
    return $pathFull.Substring($rootFull.Length).Replace('\', '/')
}

function Assert-BackupRelativeEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RelativePath
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.Contains('\') -or
        $RelativePath.StartsWith('/') -or
        $RelativePath.IndexOf([char] 0) -ge 0 -or
        $RelativePath.Split('/') -contains '..' -or
        $RelativePath.Split('/') -contains '.' -or
        $RelativePath.Split('/') -contains '') {
        throw "Unsafe backup archive entry path '$RelativePath'."
    }
    foreach ($segment in $RelativePath.Split('/')) {
        # A colon anywhere in a Windows path component addresses an NTFS ADS;
        # control characters and trailing dots/spaces are also normalized by
        # Win32 and can alias a different file than the ZIP name suggests.
        if ($segment.IndexOf(':') -ge 0 -or
            $segment -match '[\x00-\x1F]' -or
            $segment.EndsWith('.') -or
            $segment.EndsWith(' ')) {
            throw "Unsafe backup archive entry path '$RelativePath'."
        }
        if ($segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
            throw "Unsafe backup archive entry path '$RelativePath'."
        }
    }
    return $RelativePath
}

function Get-LocalnetBackupSourceEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot,
        [switch] $IncludeValidatorKeys,
        [switch] $IncludePrivateOrderShares
    )

    $root = Resolve-LocalnetPath -Path $LocalnetRoot
    Assert-BackupRegularPath -Path $root -Type Container | Out-Null
    Assert-LocalnetStoppedForBackup -LocalnetRoot $root

    $manifestPath = Assert-BackupRegularPath -Path (Join-Path $root "manifest.json") -Type Leaf
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Localnet manifest '$manifestPath' is not valid JSON: $($_.Exception.Message)"
    }
    if ([int] $manifest.app_protocol_version -ne $script:AsteriaAppProtocolVersion) {
        throw "Localnet manifest protocol $($manifest.app_protocol_version) does not match protocol $script:AsteriaAppProtocolVersion."
    }
    if ([string]::IsNullOrWhiteSpace([string] $manifest.chain_id) -or
        @($manifest.nodes).Count -ne $script:AsteriaNodeCount) {
        throw "Localnet manifest does not describe exactly four validators."
    }

    $specs = @(Get-LocalnetNodeSpecs -LocalnetRoot $root)
    foreach ($spec in $specs) {
        foreach ($port in @($spec.AbciPort, $spec.HttpPort, $spec.P2pPort, $spec.RpcPort, $spec.MetricsPort)) {
            if (-not (Test-TcpPortAvailable -Port $port)) {
                throw "TCP port 127.0.0.1:$port is in use; an unrecorded localnet process may still be running."
            }
        }
    }
    $referenceGenesis = Assert-BackupRegularPath -Path (Join-Path $specs[0].CometHome "config\genesis.json") -Type Leaf
    try {
        $genesisDocument = Get-Content -LiteralPath $referenceGenesis -Raw | ConvertFrom-Json
    }
    catch {
        throw "Reference genesis '$referenceGenesis' is not valid JSON: $($_.Exception.Message)"
    }
    $genesisHash = (Get-FileHash -LiteralPath $referenceGenesis -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string] $manifest.genesis_sha256 -ne $genesisHash) {
        throw "Localnet manifest genesis hash does not match node0 genesis."
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($managedDirectory in @("apps", "comet", "secrets")) {
        Assert-BackupRegularPath -Path (Join-Path $root $managedDirectory) -Type Container | Out-Null
    }
    $entries.Add([PSCustomObject]@{
        Source = $manifestPath
        Relative = "manifest.json"
        Secret = $false
    })
    foreach ($spec in $specs) {
        $nodeGenesis = Assert-BackupRegularPath -Path (Join-Path $spec.CometHome "config\genesis.json") -Type Leaf
        $nodeHash = (Get-FileHash -LiteralPath $nodeGenesis -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($nodeHash -ne $genesisHash) {
            throw "Genesis hash differs for $($spec.Name)."
        }
        Assert-BackupRegularPath -Path (Split-Path -Parent $spec.AppData) -Type Container | Out-Null
        $appData = Assert-BackupRegularPath -Path $spec.AppData -Type Leaf
        $entries.Add([PSCustomObject]@{
            Source = $appData
            Relative = "apps/$($spec.Name)/chain.redb"
            Secret = $false
        })

        $cometHome = Assert-BackupRegularPath -Path $spec.CometHome -Type Container
        $reparseDirectories = @(Get-ChildItem -LiteralPath $cometHome -Recurse -Force -Directory | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($reparseDirectories.Count -gt 0) {
            throw "CometBFT backup refuses reparse-point directory '$($reparseDirectories[0].FullName)'."
        }
        $cometFiles = @(Get-ChildItem -LiteralPath $cometHome -Recurse -Force -File)
        foreach ($file in $cometFiles) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "CometBFT backup refuses a reparse-point file '$($file.FullName)'."
            }
            $isValidatorKey = $file.Name -in @("node_key.json", "priv_validator_key.json")
            if ($isValidatorKey -and -not $IncludeValidatorKeys) {
                continue
            }
            $relative = Get-BackupRelativePath -Root $root -Path $file.FullName
            $entries.Add([PSCustomObject]@{
                Source = $file.FullName
                Relative = $relative
                Secret = $isValidatorKey
            })
        }
    }

    $privateRoot = Assert-BackupRegularPath -Path (Join-Path $root "secrets\private-order") -Type Container
    $publicKey = Assert-BackupRegularPath -Path (Join-Path $privateRoot "public-key-set.json") -Type Leaf
    $session = Assert-BackupRegularPath -Path (Join-Path $privateRoot "dkg-session.json") -Type Leaf
    try {
        $publicDocument = Get-Content -LiteralPath $publicKey -Raw | ConvertFrom-Json
        $sessionDocument = Get-Content -LiteralPath $session -Raw | ConvertFrom-Json
    }
    catch {
        throw "Private-order public key or DKG session is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $genesisDocument.app_state.private_order_key_set -or
        [string] $genesisDocument.app_state.private_order_key_set.key_id -ne [string] $publicDocument.key_id) {
        throw "Genesis private-order key ID does not match the provisioned public key set."
    }
    if ([int] $publicDocument.threshold -ne 3 -or [int] $publicDocument.validator_count -ne 4 -or
        [int] @($publicDocument.validators).Count -ne 4) {
        throw "Private-order public key set is not a 3-of-4 four-validator configuration."
    }
    if ([string] $sessionDocument.kind -ne "initial" -or
        [long] $sessionDocument.epoch -ne [long] $publicDocument.epoch) {
        throw "Private-order DKG session does not match the public key epoch."
    }
    $entries.Add([PSCustomObject]@{ Source = $publicKey; Relative = "secrets/private-order/public-key-set.json"; Secret = $false })
    $entries.Add([PSCustomObject]@{ Source = $session; Relative = "secrets/private-order/dkg-session.json"; Secret = $false })

    if ($IncludePrivateOrderShares) {
        Protect-PrivateOrderConfig -Path $privateRoot
        foreach ($node in 0..3) {
            $share = Assert-BackupRegularPath -Path (Get-PrivateOrderSharePath -LocalnetRoot $root -Node $node) -Type Leaf
            $entries.Add([PSCustomObject]@{
                Source = $share
                Relative = "secrets/private-order/node$node.key-share"
                Secret = $true
            })
        }
    }

    return @($entries | Sort-Object Relative)
}

function Copy-BackupSourceFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Source,
        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    Assert-BackupRegularPath -Path $Source -Type Leaf | Out-Null
    $destinationParent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
    Assert-BackupNoReparseAncestors -Path $destinationParent | Out-Null
    [IO.File]::Copy($Source, $Destination, $false)
    Assert-BackupRegularPath -Path $Destination -Type Leaf | Out-Null
    # Re-check the source after the copy so a path swap during staging cannot
    # silently turn a regular file into a reparse point.
    Assert-BackupRegularPath -Path $Source -Type Leaf | Out-Null
    $sourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant()
    $destinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -ne $destinationHash) {
        throw "Source '$Source' changed while it was being copied."
    }
}

function Get-BackupFileRecords {
    param(
        [Parameter(Mandatory = $true)]
        [string] $StagingRoot
    )

    $root = Assert-BackupRegularPath -Path $StagingRoot -Type Container
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File)
    return @($files | ForEach-Object {
        if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Backup staging contains a reparse-point file '$($_.FullName)'."
        }
        $relative = Assert-BackupRelativeEntry (Get-BackupRelativePath -Root $root -Path $_.FullName)
        [ordered]@{
            path = $relative
            bytes = [long] $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object path)
}

function Write-BackupZipArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string] $StagingRoot,
        [Parameter(Mandatory = $true)]
        [string] $ArchivePath
    )

    $root = Assert-BackupRegularPath -Path $StagingRoot -Type Container
    $archive = $null
    $stream = $null
    try {
        $stream = [IO.File]::Open($ArchivePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Force -File | Sort-Object FullName)) {
            Assert-BackupRegularPath -Path $file.FullName -Type Leaf | Out-Null
            $relative = Assert-BackupRelativeEntry (Get-BackupRelativePath -Root $root -Path $file.FullName)
            $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
            $input = $null
            $output = $null
            try {
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                $input.CopyTo($output)
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                if ($null -ne $input) { $input.Dispose() }
            }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) {
            $stream.Flush($true)
            $stream.Dispose()
        }
    }
}

function Get-ArchiveEntries {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ArchivePath
    )

    $stream = $null
    $archive = $null
    try {
        $stream = [IO.File]::OpenRead($ArchivePath)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        return @($archive.Entries)
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Read-BackupManifestFromArchive {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ArchivePath,
        [long] $MaxBytes = 107374182400,
        [long] $MaxFileBytes = 17179869184
    )

    Assert-BackupLimitArguments -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes
    $archiveFile = Assert-BackupRegularPath -Path $ArchivePath -Type Leaf
    if ((Get-Item -LiteralPath $archiveFile).Length -gt $MaxBytes) {
        throw "Backup archive exceeds the configured maximum size of $MaxBytes bytes."
    }
    $stream = $null
    $archive = $null
    try {
        $stream = [IO.File]::OpenRead($archiveFile)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        if ($archive.Entries.Count -gt $script:AsteriaBackupMaxArchiveEntries) {
            throw "Backup archive contains more than $script:AsteriaBackupMaxArchiveEntries entries."
        }
        $entries = @{}
        foreach ($entry in $archive.Entries) {
            $name = Assert-BackupRelativeEntry $entry.FullName
            if ($entries.ContainsKey($name)) {
                throw "Backup archive contains duplicate entry '$name'."
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                throw "Backup archive contains a directory entry '$name'; directories are implicit."
            }
            $entries[$name] = $entry
        }
        if (-not $entries.ContainsKey("backup-manifest.json")) {
            throw "Backup archive does not contain backup-manifest.json."
        }
        $manifestEntry = $entries["backup-manifest.json"]
        $manifestLimit = $script:AsteriaBackupMaxManifestBytes
        if ($manifestEntry.Length -le 0 -or $manifestEntry.Length -gt $manifestLimit -or
            $manifestEntry.CompressedLength -gt $manifestLimit) {
            throw "backup-manifest.json must be between 1 byte and 8 MiB compressed and uncompressed."
        }
        $reader = New-Object IO.StreamReader($manifestEntry.Open(), [Text.Encoding]::UTF8, $true)
        try {
            $manifest = $reader.ReadToEnd() | ConvertFrom-Json
        }
        finally {
            $reader.Dispose()
        }
        $manifestFiles = @($manifest.files)
        if ([int] $manifest.schema_version -ne 1 -or $manifestFiles.Count -eq 0) {
            throw "Backup manifest schema is unsupported or contains no files."
        }
        if ($manifestFiles.Count -gt $script:AsteriaBackupMaxArchiveEntries) {
            throw "Backup manifest contains more than $script:AsteriaBackupMaxArchiveEntries files."
        }
        $declared = @{}
        [long] $declaredBytes = 0
        foreach ($file in $manifestFiles) {
            $name = Assert-BackupRelativeEntry ([string] $file.path)
            if ($name -eq "backup-manifest.json" -or $declared.ContainsKey($name)) {
                throw "Backup manifest contains an invalid or duplicate file path '$name'."
            }
            if (-not $entries.ContainsKey($name)) {
                throw "Backup manifest references missing archive entry '$name'."
            }
            $fileBytes = [long] $file.bytes
            if ($fileBytes -lt 0 -or [string] $file.sha256 -notmatch '^[0-9a-f]{64}$') {
                throw "Backup manifest contains invalid metadata for '$name'."
            }
            if ($fileBytes -gt $MaxFileBytes) {
                throw "Backup archive entry '$name' exceeds the configured per-file maximum of $MaxFileBytes bytes."
            }
            if ($fileBytes -gt ($MaxBytes - $declaredBytes)) {
                throw "Backup archive declares more than the configured maximum of $MaxBytes bytes."
            }
            $declaredBytes += $fileBytes
            $declared[$name] = $file
        }
        $unexpected = @($entries.Keys | Where-Object { $_ -ne "backup-manifest.json" -and -not $declared.ContainsKey($_) })
        if ($unexpected.Count -gt 0) {
            throw "Backup archive contains files absent from its manifest: $($unexpected -join ', ')"
        }
        return [PSCustomObject]@{
            ArchivePath = $archiveFile
            Manifest = $manifest
            Entries = $entries
            Declared = $declared
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Assert-BackupArchiveContent {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $VerifiedArchive,
        [long] $MaxBytes = 107374182400,
        [long] $MaxFileBytes = 17179869184
    )

    Assert-BackupLimitArguments -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes
    $stream = $null
    $archive = $null
    [long] $totalBytes = 0
    try {
        $stream = [IO.File]::OpenRead($VerifiedArchive.ArchivePath)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        foreach ($file in $VerifiedArchive.Manifest.files) {
            $name = [string] $file.path
            $entry = $archive.GetEntry($name)
            if ($null -eq $entry) {
                throw "Backup archive entry '$name' disappeared during content verification."
            }
            $declaredEntryBytes = [long] $file.bytes
            if ($declaredEntryBytes -gt $MaxFileBytes -or $entry.Length -gt $MaxFileBytes) {
                throw "Backup archive entry '$name' exceeds the configured per-file maximum of $MaxFileBytes bytes."
            }
            $input = $null
            $hash = [Security.Cryptography.SHA256]::Create()
            $hashBytes = $null
            [long] $entryBytes = 0
            try {
                $input = $entry.Open()
                $buffer = New-Object byte[] 1048576
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    [void] $hash.TransformBlock($buffer, 0, $read, $buffer, 0)
                    if ($read -gt ($MaxFileBytes - $entryBytes)) {
                        throw "Backup archive entry '$name' expands beyond the configured per-file maximum of $MaxFileBytes bytes."
                    }
                    $entryBytes += $read
                    if ($read -gt ($MaxBytes - $totalBytes)) {
                        throw "Backup archive expands beyond the configured maximum of $MaxBytes bytes."
                    }
                    $totalBytes += $read
                }
                [void] $hash.TransformFinalBlock([byte[]]::new(0), 0, 0)
                $hashBytes = $hash.Hash
            }
            finally {
                if ($null -ne $input) { $input.Dispose() }
                $hash.Dispose()
            }
            $actualHash = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
            if ($entryBytes -ne [long] $file.bytes -or $actualHash -ne [string] $file.sha256) {
                throw "Backup archive entry '$name' failed its size or SHA-256 check."
            }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Expand-VerifiedBackupArchive {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject] $VerifiedArchive,
        [Parameter(Mandatory = $true)]
        [string] $DestinationRoot,
        [long] $MaxBytes = 107374182400,
        [long] $MaxFileBytes = 17179869184
    )

    Assert-BackupLimitArguments -MaxBytes $MaxBytes -MaxFileBytes $MaxFileBytes
    $destination = [IO.Path]::GetFullPath($DestinationRoot)
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Assert-BackupNoReparseAncestors -Path $destination | Out-Null
    $stream = $null
    $archive = $null
    [long] $totalBytes = 0
    try {
        $stream = [IO.File]::OpenRead($VerifiedArchive.ArchivePath)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
        foreach ($file in $VerifiedArchive.Manifest.files) {
            $name = Assert-BackupRelativeEntry ([string] $file.path)
            $entry = $archive.GetEntry($name)
            if ($null -eq $entry) {
                throw "Backup archive entry '$name' disappeared during restore."
            }
            $declaredEntryBytes = [long] $file.bytes
            if ($declaredEntryBytes -gt $MaxFileBytes -or $entry.Length -gt $MaxFileBytes) {
                throw "Backup archive entry '$name' exceeds the configured per-file maximum of $MaxFileBytes bytes."
            }
            $target = [IO.Path]::GetFullPath((Join-Path $destination ($name.Replace('/', '\'))))
            if (-not (Test-BackupPathWithin -Path $target -Root $destination)) {
                throw "Restore entry '$name' escapes destination root."
            }
            $parent = Split-Path -Parent $target
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
            Assert-BackupNoReparseAncestors -Path $parent | Out-Null
            $input = $null
            $output = $null
            $hash = [Security.Cryptography.SHA256]::Create()
            $hashBytes = $null
            [long] $entryBytes = 0
            try {
                $input = $entry.Open()
                $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $buffer = New-Object byte[] 1048576
                while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($read -gt ($MaxFileBytes - $entryBytes)) {
                        throw "Backup archive entry '$name' expands beyond the configured per-file maximum of $MaxFileBytes bytes."
                    }
                    if ($read -gt ($MaxBytes - $totalBytes)) {
                        throw "Backup archive expands beyond the configured maximum of $MaxBytes bytes."
                    }
                    $output.Write($buffer, 0, $read)
                    [void] $hash.TransformBlock($buffer, 0, $read, $buffer, 0)
                    $entryBytes += $read
                    $totalBytes += $read
                }
                [void] $hash.TransformFinalBlock((New-Object byte[] 0), 0, 0)
                $hashBytes = $hash.Hash
            }
            finally {
                if ($null -ne $output) { $output.Dispose() }
                if ($null -ne $input) { $input.Dispose() }
                $hash.Dispose()
            }
            Assert-BackupRegularPath -Path $target -Type Leaf | Out-Null
            $actualHash = [BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
            if ($entryBytes -ne $declaredEntryBytes -or $actualHash -ne [string] $file.sha256) {
                throw "Restored file '$name' failed its size or SHA-256 check."
            }
        }
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}
