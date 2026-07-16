[CmdletBinding()]
param(
    [string] $ToolsRoot,
    [string] $GoBinary
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")

if ([string]::IsNullOrWhiteSpace($ToolsRoot)) {
    $ToolsRoot = Join-Path (Get-AsteriaRepositoryRoot) ".tools"
}
$ToolsRoot = Resolve-LocalnetPath -Path $ToolsRoot

$cometVersion = "0.38.23"
$cometDirectory = Join-Path $ToolsRoot "bin"
$cometBinary = Join-Path $cometDirectory "cometbft.exe"
$verificationGoBinaries = @()
if (-not [string]::IsNullOrWhiteSpace($GoBinary)) {
    $GoBinary = Resolve-LocalnetPath -Path $GoBinary
    $verificationGoBinaries += $GoBinary
}

if (Test-Path -LiteralPath $cometBinary -PathType Leaf) {
    [void] (Assert-CometBinary -CometBinary $cometBinary -AdditionalGoBinaries $verificationGoBinaries)
    Write-Host "CometBFT v$cometVersion is already installed at $cometBinary"
    return
}

$goVersion = "1.26.5"
$goArchiveName = "go$goVersion.windows-amd64.zip"
$goArchiveUrl = "https://go.dev/dl/$goArchiveName"
$goArchiveSha256 = "97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38"

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $goRoot = Join-Path $ToolsRoot "go"
    $GoBinary = Join-Path $goRoot "bin\go.exe"
    if (-not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
        $downloadDirectory = Join-Path $ToolsRoot "downloads"
        $archivePath = Join-Path $downloadDirectory $goArchiveName
        New-Item -ItemType Directory -Force -Path $downloadDirectory | Out-Null

        $needsDownload = $true
        if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
            $existingHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            $needsDownload = $existingHash -ne $goArchiveSha256
        }
        if ($needsDownload) {
            Write-Host "Downloading pinned Go $goVersion toolchain..."
            Invoke-WebRequest -Uri $goArchiveUrl -OutFile $archivePath -UseBasicParsing
        }

        $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $goArchiveSha256) {
            throw "Go archive checksum mismatch. Expected $goArchiveSha256, got $actualHash at '$archivePath'."
        }

        if (Test-Path -LiteralPath $goRoot) {
            $entries = @(Get-ChildItem -LiteralPath $goRoot -Force)
            if ($entries.Count -gt 0) {
                throw "Refusing to overwrite incomplete Go toolchain directory '$goRoot'. Choose another -ToolsRoot."
            }
        }
        Write-Host "Extracting verified Go $goVersion toolchain..."
        Expand-Archive -LiteralPath $archivePath -DestinationPath $ToolsRoot
    }
}
else {
    $GoBinary = Resolve-LocalnetPath -Path $GoBinary
}

if (-not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
    throw "Go binary was not found at '$GoBinary'."
}

$goVersionOutput = @(& $GoBinary version 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to run '$GoBinary version': $($goVersionOutput -join [Environment]::NewLine)"
}
Write-Host ($goVersionOutput -join [Environment]::NewLine)

New-Item -ItemType Directory -Force -Path $cometDirectory | Out-Null
$oldGoBin = $env:GOBIN
try {
    $env:GOBIN = $cometDirectory
    Write-Host "Building CometBFT v$cometVersion from its versioned Go module..."
    Invoke-CheckedCommand -FilePath $GoBinary -ArgumentList @(
        "install",
        "github.com/cometbft/cometbft/cmd/cometbft@v$cometVersion"
    )
}
finally {
    if ($null -eq $oldGoBin) {
        Remove-Item Env:GOBIN -ErrorAction SilentlyContinue
    }
    else {
        $env:GOBIN = $oldGoBin
    }
}

[void] (Assert-CometBinary -CometBinary $cometBinary -AdditionalGoBinaries @($GoBinary))
Write-Host "Installed CometBFT v$cometVersion at $cometBinary"
