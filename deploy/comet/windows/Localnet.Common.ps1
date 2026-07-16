Set-StrictMode -Version Latest

$script:LocalnetScriptsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:AsteriaRepositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $script:LocalnetScriptsRoot "..\..\..")
)
$script:AsteriaCometVersion = "0.38.23"
$script:AsteriaNodeCount = 4
$script:AsteriaAppProtocolVersion = 5

function Get-AsteriaRepositoryRoot {
    return $script:AsteriaRepositoryRoot
}

function Get-DefaultLocalnetRoot {
    return (Join-Path $script:AsteriaRepositoryRoot "data\localnet")
}

function Get-DefaultCometBinary {
    return (Join-Path $script:AsteriaRepositoryRoot ".tools\bin\cometbft.exe")
}

function Get-PrivateOrderConfigRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot
    )

    return (Join-Path (Resolve-LocalnetPath -Path $LocalnetRoot) "secrets\private-order")
}

function Get-PrivateOrderPublicKeyPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot
    )

    return (Join-Path (Get-PrivateOrderConfigRoot -LocalnetRoot $LocalnetRoot) "public-key-set.json")
}

function Get-PrivateOrderSharePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 3)]
        [int] $Node
    )

    return (Join-Path (Get-PrivateOrderConfigRoot -LocalnetRoot $LocalnetRoot) "node$Node.key-share")
}

function Protect-PrivateOrderDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Private-order directory was not found at '$resolved'."
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Private-order directory must not be a reparse point: '$resolved'."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $currentSid = "*$($identity.Value)"
    $systemSid = "*S-1-5-18"
    & icacls.exe $resolved `
        /inheritance:r `
        /grant:r "${currentSid}:(OI)(CI)F" "${systemSid}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to protect private-order directory '$resolved'."
    }
    $directoryAcl = Get-Acl -LiteralPath $resolved
    $unexpectedDirectoryRules = @($directoryAcl.Access | Where-Object {
        $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $sid -notin @($identity.Value, "S-1-5-18") -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow
    })
    if (-not $directoryAcl.AreAccessRulesProtected -or $unexpectedDirectoryRules.Count -ne 0) {
        throw "Private-order directory ACL contains an inherited, denied, or unexpected principal."
    }
}

function Protect-PrivateOrderConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Private-order configuration directory was not found at '$resolved'."
    }
    Protect-PrivateOrderDirectory -Path $resolved
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $currentSid = "*$($identity.Value)"
    $systemSid = "*S-1-5-18"

    foreach ($node in 0..3) {
        $sharePath = Join-Path $resolved "node$node.key-share"
        if (-not (Test-Path -LiteralPath $sharePath -PathType Leaf)) {
            throw "Private-order share file is missing for node$node."
        }
        & icacls.exe $sharePath `
            /inheritance:r `
            /grant:r "${currentSid}:R" "${systemSid}:F" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to protect private-order share file for node$node."
        }
        $shareAcl = Get-Acl -LiteralPath $sharePath
        $unexpectedRules = @($shareAcl.Access | Where-Object {
            $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            $sid -notin @($identity.Value, "S-1-5-18") -or
                $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow
        })
        if (-not $shareAcl.AreAccessRulesProtected -or $unexpectedRules.Count -ne 0) {
            throw "Private-order share ACL contains an inherited, denied, or unexpected principal for node$node."
        }
    }
}

function Enable-PrivateOrderConfigRemoval {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot
    )

    $root = Resolve-LocalnetPath -Path $LocalnetRoot
    $resolved = [IO.Path]::GetFullPath((Get-PrivateOrderConfigRoot -LocalnetRoot $root))
    $expected = [IO.Path]::GetFullPath((Join-Path $root "secrets\private-order"))
    if ($resolved -ine $expected) {
        throw "Refusing to change ACLs outside the managed private-order directory."
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        return
    }
    foreach ($candidate in @((Join-Path $root "secrets"), $resolved)) {
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to change ACLs through reparse point '$candidate'."
        }
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $currentSid = "*$($identity.Value)"
    & icacls.exe $resolved /grant:r "${currentSid}:F" /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to grant removal access to '$resolved'."
    }
}

function Resolve-LocalnetPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [string] $BasePath = $script:AsteriaRepositoryRoot
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Content
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Write-Utf8NoBomAtomic {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Content
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $directory = Split-Path -Parent $resolved
    $fileName = Split-Path -Leaf $resolved
    $temporaryPath = Join-Path $directory ".$fileName.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$temporaryPath.backup"

    try {
        Write-Utf8NoBom -Path $temporaryPath -Content $Content
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            [IO.File]::Replace($temporaryPath, $resolved, $backupPath, $true)
        }
        elseif (Test-Path -LiteralPath $resolved) {
            throw "Atomic file destination '$resolved' exists but is not a regular file."
        }
        else {
            [IO.File]::Move($temporaryPath, $resolved)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupPath -Force
        }
    }
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $true)]
        [string[]] $ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($ArgumentList -join ' ')"
    }
}

function Assert-CometBinary {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CometBinary,
        [string[]] $AdditionalGoBinaries = @()
    )

    $resolved = Resolve-LocalnetPath -Path $CometBinary
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "CometBFT binary was not found at '$resolved'. Run Install-CometBft.ps1 first or pass -CometBinary."
    }

    $versionOutput = @(& $resolved version 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to run '$resolved version': $($versionOutput -join [Environment]::NewLine)"
    }
    $reportedVersion = ($versionOutput | Select-Object -First 1).ToString().Trim().TrimStart("v")
    if ($reportedVersion -eq $script:AsteriaCometVersion) {
        return $resolved
    }

    # The upstream v0.38.23 tag still prints 0.38.22. Verify the embedded Go
    # module version before accepting that known mismatch.
    $toolsRoot = Split-Path -Parent (Split-Path -Parent $resolved)
    $goCandidates = @($AdditionalGoBinaries | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }) + @(
        (Join-Path $toolsRoot "go\bin\go.exe"),
        (Join-Path $script:AsteriaRepositoryRoot ".tools\go\bin\go.exe"),
        (Join-Path $script:AsteriaRepositoryRoot ".tools\go\1.26.5\go\bin\go.exe")
    )
    $systemGo = Get-Command go -ErrorAction SilentlyContinue
    if ($null -ne $systemGo) {
        $goCandidates += $systemGo.Source
    }
    foreach ($goBinary in ($goCandidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $goBinary -PathType Leaf)) {
            continue
        }
        $buildInfo = @(& $goBinary version -m $resolved 2>&1)
        if ($LASTEXITCODE -eq 0 -and
            ($buildInfo -match '^\s*mod\s+github\.com/cometbft/cometbft\s+v0\.38\.23(?:\s|$)')) {
            Write-Warning "CometBFT v0.38.23 has an upstream display-version bug and reports $reportedVersion; embedded module metadata confirms v0.38.23."
            return $resolved
        }
    }
    throw "Asteria localnet requires CometBFT $script:AsteriaCometVersion. '$resolved' reports '$reportedVersion' and has no verifiable v0.38.23 Go module metadata."
}

function Get-LocalnetNodeSpecs {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot
    )

    $root = Resolve-LocalnetPath -Path $LocalnetRoot
    for ($node = 0; $node -lt $script:AsteriaNodeCount; $node++) {
        [PSCustomObject]@{
            Node = $node
            Name = "node$node"
            AbciPort = 26658 + (100 * $node)
            HttpPort = 8080 + $node
            P2pPort = 26656 + (100 * $node)
            RpcPort = 26657 + (100 * $node)
            MetricsPort = 26660 + (100 * $node)
            AppData = Join-Path $root "apps\node$node\chain.redb"
            CometHome = Join-Path $root "comet\node$node"
        }
    }
}

function Get-ProcessRecordPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $LocalnetRoot,
        [Parameter(Mandatory = $true)]
        [ValidateSet("app", "comet")]
        [string] $Kind,
        [Parameter(Mandatory = $true)]
        [int] $Node
    )

    return (Join-Path (Resolve-LocalnetPath -Path $LocalnetRoot) "run\$Kind-node$Node.json")
}

function Read-ProcessRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RecordPath
    )

    if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) {
        return $null
    }
    try {
        return (Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Invalid localnet process record '$RecordPath': $($_.Exception.Message)"
    }
}

function Get-RecordedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RecordPath
    )

    $record = Read-ProcessRecord -RecordPath $RecordPath
    if ($null -eq $record) {
        return $null
    }

    $process = Get-Process -Id ([int] $record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $null
    }

    try {
        $actualExecutable = [IO.Path]::GetFullPath($process.Path)
        $expectedExecutable = [IO.Path]::GetFullPath([string] $record.executable)
        $actualStartTime = $process.StartTime.ToFileTimeUtc()
    }
    catch {
        return $null
    }

    if ($actualExecutable -ine $expectedExecutable -or $actualStartTime -ne [long] $record.start_time_filetime_utc) {
        return $null
    }
    return $process
}

function ConvertTo-WindowsCommandLineArgument {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object Text.StringBuilder
    [void] $builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void] $builder.Append(('\' * (($backslashes * 2) + 1)))
            [void] $builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void] $builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void] $builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void] $builder.Append(('\' * ($backslashes * 2)))
    }
    [void] $builder.Append('"')
    return $builder.ToString()
}

function Start-RecordedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $true)]
        [string[]] $ArgumentList,
        [Parameter(Mandatory = $true)]
        [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string] $StandardOutputPath,
        [Parameter(Mandatory = $true)]
        [string] $StandardErrorPath,
        [Parameter(Mandatory = $true)]
        [string] $RecordPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet("app", "comet")]
        [string] $Kind,
        [Parameter(Mandatory = $true)]
        [int] $Node,
        [hashtable] $ProcessEnvironment = @{}
    )

    $executable = [IO.Path]::GetFullPath($FilePath)
    $commandLine = ($ArgumentList | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value $_ }) -join ' '

    # Some Windows hosts expose both Path and PATH. Start-Process builds a
    # case-insensitive environment dictionary and otherwise rejects that block.
    $pathKeys = @([Environment]::GetEnvironmentVariables("Process").Keys | Where-Object {
        $_.ToString() -ieq "PATH"
    })
    if ($pathKeys.Count -gt 1) {
        $pathValue = [Environment]::GetEnvironmentVariable("PATH", "Process")
        [Environment]::SetEnvironmentVariable("Path", $null, "Process")
        [Environment]::SetEnvironmentVariable("PATH", $pathValue, "Process")
    }
    $originalEnvironment = @{}
    foreach ($name in $ProcessEnvironment.Keys) {
        if ($name -notmatch '^ASTERIA_PRIVATE_(VALIDATOR_ID|KEY_SHARE_FILE)$') {
            throw "Start-RecordedProcess refuses unsupported private environment variable '$name'."
        }
    }
    try {
        foreach ($name in $ProcessEnvironment.Keys) {
            $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
            [Environment]::SetEnvironmentVariable($name, [string] $ProcessEnvironment[$name], "Process")
        }
        $process = Start-Process -FilePath $executable `
            -ArgumentList $commandLine `
            -WorkingDirectory $WorkingDirectory `
            -RedirectStandardOutput $StandardOutputPath `
            -RedirectStandardError $StandardErrorPath `
            -WindowStyle Hidden `
            -PassThru
    }
    finally {
        foreach ($name in $ProcessEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
        }
    }
    Start-Sleep -Milliseconds 100
    $process.Refresh()
    if ($process.HasExited) {
        $errorText = if (Test-Path -LiteralPath $StandardErrorPath) {
            Get-Content -LiteralPath $StandardErrorPath -Raw
        }
        else {
            ""
        }
        throw "$Kind node$Node exited during startup (exit $($process.ExitCode)). $errorText"
    }

    try {
        $record = [ordered]@{
            kind = $Kind
            node = $Node
            pid = $process.Id
            executable = $executable
            start_time_filetime_utc = $process.StartTime.ToFileTimeUtc()
            stdout = [IO.Path]::GetFullPath($StandardOutputPath)
            stderr = [IO.Path]::GetFullPath($StandardErrorPath)
        }
        Write-Utf8NoBomAtomic -Path $RecordPath -Content ($record | ConvertTo-Json)
    }
    catch {
        $recordError = $_
        $terminationError = $null
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -ErrorAction Stop
                [void] $process.WaitForExit(10000)
                $process.Refresh()
                if (-not $process.HasExited) {
                    throw "process did not exit within 10 seconds"
                }
            }
        }
        catch {
            $terminationError = $_.Exception.Message
        }

        $message = "Failed to persist the $Kind node$Node process record for PID $($process.Id): $($recordError.Exception.Message)"
        if ($null -ne $terminationError) {
            $message += ". The newly started process could not be terminated: $terminationError"
        }
        else {
            $message += ". The newly started process was terminated."
        }
        throw $message
    }
    return $process
}

function Test-TcpPortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Port
    )

    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        return $true
    }
    catch [Net.Sockets.SocketException] {
        return $false
    }
    finally {
        $listener.Stop()
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory = $true)]
        [int] $Port,
        [Parameter(Mandatory = $true)]
        [DateTime] $Deadline,
        [string] $Description = "TCP port"
    )

    while ([DateTime]::UtcNow -lt $Deadline) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $connect = $client.ConnectAsync("127.0.0.1", $Port)
            if ($connect.Wait(250) -and $client.Connected) {
                return
            }
        }
        catch {
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }
    throw "Timed out waiting for $Description on 127.0.0.1:$Port."
}

function Get-CometRpcResult {
    param(
        [Parameter(Mandatory = $true)]
        [int] $RpcPort,
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $uri = "http://127.0.0.1:$RpcPort/$Path"
    return (Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 4).result
}
