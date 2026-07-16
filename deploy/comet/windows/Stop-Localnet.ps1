[CmdletBinding()]
param(
    [string] $LocalnetRoot
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Localnet.Common.ps1")

if ([string]::IsNullOrWhiteSpace($LocalnetRoot)) {
    $LocalnetRoot = Get-DefaultLocalnetRoot
}
$LocalnetRoot = Resolve-LocalnetPath -Path $LocalnetRoot

$stopped = 0
$failures = @()
foreach ($kind in @("comet", "app")) {
    foreach ($node in @(3, 2, 1, 0)) {
        $recordPath = Get-ProcessRecordPath -LocalnetRoot $LocalnetRoot -Kind $kind -Node $node
        try {
            $record = Read-ProcessRecord -RecordPath $recordPath
            if ($null -eq $record) {
                continue
            }
            $process = Get-RecordedProcess -RecordPath $recordPath
        }
        catch {
            $failures += "$kind node$node record '$recordPath': $($_.Exception.Message)"
            Write-Warning "Skipping the invalid process record for $kind node$node; continuing with the other localnet processes."
            continue
        }
        if ($null -ne $process) {
            Write-Host "Stopping $kind node$node (PID $($process.Id))..."
            try {
                Stop-Process -Id $process.Id -ErrorAction Stop
                [void] $process.WaitForExit(10000)
                $process.Refresh()
                if (-not $process.HasExited) {
                    throw "process did not exit within 10 seconds"
                }
                $stopped++
            }
            catch {
                $failures += "$kind node$node PID $($process.Id): $($_.Exception.Message)"
                continue
            }
        }
        else {
            Write-Host "Removing stale process record for $kind node$node."
        }
        Remove-Item -LiteralPath $recordPath -Force
    }
}

Write-Host "Stopped $stopped localnet processes. Persistent chain data and logs were preserved at $LocalnetRoot"
if ($failures.Count -gt 0) {
    throw "Some localnet processes could not be stopped; their PID records were preserved: $($failures -join '; ')"
}
