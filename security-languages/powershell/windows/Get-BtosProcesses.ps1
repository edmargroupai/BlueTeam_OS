# Version: 1.0.0
# Purpose: Read-only process inventory. Invoked only by the Python execution broker.
# Least privilege: no elevation required. Dry-run by default.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$Limit = 50
)
$ErrorActionPreference = 'Stop'
if ($Limit -lt 1 -or $Limit -gt 500) { throw 'Limit out of range' }
Write-Information ("btos.collect.windows.processes version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{
        action    = 'collect.windows.processes'
        dry_run   = $true
        limit     = $Limit
        processes = @()
    } | ConvertTo-Json -Compress
    exit 0
}
Get-Process | Select-Object -First $Limit Id, ProcessName, Path | ConvertTo-Json -Compress
