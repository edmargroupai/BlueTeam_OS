# Version: 1.0.0
# Purpose: Read-only service inventory. Invoked only by the Python execution broker.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$Limit = 50
)
$ErrorActionPreference = 'Stop'
if ($Limit -lt 1 -or $Limit -gt 500) { throw 'Limit out of range' }
Write-Information ("btos.collect.windows.services version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{ action = 'collect.windows.services'; dry_run = $true; limit = $Limit; services = @() } | ConvertTo-Json -Compress
    exit 0
}
Get-Service | Select-Object -First $Limit Name, Status, StartType | ConvertTo-Json -Compress
