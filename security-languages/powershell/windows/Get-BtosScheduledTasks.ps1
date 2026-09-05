# Version: 1.0.0
# Purpose: Read-only scheduled task inventory. Invoked only by the Python execution broker.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$Limit = 50
)
$ErrorActionPreference = 'Stop'
if ($Limit -lt 1 -or $Limit -gt 500) { throw 'Limit out of range' }
Write-Information ("btos.collect.windows.scheduled_tasks version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{ action = 'collect.windows.scheduled_tasks'; dry_run = $true; limit = $Limit; tasks = @() } | ConvertTo-Json -Compress
    exit 0
}
Get-ScheduledTask | Select-Object -First $Limit TaskName, TaskPath, State | ConvertTo-Json -Compress
