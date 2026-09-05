# Version: 1.0.0
# Purpose: Read-only recent Security log events. Invoked only by the Python execution broker.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$MaxEvents = 20
)
$ErrorActionPreference = 'Stop'
if ($MaxEvents -lt 1 -or $MaxEvents -gt 200) { throw 'MaxEvents out of range' }
Write-Information ("btos.collect.windows.events version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{ action = 'collect.windows.events'; dry_run = $true; max_events = $MaxEvents; events = @() } | ConvertTo-Json -Compress
    exit 0
}
Get-WinEvent -LogName Security -MaxEvents $MaxEvents | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName | ConvertTo-Json -Compress
