# Version: 1.0.0
# Read-only Windows Security log query template. No command construction from strings.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$Hours = 1,
    [int]$MaxEvents = 100
)
$ErrorActionPreference = 'Stop'
if ($Hours -lt 1 -or $Hours -gt 24) { throw 'Hours out of range' }
if ($MaxEvents -lt 1 -or $MaxEvents -gt 1000) { throw 'MaxEvents out of range' }
if ($DryRun) {
    [pscustomobject]@{
        action     = 'collect.windows.auth_events'
        dry_run    = $true
        hours      = $Hours
        max_events = $MaxEvents
        events     = @()
    } | ConvertTo-Json -Compress
    exit 0
}
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625, 4624; StartTime = (Get-Date).AddHours(-1 * $Hours) } -MaxEvents $MaxEvents |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json -Compress
