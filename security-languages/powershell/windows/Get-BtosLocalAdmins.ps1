# Version: 1.0.0
# Purpose: Read-only local Administrators membership. Invoked only by the Python execution broker.
[CmdletBinding()]
param(
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Write-Information ("btos.collect.windows.local_admins version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{ action = 'collect.windows.local_admins'; dry_run = $true; members = @() } | ConvertTo-Json -Compress
    exit 0
}
Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json -Compress
