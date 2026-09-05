# Version: 1.0.0
# Read-only privileged group membership listing. Requires AD module when not dry-run.
[CmdletBinding()]
param(
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if ($DryRun) {
    [pscustomobject]@{
        action  = 'collect.ad.privileged_groups'
        dry_run = $true
        groups  = @('Domain Admins', 'Enterprise Admins', 'Administrators')
    } | ConvertTo-Json -Compress
    exit 0
}
@(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators'
) | ForEach-Object {
    Get-ADGroupMember -Identity $_ -Recursive | Select-Object @{n = 'Group'; e = { $_ } }, SamAccountName
} | ConvertTo-Json -Compress
