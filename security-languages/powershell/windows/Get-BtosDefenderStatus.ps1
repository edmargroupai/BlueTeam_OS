# Version: 1.0.0
# Purpose: Read-only Microsoft Defender status. Invoked only by the Python execution broker.
[CmdletBinding()]
param(
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Write-Information ("btos.collect.windows.defender version=1.0.0 dryRun={0}" -f $DryRun.IsPresent)
if ($DryRun) {
    [pscustomobject]@{ action = 'collect.windows.defender'; dry_run = $true; status = @() } | ConvertTo-Json -Compress
    exit 0
}
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled | ConvertTo-Json -Compress
