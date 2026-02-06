<#
.SYNOPSIS
    Office Version & Update Channel Audit

.NOTES
    Name:       OfficeVersionandUpdateChannelAudit.ps1
    Author:     Stu Villanti (s.villanti@kenstra.com.au)
    Version:    4.0


.DESCRIPTION
    Audits Microsoft Office Click-to-Run (C2R) on the local machine and reports:
      - Office Version (VersionToReport)
      - Update Channel (resolved to a human-readable name)
      - Update Channel GUID
      - Optional “AtRisk” boolean if a minimum secure version is supplied

    This is safe for MSP/RMM execution (N-able / Take Control):
      - No changes are made to the system
      - Output is a single structured object (easy to paste into ticket notes)
      - If Office C2R is not detected, outputs a clear message/object and exits cleanly

.PARAMETER MinSecureVersion
    Optional minimum secure Office version to compare against.
    If provided, AtRisk will be:
      - $true  = installed version is below minimum
      - $false = installed version is equal/above minimum
    If not provided, AtRisk is $null.

.EXAMPLE
    .\Office-Audit.ps1

.EXAMPLE
    .\Office-Audit.ps1 -MinSecureVersion 16.0.14326.21336

.OUTPUTS
    PSCustomObject with audit results.

.EXITCODES
    0 = success / not detected / informational only
    (This script is designed NOT to generate “failed” noise in RMM.)

#>

[CmdletBinding()]
param (
    # Optional minimum secure version for comparison
    [Parameter(Mandatory = $false)]
    [version]$MinSecureVersion
)

# ------------------------------------------------------------
# 1) Locate Office Click-to-Run configuration registry key
# ------------------------------------------------------------
# This key exists when Office is installed via Click-to-Run (most M365 installs).
$RegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

# If C2R isn't installed, report and exit cleanly (avoid RMM alert storms).
if (-not (Test-Path $RegPath)) {
    # You can choose either a simple message OR an object.
    # Object is nicer for consistent reporting.
    [PSCustomObject]@{
        ComputerName      = $env:COMPUTERNAME
        OfficeDetected    = $false
        OfficeVersion     = $null
        UpdateChannel     = $null
        UpdateChannelGuid = $null
        AtRisk            = $null
        Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Note              = "Office Click-to-Run not detected"
    }
    exit 0
}

# ------------------------------------------------------------
# 2) Read config values
# ------------------------------------------------------------
# VersionToReport: Office version that Office reports (what you normally care about)
# UpdateChannel:   URL including a GUID for the channel (Current/Monthly Enterprise/etc.)
$config = Get-ItemProperty -Path $RegPath

# Defensive parsing:
# If VersionToReport is missing or malformed, this will throw — we handle below.
try {
    $Version = [version]$config.VersionToReport
} catch {
    $Version = $null
}

$ChannelUrl = [string]$config.UpdateChannel

# ------------------------------------------------------------
# 3) Resolve channel GUID -> human-readable name
# ------------------------------------------------------------
# Channel GUID is typically the final path segment of the UpdateChannel URL.
# Example:
#   http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60
$ChannelGuid = $null
if ($ChannelUrl) {
    $ChannelGuid = ($ChannelUrl -split "/")[-1]
}

# Known channel mappings (common Microsoft 365 channels)
$ChannelMap = @{
    "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" = "Current Channel"
    "55336b82-a18d-4dd6-b5f6-9e5095c314a6" = "Monthly Enterprise Channel"
    "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" = "Semi-Annual Enterprise Channel (Preview)"
    "b8f9b850-328d-4355-9145-c59439a0c4cf" = "Semi-Annual Enterprise Channel"
    "f2e724c1-748f-4b47-8c6f-37a8a7a8f48c" = "Beta Channel"
}

$ChannelName = $null
if ($ChannelGuid -and $ChannelMap.ContainsKey($ChannelGuid)) {
    $ChannelName = $ChannelMap[$ChannelGuid]
} else {
    $ChannelName = "Unknown / Custom Channel"
}

# ------------------------------------------------------------
# 4) Optional version comparison (AtRisk)
# ------------------------------------------------------------
# If MinSecureVersion is supplied:
#   AtRisk = installed version is less than minimum
# Otherwise:
#   AtRisk = $null
$AtRisk = $null
if ($MinSecureVersion -and $Version) {
    $AtRisk = ($Version -lt $MinSecureVersion)
}

# ------------------------------------------------------------
# 5) Output (structured object for RMM / ticket notes)
# ------------------------------------------------------------
[PSCustomObject]@{
    ComputerName      = $env:COMPUTERNAME
    OfficeDetected    = $true
    OfficeVersion     = if ($Version) { $Version.ToString() } else { $null }
    UpdateChannel     = $ChannelName
    UpdateChannelGuid = $ChannelGuid
    AtRisk            = $AtRisk
    Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

exit 0
