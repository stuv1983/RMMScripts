<#
.SYNOPSIS
    Detect-OfficeUpdate.ps1
    Intune Win32 detection script (Update Only Mode for Office Click-to-Run).

.NOTES
    NAME: Detect-OfficeUpdate
    AUTHOR: Stu    
#>

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$TargetVersion = [version]"16.0.17328.20142" 
$RegPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

# ==============================================================================
# PHASE 1: Gatekeeper (Is Office Installed?)
# ==============================================================================
if (-not (Test-Path -Path $RegPath)) {
    Write-Output "COMPLIANT: Office Click-to-Run is not present. No action required."
    exit 0
}

# ==============================================================================
# PHASE 2: Version Evaluation
# ==============================================================================
$CurrentVersionString = (Get-ItemProperty -Path $RegPath -Name "VersionToReport" -ErrorAction SilentlyContinue).VersionToReport

if ([string]::IsNullOrWhiteSpace($CurrentVersionString)) {
    Write-Output "NON-COMPLIANT: Office is installed but version cannot be determined."
    exit 1
}

if ([version]$CurrentVersionString -lt $TargetVersion) {
    Write-Output "NON-COMPLIANT: Office version ($CurrentVersionString) is older than target ($TargetVersion)."
    exit 1
}

# Victory
Write-Output "COMPLIANT: Meets required Office update standard."
exit 0