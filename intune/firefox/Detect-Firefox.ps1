<#
.SYNOPSIS
    Mozilla Firefox Phase 2 Enforcement Detection
.DESCRIPTION
    Validates Firefox compliance using file-based [version] retrieval and x86 architecture trapping.
#>

$FirefoxSystem64 = "C:\Program Files\Mozilla Firefox\firefox.exe"
$FirefoxSystem86 = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"

# FIXED: Ensure this uses the 2-part format (Major.Minor) to match Mozilla's native EXE versioning
$MinimumVersion = [version]"148.0" 
$AppDataInstallFound = $false

# ------------------------------------------------------------------------
# 1. ARCHITECTURE & SHADOW IT TRAPS
# ------------------------------------------------------------------------
if (Test-Path $FirefoxSystem86) {
    Write-Output "Non-Compliant (Exit 1): 32-bit Firefox installation detected."
    exit 1
}

$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

foreach ($Profile in $UserProfiles) {
    if (Test-Path (Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox\firefox.exe")) { 
        $AppDataInstallFound = $true; break 
    }
}

if ($AppDataInstallFound) {
    Write-Output "Non-Compliant (Exit 1): Rogue AppData installation detected."
    exit 1
}

# ------------------------------------------------------------------------
# 2. ESCAPE HATCH & VERSION FLOOR
# ------------------------------------------------------------------------
if (-not (Test-Path $FirefoxSystem64)) {
    Write-Output "Compliant (Exit 0): Firefox is not installed."
    exit 0
}

# Ensure we compare as [version] to prevent string logic errors
$CurrentVersion = [version](Get-Item $FirefoxSystem64).VersionInfo.ProductVersion
if ($CurrentVersion -lt $MinimumVersion) {
    Write-Output "Non-Compliant (Exit 1): Firefox version $CurrentVersion is below floor $MinimumVersion."
    exit 1
}

# ------------------------------------------------------------------------
# 3. SERVICING ENGINE VALIDATION
# ------------------------------------------------------------------------
# The Mozilla Maintenance Service naturally sits at 'Manual' and 'Stopped'.
$MaintenanceService = Get-Service -Name "MozillaMaintenance" -ErrorAction SilentlyContinue

if ($null -eq $MaintenanceService) {
    Write-Output "Non-Compliant (Exit 1): Maintenance Service is missing."
    exit 1
}

if ($MaintenanceService.StartType -eq 'Disabled') {
    Write-Output "Non-Compliant (Exit 1): Maintenance Service is Disabled."
    exit 1
}

Write-Output "Compliant (Exit 0): Firefox $CurrentVersion is fully governed and healthy."
exit 0