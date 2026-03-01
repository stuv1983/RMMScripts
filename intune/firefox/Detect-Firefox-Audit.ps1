<#
.SYNOPSIS
    Mozilla Firefox Zero-Footprint Audit Detection
.DESCRIPTION
    Validates Firefox compliance.
    Exit 0 = Compliant (Intune reports 'Installed/Success')
    Exit 1 = Non-Compliant (Intune triggers No-Op and reports 'Failed')
#>

$FirefoxSystem64 = "C:\Program Files\Mozilla Firefox\firefox.exe"
$FirefoxSystem86 = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
$AppDataInstallFound = $false

# 1. 32-bit Trap (Architecture Drift)
if (Test-Path $FirefoxSystem86) {
    Write-Output "Non-Compliant: 32-bit Firefox installation detected in x86."
    exit 1
}

# 2. AppData Trap (Unmanaged Shadow IT)
$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

foreach ($Profile in $UserProfiles) {
    $AppPath = Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox\firefox.exe"
    if (Test-Path $AppPath) { $AppDataInstallFound = $true; break }
}

if ($AppDataInstallFound) {
    Write-Output "Non-Compliant: Rogue AppData installation detected."
    exit 1
}

# 3. Escape Hatch (Not Installed)
if (-not (Test-Path $FirefoxSystem64)) {
    Write-Output "Compliant: Firefox is not installed."
    exit 0
}

# 4. Broken Service Trap (Servicing Engine Validation)
$MaintenanceService = Get-Service -Name "MozillaMaintenance" -ErrorAction SilentlyContinue

if ($null -eq $MaintenanceService) {
    Write-Output "Non-Compliant: Maintenance Service is missing."
    exit 1
}

if ($MaintenanceService.StartType -eq 'Disabled') {
    Write-Output "Non-Compliant: Maintenance Service is Disabled."
    exit 1
}

Write-Output "Compliant: System Firefox is healthy and governed."
exit 0