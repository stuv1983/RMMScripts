<#
.SYNOPSIS
    Google Chrome Zero-Footprint Audit Detection
.DESCRIPTION
    Validates Chrome compliance.
    Exit 0 = Compliant (Intune reports 'Installed/Success')
    Exit 1 = Non-Compliant (Intune triggers No-Op and reports 'Failed')
#>

$ChromeSystem64 = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$Chromex86 = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
$AppDataInstallFound = $false

# 1. 32-bit Trap (Architecture Drift)
if (Test-Path $Chromex86) {
    Write-Output "Non-Compliant: 32-bit installation detected in x86."
    exit 1
}

# 2. AppData Trap (Unmanaged Shadow IT)
# Safely ignoring common non-user directories without relying on regex
$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

foreach ($Profile in $UserProfiles) {
    $AppPath = Join-Path $Profile.FullName "AppData\Local\Google\Chrome\Application\chrome.exe"
    if (Test-Path $AppPath) { $AppDataInstallFound = $true; break }
}

if ($AppDataInstallFound) {
    Write-Output "Non-Compliant: Rogue AppData installation detected."
    exit 1
}

# 3. Escape Hatch (Not Installed)
if (-not (Test-Path $ChromeSystem64)) {
    Write-Output "Compliant: Chrome is not installed."
    exit 0
}

# 4. Broken Service Trap (Optimized Direct Query)
$UpdateServices = @(Get-Service -Name "gupdate", "gupdatem", "GoogleUpdater*" -ErrorAction SilentlyContinue)

if ($UpdateServices.Count -eq 0) {
    Write-Output "Non-Compliant: Update service is missing."
    exit 1
}

# Only fail if NO update services are available and enabled
if (-not ($UpdateServices | Where-Object { $_.StartType -ne 'Disabled' })) {
    Write-Output "Non-Compliant: Update services are Disabled."
    exit 1
}

Write-Output "Compliant: 64-bit System Chrome is healthy and governed."
exit 0