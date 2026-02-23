<#
.SYNOPSIS
  Detect-Firefox.ps1 
  Detection method for Intune Win32 App or Proactive Remediations.
.DESCRIPTION
  This script physically inspects the hard drive instead of relying on the registry.
  It flags a device as Compliant ONLY IF: 
  1. No vulnerable per-user installs exist in any AppData folder.
  2. The secure system install in Program Files is present and meets the minimum version.
#>

$TargetVersion = [version]"147.0.4"
$isNonCompliant = $false

# ==============================================================================
# PHASE 1: Scan for rogue per-user consumer installations
# ==============================================================================
# Define system profiles to skip during our AppData sweep
$skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")

# Gather all valid user profile directories safely
$users = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue | 
    Where-Object { $skip -notcontains $_.Name }

foreach ($u in $users) {
    # Define the exact paths where consumer Firefox installs its executables
    $targets = @(
        (Join-Path -Path $u.FullName -ChildPath "AppData\Local\Mozilla\Firefox\firefox.exe"),
        (Join-Path -Path $u.FullName -ChildPath "AppData\Local\Firefox\firefox.exe")
    )
    
    foreach ($t in $targets) {
        # If the executable exists in AppData, the device is immediately non-compliant
        if (Test-Path -LiteralPath $t) {
            Write-Output "Found rogue per-user install: $t"
            $isNonCompliant = $true
        }
    }
}

# ==============================================================================
# PHASE 2: Verify Enterprise System Installation
# ==============================================================================
# Define the standard 64-bit and 32-bit Program Files locations
$sysPaths = @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
)
$installedSysVersion = $null

# Check physical executable file for its embedded ProductVersion
foreach ($p in $sysPaths) {
    if (Test-Path -LiteralPath $p) {
        try {
            $v = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion
            if ($v) { $installedSysVersion = [version]$v; break }
        } catch {}
    }
}

# Evaluate the discovered version against our target baseline
if (-not $installedSysVersion) {
    Write-Output "System Firefox is missing."
    $isNonCompliant = $true
} elseif ($installedSysVersion -lt $TargetVersion) {
    Write-Output "System Firefox is outdated ($installedSysVersion < $TargetVersion)."
    $isNonCompliant = $true
}

# ==============================================================================
# PHASE 3: Final Intune Evaluation
# ==============================================================================
if ($isNonCompliant) {
    # Exit 1 tells Intune the app is NOT installed / Device is Non-Compliant
    Write-Output "Non-compliant: Per-user Firefox detected, or System Firefox is missing/outdated."
    exit 1
} else {
    # Exit 0 tells Intune the app IS installed / Device is Compliant
    Write-Output "Compliant: Device meets Enterprise Firefox standards."
    exit 0
}