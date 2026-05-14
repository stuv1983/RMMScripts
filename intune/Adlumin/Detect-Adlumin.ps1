# ==============================================================================
# Detect-Adlumin.ps1
# Purpose  : Intune Win32 app detection script for Adlumin MDR agent
# Run As   : SYSTEM (Intune managed device context)
# Exit 0   : Agent detected — Intune will mark app as installed
# Exit 1   : Agent not detected — Intune will trigger installation
# ------------------------------------------------------------------------------
# Detection checks (in order):
#   1. Registry uninstall keys (64-bit and 32-bit hives)
#   2. Windows services
#   3. Filesystem install paths
# ==============================================================================

$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------------------------------------------------
# CONFIGURATION
# Update these values to match the exact strings observed after a test install.
# Using exact DisplayName matching avoids false positives from unrelated software.
# ------------------------------------------------------------------------------

# Exact registry DisplayName of the installed application.
# Verify this against HKLM:\SOFTWARE\...\Uninstall\* after a manual install.
$AppDisplayName = "Adlumin MDR Agent"

# Windows service name(s) registered by the agent.
# Verify with: Get-Service | Where-Object { $_.Name -match "Adlumin" }
$ServiceNames = @("AdluminAgent", "AdluminMDR")

# Filesystem paths the installer creates.
# Verify with the vendor or by inspecting after a test install.
$InstallPaths = @(
    "C:\Program Files\Adlumin",
    "C:\Program Files (x86)\Adlumin"
)

# ------------------------------------------------------------------------------
# CHECK 1 — Registry uninstall keys
# Covers both 64-bit and 32-bit application registrations.
# ------------------------------------------------------------------------------

$RegistryHives = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$RegistryMatch = foreach ($Hive in $RegistryHives) {
    Get-ItemProperty -Path $Hive -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $AppDisplayName }
}

if ($RegistryMatch) {
    Write-Output "Detected: '$AppDisplayName' found in registry uninstall keys."
    exit 0
}

# ------------------------------------------------------------------------------
# CHECK 2 — Windows services
# The agent typically registers one or more services on install.
# ------------------------------------------------------------------------------

$ServiceMatch = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $ServiceNames -contains $_.Name }

if ($ServiceMatch) {
    Write-Output "Detected: Adlumin MDR service found — '$($ServiceMatch.Name)'."
    exit 0
}


# ------------------------------------------------------------------------------
# CHECK 3 — Filesystem install directory
# Fallback in case registry or service detection fails after a partial install.
# ------------------------------------------------------------------------------

foreach ($Path in $InstallPaths) {
    if (Test-Path -Path $Path) {
        Write-Output "Detected: Adlumin MDR install directory found at '$Path'."
        exit 0
    }
}

# ------------------------------------------------------------------------------
# Not detected — Intune will proceed with installation.
# ------------------------------------------------------------------------------

Write-Output "Not detected: Adlumin MDR agent was not found on this device."
exit 1