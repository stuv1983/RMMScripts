# ==============================================================================
# Install-Adlumin.ps1
# Purpose  : Intune Win32 app install script for Adlumin MDR agent
# Run As   : SYSTEM (Intune managed device context)
# Exit 0   : Installation succeeded
# Exit 1   : Installation failed
# Exit 3010: Installation succeeded - reboot required
#            (configure 3010 as a soft-reboot return code in the Intune portal)
# ------------------------------------------------------------------------------
# Prerequisites:
#   - AdluminInstaller.msi must be bundled in the same .intunewin package
#     as this script and placed alongside it at packaging time.
#   - Replace $TenantId below with the tenant token supplied by N-able/Adlumin
#     during onboarding before deploying to production.
# ==============================================================================

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------
# CONFIGURATION
# All values that may need to change between environments are defined here.
# ------------------------------------------------------------------------------

# Display name used in log messages.
$AppName = "Adlumin MDR Agent"

# MSI installer filename - must be present alongside this script in the .intunewin package.
$InstallerName = "AdluminInstaller.msi"

# Tenant ID supplied by N-able/Adlumin during onboarding.
# !! Replace this placeholder before deploying to production. !!
$TenantId = "REPLACE-WITH-TENANT-ID"

# Log file location - ProgramData is writable by SYSTEM and survives across sessions.
$LogDir  = "C:\ProgramData\Kenstra\Logs\Adlumin"
$LogFile = Join-Path $LogDir "Adlumin-Install.log"

# ------------------------------------------------------------------------------
# LOGGING
# All activity is written to $LogFile with a UTC timestamp.
# ------------------------------------------------------------------------------

New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
    "$Timestamp  $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# ------------------------------------------------------------------------------
# RESOLVE INSTALLER PATH
# $PSScriptRoot is the preferred method but can be empty in some Intune contexts.
# The fallback uses MyInvocation to locate the script directory reliably.
# ------------------------------------------------------------------------------

$ScriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$InstallerPath = Join-Path $ScriptDir $InstallerName

# ------------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ------------------------------------------------------------------------------

Write-Log "=== $AppName installation started ==="
Write-Log "Script directory : $ScriptDir"
Write-Log "Installer path   : $InstallerPath"

# Abort if the MSI is missing - prevents a silent no-op.
if (-not (Test-Path -Path $InstallerPath)) {
    Write-Log "ERROR: Installer not found at '$InstallerPath'. Verify the .intunewin package contents."
    exit 1
}

# Abort if the tenant ID has not been set - deploying without it would register
# the agent to no tenant and require manual remediation on every affected device.
if ($TenantId -eq "REPLACE-WITH-TENANT-ID" -or [string]::IsNullOrWhiteSpace($TenantId)) {
    Write-Log "ERROR: Tenant ID has not been configured. Update `$TenantId` before deployment."
    exit 1
}

# ------------------------------------------------------------------------------
# INSTALLATION
# Uses msiexec.exe directly:
#   /i       - install the MSI
#   /qn      - completely silent, no UI
#   /norestart - suppress automatic reboot; exit 3010 signals Intune to reboot
#   /l*v     - verbose logging to a dedicated MSI log file for troubleshooting
#   tenant=  - org token passed as a public property to the MSI
# ------------------------------------------------------------------------------

$MsiLog  = Join-Path $LogDir "Adlumin-MSI.log"
$MsiArgs = "/i `"$InstallerPath`" /qn /norestart tenant=$TenantId /l*v `"$MsiLog`""

try {
    Write-Log "Launching msiexec with arguments: $MsiArgs"

    $Process = Start-Process `
        -FilePath     "msiexec.exe" `
        -ArgumentList $MsiArgs `
        -Wait `
        -PassThru `
        -WindowStyle  Hidden

    $ExitCode = $Process.ExitCode
    Write-Log "msiexec exited with code: $ExitCode"

    switch ($ExitCode) {
        0 {
            Write-Log "Installation completed successfully."
            exit 0
        }
        3010 {
            # 3010 means success but a reboot is required to complete the install.
            # Ensure 3010 is added to the Intune Win32 app return code list
            # as type "Soft reboot" so Intune handles the restart gracefully.
            Write-Log "Installation completed successfully. A reboot is required to finish."
            exit 3010
        }
        default {
            Write-Log "ERROR: Installation failed with unexpected exit code $ExitCode. Review MSI log at '$MsiLog'."
            exit $ExitCode
        }
    }
}
catch {
    Write-Log "ERROR: An exception occurred during installation - $($_.Exception.Message)"
    exit 1
}