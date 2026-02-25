<#
.SYNOPSIS
    Force-OfficeUpdate.ps1
    Installation/Remediation script to trigger Office Click-to-Run updates.
.DESCRIPTION
    Actions performed:
    1. Locates the native OfficeC2RClient.exe updater.
    2. Triggers the update engine asynchronously in the background.

.NOTES
    NAME: Force-OfficeUpdate
    AUTHOR: Stu    
#>
#>

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$C2RClient = "$env:ProgramFiles\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
Write-Output "Starting Office update remediation..."

if (Test-Path -LiteralPath $C2RClient) {
    Write-Output "Triggering background Office update check..."
    
    # Fire the native update engine asynchronously.
    # Argument Breakdown:
    # - displaylevel=false: Hides the update splash screens and progress bars from the user.
    # - forceappshutdown=false: PREVENTS Office from killing open applications (Word, Excel, etc.) to avoid data loss. The update stages in the background and applies when the user manually closes them.
    # - Wait:$false: Allows this script to exit immediately so Intune doesn't hang while the update downloads.
    Start-Process -FilePath $C2RClient -ArgumentList "/update user displaylevel=false forceappshutdown=false" -Wait:$false
    
    Write-Output "Update triggered successfully. Intune may temporarily report 'Failed' until the background update finishes."
    exit 0
} else {
    Write-Output "ERROR: OfficeC2RClient.exe not found. Cannot trigger update."
    exit 1
}