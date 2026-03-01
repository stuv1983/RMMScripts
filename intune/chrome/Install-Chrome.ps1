<#
.SYNOPSIS
    Google Chrome Phase 2 Surgical Remediation
.DESCRIPTION
    Silently repairs update services in the background. 
    Triggers the 45-minute process gate and full MSI replacement ONLY if 
    destructive action (removing AppData/x86) or task rebuilds are required.
#>

$ErrorActionPreference = "Stop"
$MsiName = "googlechromestandaloneenterprise64.msi"
$ChromeSystem64 = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$Chromex86 = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
$NeedsDestructiveFix = $false

# ------------------------------------------------------------------------
# 1. EVALUATE DESTRUCTIVE FIX REQUIREMENT
# ------------------------------------------------------------------------
# Flag if 32-bit architecture exists
if (Test-Path $Chromex86) { $NeedsDestructiveFix = $true }

$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

# Flag if AppData shadow IT exists
foreach ($Profile in $UserProfiles) {
    if (Test-Path (Join-Path $Profile.FullName "AppData\Local\Google\Chrome\Application\chrome.exe")) { 
        $NeedsDestructiveFix = $true; break 
    }
}

# Flag if the main 64-bit application is completely missing
if (-not (Test-Path $ChromeSystem64)) { $NeedsDestructiveFix = $true }

# Flag if Scheduled Tasks are missing (Requires MSI repair to rebuild them)
$Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
    $_.TaskName -match "^GoogleUpdateTaskMachine" -or 
    $_.TaskName -match "^GoogleUpdaterTaskSystem" 
})
if ($Tasks.Count -eq 0) { $NeedsDestructiveFix = $true }

# ------------------------------------------------------------------------
# 2. SILENT SERVICE REPAIR (No User Disruption)
# ------------------------------------------------------------------------
$UpdateServices = @(Get-Service -Name "gupdate", "gupdatem", "GoogleUpdater*" -ErrorAction SilentlyContinue)
foreach ($Service in $UpdateServices) {
    if ($Service.StartType -eq 'Disabled') {
        Write-Output "Surgical Fix: Re-enabling $($Service.Name)..."
        Set-Service -Name $Service.Name -StartupType Automatic
        Start-Service -Name $Service.Name -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------------
# 3. DESTRUCTIVE FIX / MSI EXECUTION
# ------------------------------------------------------------------------
if ($NeedsDestructiveFix) {
    
    # Patient Process Gate: Wait up to 45 mins for user to finish work
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (Get-Process -Name "chrome" -ErrorAction SilentlyContinue) {
        if ($timer.Elapsed.TotalMinutes -ge 45) { 
            Write-Output "Timeout reached. Exiting 1618 to defer to next Intune sync."
            exit 1618 
        } 
        Start-Sleep -Seconds 60
    }

    # Nuke AppData Binaries (Surgically targets \Application, protects \User Data)
    foreach ($Profile in $UserProfiles) {
        $AppDir = Join-Path $Profile.FullName "AppData\Local\Google\Chrome\Application"
        if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    
    # Nuke x86 Architecture 
    if (Test-Path $Chromex86) { Remove-Item $Chromex86 -Recurse -Force -ErrorAction SilentlyContinue }

    # Execute MSI Repair/Install
    $msiPath = Join-Path $PSScriptRoot $MsiName
    Write-Output "Executing MSI Deployment..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait
}

Write-Output "Chrome Remediation Complete."
exit 0