<#
.SYNOPSIS
    Removes installed TeamViewer and forcibly stops running TeamViewer processes.
.DESCRIPTION
    1. Workstation-only guardrail.
    2. (OPTIONAL) Patient Wait Loop to prevent dropping active remote sessions.
    3. Force-kills all TeamViewer processes and services to unlock files.
    4. Uninstalls installed TeamViewer via MSI or EXE silent strings.
    5. (OPTIONAL) Portable EXE cleanup.
    6. Post-check validation.
#>

[CmdletBinding()]
param(
    [int]$StopRetries = 3,
    [int]$RetryDelaySeconds = 2
)

$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
# DEPLOYMENT TOGGLES
# ==============================================================================
# Toggle to $false force kill  
# Toggle to $true patiently wait for active remote sessions/UI to close
$WaitIfActive = $true 

# Toggle to $true to recursively hunt down and delete portable TeamViewer EXEs
$CleanPortableEXEs = $false 


# ==============================================================================
# STEP 0 – WORKSTATION GUARDRAIL
# ==============================================================================
$os = Get-CimInstance Win32_OperatingSystem
if (-not $os -or $os.ProductType -ne 1) {
    Write-Output "Skipping: Not a workstation OS."
    exit 0
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
function Get-InstalledTeamViewer {
    $Paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($p in $Paths) {
        Get-ItemProperty -Path $p | 
            Where-Object { $_.DisplayName -match 'TeamViewer' } |
            Select-Object DisplayName, DisplayVersion, UninstallString, QuietUninstallString
    }
}

function Invoke-MSIUninstall {
    param([string]$Guid)
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $Guid /qn /norestart" -Wait -PassThru -WindowStyle Hidden
    return $p.ExitCode
}

function Invoke-ExeUninstall {
    param([string]$UninstallString)
    $exe = $null; $args = $null
    
    if ($UninstallString -match '^\s*"(.*?)"\s*(.*)$') { $exe=$matches[1]; $args=$matches[2] }
    elseif ($UninstallString -match '^\s*([^\s]+)\s*(.*)$') { $exe=$matches[1]; $args=$matches[2] }
    else { return 1 }

    if ($args -notmatch '(?i)/S|/silent|/verysilent|/qn') { $args = ("$args /S").Trim() }

    $p = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if (-not $p) { return 1 }
    return $p.ExitCode
}

# ==============================================================================
# STEP 1A – PATIENT WAIT LOOP (Toggled)
# ==============================================================================
if ($WaitIfActive) {
    $maxWaitMinutes = 45
    $timer = [Diagnostics.Stopwatch]::StartNew()
    
    # We purposely DO NOT check 'TeamViewer_Service' here because it runs 24/7.
    # We only wait if the user UI is open or an active session (tv_w32/tv_x64) is running.
    $sessionProcesses = @("TeamViewer", "tv_w32", "tv_x64")

    Write-Output "Checking for active TeamViewer user sessions..."
    
    while ($true) {
        $isActive = $false
        foreach ($proc in $sessionProcesses) {
            if (Get-Process -Name $proc) {
                $isActive = $true
                break
            }
        }

        if (-not $isActive) {
            Write-Output "No active UI or remote sessions found. Proceeding..."
            break
        }

        if ($timer.Elapsed.TotalMinutes -ge $maxWaitMinutes) {
            Write-Output "WARN: Active TeamViewer session detected for over $maxWaitMinutes minutes."
            Write-Output "Deferring uninstall (Exit 1618) to prevent dropping a remote connection."
            $timer.Stop()
            exit 1618
        }

        Write-Output "TeamViewer session active. Waiting 60 seconds..."
        Start-Sleep -Seconds 60
    }
    $timer.Stop()
}

# ==============================================================================
# STEP 1B – PROCESS MURDER (Must happen before uninstall)
# ==============================================================================
Write-Output "Terminating all TeamViewer processes to unlock files..."

# We kill everything here, including the 24/7 background service
$tvProcesses = @("TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64")

foreach ($procName in $tvProcesses) {
    $running = Get-Process -Name $procName
    if ($running) {
        Write-Output "Found active process: $procName. Terminating..."
        Stop-Process -Name $procName -Force
        Start-Sleep -Seconds 1
        
        # Scorched Earth fallback if it resisted
        if (Get-Process -Name $procName) {
            Write-Output "Process resisted. Executing taskkill..."
            & taskkill.exe /IM "$($procName).exe" /F /T
        }
    }
}
Start-Sleep -Seconds 3 # Give OS time to fully release file locks

# ==============================================================================
# STEP 2 – UNINSTALL TARGETS
# ==============================================================================
$failed = $false
$installed = @(Get-InstalledTeamViewer)

if ($installed.Count -gt 0) {
    Write-Output "Installed TeamViewer entries found. Beginning uninstalls..."
    
    foreach ($app in $installed) {
        $cmd = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { $app.UninstallString }
        if (-not $cmd) { 
            Write-Output "WARN: Uninstall string missing for $($app.DisplayName)"
            $failed = $true
            continue 
        }

        # Extract MSI GUID if present
        $guid = $null
        $m = [regex]::Match($cmd, '\{[0-9A-Fa-f\-]{36}\}')
        if ($m.Success) { $guid = $m.Value }

        if ($guid) {
            Write-Output "Removing (MSI): $($app.DisplayName) [$guid]"
            $code = Invoke-MSIUninstall $guid
        } else {
            Write-Output "Removing (EXE): $($app.DisplayName)"
            $code = Invoke-ExeUninstall $cmd
        }

        Write-Output " -> ExitCode: $code"
        # 1605 = "This action is only valid for products that are currently installed" (Ignore)
        if ($code -ne 0 -and $code -ne 3010 -and $code -ne 1605) { $failed = $true }
    }
} else {
    Write-Output "No installed TeamViewer registry entries found."
}

# ==============================================================================
# STEP 3 – PORTABLE EXE CLEANUP (Toggled via variable)
# ==============================================================================
if ($CleanPortableEXEs) {
    Write-Output "Sweeping user profiles for portable EXEs..."
    $UserPaths = @(
      "$env:SystemDrive\Users\*\Downloads",
      "$env:SystemDrive\Users\*\Desktop",
      "$env:SystemDrive\Users\*\AppData\Local\Temp"
    )
    foreach ($base in $UserPaths) {
      Get-ChildItem -Path $base -Recurse -Include "*TeamViewer*.exe" | ForEach-Object {
          Write-Output "Deleting Portable EXE: $($_.FullName)"
          Remove-Item -LiteralPath $_.FullName -Force
      }
    }
}

# ==============================================================================
# STEP 4 – POST-CHECK VALIDATION
# ==============================================================================
$remainingInstalled = @(Get-InstalledTeamViewer)
$remainingRunning = Get-Process -Name "TeamViewer"

if ($remainingInstalled.Count -gt 0 -or $remainingRunning -or $failed) {
    Write-Output "ERROR: TeamViewer footprint remains on the device, or an uninstaller threw an error."
    exit 1
}

Write-Output "SUCCESS: TeamViewer has been completely eradicated."
exit 0