#requires -version 5.1
<#
.SYNOPSIS
  Automated Windows Disk Cleanup (CleanMgr) for RMM - Zero UI (Session 0).
  Includes custom cleanup for per-user AppData\Local\Temp directories.

  .NOTES
    Name:       DiskCleanup.ps1
    Author:     Stu Villanti
    Version:    3.1
    
.DESCRIPTION
  - Configures Disk Cleanup categories via registry StateFlags.
  - Runs cleanmgr.exe via a temporary Scheduled Task as SYSTEM.
  - Empties C:\Users\*\AppData\Local\Temp for all profiles.
  - Forces execution in Session 0, guaranteeing NO UI is shown to the user.
  - Includes self-cleanup of tasks and timeout logic.

.PARAMETER Mode
  "test", "check", or "dryrun" to simulate execution without deleting files.
#>

[CmdletBinding()]
param(
    [string]$Mode = ""
)

# ----------------------------
# 1. Environment & Safety Checks
# ----------------------------

$RunId = [guid]::NewGuid().ToString('N')
$ErrorActionPreference = 'Stop'

$CheckOnly = $false
if ($Mode -match '^(test|check|dryrun)$') { $CheckOnly = $true }

# Force 64-bit PowerShell
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $sysnativePS = Join-Path $env:WINDIR 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $sysnativePS) {
        $scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        if ($Mode) { $scriptArgs += "-Mode"; $scriptArgs += $Mode }
        
        & $sysnativePS @scriptArgs
        exit $LASTEXITCODE
    }
}

# --- Configuration ---
$ProfileId = 191
$Categories = @(
    'Temporary Files', 'Temporary Setup Files', 'Recycle Bin', 
    'Windows Error Reporting Files', 'System error memory dump files', 
    'System error minidump files', 'DirectX Shader Cache', 
    'Update Cleanup', 'Device Driver Packages', 'Old ChkDsk Files', 
    'Setup Log Files', 'Thumbnail Cache'
)

# --- Helper Functions ---

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "$ts [$Level] [RunId=$RunId] $Message"
}

function Format-Bytes {
    param([double]$Bytes)
    $units = @('B','KB','MB','GB','TB')
    $i = 0
    while ($Bytes -ge 1024 -and $i -lt 4) { $Bytes /= 1024; $i++ }
    "{0:N2} {1}" -f $Bytes, $units[$i]
}

function Get-DiskFreeSnapshot {
    $snap = @{}
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $snap[$_.DeviceID] = [pscustomobject]@{
            Drive = $_.DeviceID; Free = $_.FreeSpace; Size = $_.Size
        }
    }
    return $snap
}

function Set-CleanMgrRegistry {
    Write-Log "Configuring Registry for CleanMgr (Profile $ProfileId)..."
    $root = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    $available = Get-ChildItem $root -ErrorAction Stop
    $stateName = "StateFlags{0:D4}" -f $ProfileId

    foreach ($cat in $available) {
        if ($Categories -contains $cat.PSChildName) {
            if ($CheckOnly) { Write-Log "[DRYRUN] Would ENABLE: $($cat.PSChildName)" }
            else { New-ItemProperty -Path $cat.PSPath -Name $stateName -PropertyType DWord -Value 2 -Force | Out-Null }
        } elseif (-not $CheckOnly) {
            Remove-ItemProperty -Path $cat.PSPath -Name $stateName -ErrorAction SilentlyContinue
        }
    }
}

function Clear-UserTempFolders {
    Write-Log "Starting cleanup of User AppData\Local\Temp folders..."
    $userRoot = 'C:\Users'
    $skipProfiles = @('Default', 'Default User', 'Public', 'All Users')
    
    $profiles = Get-ChildItem -Path $userRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $skipProfiles -notcontains $_.Name }
    
    $totalFreedBytes = 0
    
    foreach ($p in $profiles) {
        $tempPath = Join-Path $p.FullName 'AppData\Local\Temp'
        if (Test-Path $tempPath) {
            if ($CheckOnly) {
                Write-Log "[DRYRUN] Would clean: $tempPath"
            } else {
                # Calculate size before deletion
                $beforeSize = (Get-ChildItem -Path $tempPath -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                
                # Delete contents (ignoring locked files gracefully)
                Get-ChildItem -Path $tempPath -Force -ErrorAction SilentlyContinue | 
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                
                # Calculate size after deletion
                $afterSize = (Get-ChildItem -Path $tempPath -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                
                $freed = $beforeSize - $afterSize
                if ($freed -gt 0) {
                    $totalFreedBytes += $freed
                    Write-Log "Freed $(Format-Bytes $freed) from $($p.Name)'s Temp folder."
                }
            }
        }
    }
    
    if (-not $CheckOnly -and $totalFreedBytes -gt 0) {
        Write-Log "Total freed from User Temp folders: $(Format-Bytes $totalFreedBytes)"
    } elseif (-not $CheckOnly) {
        Write-Log "No user temp files could be cleared (files may be locked or already clean)."
    }
}

function Invoke-CleanMgrHidden {
    param(
        [string]$CleanMgrPath,
        [int]$ProfileId,
        [int]$TimeoutSeconds = 3600
    )

    Get-ScheduledTask | Where-Object TaskName -like 'DiskCleanup-RMM-*' | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    $taskName = "DiskCleanup-RMM-$([guid]::NewGuid().ToString('N'))"
    $mgrArgs  = "/SAGERUN:$ProfileId"

    Write-Log "Creating Hidden Scheduled Task (SYSTEM/Session 0): $taskName"
    
    $action    = New-ScheduledTaskAction -Execute $CleanMgrPath -Argument $mgrArgs
    $trigger   = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(5))
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds) -StartWhenAvailable -AllowStartIfOnBatteries

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    
    try {
        Start-ScheduledTask -TaskName $taskName
        Write-Log "Task started. Waiting for completion (Max ${TimeoutSeconds}s)..."

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 10
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            
            if ($info.TaskState -ne 'Running') {
                return $info.LastTaskResult
            }
        }
        throw "Timeout: CleanMgr took longer than $TimeoutSeconds seconds."
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Task cleanup complete."
    }
}

# --- Main Execution ---
$mutex = New-Object System.Threading.Mutex($false, "Global\DiskCleanup-RMM")
if (-not $mutex.WaitOne(1000)) { Write-Log "Script already running." "WARN"; exit 0 }

try {
    Write-Log "==== Starting Disk Cleanup Automation ===="
    
    $before = Get-DiskFreeSnapshot
    $before.Values | ForEach-Object { Write-Log "Drive $($_.Drive): $(Format-Bytes $_.Free) Free" }

    # 1. Clean User Temp Folders first
    Clear-UserTempFolders

    # 2. Configure and run CleanMgr for System tasks
    Set-CleanMgrRegistry

    $cleanmgr = Join-Path $env:SystemRoot 'System32\cleanmgr.exe'
    
    if ($CheckOnly) {
        Write-Log "[DRYRUN] Skipping actual CleanMgr execution."
    } else {
        $res = Invoke-CleanMgrHidden -CleanMgrPath $cleanmgr -ProfileId $ProfileId
        Write-Log "CleanMgr execution finished. Exit Code: $res"
    }

    $after = Get-DiskFreeSnapshot
    foreach ($k in $after.Keys) {
        $b = $before[$k]; $a = $after[$k]
        if ($b -and $a) {
            $delta = $a.Free - $b.Free
            $sign = if ($delta -ge 0) {"+"} else {"-"}
            Write-Log "Drive $k Result: $(Format-Bytes $a.Free) Free (Total Space Reclaimed: $sign$(Format-Bytes ([math]::Abs($delta))))"
        }
    }
}
catch {
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" "ERROR"
    exit 1
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}