<#
.SYNOPSIS
    Mozilla Firefox Lean Remediation (Intune Optimized)
#>

$ErrorActionPreference = "Stop"

# Setup local transcript logging
$LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Start-Transcript -Path "$LogDir\Firefox_LeanRemediation.log" -Append -Force

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# Dynamically find the newest MSI
$MsiFile = Get-ChildItem -Path $ScriptDir -Filter "Firefox Setup*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $MsiFile) {
    Write-Output "[Error] No Firefox MSI found in $ScriptDir."
    Stop-Transcript
    exit 1
}
$MsiPath = $MsiFile.FullName

$Firefox64Exe = "C:\Program Files\Mozilla Firefox\firefox.exe"
$Firefox86Dir = "C:\Program Files (x86)\Mozilla Firefox"
$RoguePaths = @("AppData\Local\Mozilla Firefox", "AppData\Local\Programs\Mozilla Firefox")

Write-Output "=== Starting Firefox Lean Remediation ==="

# 1. THE GATE: Wait for active processes
Write-Output "[Check] Checking for active Firefox processes..."
$timer = [Diagnostics.Stopwatch]::StartNew()
while (Get-Process -Name "firefox" -ErrorAction SilentlyContinue) {
    $elapsed = [math]::Round($timer.Elapsed.TotalMinutes, 1)
    Write-Output "   [Wait] Firefox is actively running (Elapsed: $elapsed / 45 mins)..."
    if ($timer.Elapsed.TotalMinutes -ge 45) { 
        Write-Output "   [Timeout] Exiting 1618 to defer deployment."
        Stop-Transcript
        exit 1618 
    }
    Start-Sleep -Seconds 5
}

# 2. CLEANUP: Purge x86, AppData, and old Desktop/Start Menu Icons
Write-Output "[Cleanup] Scanning for unmanaged binaries..."
if (Test-Path $Firefox86Dir) { 
    Write-Output " -> Removing 32-bit installation directory."
    Remove-Item $Firefox86Dir -Recurse -Force -ErrorAction SilentlyContinue 
    if (Test-Path $Firefox86Dir) {
        Write-Output "[Fatal Error] Failed to remove 32-bit directory."
        Stop-Transcript
        exit 1
    }
}

$UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "NTUSER.DAT") }
foreach ($Profile in $UserProfiles) {
    foreach ($RelativePath in $RoguePaths) {
        $AppDir = Join-Path $Profile.FullName $RelativePath
        if (Test-Path $AppDir) { 
            Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue 
        }
    }
}

$shell = New-Object -ComObject WScript.Shell
$deletePaths = @("C:\Users\*\Desktop\*.lnk", "C:\Users\Public\Desktop\*.lnk", "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk", "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk")
try {
    Get-ChildItem -Path $deletePaths -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($shell.CreateShortcut($_.FullName).TargetPath -match "(?i)firefox\.exe$") {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
} catch {}

# 3. INSTALLATION: Deploy 64-bit Enterprise MSI
Write-Output "[Deployment] Executing Enterprise MSI Installation..."
$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$MsiPath`" ALLUSERS=1 /qn /norestart" -Wait -PassThru

if ($Process.ExitCode -ne 0 -and $Process.ExitCode -ne 3010) {
    Write-Output "[Error] MSI Failed with Exit Code: $($Process.ExitCode)"
    Stop-Transcript
    exit $Process.ExitCode
}

# 4. SHORTCUT FIX: Redirect broken taskbar pins
Write-Output "[Sanitization] Redirecting Taskbar pins..."
$taskbarPaths = @("C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk")
try {
    Get-ChildItem -Path $taskbarPaths -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $shortcut = $shell.CreateShortcut($_.FullName)
            if ($shortcut.TargetPath -match "(?i)firefox\.exe$") {
                $shortcut.TargetPath = $Firefox64Exe
                $shortcut.WorkingDirectory = "C:\Program Files\Mozilla Firefox"
                $shortcut.Save()
            }
        } catch {}
    }
} catch {}

Write-Output "=== Firefox Installation Script Completed ==="
Stop-Transcript
exit 0