<# 
.SYNOPSIS
    Google Chrome Update & Audit Script (Pending Reboot Edition)
    
.DESCRIPTION
    Updates Google Chrome using Winget but prioritizes detecting "Pending Reboot" states.
    Uses Registry checks to see if Chrome has staged an update but hasn't relaunched.
    
.NOTES
    Author:     Stu Villanti
    Email:      stuart.villanti@gmail.com
    Created:    2025-12-10
    Version:    1.4
    
    - Correctly handles Chrome's "staged update" behavior using Registry keys.
    - Displays the pending version number when a reboot is required.
    - Fully commented for RMM auditing and troubleshooting.
#>

# --- CONFIGURATION ---
$ErrorActionPreference = "Stop"   # Stop script execution on any critical error to prevent cascading failures
$ProcessName = "chrome"           # The process name to check for
$ForceClose  = $false             # Set to $true to forcibly kill Chrome if running (Aggressive Mode)

# --- VISUAL HEADERS FOR LOGS ---
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "   CHROME UPDATE & AUDIT TOOL"
Write-Host "==========================================`n" -ForegroundColor Cyan

# --- STEP 1: CHECK PROCESS STATUS ---
# We use a Try/Catch block here because Get-Process throws a hard error if permissions fail or the process query times out.
try {
    $RunningProcess = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
} catch {
    $RunningProcess = $null
}

# --- LOGIC BRANCH: IF CHROME IS RUNNING ---
# Condition: Is the user currently using the browser?
if ($RunningProcess) {
    
    # Capture the version of Chrome currently loaded in RAM (Memory)
    [version]$RunningVersion = $RunningProcess[0].MainModule.FileVersion

    # --- PENDING REBOOT DETECTION (REGISTRY METHOD) ---
    # Chrome sets a flag in the registry when an update is staged but waiting for a restart.
    
    $PendingReboot = $false
    $RegVersion = $null
    
    # {8A69D345...} is the specific AppGUID for Google Chrome Stable
    $RegPath = "HKLM:\SOFTWARE\WOW6432Node\Google\Update\ClientState\{8A69D345-D564-463C-AFF1-A69D9E530F96}"
    
    # Condition: Does the Google Update registry key exist?
    if (Test-Path $RegPath) {
        # Retrieve the 'pv' (Product Version) value from the registry
        $RegVersionStr = (Get-ItemProperty -Path $RegPath -Name "pv" -ErrorAction SilentlyContinue).pv
        
        # Condition: Did we successfully read a version string?
        if ($RegVersionStr) {
            [version]$RegVersion = $RegVersionStr
            
            # Condition: Is the Staged/Registry version newer than the Running Process?
            if ($RegVersion -gt $RunningVersion) {
                $PendingReboot = $true
            }
        }
    }

    # --- ACTION DECISION: PENDING REBOOT DETECTED ---
    # Condition: Is a reboot actually pending based on our registry check?
    if ($PendingReboot) {
         # Condition: Are we in Aggressive Mode ($ForceClose = $true)?
         if ($ForceClose) {
             # Action: Kill the browser so the new version launches immediately
             Write-Host " [!] PENDING REBOOT DETECTED (Target: $RegVersion). Force closing..." -ForegroundColor Magenta
             Stop-Process -Name $ProcessName -Force -ErrorAction SilentlyContinue
         } else {
             # Action: Log the specific version waiting in the wings and exit gracefully
             Write-Host " [!] PENDING REBOOT DETECTED" -ForegroundColor Magenta
             Write-Host "     Running Version:   $RunningVersion"
             Write-Host "     Staged Version:    $RegVersion"
             Write-Host "     Action: Skipped. Chrome needs a relaunch to finish update to $RegVersion." -ForegroundColor Yellow
             Write-Host "`n==========================================" -ForegroundColor Cyan
             Exit 0
         }
    }

    # --- ACTION DECISION: NO REBOOT PENDING ---
    # If we get here, Chrome is running but might just be old (no update staged yet).
    
    # Condition: Are we in Aggressive Mode?
    if ($ForceClose) {
        Write-Host " [!] Chrome is running ($RunningVersion). Force closing..." -ForegroundColor Yellow
        Stop-Process -Name $ProcessName -Force -ErrorAction SilentlyContinue
    }
    else {
        # Default Safe Mode: Just audit the version and skip
        Write-Host " [i] STATUS: Chrome is currently running ($RunningVersion)." -ForegroundColor Yellow
        Write-Host " ... Checking Winget repository for updates ..." -ForegroundColor Gray
        
        $WingetList = winget list --id Google.Chrome --source winget | Out-String
        $WingetLine = $WingetList -split "`n" | Where-Object { $_ -match "Google.Chrome" } | Select-Object -First 1

        # SCENARIO A: Winget reports two versions (Installed vs Available)
        if ($WingetLine -match "(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)") {
            [version]$AvailableWinGet = $matches[2]
            
            # Condition: Is the repository version newer than what we are running?
            if ($AvailableWinGet -gt $RunningVersion) {
                Write-Host " [!] UPDATE AVAILABLE" -ForegroundColor Yellow
                Write-Host "     Current:   $RunningVersion"
                Write-Host "     Available: $AvailableWinGet"
            } else {
                Write-Host " [OK] System is up to date." -ForegroundColor Green
            }
            
        # SCENARIO B: Winget only reports ONE version (Usually means up to date)
        } elseif ($WingetLine -match "(\d+\.\d+\.\d+\.\d+)") {
             [version]$SingleVersion = $matches[1]
             
             # Condition: Is that single version newer than ours? (Rare, but possible if local detection fails)
             if ($SingleVersion -gt $RunningVersion) {
                 Write-Host " [!] UPDATE AVAILABLE" -ForegroundColor Yellow
                 Write-Host "     Current:   $RunningVersion"
                 Write-Host "     Available: $SingleVersion"
             } else {
                 Write-Host " [OK] System is up to date." -ForegroundColor Green
             }
             
        # SCENARIO C: Parsing failed
        } else {
            Write-Host " [?] Could not parse Winget data." -ForegroundColor Gray
            Write-Host "     Raw: $WingetLine"
        }
        
        Write-Host "`n==========================================" -ForegroundColor Cyan
        Exit 0
    }
}

# --- STEP 2: EXECUTE UPDATE (IF CHROME IS NOT RUNNING) ---
# Condition: Check if Winget is accessible in the current path
$winget = Get-Command "winget.exe" -ErrorAction SilentlyContinue

if (-not $winget) {
    Write-Host " [!] Winget not found." -ForegroundColor Red
    Exit 1
}

Write-Host " [i] Chrome is closed. Starting update process..." -ForegroundColor Cyan

# Try/Catch block for the actual update process to handle crashes or execution errors
try {
    $arguments = @("upgrade", "--id", "Google.Chrome", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--include-unknown")
    
    $process = Start-Process -FilePath $winget.Source -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden

    # Switch statement to handle specific Winget exit codes
    switch ($process.ExitCode) {
        0 { 
            # Code 0 = Success
            Write-Host " [OK] SUCCESS: Chrome updated." -ForegroundColor Green 
        }
        231660240 { 
            # Code 231660240 = "No applicable update found" (Already up to date)
            Write-Host " [OK] SUCCESS: No update needed." -ForegroundColor Green 
        }
        default { 
            # Any other code is treated as an error/warning
            Write-Host " [!] ERROR: Winget exit code $($process.ExitCode)" -ForegroundColor Red 
        }
    }
}
catch {
    Write-Host " [!] CRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Exit 0