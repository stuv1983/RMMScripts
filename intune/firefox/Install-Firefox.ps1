<#
.SYNOPSIS
    Mozilla Firefox Phase 2 Surgical Remediation & Sanitization
.DESCRIPTION
    Executes a smart migration from unmanaged/32-bit Firefox to Enterprise 64-bit MSI.
    - Synchronously deploys the MSI over existing installs if the version falls below the security floor.
    - Purges AppData Shadow IT binaries (Protects User Data).
    - Respects native profiles.ini Default=1 flags before mapping to Enterprise hashes.
    - Includes a 45-minute "Patient Process Gate" to avoid interrupting active users.
#>

$ErrorActionPreference = "Stop"
$MsiName = "Firefox Setup 148.0.msi" 
$FirefoxSystem64 = "C:\Program Files\Mozilla Firefox\firefox.exe"
$FirefoxSystem86 = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
$MinimumVersion = [version]"148.0" 

$NeedsCleanup = $false
$NeedsMSI = $false

# ------------------------------------------------------------------------
# CORE FUNCTIONS
# ------------------------------------------------------------------------
function Rebind-FirefoxProfiles {
    Write-Output "[Migration] --- PHASE 2B: SMART PROFILE REBINDING ---"
    $users = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $ffAppData = "$($u.FullName)\AppData\Roaming\Mozilla\Firefox"
        $profilesDir = "$ffAppData\Profiles"
        $installsIni = "$ffAppData\installs.ini"
        $profilesIni = "$ffAppData\profiles.ini"

        if (-not (Test-Path -LiteralPath $profilesIni) -or -not (Test-Path -LiteralPath $profilesDir)) { continue }

        $activeProfilePath = ""
        $iniContent = Get-Content -LiteralPath $profilesIni -ErrorAction SilentlyContinue

        # 1A. METHOD A: Trust the native profiles.ini user choice
        $isProfileBlock = $false
        $tempPath = ""
        foreach ($line in $iniContent) {
            if ($line -match "^\[Profile") { $isProfileBlock = $true; $tempPath = "" }
            elseif ($line -match "^\[") { $isProfileBlock = $false }
            
            if ($isProfileBlock) {
                if ($line -match "^Path=(.*)") { $tempPath = $matches[1].Trim() -replace '\\','/' }
                if ($line -match "^Default=1" -and $tempPath) {
                    $activeProfilePath = $tempPath
                    Write-Output " -> Native default profile discovered: $activeProfilePath"
                    break
                }
            }
        }

        # 1B. METHOD B: Fallback to places.sqlite timestamp if native parsing fails
        if (-not $activeProfilePath) {
            Write-Output " -> No native default found. Falling back to timestamp heuristics..."
            $latestTime = [datetime]::MinValue
            $profDirs = Get-ChildItem -Path $profilesDir -Directory -ErrorAction SilentlyContinue
            
            foreach ($pd in $profDirs) {
                $dbFile = Join-Path -Path $pd.FullName -ChildPath "places.sqlite"
                if (Test-Path -LiteralPath $dbFile) {
                    $lastWrite = (Get-Item -LiteralPath $dbFile).LastWriteTime
                    if ($lastWrite -gt $latestTime) {
                        $latestTime = $lastWrite
                        $activeProfilePath = "Profiles/$($pd.Name)"
                    }
                }
            }
            if (-not $activeProfilePath -and $profDirs) { $activeProfilePath = "Profiles/$($profDirs[0].Name)" }
        }

        if (-not $activeProfilePath) { continue }
        Write-Output " -> Target active profile locked as: $activeProfilePath"

        # 2. Clear installs.ini cache
        if (Test-Path -LiteralPath $installsIni) { Remove-Item -LiteralPath $installsIni -Force -ErrorAction SilentlyContinue }

        # 3. Safely rebuild profiles.ini
        $newIniContent = @()
        $skipInstallBlock = $false
        $hasGeneral = $false
        $hasStartWithLast = $false

        foreach ($line in $iniContent) {
            if ($line -match "^\[Install") { $skipInstallBlock = $true; continue }
            if ($line -match "^\[" -and $line -notmatch "^\[Install") { $skipInstallBlock = $false }
            
            if (-not $skipInstallBlock) { 
                if ($line -match "^\[General\]") { $hasGeneral = $true }
                if ($line -match "^StartWithLastProfile=") { 
                    $newIniContent += "StartWithLastProfile=1"
                    $hasStartWithLast = $true
                    continue
                }
                # Strip existing false Default=1 lines from old blocks
                if ($line -match "^Default=1" -and $line -notmatch "^\[General\]") { continue }
                $newIniContent += $line 
            }
        }

        # Ensure [General] has StartWithLastProfile=1
        if (-not $hasStartWithLast) {
            $injected = @()
            foreach ($l in $newIniContent) {
                $injected += $l
                if ($l -match "^\[General\]") { $injected += "StartWithLastProfile=1" }
            }
            if (-not $hasGeneral) {
                $injected = @("[General]", "StartWithLastProfile=1", "Version=2", "") + $injected
            }
            $newIniContent = $injected
        }

        # Inject Default=1 specifically into our active profile block
        $finalIni = @()
        foreach ($line in $newIniContent) {
            $finalIni += $line
            if ($line -match "^Path=(.*)") {
                if ($matches[1].Trim() -replace '\\','/' -eq $activeProfilePath -replace '\\','/') {
                    $finalIni += "Default=1"
                }
            }
        }

        # Clean up trailing blank lines before appending hashes
        while ($finalIni.Count -gt 0 -and [string]::IsNullOrWhiteSpace($finalIni[-1])) {
            $finalIni = $finalIni[0..($finalIni.Count - 2)]
        }

        # Inject the static Mozilla Installation Hashes
        $finalIni += ""
        $finalIni += "[Install308046B0AF4A39CB]"
        $finalIni += "Default=$activeProfilePath"
        $finalIni += "Locked=1"
        $finalIni += ""
        $finalIni += "[Install8216C80C92C4E828]"
        $finalIni += "Default=$activeProfilePath"
        $finalIni += "Locked=1"

        # RAW .NET WRITER: Saves as UTF-8 without the BOM to prevent Firefox crashes
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllLines($profilesIni, $finalIni, $utf8NoBom)

        Write-Output " -> Successfully bound Enterprise MSI to $activeProfilePath for $($u.Name)"
    }
}

# ------------------------------------------------------------------------
# 1. EVALUATE REMEDIATION REQUIREMENTS
# ------------------------------------------------------------------------
Write-Output "=== Starting Mozilla Firefox Phase 2 Remediation ==="
Write-Output "[Check] Evaluating remediation scope..."

if (Test-Path $FirefoxSystem86) { 
    Write-Output " -> Flagged: 32-bit architecture found."
    $NeedsCleanup = $true; $NeedsMSI = $true 
}

$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

foreach ($Profile in $UserProfiles) {
    if (Test-Path (Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox\firefox.exe")) { 
        Write-Output " -> Flagged: Unmanaged AppData binary found in $($Profile.Name)."
        $NeedsCleanup = $true; break 
    }
}

if (-not (Test-Path $FirefoxSystem64)) { 
    Write-Output " -> Flagged: 64-bit System application is missing."
    $NeedsMSI = $true 
}

if (Test-Path $FirefoxSystem64) {
    $CurrentVersion = [version](Get-Item $FirefoxSystem64).VersionInfo.ProductVersion
    if ($CurrentVersion -lt $MinimumVersion) {
        Write-Output " -> Flagged: Firefox version ($CurrentVersion) is below floor ($MinimumVersion)."
        $NeedsMSI = $true
    }
}

# ------------------------------------------------------------------------
# 2. SILENT SERVICE REPAIR
# ------------------------------------------------------------------------
Write-Output "[Check] Evaluating Mozilla Maintenance Service health..."
$MaintenanceService = Get-Service -Name "MozillaMaintenance" -ErrorAction SilentlyContinue

if ($null -ne $MaintenanceService -and $MaintenanceService.StartType -eq 'Disabled') {
    Write-Output "[Repair] Surgical Fix: Re-enabling MozillaMaintenance service back to Manual..."
    Set-Service -Name "MozillaMaintenance" -StartupType Manual 
}

# ------------------------------------------------------------------------
# 3. DESTRUCTIVE FIX / THE GATE / MSI EXECUTION
# ------------------------------------------------------------------------
if ($NeedsCleanup -or $NeedsMSI) {
    Write-Output "[Remediation] Environmental changes required. Entering Patient Process Gate..."
    
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (Get-Process -Name "firefox" -ErrorAction SilentlyContinue) {
        $elapsed = [math]::Round($timer.Elapsed.TotalMinutes, 1)
        Write-Output "   [Wait] Firefox is actively running. Waiting for user to close it (Elapsed: $elapsed / 45 mins)..."
        if ($timer.Elapsed.TotalMinutes -ge 45) { 
            Write-Output "   [Timeout] Maximum wait time reached. Exiting 1618 to defer."
            exit 1618 
        }
        Start-Sleep -Seconds 60
    }
    Write-Output "   [Clear] Firefox is closed. Proceeding."

    if ($NeedsCleanup -or $NeedsMSI) { Rebind-FirefoxProfiles }

    if ($NeedsCleanup) {
        Write-Output "[Cleanup] Removing unmanaged binaries and architecture..."
        foreach ($Profile in $UserProfiles) {
            $AppDir = Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox"
            if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
        if (Test-Path $FirefoxSystem86) { Remove-Item $FirefoxSystem86 -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $ExitCode = 0
    if ($NeedsMSI) {
        Write-Output "[Deployment] Executing Enterprise MSI Installation to forcefully patch device..."
        $msiPath = Join-Path $PSScriptRoot $MsiName
        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" ALLUSERS=1 /qn /norestart" -Wait -PassThru
        $ExitCode = $Process.ExitCode
    } else {
        Write-Output "[Deployment] 64-bit installation is already present and secure. Skipping MSI reinstall."
    }

    # ------------------------------------------------------------------------
    # 4. DESKTOP SANITIZATION & SHORTCUT REWIRING
    # ------------------------------------------------------------------------
    if ($ExitCode -eq 0 -or $ExitCode -eq 3010) {
        Write-Output "[Sanitization] Rewiring shortcuts and cleaning desktop stubs..."
        $shell = New-Object -ComObject WScript.Shell
        $newTarget = $FirefoxSystem64
        $newWorkingDir = Split-Path -Path $newTarget -Parent

        foreach ($Profile in $UserProfiles) {
            $UserDesktop = Join-Path $Profile.FullName "Desktop"
            if (Test-Path $UserDesktop) {
                if (Test-Path (Join-Path $UserDesktop "firefox.exe")) {
                    Remove-Item -Path (Join-Path $UserDesktop "firefox.exe") -Force -ErrorAction SilentlyContinue
                }
                
                $links = Get-ChildItem -Path $UserDesktop -Filter "*.lnk" -File -ErrorAction SilentlyContinue
                foreach ($link in $links) {
                    try {
                        $shortcut = $shell.CreateShortcut($link.FullName)
                        if ($shortcut.TargetPath -match "(?i)Mozilla.*firefox\.exe") {
                            Remove-Item -LiteralPath $link.FullName -Force -ErrorAction SilentlyContinue
                        }
                    } catch {}
                }
            }
        }

        $searchPaths = @(
            "C:\Users\Public\Desktop\*.lnk", 
            "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk", 
            "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk", 
            "C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk"
        )
        foreach ($link in (Get-ChildItem -Path $searchPaths -ErrorAction SilentlyContinue)) {
            try {
                $shortcut = $shell.CreateShortcut($link.FullName)
                if ($shortcut.TargetPath -match "(?i)Mozilla.*firefox\.exe") {
                    $shortcut.TargetPath = $newTarget
                    $shortcut.WorkingDirectory = $newWorkingDir
                    $shortcut.Save()
                }
            } catch {}
        }
    } else {
        Write-Output "[Error] MSI Failed with Exit Code: $ExitCode"
        exit $ExitCode
    }
} else {
    Write-Output "[Complete] No destructive changes or patching required. Device is compliant."
}

Write-Output "=== Firefox Remediation Completed Successfully ==="
exit 0