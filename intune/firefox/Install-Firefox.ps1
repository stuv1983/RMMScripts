<#
.SYNOPSIS
  Remediate-Firefox-EnterpriseMigration.ps1
  Installation/Remediation script for Intune Win32 App.
#>

$ErrorActionPreference = "Stop"

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$TargetVersion = [version]"147.0.4"
$MsiName = "Firefox Setup 147.0.4.msi"  

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
function Wait-ForFirefoxToClose {
    Write-Output "--- PHASE 0: PATIENT PROCESS GATE ---"
    $maxWaitMinutes = 45
    $timer = [Diagnostics.Stopwatch]::StartNew()

    Write-Output "Checking if Firefox is actively running..."

    while (Get-Process -Name "firefox" -ErrorAction SilentlyContinue) {
        if ($timer.Elapsed.TotalMinutes -ge $maxWaitMinutes) {
            Write-Output "WARN: Firefox has been open for over $maxWaitMinutes minutes."
            Write-Output "Deferring migration (Exit 1618) to prevent Intune timeout."
            $timer.Stop()
            exit 1618
        }
        Write-Output "Firefox is running. Waiting 60 seconds..."
        Start-Sleep -Seconds 60
    }
    Write-Output "Firefox is closed! Proceeding with migration..."
    $timer.Stop()
}

function Remove-PerUserFirefoxBinaries {
    Write-Output "--- PHASE 1: SURGICAL PER-USER CLEANUP ---"
    $users = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue
    
    foreach ($u in $users) {
        if ($u.Name -match "^(All Users|Default|Default User|Public|WDAGUtilityAccount|Administrator)$") { continue }
        
        $pathsToCheck = @(
            "$($u.FullName)\AppData\Local\Mozilla Firefox",
            "$($u.FullName)\AppData\Local\Mozilla\Firefox",
            "$($u.FullName)\AppData\Local\Firefox"
        )
        
        foreach ($folder in $pathsToCheck) {
            $exe = "$folder\firefox.exe"
            if (Test-Path -LiteralPath $exe) {
                Write-Output ">> Found rogue binary at: $exe"
                $items = Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    # GUARDRAIL: Protect profile caches, crash reports, and telemetry
                    if ($item.Name -match "(?i)^(Profiles|Crash Reports|Pending Pings|Data|Telemetry)$") {
                        Write-Output "   [Protected] User data kept: $($item.Name)"
                        continue
                    }
                    try {
                        Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                        Write-Output "   [Deleted] $($item.Name)"
                    } catch {
                        Write-Output "   [WARN] Could not delete $($item.Name)."
                    }
                }
            }
        }
    }
}

function Fix-FirefoxDowngradeLock {
    Write-Output "--- PHASE 2A: DOWNGRADE LOCK CLEARANCE ---"
    $users = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $profilesDir = "$($u.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path -LiteralPath $profilesDir) {
            $profiles = Get-ChildItem -Path $profilesDir -Directory -ErrorAction SilentlyContinue
            foreach ($prof in $profiles) {
                $compatFile = "$($prof.FullName)\compatibility.ini"
                if (Test-Path -LiteralPath $compatFile) {
                    Remove-Item -LiteralPath $compatFile -Force -ErrorAction SilentlyContinue
                    Write-Output "Cleared downgrade lock for profile: $($prof.Name)"
                }
            }
        }
    }
}

function Rebind-FirefoxProfiles {
    Write-Output "--- PHASE 2B: SMART PROFILE REBINDING ---"
    $users = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue
    foreach ($u in $users) {
        $ffAppData = "$($u.FullName)\AppData\Roaming\Mozilla\Firefox"
        $profilesDir = "$ffAppData\Profiles"
        $installsIni = "$ffAppData\installs.ini"
        $profilesIni = "$ffAppData\profiles.ini"

        if (-not (Test-Path -LiteralPath $profilesIni) -or -not (Test-Path -LiteralPath $profilesDir)) { continue }

        # 1. Identify the ACTUALLY ACTIVE profile by finding the newest places.sqlite database
        $activeProfilePath = ""
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

        # Fallback if places.sqlite doesn't exist
        if (-not $activeProfilePath) {
            foreach ($pd in $profDirs) { $activeProfilePath = "Profiles/$($pd.Name)"; break }
        }

        Write-Output ">> Target active profile identified as: $activeProfilePath"

        # 2. Clear installs.ini
        if (Test-Path -LiteralPath $installsIni) { Remove-Item -LiteralPath $installsIni -Force -ErrorAction SilentlyContinue }

        # 3. Safely rebuild profiles.ini
        $iniContent = Get-Content -LiteralPath $profilesIni
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

        # Inject the static Mozilla Installation Hashes
        $finalIni += ""
        $finalIni += "[Install308046B0AF4A39CB]"
        $finalIni += "Default=$activeProfilePath"
        $finalIni += "Locked=1"
        $finalIni += ""
        $finalIni += "[Install8216C80C92C4E828]"
        $finalIni += "Default=$activeProfilePath"
        $finalIni += "Locked=1"

        $finalIni | Set-Content -LiteralPath $profilesIni -Force
        Write-Output "Successfully bound Enterprise MSI to $activeProfilePath for $($u.Name)"
    }
}

function Remove-Legacy32BitFirefox {
    Write-Output "--- PHASE 3: LEGACY 32-BIT SCRUB ---"
    if ([Environment]::Is64BitOperatingSystem) {
        $x86Path = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Mozilla Firefox"
        $helper = Join-Path -Path $x86Path -ChildPath "uninstall\helper.exe"
        if (Test-Path -LiteralPath $helper) {
            try {
                Start-Process -FilePath $helper -ArgumentList "/S" -Wait -PassThru -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 2 
            } catch {}
        }
        if (Test-Path -LiteralPath (Join-Path -Path $x86Path -ChildPath "firefox.exe")) {
            Remove-Item -LiteralPath $x86Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "Force-removed lingering 32-bit binaries."
        }
    }
}

function Get-FirefoxMsiFileVersion {
    $paths = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") | 
        Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    foreach ($p in $paths) {
        try {
            $v = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion
            if ($v) { return [version]$v }
        } catch {}
    }
    return $null
}

function Get-MsiPath {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    return (Join-Path -Path $scriptDir -ChildPath $MsiName)
}

function Update-FirefoxShortcuts {
    Write-Output "--- PHASE 5: SHORTCUT REMEDIATION ---"
    $shell = New-Object -ComObject WScript.Shell
    $newTarget = if ([Environment]::Is64BitOperatingSystem) { Join-Path -Path $env:ProgramFiles -ChildPath "Mozilla Firefox\firefox.exe" } 
                 else { Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Mozilla Firefox\firefox.exe" }
    $newWorkingDir = Split-Path -Path $newTarget -Parent
    $searchPaths = @("C:\Users\*\Desktop\*.lnk", "C:\Users\Public\Desktop\*.lnk", "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk", "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk")
    
    foreach ($link in (Get-ChildItem -Path $searchPaths -ErrorAction SilentlyContinue)) {
        try {
            $shortcut = $shell.CreateShortcut($link.FullName)
            if ($shortcut.TargetPath -match "(?i)Mozilla.*firefox\.exe") {
                if ($link.FullName -match "(?i)C:\\Users\\[^\\]+\\Desktop\\" -and $link.FullName -notmatch "(?i)C:\\Users\\Public\\") {
                    Remove-Item -LiteralPath $link.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }
                $shortcut.TargetPath = $newTarget
                $shortcut.WorkingDirectory = $newWorkingDir
                $shortcut.Save()
            }
        } catch {}
    }
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
try {
    Write-Output "Starting Firefox Enterprise migration..."
    Wait-ForFirefoxToClose
    Remove-PerUserFirefoxBinaries
    Fix-FirefoxDowngradeLock
    Rebind-FirefoxProfiles
    Remove-Legacy32BitFirefox

    Write-Output "--- PHASE 4: ENTERPRISE MSI DEPLOYMENT ---"
    $installedVersion = Get-FirefoxMsiFileVersion
    if (-not $installedVersion -or $installedVersion -lt $TargetVersion) {
        $sysPath = "$env:ProgramFiles\Mozilla Firefox"
        if (Test-Path -LiteralPath $sysPath) { Remove-Item -LiteralPath $sysPath -Recurse -Force -ErrorAction SilentlyContinue }
        
        $msiPath = Get-MsiPath
        if (-not (Test-Path -LiteralPath $msiPath)) { throw "MSI not found: $msiPath" }

        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" ALLUSERS=1 /qn /norestart" -Wait -PassThru
        if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { throw "MSI failed: $($proc.ExitCode)" }
    }
    Update-FirefoxShortcuts
    Write-Output "Remediation complete."
    exit 0 
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}