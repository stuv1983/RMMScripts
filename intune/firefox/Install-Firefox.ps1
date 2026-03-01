<#
.SYNOPSIS
    Mozilla Firefox Phase 2 Surgical Remediation & Profile Rebinding
.DESCRIPTION
    Executes a smart migration. Removes AppData binaries but maps the user's 
    existing history and bookmarks to the new Enterprise MSI installation.
#>

$ErrorActionPreference = "Stop"
$MsiName = "Firefox Setup Enterprise.msi"
$FirefoxSystem64 = "C:\Program Files\Mozilla Firefox\firefox.exe"
$FirefoxSystem86 = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
$NeedsDestructiveFix = $false

# ------------------------------------------------------------------------
# 1. EVALUATE DESTRUCTIVE FIX REQUIREMENT
# ------------------------------------------------------------------------
if (Test-Path $FirefoxSystem86) { $NeedsDestructiveFix = $true }
$ExcludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
$UserProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin $ExcludedProfiles }

foreach ($Profile in $UserProfiles) {
    if (Test-Path (Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox\firefox.exe")) { 
        $NeedsDestructiveFix = $true; break 
    }
}
if (-not (Test-Path $FirefoxSystem64)) { $NeedsDestructiveFix = $true }

# ------------------------------------------------------------------------
# 2. SILENT SERVICE REPAIR (No Process Gate Required)
# ------------------------------------------------------------------------
$MaintenanceService = Get-Service -Name "MozillaMaintenance" -ErrorAction SilentlyContinue
if ($null -ne $MaintenanceService -and $MaintenanceService.StartType -eq 'Disabled') {
    Write-Output "Surgical Fix: Re-enabling MozillaMaintenance service back to Manual..."
    Set-Service -Name "MozillaMaintenance" -StartupType Manual 
}

# ------------------------------------------------------------------------
# 3. DESTRUCTIVE FIX / PROFILE REBINDING / MSI EXECUTION
# ------------------------------------------------------------------------
if ($NeedsDestructiveFix) {
    
    # Patient Process Gate
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (Get-Process -Name "firefox" -ErrorAction SilentlyContinue) {
        if ($timer.Elapsed.TotalMinutes -ge 45) { 
            Write-Output "Timeout reached. Exiting 1618 to defer to next Intune sync."
            exit 1618 
        }
        Start-Sleep -Seconds 60
    }

    # Smart Profile Rebinding Logic: Finds the most recently used profile database
    foreach ($u in $UserProfiles) {
        $ffAppData = "$($u.FullName)\AppData\Roaming\Mozilla\Firefox"
        $profilesDir = "$ffAppData\Profiles"
        $profilesIni = "$ffAppData\profiles.ini"
        
        if (Test-Path $profilesIni -and (Test-Path $profilesDir)) {
            $activeProfilePath = ""
            $latestTime = [datetime]::MinValue
            $profDirs = Get-ChildItem -Path $profilesDir -Directory -ErrorAction SilentlyContinue
            
            # Locate the newest places.sqlite to identify the active user profile
            foreach ($pd in $profDirs) {
                $dbFile = Join-Path $pd.FullName "places.sqlite"
                if (Test-Path $dbFile) {
                    $lastWrite = (Get-Item $dbFile).LastWriteTime
                    if ($lastWrite -gt $latestTime) {
                        $latestTime = $lastWrite
                        $activeProfilePath = "Profiles/$($pd.Name)"
                    }
                }
            }
            if (-not $activeProfilePath -and $profDirs) { $activeProfilePath = "Profiles/$($profDirs[0].Name)" }

            # Inject the Enterprise MSI Installation Hashes to lock the profile
            if ($activeProfilePath) {
                Write-Output "Binding $($u.Name) to target Enterprise profile $activeProfilePath..."
                $finalIni = @("[General]", "StartWithLastProfile=1", "Version=2", "")
                $finalIni += "[Install308046B0AF4A39CB]", "Default=$activeProfilePath", "Locked=1", ""
                $finalIni += "[Install8216C80C92C4E828]", "Default=$activeProfilePath", "Locked=1"
                $finalIni | Set-Content $profilesIni -Force
            }
        }
    }

    # Nuke AppData & x86 Directories (Binaries only, keeps \Roaming intact)
    foreach ($Profile in $UserProfiles) {
        $AppDir = Join-Path $Profile.FullName "AppData\Local\Mozilla Firefox"
        if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path $FirefoxSystem86) { Remove-Item $FirefoxSystem86 -Recurse -Force -ErrorAction SilentlyContinue }

    # Execute MSI
    $msiPath = Join-Path $PSScriptRoot $MsiName
    Write-Output "Executing MSI Deployment..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" ALLUSERS=1 /qn /norestart" -Wait
}

Write-Output "Firefox Remediation Complete."
exit 0