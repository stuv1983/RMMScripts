<#
.SYNOPSIS
  Remediate-Firefox-EnterpriseMigration.ps1
  Installation/Remediation script for Intune Win32 App.
.DESCRIPTION
  Actions performed:
  1. Deletes rogue per-user Firefox binaries from all AppData folders (deferring if locked).
  2. Installs or upgrades the Enterprise MSI system-wide.
  3. Deletes duplicate personal desktop shortcuts.
  4. Rewires Taskbar and Start Menu shortcuts to point to the new Enterprise path.
#>

$ErrorActionPreference = "Stop"

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$TargetVersion = [version]"147.0.4"
$MsiName64 = "Firefox Setup 147.0.4-64bit.msi"
$MsiName32 = "Firefox Setup 147.0.4-32bit.msi"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
function Get-UserProfileDirs {
    # Safely returns all human user profile directories, ignoring default/system accounts
    $skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")
    Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $skip -notcontains $_.Name }
}

function Update-FirefoxShortcuts {
    Write-Output "Scanning for per-user Firefox shortcuts to redirect or remove..."
    $shell = New-Object -ComObject WScript.Shell
    
    # Determine the correct new Program Files path based on OS architecture
    $newTarget = if ([Environment]::Is64BitOperatingSystem) {
        Join-Path -Path $env:ProgramFiles -ChildPath "Mozilla Firefox\firefox.exe"
    } else {
        Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Mozilla Firefox\firefox.exe"
    }
    $newWorkingDir = Split-Path -Path $newTarget -Parent

    # Search paths for potential rogue shortcuts (Desktop, Start Menu, Taskbar)
    $searchPaths = @(
        "C:\Users\*\Desktop\*.lnk",
        "C:\Users\Public\Desktop\*.lnk",
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk",
        "C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk"
    )

    $links = Get-ChildItem -Path $searchPaths -ErrorAction SilentlyContinue
    
    foreach ($link in $links) {
        try {
            $shortcut = $shell.CreateShortcut($link.FullName)
            $target = $shortcut.TargetPath
            
            # Match any shortcut pointing to the old AppData install OR the new MSI install (to fix blank icons)
            if ($target -match "(?i)AppData\\Local\\Mozilla.*firefox\.exe" -or $target -match "(?i)Mozilla Firefox\\firefox\.exe") {
                
                # Prevent the "Two Shortcut" bug: Delete personal desktop shortcuts since the MSI makes a Public one
                if ($link.FullName -match "(?i)C:\\Users\\[^\\]+\\Desktop\\" -and $link.FullName -notmatch "(?i)C:\\Users\\Public\\") {
                    Write-Output "Removing duplicate per-user desktop shortcut: $($link.FullName)"
                    Remove-Item -LiteralPath $link.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }

                # For Taskbar, Start Menu, and the Public Desktop shortcut: Rewire and fix the icon
                Write-Output "Redirecting/Fixing shortcut: $($link.FullName)"
                $shortcut.TargetPath = $newTarget
                $shortcut.WorkingDirectory = $newWorkingDir
                $shortcut.IconLocation = "$newTarget,0"
                $shortcut.Save()
            }
        } catch {}
    }
}

function Remove-PerUserFirefoxBinaries {
    # Scans AppData and silently removes consumer binaries. Leaves Roaming profile data intact.
    $removedAny = $false
    foreach ($p in (Get-UserProfileDirs)) {
        $targets = @(
            (Join-Path -Path $p.FullName -ChildPath "AppData\Local\Mozilla\Firefox"),
            (Join-Path -Path $p.FullName -ChildPath "AppData\Local\Firefox")
        )

        foreach ($t in $targets) {
            if (Test-Path -LiteralPath $t) {
                Write-Output "Attempting to remove per-user Firefox binaries: $t"
                try {
                    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction Stop
                    $removedAny = $true
                }
                catch {
                    # Silent Deferral: If the user has Firefox open, we don't force close. 
                    # We catch the locked-file error and defer deletion to the next Intune cycle.
                    Write-Output "WARN: Files in $t are locked by a running process. Deferring cleanup."
                    $removedAny = $true
                }
            }
        }
    }
    return $removedAny
}

function Get-FirefoxMsiFileVersion {
    # Reads the physical version of the executable in Program Files
    $paths = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    foreach ($p in $paths) {
        try {
            $v = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion
            if ($v) { return [version]$v }
        } catch {}
    }
    return $null
}

function Get-MsiPath {
    # Dynamically locates the MSI file next to where the script is running
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $name = if ([Environment]::Is64BitOperatingSystem) { $MsiName64 } else { $MsiName32 }
    return (Join-Path -Path $scriptDir -ChildPath $name)
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
try {
    Write-Output "Starting Firefox enterprise migration remediation..."

    # 1) Clear out rogue consumer binaries from user profiles
    $perUserRemoved = Remove-PerUserFirefoxBinaries

    # 2) Check if the System Version is missing or out of date
    $installedVersion = Get-FirefoxMsiFileVersion
    $needsInstall = (-not $installedVersion -or $installedVersion -lt $TargetVersion)

    # 3) Install or Upgrade the Enterprise MSI
    if ($needsInstall) {
        $msiPath = Get-MsiPath
        if (-not (Test-Path -LiteralPath $msiPath)) { throw "MSI not found: $msiPath" }

        Write-Output "Installing Enterprise MSI: $msiPath"
        # /i = install, ALLUSERS=1 = System-wide, /qn = silent, /norestart = suppress reboots
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" ALLUSERS=1 /qn /norestart" -Wait -PassThru
        Write-Output "MSI exit code: $($proc.ExitCode)"
    } else {
        Write-Output "Enterprise MSI already meets target ($installedVersion >= $TargetVersion)."
    }

    # 4) Clean up duplicates and redirect user pins AFTER the MSI exists
    Update-FirefoxShortcuts

    # Exit cleanly to Intune
    exit 0 
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    # Exit 1 tells Intune the installation failed
    exit 1
}