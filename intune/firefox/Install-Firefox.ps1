<#
.SYNOPSIS
  Remediate-Firefox-EnterpriseMigration.ps1
  Installation/Remediation script for Intune Win32 App.
.DESCRIPTION
  Actions performed:
  1. Deletes rogue per-user Firefox binaries from AppData.
  2. Scrubs legacy 32-bit System installations if running on a 64-bit OS.
  3. Installs or upgrades the Enterprise MSI system-wide.
  4. Deletes duplicate personal desktop shortcuts.
  5. Rewires Taskbar and Start Menu shortcuts to point to the new Enterprise path.
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
function Get-UserProfileDirs {
    $skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")
    Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $skip -notcontains $_.Name }
}

function Update-FirefoxShortcuts {
    Write-Output "Scanning for per-user Firefox shortcuts to redirect or remove..."
    $shell = New-Object -ComObject WScript.Shell
    
    $newTarget = if ([Environment]::Is64BitOperatingSystem) {
        Join-Path -Path $env:ProgramFiles -ChildPath "Mozilla Firefox\firefox.exe"
    } else {
        Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Mozilla Firefox\firefox.exe"
    }
    $newWorkingDir = Split-Path -Path $newTarget -Parent

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
            
            if ($target -match "(?i)AppData\\Local\\Mozilla.*firefox\.exe" -or $target -match "(?i)Mozilla Firefox\\firefox\.exe") {
                
                # Prevent the "Two Shortcut" bug: Delete personal desktop shortcuts since the MSI makes a Public one
                if ($link.FullName -match "(?i)C:\\Users\\[^\\]+\\Desktop\\" -and $link.FullName -notmatch "(?i)C:\\Users\\Public\\") {
                    Write-Output "Removing duplicate per-user desktop shortcut: $($link.FullName)"
                    Remove-Item -LiteralPath $link.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }

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
                    Write-Output "WARN: Files in $t are locked by a running process. Deferring cleanup."
                    $removedAny = $true
                }
            }
        }
    }
    return $removedAny
}

function Remove-Legacy32BitFirefox {
    if ([Environment]::Is64BitOperatingSystem) {
        $x86Path = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Mozilla Firefox"
        $helper = Join-Path -Path $x86Path -ChildPath "uninstall\helper.exe"
        
        if (Test-Path -LiteralPath $helper) {
            Write-Output "Found legacy 32-bit Firefox. Executing uninstaller silently..."
            try {
                Start-Process -FilePath $helper -ArgumentList "/S" -Wait -PassThru -ErrorAction Stop | Out-Null
                Write-Output "Legacy 32-bit uninstall completed."
                Start-Sleep -Seconds 2 # Allow OS to release file locks
            } catch {
                Write-Output "WARN: Failed to run 32-bit uninstaller."
            }
        }
        
        # Cleanup lingering ghost binaries to satisfy vulnerability scanners
        if (Test-Path -LiteralPath (Join-Path -Path $x86Path -ChildPath "firefox.exe")) {
            Write-Output "Force removing lingering 32-bit binaries..."
            Remove-Item -LiteralPath $x86Path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-FirefoxMsiFileVersion {
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
    # Dynamically locates the unified MSI file next to where the script is running
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    return (Join-Path -Path $scriptDir -ChildPath $MsiName)
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
try {
    Write-Output "Starting Firefox enterprise migration remediation..."

    # 1) Clear out rogue consumer binaries from user profiles
    $perUserRemoved = Remove-PerUserFirefoxBinaries

    # 2) Scrub legacy 32-bit System installs (if applicable)
    Remove-Legacy32BitFirefox

    # 3) Check if the System Version is missing or out of date
    $installedVersion = Get-FirefoxMsiFileVersion
    $needsInstall = (-not $installedVersion -or $installedVersion -lt $TargetVersion)

    # 4) Install or Upgrade the Enterprise MSI
    if ($needsInstall) {
        $msiPath = Get-MsiPath
        if (-not (Test-Path -LiteralPath $msiPath)) { throw "MSI not found: $msiPath" }

        Write-Output "Installing Enterprise MSI: $msiPath"
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" ALLUSERS=1 /qn /norestart" -Wait -PassThru
        Write-Output "MSI exit code: $($proc.ExitCode)"
    } else {
        Write-Output "Enterprise MSI already meets target ($installedVersion >= $TargetVersion)."
    }

    # 5) Clean up duplicates and redirect user pins AFTER the MSI exists
    Update-FirefoxShortcuts

    exit 0 
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}