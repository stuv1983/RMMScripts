<#
.SYNOPSIS
    Remediate-Chrome-EnterpriseMigration.ps1
    Migrates device to managed 64-bit Enterprise Chrome standard (Strict MSI).
.DESCRIPTION
    Actions performed:
    0. Patiently waits up to 45 minutes for the user to close Chrome.
    1. Removes rogue per-user AppData Chrome binaries safely (protecting User Data).
    2. Removes legacy 32-bit system installations.
    3. (SCORCHED EARTH) Force-uninstalls any System-Level Chrome EXEs.
    4. Installs the 64-bit Enterprise MSI.
    5. Redirects all shortcuts to the new MSI path.

    .NOTES
    NAME: Install-Chrome
    AUTHOR: Stu
#>

$ErrorActionPreference = "Stop"

# ==============================================================================
# CONFIGURATION
# ==============================================================================
$TargetVersion = [version]"145.0.7632.110"
$MsiName = "googlechromestandaloneenterprise64.msi"

# ==============================================================================
# PHASE 0: PATIENT PROCESS GATE (Wait for Chrome to close)
# ==============================================================================
$maxWaitMinutes = 45
$timer = [Diagnostics.Stopwatch]::StartNew()

Write-Output "Checking if Chrome is actively running..."

while (Get-Process -Name "chrome" -ErrorAction SilentlyContinue) {
    if ($timer.Elapsed.TotalMinutes -ge $maxWaitMinutes) {
        Write-Output "WARN: Chrome has been open for over $maxWaitMinutes minutes."
        Write-Output "Deferring migration (Exit 1618) to prevent Intune timeout and user disruption."
        $timer.Stop()
        # Exit 1618 tells Intune "Device is busy, retry on next cycle."
        exit 1618
    }
    Write-Output "Chrome is running. Waiting 60 seconds before checking again..."
    Start-Sleep -Seconds 60
}

Write-Output "Chrome is closed! Proceeding with migration..."
$timer.Stop()

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
function Remove-RogueChromeBinaries {
    Write-Output "Scanning for per-user Chrome binaries..."
    $skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")
    $users = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $skip -notcontains $_.Name }

    foreach ($u in $users) {
        # Target ONLY the Application folder, strictly avoiding the \User Data\ directory
        $appPath = Join-Path -Path $u.FullName -ChildPath "AppData\Local\Google\Chrome\Application"
        
        # GUARDRAIL: Ensure we are deleting actual binaries, not an empty or hijacked folder
        $exePath = Join-Path -Path $appPath -ChildPath "chrome.exe"
        
        if (Test-Path -LiteralPath $exePath) {
            Write-Output "Per-user binaries confirmed. Safely removing application folder: $appPath"
            try { 
                Remove-Item -LiteralPath $appPath -Recurse -Force -ErrorAction Stop 
            } 
            catch { 
                Write-Output "WARN: Could not remove $appPath. It may be locked by a background process." 
            }
        }
    }
}

function Remove-SystemExeChrome {
    Write-Output "Hunting for System-Level Chrome EXEs..."
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    # Target Google Chrome installations that lack the MSI flag
    $sysExes = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName -match "^Google Chrome$" -and $_.WindowsInstaller -ne 1 }

    if ($sysExes) {
        foreach ($sysExe in $sysExes) {
            if ($sysExe.UninstallString) {
                Write-Output "Found System-Level EXE install. Ripping it out..."
                $u = $sysExe.UninstallString.Trim()
                
                # Append Chrome's native silent force-uninstall flag if it is missing
                if ($u -notmatch '--force-uninstall') { $u = "$u --force-uninstall" }
                
                try {
                    if ($u.StartsWith('"')) {
                        $exe = $u.Split('"')[1]
                        $args = $u.Substring($u.IndexOf('"',1)+1).Trim()
                        Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
                    } else {
                        $parts = $u.Split(' ',2)
                        $exe = $parts[0]
                        $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                        Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
                    }
                } catch { Write-Output "WARN: Legacy EXE uninstaller failed." }
            }
        }
        # Give the OS 3 seconds to release any lingering file locks
        Start-Sleep -Seconds 3 
    }
}

function Update-ChromeShortcuts {
    Write-Output "Redirecting per-user Chrome shortcuts to MSI path..."
    $shell = New-Object -ComObject WScript.Shell
    $newTarget = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
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
            
            # Match any shortcut pointing to the Chrome executable
            if ($shortcut.TargetPath -match "(?i)Google\\Chrome\\Application\\chrome\.exe") {
                
                # Delete personal desktop duplicates to favor the Public Desktop MSI shortcut
                if ($link.FullName -match "(?i)C:\\Users\\[^\\]+\\Desktop\\" -and $link.FullName -notmatch "(?i)C:\\Users\\Public\\") {
                    Remove-Item -LiteralPath $link.FullName -Force -ErrorAction SilentlyContinue
                    continue
                }

                # Rewire Start Menu, Taskbar, and Public Desktop shortcuts
                $shortcut.TargetPath = $newTarget
                $shortcut.WorkingDirectory = $newWorkingDir
                $shortcut.IconLocation = "$newTarget,0"
                $shortcut.Save()
            }
        } catch {}
    }
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
try {
    Write-Output "Starting Chrome Enterprise migration..."

    # 1) AppData Consumer Cleanup
    Remove-RogueChromeBinaries

    # 2) 32-bit Physical Cleanup (Legacy)
    $x86Path = "${env:ProgramFiles(x86)}\Google\Chrome\Application"
    if (Test-Path -LiteralPath $x86Path) {
        Write-Output "Removing 32-bit system Chrome..."
        Remove-Item -LiteralPath $x86Path -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 3) SCORCHED EARTH - Force uninstall System EXEs
    Remove-SystemExeChrome

    # 4) Install MSI
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $msiPath = Join-Path -Path $scriptDir -ChildPath $MsiName

    if (-not (Test-Path -LiteralPath $msiPath)) { throw "MSI not found at $msiPath" }

    Write-Output "Installing Enterprise MSI..."
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait -PassThru
    Write-Output "MSI exit code: $($proc.ExitCode)"

    # Hard fail the script if the MSI throws an error
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "MSI Installation failed with exit code $($proc.ExitCode)"
    }

    # 5) Fix Shortcuts
    Update-ChromeShortcuts

    Write-Output "Migration complete."
    exit 0
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}