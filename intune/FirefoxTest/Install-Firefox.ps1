<#
.SYNOPSIS
  Backs up Firefox user data, updates System 64-bit and 32-bit installations 
  using packaged MSIs, and safely removes dormant AppData installations.
#>
$TargetVersion = "147.0.3" 

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue" 

# Point to the MSIs located in the exact same folder as this script
$Installer64 = Join-Path $PSScriptRoot "Firefox Setup 147.0.4-64bit.msi"
$Installer32 = Join-Path $PSScriptRoot "Firefox Setup 147.0.4-32bit.msi"
$GlobalExitCode = 0

Write-Output "Executing Packaged Firefox Enterprise patch sequence..."

# ==============================================================================
# PHASE 1: BACKUP USER DATA (Non-Fatal with Explicit Logging)
# ==============================================================================
$BackupRoot = "C:\temp\FirefoxBackup"
if (-not (Test-Path $BackupRoot)) { New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null }

Write-Output "Initiating pre-update backup of Firefox Profiles..."

if (Test-Path "C:\Users") {
    $Profiles = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($profile in $Profiles) {
        $WinUserName = $profile.Name
        # Firefox stores user data in Roaming, not Local
        $UserDataPath = "$($profile.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"

        if (Test-Path $UserDataPath) {
            $UserBackupDir = "$BackupRoot\$WinUserName"
            if (-not (Test-Path $UserBackupDir)) { New-Item -Path $UserBackupDir -ItemType Directory -Force | Out-Null }
            
            $FFProfiles = Get-ChildItem -Path $UserDataPath -Directory
            
            foreach ($ffp in $FFProfiles) {
                $FFPName = $ffp.Name
                $FFPBackupDir = "$UserBackupDir\$FFPName"
                if (-not (Test-Path $FFPBackupDir)) { New-Item -Path $FFPBackupDir -ItemType Directory -Force | Out-Null }

                # places.sqlite = Bookmarks & History | logins.json = Passwords | key4.db = Password Decryption Key
                $FilesToBackup = @("places.sqlite", "logins.json", "key4.db")
                foreach ($file in $FilesToBackup) {
                    $SourceFile = "$($ffp.FullName)\$file"
                    if (Test-Path $SourceFile) {
                        try { Copy-Item -Path $SourceFile -Destination $FFPBackupDir -Force -ErrorAction Stop } catch { }
                    }
                }
            }
        }
    }
}
Write-Output "Backup phase complete."

# ==============================================================================
# PHASE 2: SYSTEM MSI INSTALL/UPDATE (From Package)
# ==============================================================================
function Update-Instance($exePath, $arch) {
    if (-not (Test-Path $exePath)) { return }
    $LocalVer = (Get-Item $exePath).VersionInfo.ProductVersion
    $CleanLocal = [version]($LocalVer -split '\s+')[0]
    
    if ($CleanLocal -lt [version]$TargetVersion) {
        Write-Output "Updating System Installation at $exePath..."
        
        $setupExe = if ($arch -eq "win64") { $Installer64 } else { $Installer32 }
        
        if (-not (Test-Path $setupExe)) {
            Write-Error "CRITICAL: $setupExe is missing from the Intune package payload!"
            $script:GlobalExitCode = 1
            return
        }
        
        $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$setupExe`" /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -eq 3010) { $script:GlobalExitCode = 3010 } elseif ($p.ExitCode -ne 0) { $script:GlobalExitCode = $p.ExitCode }
    }
}

try {
    # Update existing System installs individually
    Update-Instance -exePath "$env:ProgramFiles\Mozilla Firefox\firefox.exe" -arch "win64"
    Update-Instance -exePath "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe" -arch "win32"

    # If NO System installs exist, lay down the 64-bit baseline
    if (-not (Test-Path "$env:ProgramFiles\Mozilla Firefox\firefox.exe") -and 
        -not (Test-Path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")) {
        
        Write-Output "Deploying 64-bit System MSI baseline..."
        
        if (-not (Test-Path $Installer64)) {
            Write-Error "CRITICAL: $Installer64 is missing from the Intune package payload!"
            $GlobalExitCode = 1
        } else {
            $p = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$Installer64`" /qn /norestart" -Wait -PassThru
            if ($p.ExitCode -eq 3010) { $GlobalExitCode = 3010 } elseif ($p.ExitCode -ne 0) { $GlobalExitCode = $p.ExitCode }
        }
    }

# ==============================================================================
# PHASE 3: SAFE CVE CLEANUP (AppData Remediation)
# ==============================================================================
    Write-Output "Initiating Safe CVE Cleanup for AppData installations..."
    
    $RunningFirefoxPaths = Get-Process firefox -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

    if (Test-Path "C:\Users") {
        $Profiles = Get-ChildItem -Path "C:\Users" -Directory
        foreach ($profile in $Profiles) {
            # Rogue Firefox EXEs install into Local, while the user data is safely in Roaming
            $AppDataAppFolder = "$($profile.FullName)\AppData\Local\Mozilla Firefox"
            $AppDataExe = "$AppDataAppFolder\firefox.exe"
            
            if (Test-Path $AppDataExe) {
                $IsRunning = $RunningFirefoxPaths -contains $AppDataExe
                
                if ($IsRunning) {
                    Write-Warning "Skipping CVE Cleanup for $($profile.Name): Browser is actively running from AppData."
                } else {
                    Write-Output "Removing dormant AppData binaries for $($profile.Name) to clear CVEs..."
                    try {
                        Remove-Item -Path $AppDataAppFolder -Recurse -Force -ErrorAction Stop
                    } catch {
                        Write-Warning "Failed to remove $AppDataAppFolder - $($_.Exception.Message)"
                    }
                }
            }
        }
    }
} 
finally {
    Write-Output "Execution complete."
}

Write-Output "Exiting script with Intune Code: $GlobalExitCode"
exit $GlobalExitCode