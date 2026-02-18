<#
.SYNOPSIS
    Installs/Updates Google Chrome using Winget.
    Logic: Tries 'Upgrade' first. If Winget doesn't see Chrome, it runs 'Install' to force it.
#>
$ErrorActionPreference = 'Stop'

function Get-WingetPath {
    # Check standard alias
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) { return $winget.Source }

    # Fallback for SYSTEM context
    $vlibs = Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
    if ($vlibs) {
        foreach ($folder in $vlibs) {
            $exe = Join-Path $folder.FullName "winget.exe"
            if (Test-Path $exe) { return $exe }
        }
    }
    return $null
}

try {
    Write-Output "STARTING: Locating Winget..."
    $wingetPath = Get-WingetPath
    
    if (-not $wingetPath) {
        Write-Output "FAILED: Winget not found."
        exit 1
    }
    
    Write-Output "FOUND: $wingetPath"
    
    # Common arguments for both attempts
    # We use '--source winget' to avoid Store certificate issues
    $argsBase = "--id Google.Chrome --source winget --exact --silent --accept-source-agreements --accept-package-agreements --disable-interactivity --force"

    # --- ATTEMPT 1: UPGRADE ---
    Write-Output "ATTEMPT 1: Winget UPGRADE..."
    $proc = Start-Process -FilePath $wingetPath -ArgumentList "upgrade $argsBase" -PassThru -Wait -NoNewWindow

    # Exit Code -1978335212 (0x8A150014) means "No installed package found"
    if ($proc.ExitCode -eq -1978335212) {
        Write-Output "WARNING: Winget cannot find an existing managed package to upgrade."
        Write-Output "ATTEMPT 2: Winget INSTALL (Force Overwrite)..."
        
        # --- ATTEMPT 2: INSTALL ---
        $proc = Start-Process -FilePath $wingetPath -ArgumentList "install $argsBase" -PassThru -Wait -NoNewWindow
    }

    # --- FINAL CHECK ---
    if ($proc.ExitCode -eq 0) {
        Write-Output "SUCCESS: Winget operation completed."
        exit 0
    }
    elseif ($proc.ExitCode -eq 2316632065) { # "No update available"
        Write-Output "SUCCESS: No update needed (Already on latest)."
        exit 0
    }
    else {
        Write-Output "FAILED: Winget exited with code $($proc.ExitCode)"
        exit 1
    }
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}