<#
.SYNOPSIS
    Hardened TeamViewer Removal 
.DESCRIPTION
    Forcibly removes all TeamViewer footprints, cleans up orphan services,
    and wipes per-user AppData to prevent detection loops.
#>

# Restore error visibility to ensure failures are logged in Intune/RMM
$ErrorActionPreference = "Continue" 

# --- CONFIGURATION TOGGLES ---
$WaitIfActive = $true       # Set to $true to delay if a remote session is active
$CleanPortableEXEs = $false  # Set to $true to hunt/delete portable EXEs in Downloads/Desktop
$rebootRequired = $false
$failed = $false

# --- STEP 0: WORKSTATION GUARDRAIL ---
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if (-not $os -or $os.ProductType -ne 1) { 
    Write-Output "Target is not a workstation. Aborting uninstall for safety."
    exit 0 
}

# --- STEP 1A: OPTIONAL WAIT LOOP ---
if ($WaitIfActive) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    # We only wait for UI/Session processes, not the background service
    while ((Get-Process -Name "TeamViewer","tv_w32","tv_x64" -ErrorAction SilentlyContinue)) {
        if ($timer.Elapsed.TotalMinutes -ge 45) { 
            Write-Output "Wait limit reached. Exiting for Intune retry."
            exit 1618 
        }
        Start-Sleep -Seconds 60
    }
}

# --- STEP 1B: PROCESS & SERVICE TERMINATION ---
# Services must be stopped first to release file locks on the binaries.
Write-Output "Stopping all TeamViewer services and killing processes..."
Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue 

$tvProcs = @("TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64")
foreach ($p in $tvProcs) {
    if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
        Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        # taskkill fallback handles processes that resist standard Stop-Process signals
        if (Get-Process -Name $p -ErrorAction SilentlyContinue) { & taskkill.exe /IM "$p.exe" /F /T 2>$null }
    }
}

# --- STEP 2: REGISTRY UNINSTALLATION ---
$regPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$apps = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "^TeamViewer\b" }

foreach ($app in $apps) {
    $cmd = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { $app.UninstallString }
    if (-not $cmd) { $failed = $true; continue }

    try {
        $guidMatch = [regex]::Match($cmd, '\{[0-9A-Fa-f\-]{36}\}')
        if ($guidMatch.Success) {
            # MSI Execution
            $proc = Start-Process "msiexec.exe" -ArgumentList "/x $($guidMatch.Value) /qn /norestart" -Wait -PassThru
        } else {
            # EXE Execution: Handle quoted paths and append silent switches if missing
            if ($cmd -match '^\s*"(.*?)"\s*(.*)$') { $exe=$matches[1]; $args=$matches[2] }
            else { $parts = $cmd -split ' ',2; $exe=$parts[0]; $args=$parts[1] }
            if ($args -notmatch '(?i)/S|/silent|/qn') { $args = "$args /S" }
            $proc = Start-Process $exe -ArgumentList $args.Trim() -Wait -PassThru
        }
        
        # Track 3010 to inform Intune that a reboot is pending
        if ($proc.ExitCode -eq 3010) { $rebootRequired = $true }
        elseif ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 1605) { $failed = $true }
    } catch {
        Write-Error "Critical failure during uninstall: $($_.Exception.Message)"
        $failed = $true
    }
}

# --- STEP 3: FILESYSTEM CLEANUP ---
# Manual deletion of remnant folders prevents "Ghost" detections.
Write-Output "Cleaning up remaining directories and AppData..."
$remnantFolders = @("$env:ProgramFiles\TeamViewer", "${env:ProgramFiles(x86)}\TeamViewer", "$env:ProgramData\TeamViewer")
foreach ($f in $remnantFolders) { 
    if (Test-Path $f) { Remove-Item $f -Recurse -Force -ErrorAction SilentlyContinue } 
}

# Clean per-user AppData to prevent the Detection script from looping.
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item (Join-Path $_.FullName "AppData\Local\TeamViewer") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $_.FullName "AppData\Roaming\TeamViewer") -Recurse -Force -ErrorAction SilentlyContinue
}

# --- STEP 4: ORPHAN SERVICE DELETION ---
# Force-deleting services that registry uninstallers might have missed.
Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue | ForEach-Object {
    & sc.exe delete $_.Name
}

# --- STEP 5: FINAL VERIFICATION ---
if ((Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue) -or (Get-Process -Name "TeamViewer" -ErrorAction SilentlyContinue) -or $failed) {
    Write-Error "Post-uninstall verification failed. Footprint still remains."
    exit 1
}

# Return the appropriate code for Intune's reboot-handling engine.
if ($rebootRequired) { exit 3010 }
exit 0