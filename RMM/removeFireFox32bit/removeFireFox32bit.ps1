<#
.SYNOPSIS
    removeFireFox32bit.ps1 - Remove 32-bit Mozilla Firefox + Back up bookmarks database (places.sqlite)

.NOTES
    Name:       removeFireFox32bit.ps1
    Author:     Stu Villanti (s.villanti@kenstra.com.au)
    Version:    1.0

.DESCRIPTION
    This script is designed for MSP/RMM use to remove 32-bit Firefox installations while
    preserving user bookmarks/history by backing up the Firefox profile database file:
      - places.sqlite (contains bookmarks/history)

    What it does:
      1) Creates a backup folder (default: C:\Temp\FirefoxBackup)
      2) Enumerates all local user profiles under C:\Users
      3) Finds each Firefox profile under:
           C:\Users\<User>\AppData\Roaming\Mozilla\Firefox\Profiles\<Profile>\
         and copies places.sqlite to the backup folder
      4) Detects and uninstalls 32-bit Firefox:
           - Machine install (Program Files (x86)\Mozilla Firefox\uninstall\helper.exe)
           - Optional per-user install(s) under AppData\Local\Programs\Mozilla Firefox
      5) Reports what it did and exits with RMM-friendly exit codes

    Notes:
      - This script does NOT touch 64-bit Firefox in "C:\Program Files\Mozilla Firefox"
      - It is safe to rerun (idempotent). Backups are timestamped.

.PARAMETER BackupRoot
    Folder where backups will be stored. Default: C:\Temp\FirefoxBackup

.PARAMETER RemoveUserInstalls
    When set, attempts to remove per-user Firefox installs found under:
      C:\Users\<User>\AppData\Local\Programs\Mozilla Firefox
    (Some environments only have the machine install; leave this off if unsure.)

.PARAMETER UninstallTimeoutSeconds
    Max seconds to wait for each uninstall to finish. Default: 900 (15 minutes)

.EXITCODES
    0 = Completed successfully OR no 32-bit Firefox detected
    1 = One or more uninstall attempts failed

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$BackupRoot = "C:\Temp\FirefoxBackup",

    [Parameter()]
    [switch]$RemoveUserInstalls,

    [Parameter()]
    [int]$UninstallTimeoutSeconds = 900
)

# -----------------------------
# Helper: safe Write-Output
# -----------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Output $Message
}

# -----------------------------
# Helper: run uninstall helper.exe silently
# -----------------------------
function Invoke-FirefoxUninstall {
    <#
    .SYNOPSIS
        Executes Firefox helper.exe uninstall silently.

    .PARAMETER HelperExePath
        Full path to uninstall\helper.exe

    .PARAMETER TimeoutSeconds
        Max seconds to wait.

    .OUTPUTS
        [bool] True if it appears to have run successfully, otherwise False.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$HelperExePath,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds
    )

    if (-not (Test-Path $HelperExePath)) {
        Write-Log "Uninstall helper not found: $HelperExePath"
        return $false
    }

    # Firefox helper.exe supports:
    #   -ms  = silent mode (no UI)
    $args = "-ms"

    try {
        Write-Log "Running uninstall: `"$HelperExePath`" $args"
        $p = Start-Process -FilePath $HelperExePath -ArgumentList $args -PassThru -WindowStyle Hidden

        if (-not $p) {
            Write-Log "Uninstall did not start (no process handle returned)."
            return $false
        }

        # Wait for completion (bounded)
        $completed = $p.WaitForExit($TimeoutSeconds * 1000)

        if (-not $completed) {
            Write-Log "Uninstall timed out after $TimeoutSeconds seconds. Attempting to stop process PID $($p.Id)."
            try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
            return $false
        }

        # helper.exe exit codes are not well documented; treat 0 as success.
        Write-Log "Uninstall process exit code: $($p.ExitCode)"
        return ($p.ExitCode -eq 0)
    }
    catch {
        Write-Log "ERROR running uninstall helper: $($_.Exception.Message)"
        return $false
    }
}

# -----------------------------
# Start
# -----------------------------
Write-Log "Starting Firefox 32-bit cleanup with bookmark backup"
Write-Log "BackupRoot: $BackupRoot"
Write-Log ("RemoveUserInstalls: {0}" -f [bool]$RemoveUserInstalls)

$overallFail = $false

# -----------------------------
# STEP 1: Ensure backup root exists
# -----------------------------
try {
    if (-not (Test-Path $BackupRoot)) {
        New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
        Write-Log "Created backup root: $BackupRoot"
    } else {
        Write-Log "Backup root exists: $BackupRoot"
    }
}
catch {
    # If backup folder can’t be created, we should not proceed with removal.
    Write-Log "ERROR: Failed to create/verify backup root '$BackupRoot' - $($_.Exception.Message)"
    exit 1
}

# -----------------------------
# STEP 2: Back up places.sqlite for all local user profiles
# -----------------------------
Write-Log "Backing up Firefox places.sqlite (bookmarks/history) from all user profiles..."

# Enumerate all folders under C:\Users, excluding common non-user folders
$userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users","Administrator") }

$backupCount = 0

foreach ($user in $userFolders) {
    $userName = $user.Name

    # Firefox roaming profiles location
    $ffProfileRoot = "C:\Users\{0}\AppData\Roaming\Mozilla\Firefox\Profiles" -f $userName
    if (-not (Test-Path $ffProfileRoot)) { continue }

    Write-Log ("Found Firefox profile root for user '{0}': {1}" -f $userName, $ffProfileRoot)

    $profiles = Get-ChildItem -Path $ffProfileRoot -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $profiles) {
        $placesPath = Join-Path -Path $profile.FullName -ChildPath "places.sqlite"
        if (-not (Test-Path $placesPath)) { continue }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFileName = "Firefox_{0}_{1}_{2}.sqlite" -f $userName, $profile.Name, $timestamp
        $destPath = Join-Path -Path $BackupRoot -ChildPath $backupFileName

        try {
            Copy-Item -Path $placesPath -Destination $destPath -Force
            Write-Log ("Backed up: {0} -> {1}" -f $placesPath, $destPath)
            $backupCount++
        }
        catch {
            Write-Log ("WARNING: Failed to back up {0} - {1}" -f $placesPath, $_.Exception.Message)
            # Do not hard-fail here; continue backing up others.
        }
    }
}

Write-Log "Backup complete. places.sqlite files copied: $backupCount"

# -----------------------------
# STEP 3: Detect 32-bit Firefox machine install
# -----------------------------
# 32-bit machine install typically lives here:
$ff32Root = "C:\Program Files (x86)\Mozilla Firefox"
$ff32Helper = Join-Path $ff32Root "uninstall\helper.exe"

# 64-bit install for reference (we do not touch it):
$ff64Root = "C:\Program Files\Mozilla Firefox"

$ff32Detected = Test-Path $ff32Root
$ff64Detected = Test-Path $ff64Root

Write-Log ("Detected 32-bit Firefox (x86) folder: {0}" -f $ff32Detected)
Write-Log ("Detected 64-bit Firefox folder: {0}" -f $ff64Detected)

# -----------------------------
# STEP 4: Uninstall 32-bit Firefox machine install (if present)
# -----------------------------
if ($ff32Detected) {
    if ($PSCmdlet.ShouldProcess($ff32Root, "Uninstall 32-bit Firefox (machine install)")) {
        $ok = Invoke-FirefoxUninstall -HelperExePath $ff32Helper -TimeoutSeconds $UninstallTimeoutSeconds
        if (-not $ok) { $overallFail = $true }
    }
}

# -----------------------------
# STEP 5: Optional - remove per-user Firefox installs under AppData\Local\Programs
# -----------------------------
# Some orgs deploy Firefox per-user (not MSI) into:
#   C:\Users\<User>\AppData\Local\Programs\Mozilla Firefox
# If enabled, we attempt to run that install's helper.exe as well.
if ($RemoveUserInstalls) {
    Write-Log "RemoveUserInstalls is enabled. Checking for per-user Firefox installs..."

    foreach ($user in $userFolders) {
        $userName = $user.Name
        $userInstallRoot = "C:\Users\{0}\AppData\Local\Programs\Mozilla Firefox" -f $userName
        $userHelper = Join-Path $userInstallRoot "uninstall\helper.exe"

        if (-not (Test-Path $userInstallRoot)) { continue }

        Write-Log ("Found per-user Firefox install for '{0}': {1}" -f $userName, $userInstallRoot)

        if ($PSCmdlet.ShouldProcess($userInstallRoot, "Uninstall per-user Firefox install")) {
            $ok = Invoke-FirefoxUninstall -HelperExePath $userHelper -TimeoutSeconds $UninstallTimeoutSeconds
            if (-not $ok) { $overallFail = $true }
        }
    }
}

# -----------------------------
# STEP 6: Post-check verification (folder presence)
# -----------------------------
$ff32StillThere = Test-Path $ff32Root
Write-Log ("Post-check: 32-bit Firefox folder still present: {0}" -f $ff32StillThere)

if ($ff32Detected -and $ff32StillThere) {
    # Not always a hard failure (some remnants can remain), but it’s a strong indicator.
    Write-Log "WARNING: 32-bit Firefox folder still exists. Uninstall may not have completed fully."
    $overallFail = $true
}

# -----------------------------
# FINAL RESULT
# -----------------------------
if ($overallFail) {
    Write-Log "RESULT: Completed with errors (one or more uninstall steps failed)."
    exit 1
}

if (-not $ff32Detected) {
    Write-Log "RESULT: No 32-bit Firefox machine install detected. Nothing to remove."
    exit 0
}

Write-Log "RESULT: 32-bit Firefox removal completed successfully."
exit 0
