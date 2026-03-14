<#
.SYNOPSIS
    Mozilla Firefox Remediation
.DESCRIPTION
    Upgrades Firefox to the latest Enterprise MSI, preserves each user's active Firefox
    profile as the default, suppresses first-run onboarding, and applies enterprise policies.
#>

# Stop on any unhandled error so Intune receives a non-zero exit code
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
$Firefox64Exe = "C:\Program Files\Mozilla Firefox\firefox.exe"
$Firefox86Dir = "C:\Program Files (x86)\Mozilla Firefox"

# Locations where users sometimes self-install Firefox outside of Program Files.
# These are treated as unmanaged and removed during cleanup.
$RoguePaths = @(
    "AppData\Local\Mozilla Firefox",
    "AppData\Local\Programs\Mozilla Firefox"
)

# Firefox install hashes are a CRC of the executable path.
# These two values cover all standard Windows deployments and never change
# across Firefox versions, so we hardcode them rather than scraping at runtime
# (which has a race condition with background tasks writing the files post-install):
#   308046B0AF4A39CB = C:\Program Files\Mozilla Firefox\firefox.exe       (64-bit)
#   E7CF176E110C211B = C:\Program Files (x86)\Mozilla Firefox\firefox.exe (32-bit)
#
# Ref: https://support.mozilla.org/en-US/kb/understanding-depth-profile-installation
# Firefox 67+ assigns a dedicated default profile per installation, identified by a
# hash of the install directory path. On startup Firefox looks for an [InstallHASH]
# section in profiles.ini/installs.ini. If found and Locked=1 it uses that profile
# directly, bypassing the heuristic that would otherwise create a new default-release
# profile. We write both known hashes to ensure both 32-bit and 64-bit install paths
# are covered and the heuristic is never triggered.
# Default=1 in [ProfileN] is also maintained as the legacy fallback (pre-67 behaviour)
# and to correctly populate the "Default Profile: yes" label in about:profiles.
$KnownHashes = @("308046B0AF4A39CB", "E7CF176E110C211B")

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

function Get-FirefoxActiveProfile {
    # Reads profiles.ini content and returns a hashtable with both the Name and
    # the exact relative Path of the currently active profile.
    # Returning the original Path= (not just Name) allows restore logic to target
    # the exact folder recorded at snapshot time, falling back to name-matching
    # only if the original path no longer exists on disk.
    # Modern Firefox (67+) records the active profile path in an [InstallHASH] section.
    # Falls back to the [ProfileN] block with Default=1 for older installs.
    # PARAMETER IniContent: The raw string content of profiles.ini.
    # OUTPUTS: Hashtable with Name and Path keys, or $null if none found.
    param([string]$IniContent)

    $activePath = $null

    # --- Primary path: [InstallHASH] section ---
    # Loop every [Install...] section. On a standard machine there is only one,
    # but multiple Firefox installs (e.g. 32-bit + 64-bit) can produce multiple.
    # We take the first one that has a Default= value.
    foreach ($sec in [regex]::Matches($IniContent, '(?ms)^\[Install[^\]]+\][^\[]+')) {
        if ($sec.Value -match '(?m)^Default=(.+)') {
            $activePath = $matches[1].Trim()
            break  # Stop at the first match - we only need one active path
        }
    }

    # --- Resolve path to Name and Path, with fallback ---
    # Loop every [ProfileN] section to find either:
    #   a) the one whose Path= matches $activePath (modern Firefox), or
    #   b) the one with Default=1 (legacy fallback if no [Install...] was found)
    foreach ($sec in [regex]::Matches($IniContent, '(?ms)^\[Profile\d+\][^\[]+')) {

        # Modern path: match by the profile folder path we read from [InstallHASH]
        if ($activePath -and $sec.Value -match "(?m)^Path=$([regex]::Escape($activePath))") {
            if ($sec.Value -match '(?m)^Name=(.+)') {
                return @{ Name = $matches[1].Trim(); Path = $activePath }
            }
        }

        # Legacy fallback: no [InstallHASH] found, use the Default=1 marker instead
        if (-not $activePath -and $sec.Value -match '(?m)^Default=1') {
            $name = if ($sec.Value -match '(?m)^Name=(.+)') { $matches[1].Trim() } else { $null }
            $path = if ($sec.Value -match '(?m)^Path=(.+)') { $matches[1].Trim() } else { $null }
            if ($name) { return @{ Name = $name; Path = $path } }
        }
    }

    # No active profile could be determined
    return $null
}

function Build-InstallHashBlock {
    # Builds the INI text for one or more [InstallHASH] sections.
    # Both profiles.ini and installs.ini must contain identical [InstallHASH] entries
    # pointing to the same profile path. Firefox reads installs.ini first; if a hash
    # entry is absent from either file Firefox creates a new default-release profile
    # for that installation and ignores the one we configured.
    # Locked=1 prevents Firefox from reassigning the Default= on next launch.
    # PARAMETER Hashes: Array of hash strings (e.g. @("308046B0AF4A39CB", "E7CF176E110C211B")).
    # PARAMETER ProfileRelPath: Relative path to the profile folder as Firefox expects it (e.g. "Profiles/ab12.Stu").
    # OUTPUTS: A formatted INI string ready to be written to disk.
    param(
        [string[]]$Hashes,
        [string]$ProfileRelPath
    )

    $block = ""

    # Build one [InstallHASH] section per known hash
    foreach ($hash in $Hashes) {
        $block += "[$hash]`r`nDefault=$ProfileRelPath`r`nLocked=1`r`n`r`n"
    }

    return $block.TrimEnd()
}

function Update-ProfilesIni {
    # Updates profiles.ini to set the correct default profile and [InstallHASH] sections.
    # Performs three edits in a single read/write cycle to minimise disk I/O:
    #   1. Moves Default=1 to the correct [ProfileN] block
    #   2. Explicitly writes StartWithLastProfile=1 (insert if absent, update if present)
    #   3. Replaces all [InstallHASH] sections with fresh ones pointing to the target profile
    # Ref: https://support.mozilla.org/en-US/kb/understanding-depth-profile-installation
    # PARAMETER IniPath: Full path to the user's profiles.ini file.
    # PARAMETER ProfileRelPath: Relative profile path (e.g. "Profiles/ab12cd34.Stu").
    # PARAMETER Hashes: Array of install hashes to write [InstallHASH] sections for.
    param(
        [string]$IniPath,
        [string]$ProfileRelPath,
        [string[]]$Hashes
    )

    $ini = Get-Content $IniPath -Raw

    # --- Step 1: Move Default=1 to the correct [ProfileN] block ---
    # First strip Default=1 from every block so there is no leftover default
    $ini = [regex]::Replace($ini, '(?m)^Default=1\r?\n', '')

    # Then find the block whose Path= matches our target and inject Default=1 into it
    foreach ($sec in [regex]::Matches($ini, '(?ms)^\[Profile\d+\][^\[]+')) {
        if ($sec.Value -match "(?m)^Path=$([regex]::Escape($ProfileRelPath))") {
            $ini = $ini.Replace($sec.Value, ($sec.Value.TrimEnd() + "`r`nDefault=1`r`n"))
            break  # Only one profile should be default - stop after the first match
        }
    }

    # --- Step 2: Ensure StartWithLastProfile=1 ---
    # This tells Firefox to open the default profile immediately without showing the picker.
    # Update in-place if present; insert into [General] section if absent.
    # We write it explicitly rather than relying on Firefox's default, as this script
    # takes full ownership of profile config and being explicit avoids ambiguity.
    if ($ini -match '(?m)^StartWithLastProfile=\d') {
        $ini = [regex]::Replace($ini, '(?m)^StartWithLastProfile=\d', 'StartWithLastProfile=1')
    } elseif ($ini -match '(?m)^\[General\]') {
        # Insert after the [General] header if the key is missing entirely
        $ini = [regex]::Replace($ini, '(?m)^\[General\]', "[General]`r`nStartWithLastProfile=1")
    }

    # --- Step 3: Replace all [Install...] sections ---
    # Ref: https://support.mozilla.org/en-US/kb/understanding-depth-profile-installation
    # Firefox reads installs.ini first, then profiles.ini. Both must have matching
    # [InstallHASH] sections. With Locked=1 present Firefox uses the profile directly
    # and skips the heuristic (which would otherwise create a new default-release profile).
    # Remove every existing [InstallHASH] block (they may point to a stale profile path),
    # collapse any resulting triple blank lines, then append fresh blocks for all known hashes
    $ini = [regex]::Replace($ini, '(?ms)^\[Install[^\]]+\][^\[]+', '')
    $ini = [regex]::Replace($ini, '(\r?\n){3,}', "`r`n`r`n")
    $ini = $ini.TrimEnd() + "`r`n`r`n" + (Build-InstallHashBlock -Hashes $Hashes -ProfileRelPath $ProfileRelPath)

    Set-Content -Path $IniPath -Value $ini.TrimEnd() -Encoding UTF8 -NoNewline
}

# ---------------------------------------------------------------------------
# INIT: Logging + MSI discovery
# ---------------------------------------------------------------------------

# Create the Intune log directory if it does not already exist
$LogDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# Append to the log so all historical runs are visible in one file
Start-Transcript -Path "$LogDir\Firefox_Remediation.log" -Append -Force

# $PSScriptRoot is available when the script is run as a file;
# fall back to parsing the invocation path when run interactively
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# Find the newest Firefox MSI in the same folder as this script.
# Sorting by LastWriteTime ensures we pick the right file if multiple MSIs are present.
$MsiFile = Get-ChildItem -Path $ScriptDir -Filter "Firefox Setup*.msi" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Exit cleanly if no MSI is found - Intune will report the failure
if ($null -eq $MsiFile) { Write-Output "[Error] No Firefox MSI found."; Stop-Transcript; exit 1 }
$MsiPath = $MsiFile.FullName

Write-Output "=== Starting Firefox Remediation ==="

# ---------------------------------------------------------------------------
# 1. GATE: Wait for Firefox to close before touching anything
#    We cannot upgrade Firefox while it is running - the MSI will fail.
#    Exit 1 is used on timeout rather than 1618 (which is a Windows Installer
#    "another install in progress" code and may be misinterpreted by tooling).
#    Intune will re-evaluate compliance and retry on the next check-in cycle.
# ---------------------------------------------------------------------------
Write-Output "[Check] Checking for active Firefox processes..."
$timer = [Diagnostics.Stopwatch]::StartNew()

# Keep checking every 5 seconds until Firefox closes or 45 minutes elapse
while (Get-Process -Name "firefox" -ErrorAction SilentlyContinue) {
    $elapsed = [math]::Round($timer.Elapsed.TotalMinutes, 1)
    Write-Output "   [Wait] Firefox running ($elapsed / 45 mins)..."

    # Bail out after 45 minutes - exit 1 so Intune marks as failed and retries
    if ($timer.Elapsed.TotalMinutes -ge 45) {
        Write-Output "   [Timeout] Firefox still running after 45 minutes - exiting."
        Stop-Transcript
        exit 1
    }
    Start-Sleep -Seconds 5
}

# ---------------------------------------------------------------------------
# 2. CLEANUP: Remove x86 install, rogue AppData installs, old shortcuts
#    Rogue paths exist when users have self-installed Firefox outside of
#    Program Files. These interfere with the enterprise MSI deployment.
# ---------------------------------------------------------------------------
Write-Output "[Cleanup] Scanning for unmanaged binaries..."

# --- 2a: Remove the registered x86 product cleanly before touching the folder ---
# Querying the uninstall registry first ensures any MSI-registered product is
# properly uninstalled (removes registry entries, prevents repair/self-heal).
# Direct folder deletion alone leaves stale uninstall entries in inventory.
$x86UninstallKey = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                                  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" `
    -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Mozilla Firefox*" -and $_.InstallLocation -like "*Program Files (x86)*" } |
    Select-Object -First 1

if ($x86UninstallKey) {
    Write-Output " -> Found registered x86 Firefox: $($x86UninstallKey.DisplayName)"
    $uninstallStr = $x86UninstallKey.UninstallString
    if ($uninstallStr) {
        if ($uninstallStr -match '\{[A-F0-9\-]+\}') {
            # MSI-registered product - uninstall via msiexec with the product GUID
            $guid = $matches[0]
            Write-Output " -> Uninstalling x86 product via MSI (GUID: $guid)..."
            $uninstall = Start-Process -FilePath "msiexec.exe" `
                -ArgumentList "/x $guid /qn /norestart" `
                -Wait -PassThru
            if ($uninstall.ExitCode -eq 0 -or $uninstall.ExitCode -eq 3010) {
                Write-Output " -> x86 MSI product uninstalled cleanly (exit $($uninstall.ExitCode))"
            } else {
                Write-Output " -> Warning: x86 MSI uninstall returned exit $($uninstall.ExitCode) - will attempt folder removal"
            }
        } elseif ($uninstallStr -match '(?i)helper\.exe') {
            # Exe-based uninstaller (e.g. AppData self-install uses helper.exe /S)
            # Extract the exe path - may be quoted
            $exePath = if ($uninstallStr -match '^\"([^\"]+)\"') { $matches[1] } else { $uninstallStr.Split(' ')[0] }
            if (Test-Path $exePath) {
                Write-Output " -> Uninstalling x86 product via exe uninstaller: $exePath"
                $uninstall = Start-Process -FilePath $exePath -ArgumentList "/S" -Wait -PassThru
                Write-Output " -> Exe uninstaller completed (exit $($uninstall.ExitCode))"
            } else {
                Write-Output " -> Warning: exe uninstaller not found at $exePath - will attempt folder removal"
            }
        } else {
            Write-Output " -> Warning: unrecognised UninstallString format, skipping product uninstall: $uninstallStr"
        }
    } else {
        Write-Output " -> Warning: no UninstallString found for registered x86 product"
    }
}

# Remove the x86 folder if it still exists (covers unregistered copies or failed uninstall)
if (Test-Path $Firefox86Dir) {
    Write-Output " -> Removing x86 folder: $Firefox86Dir"
    Remove-Item $Firefox86Dir -Recurse -Force -ErrorAction SilentlyContinue

    # Verify removal succeeded - if it still exists something is locking it
    if (Test-Path $Firefox86Dir) {
        Write-Output "[Fatal Error] Failed to remove x86 dir - a file may be locked."
        Stop-Transcript
        exit 1
    }
    Write-Output " -> Removed 32-bit installation directory."
}

# Get all real user profiles by checking for NTUSER.DAT (excludes system accounts)
$UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName "NTUSER.DAT") }

# --- 2b: Remove per-user AppData Firefox registrations from HKCU ---
# AppData self-installs register in HKCU (not HKLM), so the HKLM scan above misses them.
# These HKCU registrations leave stale scheduled tasks running in the user context
# that can overwrite installs.ini after our script exits.
# We temporarily load each user's registry hive to find and clean these up.
foreach ($WinUser in $UserProfiles) {
    $hiveFile     = Join-Path $WinUser.FullName "NTUSER.DAT"

    # Determine the registry path to use for this user's HKCU.
    # If the user is currently logged in their hive is already mounted under HKU\<SID>.
    # If they are logged out we must load the offline NTUSER.DAT file temporarily.
    # Trying to load an already-mounted hive causes "file in use" errors.
    $userSid = (New-Object System.Security.Principal.NTAccount($WinUser.Name)).Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
    $alreadyMounted = Test-Path "Registry::HKEY_USERS\$userSid"

    $hiveMountKey  = $null
    $useTemporary  = $false

    if ($alreadyMounted) {
        # User is logged in - use their already-mounted hive directly
        $hiveMountKey = $userSid
        Write-Output "   [Cleanup] $($WinUser.Name): hive already mounted (SID: $userSid)"
    } else {
        # User is logged out - load the offline hive under a temporary key
        $hiveMountKey = "TempHive_$($WinUser.Name)"
        $null = & reg load "HKU\$hiveMountKey" $hiveFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "   Warning: Could not load hive for $($WinUser.Name) - HKCU cleanup skipped"
            continue
        }
        $useTemporary = $true
        Write-Output "   [Cleanup] $($WinUser.Name): hive loaded from disk"
    }

    try {
        # Search HKCU uninstall keys for any registered Firefox installation
        $hkcuPaths = @(
            "Registry::HKEY_USERS\$hiveMountKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "Registry::HKEY_USERS\$hiveMountKey\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        $appDataKey = Get-ChildItem $hkcuPaths -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "*Mozilla Firefox*" } |
            Select-Object -First 1

        if ($appDataKey) {
            Write-Output " -> Found HKCU Firefox registration for $($WinUser.Name): $($appDataKey.DisplayName)"
            $uninstallStr = $appDataKey.UninstallString

            # AppData installs use helper.exe /S for uninstall (not MSI GUID)
            if ($uninstallStr -and $uninstallStr -match '(?i)helper\.exe') {
                $exePath = if ($uninstallStr -match '^"([^"]+)"') { $matches[1] } else { $uninstallStr.Split(' ')[0] }
                if (Test-Path $exePath) {
                    Write-Output "   -> Running HKCU Firefox uninstaller: $exePath"
                    Start-Process -FilePath $exePath -ArgumentList "/S" -Wait | Out-Null
                    Write-Output "   -> HKCU Firefox uninstaller completed"
                } else {
                    Write-Output "   -> Warning: HKCU uninstaller not found at $exePath - skipping"
                }
            }
        }

        # Disable any per-user Firefox scheduled tasks in this user's hive.
        # AppData installs create Background Update and Default Browser Agent tasks in HKCU.
        # These run under the user context after our script exits and overwrite installs.ini.
        $taskCachePath = "Registry::HKEY_USERS\$hiveMountKey\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Mozilla"
        if (Test-Path $taskCachePath) {
            Get-ChildItem $taskCachePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Output "   -> Disabling per-user Firefox task in hive: $($_.PSChildName)"
                # Set the Enabled DWORD to 0 to disable the task
                try {
                    Set-ItemProperty -Path $_.PSPath -Name "Index" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                } catch {
                    Write-Output "   -> Warning: Could not disable task $($_.PSChildName) - $_"
                }
            }
        }
    } catch {
        Write-Output "   Warning: HKCU cleanup failed for $($WinUser.Name) - $_"
    } finally {
        # Only unload if we loaded it ourselves - never unload a live user's hive
        if ($useTemporary) {
            [GC]::Collect()
            Start-Sleep -Milliseconds 500
            $null = & reg unload "HKU\$hiveMountKey" 2>&1
        }
    }
}

# --- 2c: Remove rogue per-user AppData Firefox installs ---
# Log each attempt so failures are visible rather than silently ignored
foreach ($WinUser in $UserProfiles) {
    foreach ($RelPath in $RoguePaths) {
        $AppDir = Join-Path $WinUser.FullName $RelPath
        if (Test-Path $AppDir) {
            Write-Output " -> Found rogue install for $($WinUser.Name): $AppDir"
            Remove-Item $AppDir -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $AppDir) {
                Write-Output "   Warning: Could not remove $AppDir - files may be locked"
            } else {
                Write-Output "   Removed: $AppDir"
            }
        }
    }
}

# --- 2c: Remove existing Firefox shortcuts so the MSI creates clean ones ---
# Old shortcuts may point to the x86 path we just removed, which would leave broken pins.
$shell = New-Object -ComObject WScript.Shell
$deletePaths = @(
    "C:\Users\*\Desktop\*.lnk",
    "C:\Users\Public\Desktop\*.lnk",
    "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk"
)
try {
    # Inspect every .lnk file in the candidate paths
    Get-ChildItem -Path $deletePaths -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            # Only delete shortcuts that actually target firefox.exe
            # so we don't accidentally remove unrelated shortcuts
            if ($shell.CreateShortcut($_.FullName).TargetPath -match "(?i)firefox\.exe$") {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Output "   Warning: Could not inspect shortcut $($_.FullName) - $_"
        }
    }
} catch {
    Write-Output "   Warning: Shortcut path enumeration failed - $_"
}

# ---------------------------------------------------------------------------
# 3. PRE-INSTALL: Snapshot each user's active Firefox profile
#    We capture both the profile Name and its original Path= from profiles.ini.
#    Storing the exact path makes restore deterministic - we use it directly
#    post-install rather than relying solely on name-matching which can
#    mis-target when multiple folders share the same name suffix.
#    We do this BEFORE the MSI runs because the upgrade creates new profile
#    folders and rewrites installs.ini.
# ---------------------------------------------------------------------------
Write-Output "[ProfileSave] Snapshotting Firefox profile configuration before upgrade..."

# Hashtable keyed by Windows user folder path, storing profile metadata per user
$ProfileSnapshots = @{}

# Loop every real user account on the machine
foreach ($WinUser in $UserProfiles) {
    $FirefoxDir   = Join-Path $WinUser.FullName "AppData\Roaming\Mozilla\Firefox"
    $IniPath      = Join-Path $FirefoxDir "profiles.ini"
    $InstallsPath = Join-Path $FirefoxDir "installs.ini"
    $ProfilesDir  = Join-Path $FirefoxDir "Profiles"

    # Skip users who have never run Firefox (no profiles.ini means no profile data to preserve)
    if (-not (Test-Path $IniPath)) { continue }

    try {
        # Delegate profile resolution to the helper - returns Name and Path
        $activeProfile = Get-FirefoxActiveProfile -IniContent (Get-Content $IniPath -Raw)

        # Skip if we could not identify an active profile (e.g. only default-release exists)
        if (-not $activeProfile) {
            Write-Output "   [ProfileSave] $($WinUser.Name): no active profile found - skipping."
            continue
        }

        Write-Output "   [ProfileSave] $($WinUser.Name): active profile = '$($activeProfile.Name)' (path: $($activeProfile.Path))"

        # Store both Name and original Path for deterministic restore
        $ProfileSnapshots[$WinUser.FullName] = @{
            IniPath         = $IniPath
            InstallsPath    = $InstallsPath
            ProfilesDir     = $ProfilesDir
            TargetName      = $activeProfile.Name
            OriginalRelPath = $activeProfile.Path  # Exact path from profiles.ini pre-upgrade
        }
    } catch {
        # Log the error but continue processing other users
        Write-Output "   [ProfileSave] Warning: $($WinUser.Name) - $_"
    }
}

# ---------------------------------------------------------------------------
# 4. INSTALL MSI
#    /qn = quiet (no UI), /norestart = defer any required reboot to Intune.
#    Exit code 3010 = success but a reboot is pending - acceptable for Intune.
# ---------------------------------------------------------------------------
Write-Output "[Deployment] Executing Enterprise MSI Installation..."
$Process = Start-Process -FilePath "msiexec.exe" `
    -ArgumentList "/i `"$MsiPath`" ALLUSERS=1 /qn /norestart" `
    -Wait -PassThru

# Any exit code other than 0 (success) or 3010 (reboot pending) is a genuine failure
if ($Process.ExitCode -ne 0 -and $Process.ExitCode -ne 3010) {
    Write-Output "[Error] MSI Exit Code: $($Process.ExitCode)"
    Stop-Transcript
    exit $Process.ExitCode
}

# ---------------------------------------------------------------------------
# 5. ENTERPRISE POLICIES
#    Policies are written to two locations for maximum compatibility:
#      Registry (HKLM:\SOFTWARE\Policies\Mozilla\Firefox) - highest priority,
#        equivalent to GPO. Takes effect immediately without requiring a restart.
#      Registry is sufficient for Intune-managed Windows devices. policies.json
#      is only needed for non-domain or non-Windows scenarios which do not apply here.
#    Key policies:
#      AppAutoUpdate              - enables silent background updates via Firefox's
#                                   built-in updater (no Intune repackaging needed)
#      DisableDefaultBrowserAgent - stops the background agent from resetting
#                                   installs.ini and creating a new default profile
# ---------------------------------------------------------------------------
Write-Output "[Policies] Writing Firefox enterprise policies..."
$regBase = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"

# Define all registry values as a nested hashtable: path -> { name -> value }
# Types are explicit ([int]/[string]) so we can determine DWord vs String correctly
$regDefs = @{
    "$regBase" = @{
        OverrideFirstRunPage       = [string]""  # Blank = no welcome page on first run
        OverridePostUpdatePage     = [string]""  # Blank = no "what's new" page after update
        DontCheckDefaultBrowser    = [int]1      # Suppress "make Firefox default" prompt
        DisableFirefoxStudies      = [int]1      # No A/B experiments on managed devices
        DisableTelemetry           = [int]1      # No usage data sent to Mozilla
        DisableDefaultBrowserAgent = [int]1      # Prevent agent from resetting installs.ini
        AppAutoUpdate              = [int]1      # Allow Firefox to self-update silently
    }
    "$regBase\UserMessaging" = @{
        WhatsNew                 = [int]0  # No "what's new" panel in toolbar
        ExtensionRecommendations = [int]0  # No extension suggestion popups
        FeatureRecommendations   = [int]0  # No feature suggestion popups
        UrlbarInterventions      = [int]0  # No address bar suggestions/promotions
        MoreFromMozilla          = [int]0  # No "more from Mozilla" promotions
    }
}

# Write each registry key and its values
foreach ($path in $regDefs.Keys) {

    # Create the registry key if it does not already exist
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }

    # Write each value under this key
    foreach ($name in $regDefs[$path].Keys) {
        $val      = $regDefs[$path][$name]
        $propType = if ($val -is [int]) { "DWord" } else { "String" }

        # Use $null -ne check rather than truthy test - a truthy check on an empty
        # string value returns $false and would incorrectly trigger New-ItemProperty
        if ($null -ne (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue)) {
            Set-ItemProperty -Path $path -Name $name -Value $val -Force
        } else {
            New-ItemProperty -Path $path -Name $name -Value $val -PropertyType $propType -Force | Out-Null
        }
    }
}

Write-Output "   [Policies] Registry policies written"

# Disable the machine-wide Default Browser Agent scheduled task.
# This task writes to installs.ini and would overwrite our profile settings.
# Background Update tasks are left enabled - those deliver silent Firefox updates.
# Per-user AppData Firefox tasks were already handled in step 2b via hive loading.
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -like "*Firefox Default Browser Agent*" } |
    ForEach-Object {
        Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
        Write-Output "   [Policies] Disabled Default Browser Agent task: $($_.TaskName)"
    }

# ---------------------------------------------------------------------------
# 6. POST-INSTALL: Restore each user's default profile
#    The MSI creates new empty profile folders and rewrites installs.ini.
#    We must update both profiles.ini and installs.ini for every user to
#    point back to their original named profile before they next open Firefox.
#
#    Restore strategy (most to least deterministic):
#      1. Use the original Path= captured pre-install if that folder still exists
#      2. Fall back to name-matching (oldest *.ProfileName folder) if original is gone
#
#    Both files must agree: Firefox reads installs.ini first. If a hash entry
#    is missing from either file, Firefox creates a new default-release profile.
# ---------------------------------------------------------------------------
Write-Output "[ProfileRestore] Restoring Firefox profile configuration after upgrade..."

# Process each user whose profile we snapshotted in step 3
foreach ($UserPath in $ProfileSnapshots.Keys) {
    $Snap        = $ProfileSnapshots[$UserPath]
    $TargetName  = $Snap.TargetName
    $ProfilesDir = $Snap.ProfilesDir

    try {
        # Sanity check - profiles.ini should always exist at this point, but verify
        if (-not (Test-Path $Snap.IniPath)) {
            Write-Output "   [ProfileRestore] profiles.ini missing for $UserPath - skipping."
            continue
        }

        # --- Resolve the profile folder path ---
        # Strategy 1: use the exact original relative path captured before the upgrade.
        # This is deterministic and avoids name-collision edge cases.
        $relPath = $null
        if ($Snap.OriginalRelPath) {
            $originalAbsPath = Join-Path (Split-Path $Snap.IniPath) $Snap.OriginalRelPath.Replace('/', '\')
            if (Test-Path $originalAbsPath) {
                $relPath = $Snap.OriginalRelPath
                Write-Output "   [ProfileRestore] Using original path: $relPath"
            } else {
                Write-Output "   [ProfileRestore] Original path '$($Snap.OriginalRelPath)' not found - falling back to name match"
            }
        }

        # Strategy 2: name-match fallback - find oldest *.ProfileName folder.
        # Multiple folders with the same suffix accumulate across upgrades;
        # the oldest is most likely to be the one containing the user's data.
        if (-not $relPath -and (Test-Path $ProfilesDir)) {
            $targetFolder = Get-ChildItem $ProfilesDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*.$TargetName" } |
                Sort-Object CreationTime |
                Select-Object -First 1  # Oldest = most likely original

            if ($targetFolder) {
                $relPath = "Profiles/$($targetFolder.Name)"
                Write-Output "   [ProfileRestore] Name-matched folder: $($targetFolder.Name)"
            }
        }

        # If neither strategy found a folder this profile may have been deleted
        if (-not $relPath) {
            Write-Output "   [ProfileRestore] No folder found for '$TargetName' - skipping."
            continue
        }

        Write-Output "   [ProfileRestore] Target: '$TargetName' -> $relPath"

        # Update profiles.ini: sets Default=1, StartWithLastProfile=1, and [InstallHASH] sections
        Update-ProfilesIni -IniPath $Snap.IniPath -ProfileRelPath $relPath -Hashes $KnownHashes
        Write-Output "   [ProfileRestore] profiles.ini updated"

        # Write installs.ini with matching [InstallHASH] entries for both known hashes.
        # This file is read by Firefox before profiles.ini and must be consistent with it.
        Set-Content -Path $Snap.InstallsPath `
            -Value (Build-InstallHashBlock -Hashes $KnownHashes -ProfileRelPath $relPath) `
            -Encoding UTF8 -NoNewline
        Write-Output "   [ProfileRestore] installs.ini written ($($KnownHashes.Count) hashes)"

        # Write compatibility.ini into the profile folder.
        # Ref: https://support.mozilla.org/en-US/kb/understanding-depth-profile-installation
        # When migrating from an AppData install to Program Files, Firefox reads
        # compatibility.ini to see which installation last used this profile.
        # If it records an AppData path, Firefox treats this as "profile used by a
        # different install" and creates a new default-release profile instead - even
        # with Locked=1 set in installs.ini. Writing this file with the Program Files
        # path tells Firefox the profile already belongs to this installation.
        $profileAbsPath = Join-Path (Split-Path $Snap.IniPath) $relPath.Replace('/', '\')
        $compatIni = Join-Path $profileAbsPath "compatibility.ini"
        $compatContent = "[Compatibility]`r`nLastVersion=148.0_20250401144603/148.0_20250401144603`r`nLastOSABI=winnt_x86_64-msvc`r`nLastPlatformDir=C:\Program Files\Mozilla Firefox`r`nLastAppDir=C:\Program Files\Mozilla Firefox\browser`r`n"
        Set-Content -Path $compatIni -Value $compatContent -Encoding UTF8 -NoNewline
        Write-Output "   [ProfileRestore] compatibility.ini written (LastPlatformDir -> Program Files)"

        # Write user.js into the profile folder.
        # Firefox re-applies user.js on every launch, overriding prefs.js values.
        # This ensures onboarding suppression survives Firefox self-updates.
        $userJs = Join-Path $profileAbsPath "user.js\"
@'
// Suppress Firefox first-run onboarding - managed by IT deployment
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_override_url", "");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.aboutwelcome.didSeeFinalScreen", true);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.laterrun.enabled", false);
user_pref("browser.migration.version", 999);
user_pref("datareporting.policy.firstRunURL", "");
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
'@ | Set-Content -Path $userJs -Encoding UTF8
        Write-Output "   [ProfileRestore] Done for $(Split-Path $UserPath -Leaf)"

    } catch {
        # Log the failure but continue restoring other users
        Write-Output "   [ProfileRestore] Warning: Failed for $UserPath - $_"
    }
}

# ---------------------------------------------------------------------------
# 7. SHORTCUT FIX: Redirect pinned taskbar shortcuts to the 64-bit path
#    After removing the x86 install in step 2, any shortcuts pinned to the
#    old 32-bit firefox.exe are now broken. Update them to the 64-bit path.
#    Note: taskbar pin repair can be temperamental depending on Windows version
#    and shell cache state - this is best-effort rather than guaranteed.
# ---------------------------------------------------------------------------
Write-Output "[Sanitization] Redirecting Taskbar pins..."
$taskbarPaths = @("C:\Users\*\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk")
try {
    Get-ChildItem -Path $taskbarPaths -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $sc = $shell.CreateShortcut($_.FullName)

            # Only update shortcuts that target a firefox.exe (any path)
            if ($sc.TargetPath -match "(?i)firefox\.exe$") {
                $sc.TargetPath       = $Firefox64Exe
                $sc.WorkingDirectory = "C:\Program Files\Mozilla Firefox"
                $sc.Save()
            }
        } catch {
            Write-Output "   Warning: Could not update taskbar shortcut $($_.FullName) - $_"
        }
    }
} catch {
    Write-Output "   Warning: Taskbar path enumeration failed - $_"
}

# ---------------------------------------------------------------------------
# 8. RE-ASSERT installs.ini AS FINAL STEP
#    Something (MSI post-install actions, residual registered product, background task)
#    can overwrite installs.ini after step 6. Re-writing it here as the last operation
#    before validation ensures our settings survive any post-install activity.
# ---------------------------------------------------------------------------
Write-Output "[ProfileRestore] Re-asserting installs.ini after all post-install activity..."
foreach ($UserPath in $ProfileSnapshots.Keys) {
    $Snap    = $ProfileSnapshots[$UserPath]
    $relPath = $null

    # Resolve the same path we used in step 6
    if ($Snap.OriginalRelPath) {
        $originalAbsPath = Join-Path (Split-Path $Snap.IniPath) $Snap.OriginalRelPath.Replace('/', '\')
        if (Test-Path $originalAbsPath) { $relPath = $Snap.OriginalRelPath }
    }
    if (-not $relPath -and (Test-Path $Snap.ProfilesDir)) {
        $tf = Get-ChildItem $Snap.ProfilesDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*.$($Snap.TargetName)" } |
            Sort-Object CreationTime | Select-Object -First 1
        if ($tf) { $relPath = "Profiles/$($tf.Name)" }
    }

    if ($relPath) {
        Set-Content -Path $Snap.InstallsPath `
            -Value (Build-InstallHashBlock -Hashes $KnownHashes -ProfileRelPath $relPath) `
            -Encoding UTF8 -NoNewline
        Write-Output "   [ProfileRestore] installs.ini re-asserted for $(Split-Path $UserPath -Leaf) -> $relPath"
    }
}

# ---------------------------------------------------------------------------
# 9. POST-INSTALL VALIDATION
#    Confirm the end state is correct before reporting success to Intune.
#    Exits with code 1 if any critical check fails so Intune marks as failed.
# ---------------------------------------------------------------------------
Write-Output "[Validation] Verifying installation state..."
$validationFailed = $false

# Check firefox.exe exists at the expected 64-bit path
if (Test-Path $Firefox64Exe) {
    $ffVersion = (Get-Item $Firefox64Exe).VersionInfo.ProductVersion
    Write-Output "   [OK] firefox.exe found - version $ffVersion"
} else {
    Write-Output "   [FAIL] firefox.exe not found at $Firefox64Exe"
    $validationFailed = $true
}

# Check x86 directory is gone
if (Test-Path $Firefox86Dir) {
    Write-Output "   [FAIL] x86 directory still exists: $Firefox86Dir"
    $validationFailed = $true
} else {
    Write-Output "   [OK] x86 directory absent"
}

# Check registry policies key exists
if (Test-Path $regBase) {
    Write-Output "   [OK] Registry policies key present: $regBase"
} else {
    Write-Output "   [FAIL] Registry policies key missing: $regBase"
    $validationFailed = $true
}

if ($validationFailed) {
    Write-Output "[Error] One or more validation checks failed - see above."
    Stop-Transcript
    exit 1
}

Write-Output "=== Firefox Remediation Completed ==="
Stop-Transcript
exit 0
