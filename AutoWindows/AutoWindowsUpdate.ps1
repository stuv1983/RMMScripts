<#
.SYNOPSIS
    Windows Update helper for RMM use. Clean non-admin version.

.DESCRIPTION
    - Designed for RMMs passing parameters as strings ("true"/"false").
    - REMOVED: All calls to Start-Service and explicit service checks to allow for non-elevated scans.
    - Two modes:
        * CheckOnly: Scans for available updates. Designed to work without Admin rights.
        * Install  : Scans, downloads, and installs updates. REQUIRES Admin rights (will fail without them).
    - Prints clear RESULT lines for dashboards/ticket notes.
    - Returns standard exit codes for policy/alert handling (see Exit Codes).

.PARAMETER CheckOnly
    String/Boolean. If true, only performs a scan and reports findings. Mutually exclusive with -Install.

.PARAMETER Install
    String/Boolean. If true, scans and installs updates. Mutually exclusive with -CheckOnly.

.PARAMETER AutoReboot
    String/Boolean. If true (and Install is true), the script will reboot automatically when required (Requires Admin).

.PARAMETER VerboseOutput
    String/Boolean. If true, enables detailed progress messages (Write-Verbose).

.EXIT CODES
    0  - Success. No updates available and no reboot required.
    1  - Success. Updates installed, no reboot required.
    2  - Success. Reboot required (either pending prior to run or required after install).
    10 - CheckOnly: updates available.
    11 - CheckOnly: reboot pending (detected before scan).
    40 - Windows Update failure (exception thrown, e.g., missing Admin rights, network/proxy error).
#>

[CmdletBinding()]
param(
    # Accept 'true'/'false' strings or real booleans (from AMP/RMM or console)
    [Parameter()] [object]$CheckOnly,
    [Parameter()] [object]$Install,
    [Parameter()] [object]$AutoReboot,
    [Parameter()] [object]$VerboseOutput
)

# --- Convert RMM string values ("true"/"false", "1"/"0") to Boolean ------------
function Convert-ToBool {
    <#
    .SYNOPSIS
        Converts RMM-provided parameter values to [bool].
    .OUTPUTS
        [bool]
    #>
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        # Return false if value is null
        if ($null -eq $Value) { return $false }
        # Return value directly if it is already a Boolean type
        if ($Value -is [bool]) { return $Value }
        # Numbers: treat non-zero as true
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }
        # Strings: normalize and convert
        $v = "$Value".Trim().ToLowerInvariant()
        switch ($v) {
            'true'  { return $true }
            'false' { return $false }
            '1'     { return $true }
            '0'     { return $false }
            default { return $false }
        }
    }
}

# Apply conversion to all input parameters
$CheckOnly     = Convert-ToBool $CheckOnly
$Install       = Convert-ToBool $Install
$AutoReboot    = Convert-ToBool $AutoReboot
$VerboseOutput = Convert-ToBool $VerboseOutput

# Normalise verbose preference based on input parameter
$VerbosePreference = if ($VerboseOutput) { 'Continue' } else { 'SilentlyContinue' }

# --- Safety / sanity checks ----------------------------------------------------

# Mutually exclusive mode validation
if ($CheckOnly -and $Install) {
    # Terminate script if contradictory parameters are used
    throw "Choose one mode only: set either -CheckOnly true OR -Install true (not both)."
}

# Default behaviour when neither is specified: default to Install.
if (-not $CheckOnly -and -not $Install) {
    Write-Verbose "No mode specified; defaulting to Install."
    $Install = $true
}

# AutoReboot is irrelevant when only checking, so force it to false in CheckOnly mode
if ($CheckOnly -and $AutoReboot) {
    Write-Verbose "Ignoring -AutoReboot because -CheckOnly true was selected."
    $AutoReboot = $false
}


# --- Helper functions ----------------------------------------------------------
function Get-PendingReboot {
    <#
    .SYNOPSIS
        Determines if a reboot is pending using common registry locations.
    .OUTPUTS
        [bool] True if reboot is pending; otherwise False.
    #>
    try {
        $pending = $false

        # Check: Component Based Servicing (CBS) queue for Windows updates/installs
        $keyCBS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path $keyCBS) { $pending = $true }

        # Check: Windows Update Auto Update service requirement
        $keyWUAU = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $keyWUAU) { $pending = $true }

        # Check: PendingFileRenameOperations (used by MSI/installers)
        $keyPFRO = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        # The next line might require Admin access if 'PendingFileRenameOperations' is present
        $valPFRO = (Get-ItemProperty -Path $keyPFRO -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($valPFRO) { $pending = $true }

        return [bool]$pending
    } catch {
        Write-Verbose "Get-PendingReboot check failed: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-WindowsUpdateScan {
    <#
    .SYNOPSIS
        Uses WUA COM API to scan for available software updates.
    .OUTPUTS
        [PSCustomObject] with properties:
            - Updates : IUpdateCollection (available updates)
            - Count   : [int] number of updates
            - Titles  : [string[]] update titles for easy display
    #>
    try {
        Write-Verbose "Scanning for Windows updates... please wait"
        # Note: WUA COM object invocation handles starting BITS/WUAUSERV automatically (or fails if it cannot).
        $session   = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher  = $session.CreateUpdateSearcher()
        # Criteria: Not installed, not hidden, and a software type (excludes drivers by default)
        $criteria  = "IsInstalled=0 and IsHidden=0 and Type='Software'"
        Write-Verbose "WUA Criteria: $criteria"

        # Perform the actual search operation
        $result    = $searcher.Search($criteria)
        Write-Verbose "[WUA Debug] Search ResultCode: $($result.ResultCode) (2=Succeeded)"
        $updates   = $result.Updates

        # Extract titles for verbose output
        $titles = @()
        for ($i = 0; $i -lt $updates.Count; $i++) {
            $titles += $updates.Item($i).Title
        }

        # Return structured data object
        return [PSCustomObject]@{
            Updates = $updates
            Count   = [int]$updates.Count
            Titles  = $titles
        }
    } catch {
        # Catch network/COM/HRESULT errors (e.g., 0x8024402C or Access Denied if WUA fails to start services)
        throw "Windows Update scan failed: $($_.Exception.Message)"
    }
}

function Install-WindowsUpdates {
    <#
    .SYNOPSIS
        Downloads and installs a provided IUpdateCollection.
    .PARAMETER Updates
        IUpdateCollection to install.
    .OUTPUTS
        [PSCustomObject] with properties:
            - DownloadResult : Result code from downloader
            - InstallResult  : Result code from installer
            - RebootRequired : [bool]
            - Succeeded      : [string[]] titles installed successfully
            - Failed         : [string[]] titles that failed
    #>
    param([Parameter(Mandatory)]$Updates)

    try {
        # Note: Download and Install operations typically REQUIRE administrator rights.
        $session    = New-Object -ComObject 'Microsoft.Update.Session'
        $downloader = $session.CreateUpdateDownloader()
        $installer  = $session.CreateUpdateInstaller()

        # Accept EULAs where needed and build a new collection for selected updates
        $toInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'

        for ($i = 0; $i -lt $Updates.Count; $i++) {
            $u = $Updates.Item($i)
            # Accept EULA if required, as installation will fail otherwise
            if ($u.EulaAccepted -eq $false) {
                Write-Verbose "Accepting EULA for: $($u.Title)"
                $u.AcceptEula()
            }
            # Add to the collection of updates to install
            [void]$toInstall.Add($u)
        }

        # Safety check if collection somehow ended up empty
        if ($toInstall.Count -eq 0) {
            Write-Verbose "No eligible updates to install."
            return [PSCustomObject]@{
                DownloadResult = 2
                InstallResult  = 2
                RebootRequired = $false
                Succeeded      = @()
                Failed         = @()
            }
        }

        # --- Download Phase ---
        Write-Verbose "Downloading $($toInstall.Count) update(s)..."
        $downloader.Updates = $toInstall
        $dlResult = $downloader.Download()
        Write-Verbose "Download result: $($dlResult.ResultCode) (2=Succeeded)"

        # --- Install Phase ---
        Write-Verbose "Installing updates..."
        $installer.Updates = $toInstall
        $inResult = $installer.Install()
        Write-Verbose "Install result: $($inResult.ResultCode) (2=Succeeded)"
        $rebootRequired = [bool]$inResult.RebootRequired

        # Summarise results
        $succeeded = @()
        $failed    = @()

        for ($i = 0; $i -lt $toInstall.Count; $i++) {
            $u = $toInstall.Item($i)
            $hr = $inResult.GetUpdateResult($i).HResult
            # HResult 0 means success
            if ($hr -eq 0) { $succeeded += $u.Title } else { $failed += $u.Title }
        }

        # Return structured results object
        return [PSCustomObject]@{
            DownloadResult = $dlResult.ResultCode
            InstallResult  = $inResult.ResultCode
            RebootRequired = $rebootRequired
            Succeeded      = $succeeded
            Failed         = $failed
        }
    } catch {
        # Catch errors during COM operations (e.g., Access Denied if not elevated)
        throw "Windows Update install failed: $($_.Exception.Message)"
    }
}

# --- Initial reboot check ------------------------------------------------------
# Perform an initial check for pending reboot status
$rebootPendingBefore = Get-PendingReboot
if ($rebootPendingBefore) {
    Write-Verbose "Reboot is pending before we start."
}

# --- Main flow -----------------------------------------------------------------
try {
    # 1. Invoke the WUA scan
    $scan = Invoke-WindowsUpdateScan

    if ($CheckOnly) {
        # Mode: CheckOnly
        
        # Check 1: If a reboot was already pending.
        if ($rebootPendingBefore) {
            Write-Verbose "Reboot pending detected. Exiting with code 11 if no updates are found, otherwise code 10."
            # If a reboot is pending AND there are no updates found, exit with code 11.
            if ($scan.Count -eq 0) {
                Write-Host "RESULT: No updates found, but a reboot is pending."
                exit 11
            }
        }

        # Check 2: Report updates found (if scan count > 0) and exit with code 10.
        if ($scan.Count -gt 0) {
            Write-Host "RESULT: $($scan.Count) update(s) available."
            if ($VerboseOutput -and $scan.Titles.Count -gt 0) {
                Write-Host "Available updates:"
                # Output update titles in verbose mode
                $scan.Titles | ForEach-Object { Write-Host " - $_" }
            }
            exit 10
        } 
        # Check 3: No updates found and no reboot pending, exit with code 0.
        else {
            Write-Host "RESULT: No updates found."
            exit 0
        }
    }
    else {
        # Mode: Install
        $overallRebootNeeded = $rebootPendingBefore
        $installedAnything = $false

        if ($scan.Count -gt 0) {
            Write-Verbose "Found $($scan.Count) update(s) to install."
            # Perform the download and install operation
            $result = Install-WindowsUpdates -Updates $scan.Updates

            if ($result.Succeeded.Count -gt 0) {
                $installedAnything = $true
                Write-Host "RESULT: Installed $($result.Succeeded.Count) update(s)."
                if ($VerboseOutput) {
                    Write-Host "Installed:"
                    # Output successfully installed titles
                    $result.Succeeded | ForEach-Object { Write-Host " - $_" }
                }
            }
            if ($result.Failed.Count -gt 0) {
                # Installation failure likely indicates missing Admin rights or an environmental issue
                Write-Warning "The following updates failed: (This often indicates missing Administrator rights.)"
                $result.Failed | ForEach-Object { Write-Warning " - $_" }
            }
            if ($result.RebootRequired) {
                $overallRebootNeeded = $true
                Write-Verbose "Installer reports a reboot is required."
            }
        } else {
            Write-Host "RESULT: No updates found to install."
        }

        # Final check for reboot state after the installation phase
        if (-not $overallRebootNeeded) {
            $overallRebootNeeded = Get-PendingReboot
        }

        # --- Final Reboot Logic and Exit Codes for Install Mode ---
        if ($overallRebootNeeded) {
            Write-Host "RESULT: Reboot required."
            if ($AutoReboot) {
                # Initiate system reboot (requires Admin rights)
                Write-Verbose "AutoReboot=true; initiating reboot in 60 seconds. (This command requires Administrator rights.)"
                shutdown.exe /r /t 60 /c "Windows Updates installed. Reboot scheduled by AutoWindowsUpdate.ps1."
            }
            # Exit with code 2: Reboot required
            exit 2
        } else {
            if ($installedAnything) {
                # Exit with code 1: Updates installed, no reboot required
                exit 1
            } else {
                # Exit with code 0: Nothing was installed and no reboot is pending
                exit 0
            }
        }
    }
}
catch {
    # Global exception handler for COM/HRESULT errors
    Write-Error $_.Exception.Message
    Write-Host "RESULT: Windows Update failed."
    # Exit with code 40: Generic script/Windows Update failure
    exit 40
}