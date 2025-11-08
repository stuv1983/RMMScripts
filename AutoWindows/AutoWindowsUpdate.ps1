<#
## Version: 2025-11-08 NonAdmin/AMP-friendly v1.3 (Admin Check Removed)
.SYNOPSIS
    Windows Update helper for RMM use (N-able AMP/Automation Manager, etc.).
    Accepts "true"/"false" strings from RMM as well as PowerShell booleans.

.DESCRIPTION
    - Designed to work with RMMs that pass parameters as strings ("true"/"false").
    - Two modes:
        * CheckOnly: scan and report available updates, do not download/install.
        * Install  : scan, download, install updates. Optional AutoReboot.
    - Prints clear RESULT lines for dashboards/ticket notes.
    - Returns exit codes for policy/alert handling (see Exit Codes).
    - Verbose output toggled using -VerboseOutput true|false.
    - NOTE: While CheckOnly mode may work without elevation, Install mode typically REQUIRES admin rights.

.PARAMETER CheckOnly
    String/Boolean. If true, only performs a scan and reports findings. Mutually exclusive with -Install.

.PARAMETER Install
    String/Boolean. If true, scans and installs updates. Mutually exclusive with -CheckOnly.

.PARAMETER AutoReboot
    String/Boolean. If true (and Install is true), the script will reboot automatically when required.

.PARAMETER VerboseOutput
    String/Boolean. If true, enables detailed progress messages (Write-Verbose).

.EXIT CODES
    0  - Success. No updates available and no reboot required.
    1  - Success. Updates installed, no reboot required.
    2  - Success. Reboot required (either pending prior to run or required after install).
    10 - CheckOnly: updates available.
    11 - CheckOnly: reboot pending (detected before scan).
    20 - Core services failed to start (BITS/WUAUSERV/CRYPTSVC).
    40 - Windows Update failure (exception thrown).

.EXAMPLES
    .\AutoWindowsUpdate.ps1 -CheckOnly true -VerboseOutput true
    .\AutoWindowsUpdate.ps1 -Install true -VerboseOutput true
    .\AutoWindowsUpdate.ps1 -Install true -AutoReboot true -VerboseOutput true
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
    .DESCRIPTION
        Accepts $null, [bool], numbers, or strings such as "true"/"false", "1"/"0".
    .PARAMETER Value
        Input value to convert.
    .OUTPUTS
        [bool]
    #>
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        # Numbers: treat non-zero as true
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }
        # Strings: normalize
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

$CheckOnly     = Convert-ToBool $CheckOnly
$Install       = Convert-ToBool $Install
$AutoReboot    = Convert-ToBool $AutoReboot
$VerboseOutput = Convert-ToBool $VerboseOutput

# Normalise verbose preference (no need to use -Verbose switch)
$VerbosePreference = if ($VerboseOutput) { 'Continue' } else { 'SilentlyContinue' }

# --- Safety / sanity checks ----------------------------------------------------
# Mutually exclusive mode validation
if ($CheckOnly -and $Install) {
    throw "Choose one mode only: set either -CheckOnly true OR -Install true (not both)."
}

# Default behaviour when neither is specified: default to Install.
if (-not $CheckOnly -and -not $Install) {
    Write-Verbose "No mode specified; defaulting to Install."
    $Install = $true
}

# AutoReboot is irrelevant when only checking
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

        # Component Based Servicing
        $keyCBS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path $keyCBS) { $pending = $true }

        # Windows Update Auto Update reboot required
        $keyWUAU = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $keyWUAU) { $pending = $true }

        # PendingFileRenameOperations
        $keyPFRO = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $valPFRO = (Get-ItemProperty -Path $keyPFRO -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($valPFRO) { $pending = $true }

        return [bool]$pending
    } catch {
        Write-Verbose "Get-PendingReboot check failed: $($_.Exception.Message)"
        return $false
    }
}

function Start-RequiredService {
    <#
    .SYNOPSIS
        Ensures a service is running; attempts to start if stopped.
    .PARAMETER Name
        Service name (not display name), e.g., 'bits'.
    .OUTPUTS
        [bool] True if service is running at end of function; False otherwise.
    #>
    param([Parameter(Mandatory)][string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop

        if ($svc.Status -ne 'Running') {
            Write-Verbose "Starting service: $Name"
            Start-Service -Name $Name -ErrorAction Stop

            # Wait briefly to confirm it is running
            for ($i = 0; $i -lt 20; $i++) {
                $svc.Refresh()
                if ($svc.Status -eq 'Running') { break }
                Start-Sleep -Seconds 1
            }
        }

        # Refresh and confirm
        $svc.Refresh()
        if ($svc.Status -ne 'Running') {
            Write-Host "Service check failed for ${Name}: status is $($svc.Status)"
            return $false
        }
        return $true
    } catch {
        Write-Host "Service check failed for ${Name}: $($_.Exception.Message)"
        return $false
    }
}

function Ensure-CoreServices {
    <#
    .SYNOPSIS
        Ensures core update services are available.
    .DESCRIPTION
        - In Install mode: attempts to start and ENFORCES running state for BITS/WUAUSERV/CRYPTSVC.
        - In CheckOnly mode: reports status and CONTINUES without enforcing (no exit).
    .PARAMETER Enforce
        [bool] If true, enforce and return $false on any failure; if false, do not enforce.
    .OUTPUTS
        [bool] True if services are OK (or not enforced); False only when Enforce=$true and a start/check fails.
    #>
    param([bool]$Enforce)

    $ok = $true
    foreach ($svc in @('bits','wuauserv','cryptsvc')) {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            if ($Enforce) {
                # Attempt to start service (requires Admin rights)
                if (-not (Start-RequiredService -Name $svc)) { $ok = $false }
            } else {
                # Non-enforcing: just report status if not running
                if ($s.Status -ne 'Running') {
                    Write-Verbose "Service $svc is not running (non-enforced mode). Proceeding with best-effort scan."
                }
            }
        } catch {
            if ($Enforce) {
                Write-Host "Service check failed for ${svc}: $($_.Exception.Message)"
                $ok = $false
            } else {
                Write-Verbose "Service $svc status query failed (best-effort scan will continue): $($_.Exception.Message)"
            }
        }
    }
    return $ok
}


function Invoke-WindowsUpdateScan {
    <#
    .SYNOPSIS
        Uses WUA COM API to scan for available software updates.
    .OUTPUTS
        [PSCustomObject] with properties:
            - Updates       : IUpdateCollection (available updates)
            - Count         : [int] number of updates
            - Titles        : [string[]] update titles for easy display
    #>
    try {
        Write-Verbose "Scanning for Windows updates... please wait"
        # Note: New-Object -ComObject 'Microsoft.Update.Session' typically works without admin rights for scanning.
        $session   = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher  = $session.CreateUpdateSearcher()
        $criteria  = "IsInstalled=0 and IsHidden=0 and Type='Software'"
        Write-Verbose "WUA Criteria: $criteria"

        $result    = $searcher.Search($criteria)
        Write-Verbose "[WUA Debug] Search ResultCode: $($result.ResultCode) (2=Succeeded)"
        $updates   = $result.Updates

        $titles = @()
        for ($i = 0; $i -lt $updates.Count; $i++) {
            $titles += $updates.Item($i).Title
        }

        return [PSCustomObject]@{
            Updates = $updates
            Count   = [int]$updates.Count
            Titles  = $titles
        }
    } catch {
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
            if ($u.EulaAccepted -eq $false) {
                Write-Verbose "Accepting EULA for: $($u.Title)"
                $u.AcceptEula()
            }
            # Add to collection
            [void]$toInstall.Add($u)
        }

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

        # Download
        Write-Verbose "Downloading $($toInstall.Count) update(s)..."
        $downloader.Updates = $toInstall
        $dlResult = $downloader.Download()
        Write-Verbose "Download result: $($dlResult.ResultCode) (2=Succeeded)"

        # Install
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
            if ($hr -eq 0) { $succeeded += $u.Title } else { $failed += $u.Title }
        }

        return [PSCustomObject]@{
            DownloadResult = $dlResult.ResultCode
            InstallResult  = $inResult.ResultCode
            RebootRequired = $rebootRequired
            Succeeded      = $succeeded
            Failed         = $failed
        }
    } catch {
        throw "Windows Update install failed: $($_.Exception.Message)"
    }
}

# --- Core service pre-checks ---------------------------------------------------
# In CheckOnly: best-effort (no enforcement). In Install: enforce services running (which requires Admin).
$servicesOk = if ($CheckOnly) { Ensure-CoreServices -Enforce:$false } else { Ensure-CoreServices -Enforce:$true }
if (-not $servicesOk -and -not $CheckOnly) {
    Write-Host "RESULT: One or more core services failed to start. (Installation requires Administrator rights.)"
    exit 20
}

# --- Initial reboot check (so RMM can see prior state) -------------------------
$rebootPendingBefore = Get-PendingReboot
if ($rebootPendingBefore) {
    Write-Verbose "Reboot is pending before we start."
}

# --- Main flow -----------------------------------------------------------------
try {
    $scan = Invoke-WindowsUpdateScan

    if ($CheckOnly) {
        # Mode: CheckOnly
        if ($rebootPendingBefore) {
            Write-Verbose "Reboot pending detected. Exiting with code 11 if no updates are found, otherwise code 10."
            # If a reboot is pending and there are no updates, exit with 11.
            if ($scan.Count -eq 0) {
                Write-Host "RESULT: No updates found, but a reboot is pending."
                exit 11
            }
        }

        if ($scan.Count -gt 0) {
            Write-Host "RESULT: $($scan.Count) update(s) available."
            if ($VerboseOutput -and $scan.Titles.Count -gt 0) {
                Write-Host "Available updates:"
                $scan.Titles | ForEach-Object { Write-Host " - $_" }
            }
            exit 10
        } else {
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
            $result = Install-WindowsUpdates -Updates $scan.Updates
            if ($result.Succeeded.Count -gt 0) {
                $installedAnything = $true
                Write-Host "RESULT: Installed $($result.Succeeded.Count) update(s)."
                if ($VerboseOutput) {
                    Write-Host "Installed:"
                    $result.Succeeded | ForEach-Object { Write-Host " - $_" }
                }
            }
            if ($result.Failed.Count -gt 0) {
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

        # Confirm reboot state after install
        if (-not $overallRebootNeeded) {
            $overallRebootNeeded = Get-PendingReboot
        }

        # Reboot logic
        if ($overallRebootNeeded) {
            Write-Host "RESULT: Reboot required."
            if ($AutoReboot) {
                Write-Verbose "AutoReboot=true; initiating reboot in 60 seconds. (This command requires Administrator rights.)"
                shutdown.exe /r /t 60 /c "Windows Updates installed. Reboot scheduled by AutoWindowsUpdate.ps1."
            }
            exit 2
        } else {
            if ($installedAnything) {
                exit 1
            } else {
                exit 0
            }
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    Write-Host "RESULT: Windows Update failed."
    exit 40
}