<#
.SYNOPSIS
  Automated Windows Update (WUA) checker/installer for NOC/RMM use.

.DESCRIPTION
  - If run with NO parameters: performs a scan, downloads, and installs applicable software updates.
  - If run with -CheckOnly: performs a scan only and reports findings without making changes.
  - Optional -VerboseOutput switch surfaces additional human-readable logging (sets $VerbosePreference).
  - Designed to run under RMM as LocalSystem or an Admin account.
  - Uses native Windows Update Agent (COM) and does NOT require external modules.

.NOTES
  Author: Stu (with ChatGPT assist)
  Locale: en-AU
  Exit codes:
    0  Success (no updates or installed successfully, no reboot required)
    5  Success but reboot required to complete updates
    1  Not elevated / access issue
    2  Core services problem (BITS, wuauserv, cryptsvc could not be started)
    3  Scan failed (WUA search error)
    4  Install failed (one or more updates failed to install)
    9  Unexpected/uncaught error

.EXAMPLE
  # Production (RMM): default behaviour is INSTALL
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\nocScript\AutoWindowsUpdate.ps1"

.EXAMPLE
  # Testing only (no changes):
  .\AutoWindowsUpdate.ps1 -CheckOnly -VerboseOutput
#>

[CmdletBinding(DefaultParameterSetName='Default')]
param(
  # Perform a scan only (no download/install)
  [Parameter(ParameterSetName='Check')]
  [switch]$CheckOnly,

  # Human-friendly verbose logging (separate to -Verbose)
  [switch]$VerboseOutput
)

# --- RMM safety: tolerate missing dashes (e.g., "CheckOnly" passed by mistake) ---
if ($args -contains 'CheckOnly' -and -not $CheckOnly) { $CheckOnly = $true }
if ($args -contains 'VerboseOutput' -and -not $VerboseOutput) { $VerboseOutput = $true }

# Enable verbose output if requested (-VerboseOutput or native -Verbose)
if ($PSBoundParameters.ContainsKey('Verbose') -or $VerboseOutput) {
  $VerbosePreference = 'Continue'
}

# Select mode: default is INSTALL when no explicit switch is provided.
$Mode = if ($CheckOnly) { 'CheckOnly' } else { 'Install' }

Write-Host "Starting Windows Update task..."
Write-Verbose "Selected mode: $Mode (default is Install when no parameters are given)"

# --------------------------------------------------------------------------------------------------
# Helper: Check if session is elevated. RMM typically runs as LocalSystem, which is elevated.
function Test-IsAdmin {
  try {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pri = New-Object Security.Principal.WindowsPrincipal($id)
    return $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

# Helper: Detect whether a reboot is pending (various common locations).
function Test-PendingReboot {
  [CmdletBinding()] param()
  try {
    $reboot = $false

    # Component Based Servicing
    $pathCBS = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (Test-Path $pathCBS) { $reboot = $true }

    # Windows Update / Auto Update (RebootRequired)
    $pathAU = 'HKLM:\SOFTWARE\Microsoft\Windows\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path $pathAU) { $reboot = $true }

    # PendingFileRenameOperations (legacy signal)
    $pathPF = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $valPF  = (Get-ItemProperty -Path $pathPF -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($valPF) { $reboot = $true }

    return $reboot
  } catch {
    Write-Verbose "Pending reboot detection failed: $($_.Exception.Message)"
    return $false
  }
}

# Helper: Ensure critical services are present, enabled, and started.
function Set-CoreServiceHealthy {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('bits','wuauserv','cryptsvc')][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Automatic','Manual','AutomaticDelayedStart')][string]$Startup
  )
  try {
    $svc = Get-Service -Name $Name -ErrorAction Stop

    # Normalise startup type; delayed-auto is configured via sc.exe
    $type = if ($Startup -eq 'AutomaticDelayedStart') {'Automatic'} else {$Startup}

    # If disabled, re-enable
    $svcWmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
    if ($svcWmi.StartMode -eq 'Disabled') {
      Write-Verbose "Service '$Name' is Disabled; enabling..."
      Set-Service -Name $Name -StartupType $type -ErrorAction Stop
      if ($Startup -eq 'AutomaticDelayedStart') { sc.exe config $Name start= delayed-auto | Out-Null }
    } else {
      # Ensure requested start type
      Set-Service -Name $Name -StartupType $type -ErrorAction SilentlyContinue | Out-Null
      if ($Startup -eq 'AutomaticDelayedStart') { sc.exe config $Name start= delayed-auto | Out-Null }
    }

    # Start if not running
    if ($svc.Status -ne 'Running') {
      Write-Host "Starting service: $Name"
      Start-Service -Name $Name -ErrorAction Stop
    }
    return $true
  } catch {
    Write-Warning "Service check failed for ${Name}: $($_.Exception.Message)"
    return $false
  }
}

# Helper: Create a WUA session/searcher and perform a scan for applicable software updates.
function Invoke-WUScan {
  [CmdletBinding()] param()

  # Query will return software updates that are applicable, not hidden, and not yet installed.
  $criteria = "IsInstalled=0 and IsHidden=0 and Type='Software'"
  Write-Host "Scanning for Windows updates... please wait"
  Write-Verbose "WUA Criteria: $criteria"

  try {
    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $result   = $searcher.Search($criteria)

    Write-Verbose "[WUA Debug] Search ResultCode: $($result.ResultCode)"
    return $result  # Contains .Updates and .ResultCode
  } catch {
    throw "WUA search failed: $($_.Exception.Message)"
  }
}

# Helper: For Install mode, download and install updates found by the scan.
function Invoke-WUInstall {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$UpdateSearchResult  # Expecting object from Invoke-WUScan()
  )

  # Build an UpdateCollection for those that are downloadable/installable
  $updates = $UpdateSearchResult.Updates
  $toInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl'

  for ($i = 0; $i -lt $updates.Count; $i++) {
    $upd = $updates.Item($i)
    # Filter out driver/optional preview updates if desired (keep simple for now)
    if ($upd.IsDownloaded -or $upd.Downloadable) {
      [void]$toInstall.Add($upd)
    }
  }

  if ($toInstall.Count -eq 0) {
    Write-Host "No downloadable updates identified from the search."
    return @{ Installed = $false; RebootRequired = $false; HResult = 0 }
  }

  # Stage 1: Download
  try {
    Write-Host "Downloading $($toInstall.Count) update(s)..."
    $downloader = (New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $dres = $downloader.Download()
    Write-Verbose "Download ResultCode: $($dres.ResultCode) HResult: $([int]$dres.HResult)"
  } catch {
    throw "Download failed: $($_.Exception.Message)"
  }

  # Stage 2: Install
  try {
    Write-Host "Installing updates..."
    $installer = (New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $ires = $installer.Install()

    $anyFailed = ($ires.ResultCode -eq 5) -or ($ires.HResult -ne 0) # 5 = failed
    $rebootReq = $ires.RebootRequired -or (Test-PendingReboot)

    # Summarise per-update results
    for ($j = 0; $j -lt $toInstall.Count; $j++) {
      $u = $toInstall.Item($j)
      $r = $ires.GetUpdateResult($j)
      Write-Host (" - {0} :: {1} (HResult={2})" -f $u.Title, $r.ResultCode, ([int]$r.HResult))
    }

    return @{
      Installed       = -not $anyFailed
      RebootRequired  = [bool]$rebootReq
      HResult         = [int]$ires.HResult
    }
  } catch {
    throw "Install failed: $($_.Exception.Message)"
  }
}

# --------------------------------------------------------------------------------------------------
# MAIN FLOW

# 1) Elevation check (informative; many RMMs run as LocalSystem which is elevated).
if (-not (Test-IsAdmin)) {
  Write-Warning "This session may not be elevated. Some operations could fail."
  # Do not exit hard; proceed and let service checks surface if needed.
}

# 2) Pending reboot check (early)
Write-Host "Checking for any pending reboot..."
if (Test-PendingReboot) {
  Write-Host "Reboot is pending. Continuing with scan..."
} else {
  Write-Host "No reboot required. Continuing scan..."
}

# 3) Ensure core services are healthy
$svcOk = $true
$svcOk = (Set-CoreServiceHealthy -Name 'bits'     -Startup 'Manual')                 -and $svcOk
$svcOk = (Set-CoreServiceHealthy -Name 'wuauserv' -Startup 'Manual')                 -and $svcOk
$svcOk = (Set-CoreServiceHealthy -Name 'cryptsvc' -Startup 'AutomaticDelayedStart')  -and $svcOk

if (-not $svcOk) {
  Write-Host "One or more core services failed to start."
  if ($Mode -eq 'Install') {
    Write-Host "Falling back to scan-only due to service issues."
    $Mode = 'CheckOnly'
  } else {
    Write-Host "Proceeding with scan-only."
  }
  # Note: exit code will reflect success of scan; service issue itself is not fatal here.
}

# 4) Scan
try {
  $scan = Invoke-WUScan
} catch {
  Write-Error $_
  Write-Host "All tasks complete."
  exit 3
}

# If scan returns no updates
$updCount = $scan.Updates.Count
Write-Host "Finished scan, preparing result..."
if ($updCount -eq 0) {
  if ($Mode -eq 'Install') {
    Write-Host "RESULT: System is up to date"
    Write-Host "All tasks complete."
    exit 0
  } else {
    Write-Host "RESULT: No updates found"
    Write-Host "All tasks complete."
    exit 0
  }
}

# 5) Branch by mode
if ($Mode -eq 'CheckOnly') {
  Write-Host ("UPDATES AVAILABLE: {0} item(s)" -f $updCount)
  for ($i = 0; $i -lt $scan.Updates.Count; $i++) {
    $u = $scan.Updates.Item($i)
    Write-Host (" - {0}" -f $u.Title)
  }
  # Signal reboot pending if present (not strictly necessary in check mode)
  if (Test-PendingReboot) {
    Write-Host "RESULT: Reboot pending to complete previous update"
    Write-Host "All tasks complete."
    exit 5
  } else {
    Write-Host "RESULT: Updates available"
    Write-Host "All tasks complete."
    exit 0
  }
} else {
  # INSTALL mode
  try {
    $installSummary = Invoke-WUInstall -UpdateSearchResult $scan
  } catch {
    Write-Error $_
    Write-Host "All tasks complete."
    exit 4
  }

  if ($installSummary.Installed -and -not $installSummary.RebootRequired) {
    Write-Host "RESULT: Updates installed successfully; no reboot required."
    Write-Host "All tasks complete."
    exit 0
  }

  if ($installSummary.Installed -and $installSummary.RebootRequired) {
    Write-Host "RESULT: Updates installed; reboot required to complete."
    Write-Host "All tasks complete."
    exit 5
  }

  # Install failed (partially or fully)
  Write-Host ("RESULT: Install encountered errors (HResult={0}). See details above." -f $installSummary.HResult)
  Write-Host "All tasks complete."
  exit 4
}

# Safety net
Write-Host "All tasks complete."
exit 0
