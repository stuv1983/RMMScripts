<#
.SYNOPSIS
  AVCheck.ps1 — Endpoint antivirus and Microsoft Defender health check.

.DESCRIPTION
  Provides an RMM-friendly full (multi-line) output by default, plus optional JSON output for ingestion.

  Checks:
    1) Installed AV products (via Windows Security Center inventory)
    2) Real-time protection and signature health (best effort for non-Defender AV)
    3) Microsoft Defender Antivirus posture (via Get-MpComputerStatus)
    4) Scan recency (quick/full) for Defender if timestamps available
    5) Defender for Endpoint (MDE) Sense service presence/onboarding hints (best effort)

.NOTES
  - WSC (root\SecurityCenter2) productState decoding is not consistently documented across
    vendors/OS versions. This script treats derived RT/definition status as hints only
    and preserves raw/hex values for auditability.
  - Intended for MSP/RMM use: stable output and predictable exit codes.

#>

#region Globals / Parameters

[CmdletBinding()]
param(
  [switch]$AsJson,
  [switch]$DebugMode
)

$ErrorActionPreference = 'Stop'
$script:DebugBuffer = New-Object System.Collections.Generic.List[string]

# Record script start time for runtime telemetry (useful for RMM timeouts / slow endpoints).
$ScriptStart = Get-Date

# -----------------------------------------------------------------------------
# Allowed AV list (maintenance-friendly)
# -----------------------------------------------------------------------------
# Purpose:
#   In our environment, endpoints should only have Microsoft Defender Antivirus
#   and BitDefender (N-able managed). We still enumerate WSC products to detect
#   unexpected/leftover third-party AV installs (e.g., consumer AV, legacy agents).
#
# How it works:
#   - Windows Security Center (WSC) reports installed AV products in root\SecurityCenter2.
#   - We compare product DisplayName values against allowed regex patterns.
#   - Any non-allowed products are flagged as a WARNING issue: UNEXPECTED_AV_INSTALLED.
#
# Notes:
#   - This is intentionally WARNING (not CRITICAL) to avoid noisy false positives.
#   - Adjust patterns as required if Bitdefender branding strings change.
$AllowedAVNamePatterns = @(
  '(?i)^Microsoft Defender Antivirus$'
  '(?i)^Windows Defender$'
  '(?i)Defender'
  '(?i)^BitDefender \(N-able managed\)$'
  '(?i)^BitDefender\b'
  '(?i)Bitdefender'
)

#endregion Globals / Parameters

#region Helper Functions

function Add-Debug {
  param([string]$Message)
  if ($DebugMode) {
    $ts = (Get-Date).ToString('s')
    [void]$script:DebugBuffer.Add("$ts | $Message")
  }
}

function New-Issue {
  param(
    [Parameter(Mandatory = $true)][ValidateSet('Info','Warning','Critical')][string]$Severity,
    [Parameter(Mandatory = $true)][string]$Code,
    [Parameter(Mandatory = $true)][string]$Details,
    [Parameter(Mandatory = $true)][string]$Recommendation
  )
  return [pscustomobject]@{
    Severity       = $Severity
    Code           = $Code
    Details        = $Details
    Recommendation = $Recommendation
  }
}

function Decode-WscProductState {

  param(
    [Parameter(Mandatory = $true)][int]$ProductState
  )

  $hex = ('{0:X6}' -f ($ProductState -band 0xFFFFFF))
  $aa  = [Convert]::ToInt32($hex.Substring(0, 2), 16)
  $bb  = [Convert]::ToInt32($hex.Substring(2, 2), 16)
  $cc  = [Convert]::ToInt32($hex.Substring(4, 2), 16)

  # Best-effort mapping (commonly observed)
  $rtMap = @{
    0x00 = 'Off'
    0x10 = 'On'
    0x11 = 'Snoozed'
    0x12 = 'Expired'
  }

  $sigMap = @{
    0x00 = 'UpToDate'
    0x10 = 'OutOfDate'
    0x20 = 'Unknown'
  }

  $rtStatus  = $(if ($rtMap.ContainsKey($bb)) { $rtMap[$bb] } else { 'Unknown' })
  $sigStatus = $(if ($sigMap.ContainsKey($cc)) { $sigMap[$cc] } else { 'Unknown' })

  # Conservative booleans: only assert 'enabled' when we see the canonical 'On' value.
  $rtEnabled   = ($bb -eq 0x10)
  $sigUpToDate = ($cc -eq 0x00)

  return [pscustomobject]@{
    Raw                = $ProductState
    Hex                = '0x' + $hex
    ByteAA             = $aa
    ByteBB             = $bb
    ByteCC             = $cc
    RealtimeStatus     = $rtStatus
    DefinitionStatus   = $sigStatus
    RealtimeEnabled    = $rtEnabled
    SignaturesUpToDate = $sigUpToDate
  }
}

#endregion Helper Functions

#region Data Collectors

function Get-WSCAVProducts {
  Add-Debug 'Get-WSCAVProducts: querying root/SecurityCenter2 AntiVirusProduct.'
  $out  = @()

  # Query Windows Security Center (WSC) inventory of AV products
  $list = @()
  try {
    $list = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop
  } catch {
    Add-Debug ("Get-WSCAVProducts: query failed: {0}" -f $_.Exception.Message)
    return @()
  }

  foreach ($p in $list) {
    $raw         = $p.productState
    $decoded     = $null
    $rtEnabled   = $false
    $sigUpToDate = $false

    if ($null -ne $raw) {
      # WSC productState is not consistently documented across vendors/OS versions.
      # Decode it as *best-effort* and keep raw/hex for auditing.
      $decoded = Decode-WscProductState -ProductState $raw

      $rtEnabled   = $decoded.RealtimeEnabled
      $sigUpToDate = $decoded.SignaturesUpToDate

      # Fallback hint (legacy bitmask) – retained for reference only.
      # Do NOT rely on this for hard alerting logic.
      $rtEnabledMask   = [bool]($raw -band 0x10)
      $sigUpToDateMask = [bool]($raw -band 0x100000)

      Add-Debug ("Get-WSCAVProducts: {0} state={1} ({2}) RT={3} (mask={4}) SigUpToDate={5} (mask={6})" -f `
        $p.displayName,
        $raw,
        $decoded.Hex,
        $rtEnabled,
        $rtEnabledMask,
        $sigUpToDate,
        $sigUpToDateMask
      )
    } else {
      Add-Debug ("Get-WSCAVProducts: {0} state=NULL" -f $p.displayName)
    }

    $out += [pscustomobject]@{
      DisplayName             = $p.displayName
      PathToSignedProductExe  = $p.pathToSignedProductExe
      ProductStateRaw         = $raw
      ProductStateHex         = $(if ($decoded) { $decoded.Hex } else { $null })
      ProductStateRealtime    = $(if ($decoded) { $decoded.RealtimeStatus } else { $null })
      ProductStateDefinitions = $(if ($decoded) { $decoded.DefinitionStatus } else { $null })
      RealTimeEnabled         = $rtEnabled
      SignaturesUpToDate      = $sigUpToDate
    }
  }

  return $out
}

function Get-DefenderStatus {
  Add-Debug 'Get-DefenderStatus: querying Get-MpComputerStatus.'
  $def = [pscustomobject]@{
    Present          = $false
    ServiceStatus    = $null
    SigUpToDate      = $null
    SigAgeHours      = $null
    RTEnabled        = $null
    AMProduct        = $null
    AMEngine         = $null
    QuickScanAgeDays = $null
    FullScanAgeDays  = $null
    Raw              = $null
  }

  # Check if Defender cmdlets are available
  if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
    Add-Debug 'Get-DefenderStatus: Get-MpComputerStatus not available.'
    return $def
  }

  try {
    $mp = Get-MpComputerStatus
    $def.Present = $true
    $def.Raw     = $mp

    # Service status is best checked via WinDefend service
    try {
      $svc = Get-Service -Name 'WinDefend' -ErrorAction Stop
      $def.ServiceStatus = $svc.Status.ToString()
    } catch {
      $def.ServiceStatus = 'Unknown'
    }

    $def.RTEnabled = [bool]$mp.RealTimeProtectionEnabled

    # Signature age calculation (hours)
    if ($mp.AntivirusSignatureLastUpdated) {
      $age = New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)
      $def.SigAgeHours = [math]::Round($age.TotalHours, 2)
      $def.SigUpToDate = ($def.SigAgeHours -le 48)  # default threshold, can be tuned
    }

    $def.AMProduct = $mp.AMProductVersion
    $def.AMEngine  = $mp.AMEngineVersion

    if ($mp.QuickScanEndTime) {
      $qsAge = New-TimeSpan -Start $mp.QuickScanEndTime -End (Get-Date)
      $def.QuickScanAgeDays = [math]::Round($qsAge.TotalDays, 2)
    }

    if ($mp.FullScanEndTime) {
      $fsAge = New-TimeSpan -Start $mp.FullScanEndTime -End (Get-Date)
      $def.FullScanAgeDays = [math]::Round($fsAge.TotalDays, 2)
    }

  } catch {
    Add-Debug ("Get-DefenderStatus: failed: {0}" -f $_.Exception.Message)
  }

  return $def
}

function Get-MDEStatus {

  Add-Debug 'Get-MDEStatus: checking Sense service and registry onboarding hints.'

  $mde = [pscustomobject]@{
    SensePresent = $false
    SenseStatus  = $null
    Onboarded    = $null
    Notes        = $null
  }

  try {
    $svc = Get-Service -Name 'Sense' -ErrorAction Stop
    $mde.SensePresent = $true
    $mde.SenseStatus  = $svc.Status.ToString()
  } catch {
    $mde.SensePresent = $false
    $mde.SenseStatus  = 'NotFound'
  }

  # Registry onboarding hint (best-effort)
  try {
    $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction Stop
    if ($null -ne $reg.OnboardingState) {
      $mde.Onboarded = ($reg.OnboardingState -eq 1)
    }
  } catch {
    $mde.Onboarded = $null
  }

  return $mde
}

#endregion Data Collectors

#region Output

function Write-AVOutput {
  param(
    [Parameter(Mandatory = $true)][pscustomobject]$Result,
    [switch]$AsJson,
    [switch]$DebugMode
  )

  # If JSON requested, emit structured object for ingestion
  if ($AsJson) {
    $Result | ConvertTo-Json -Depth 10
    return
  }

  # Full mode: multi-line output suitable for tickets / human review (DEFAULT)
  Write-Output ("Status: {0}" -f $Result.Severity)
  Write-Output ("Active AV: {0}" -f $Result.ActiveAV)
  Write-Output ("Installed AV: {0}" -f $Result.InstalledAV)
  Write-Output ("Real-time AV: {0}" -f $Result.RealTimeAV)
  Write-Output ("Signature Age (hours): {0}" -f $Result.Defender.SigAgeHours)
  Write-Output ("Elapsed Seconds: {0}" -f $Result.ElapsedSeconds)
  Write-Output ("Defender RT Enabled: {0}" -f $Result.Defender.RTEnabled)
  Write-Output ("Defender AMProduct: {0}" -f $Result.Defender.AMProduct)
  Write-Output ("Defender AMEngine: {0}" -f $Result.Defender.AMEngine)
  Write-Output ("Quick Scan Age (days): {0}" -f $Result.Defender.QuickScanAgeDays)
  Write-Output ("Full Scan Age (days): {0}" -f $Result.Defender.FullScanAgeDays)

  if ($Result.MDE) {
    Write-Output ("MDE Sense Present: {0}" -f $Result.MDE.SensePresent)
    Write-Output ("MDE Sense Status: {0}" -f $Result.MDE.SenseStatus)
    Write-Output ("MDE Onboarded: {0}" -f $Result.MDE.Onboarded)
  }

  Write-Output ""
  Write-Output "Issues:"
  if (-not $Result.Issues -or $Result.Issues.Count -eq 0) {
    Write-Output "  None"
  } else {
    foreach ($i in $Result.Issues) {
      Write-Output ("  - [{0}] {1}: {2}" -f $i.Severity, $i.Code, $i.Details)
      Write-Output ("      Recommendation: {0}" -f $i.Recommendation)
    }
  }

  if ($DebugMode) {
    Write-Output ""
    Write-Output "Debug:"
    foreach ($d in $script:DebugBuffer) {
      Write-Output ("  {0}" -f $d)
    }
  }
}

#endregion Output

#region Main Logic

# Collect data
$products = Get-WSCAVProducts
$def      = Get-DefenderStatus
$mde      = Get-MDEStatus

# Determine "active" AV (best effort)
$activeAV = 'Unknown'
$realTime = 'Unknown'

if ($def.Present -and $def.ServiceStatus -eq 'Running') {
  $activeAV = 'Microsoft Defender Antivirus'
  $realTime = $(if ($def.RTEnabled) { 'On' } else { 'Off' })
} elseif ($products -and $products.Count -gt 0) {
  # Prefer the first WSC product as "active" (WSC doesn't always mark a single "active" reliably)
  $activeAV = ($products[0].DisplayName)
  $realTime = $(if ($products[0].RealTimeEnabled) { 'On' } else { 'Off/Unknown' })
}

# Build installed AV summary (human-readable)
$installedAVNames = @()
if ($products -and $products.Count -gt 0) {
  $installedAVNames += ($products.DisplayName | Sort-Object -Unique)
}

# Add Defender to installed list if present and running (sometimes WSC inventory lags)
if ($def.Present -and $def.ServiceStatus -eq 'Running') {
  if (-not ($installedAVNames -like '*Defender*')) {
    $installedAVNames += 'Microsoft Defender Antivirus'
  }
}

$installedAV = $(if ($installedAVNames.Count -gt 0) { ($installedAVNames -join ', ') } else { 'None detected' })

# Issues evaluation
$issues = New-Object System.Collections.Generic.List[object]
$severity = 'OK'

# Detect unexpected third-party AV products (WSC inventory)
# We allow Defender + BitDefender (N-able managed). Anything else is flagged.
$unexpectedAV = @()
if ($products -and $products.Count -gt 0) {
  foreach ($name in ($products.DisplayName | Where-Object { $_ } | Sort-Object -Unique)) {
    $isAllowed = $false
    foreach ($pat in $AllowedAVNamePatterns) {
      if ($name -match $pat) { $isAllowed = $true; break }
    }
    if (-not $isAllowed) { $unexpectedAV += $name }
  }
}

if ($unexpectedAV.Count -gt 0) {
  $msg = "Unexpected AV product(s) detected via WSC: {0}" -f ($unexpectedAV -join ', ')
  [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'UNEXPECTED_AV_INSTALLED' -Details $msg -Recommendation 'Confirm the product is approved. If not, remove/uninstall the unexpected AV to avoid conflicts and false alerts.'))
  if ($severity -ne 'Critical') { $severity = 'Warning' }
}

# Defender checks unchanged (below)
# Defender signature / RT checks (only if Defender present)
if ($def.Present) {

  if ($def.ServiceStatus -ne 'Running') {
    [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'DEF_SERVICE_STOPPED' -Details "WinDefend service status: $($def.ServiceStatus)" -Recommendation 'Start the WinDefend service and ensure it is not disabled by policy.'))
    $severity = 'Critical'
  }

  if ($def.RTEnabled -eq $false) {
    [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'DEF_REALTIME_OFF' -Details 'Microsoft Defender real-time protection is disabled.' -Recommendation 'Enable real-time protection via policy or local settings; confirm no third-party AV is disabling it.'))
    $severity = 'Critical'
  }

  if ($null -ne $def.SigUpToDate -and $def.SigUpToDate -eq $false) {
    [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_SIG_OLD' -Details "Defender signatures appear older than expected (SigAgeHours=$($def.SigAgeHours))." -Recommendation 'Trigger a signature update and confirm endpoint connectivity to update sources.'))
    if ($severity -ne 'Critical') { $severity = 'Warning' }
  }
}

# MDE hints (non-fatal by default)
if ($mde -and $mde.SensePresent) {
  if ($mde.SenseStatus -ne 'Running') {
    [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'MDE_SENSE_NOT_RUNNING' -Details 'Sense service present but not running.' -Recommendation 'Check onboarding status, service startup type, and tenant connectivity.'))
    if ($severity -ne 'Critical') { $severity = 'Warning' }
  }
}

# Total execution time (seconds)
$ElapsedSeconds = [math]::Round(((Get-Date) - $ScriptStart).TotalSeconds, 2)

# Compose result
$result = [pscustomobject]@{
  Severity       = $severity
  ActiveAV       = $activeAV
  InstalledAV    = $installedAV
  RealTimeAV     = $realTime
  Defender       = $def
  MDE            = $mde
  Products       = $products
  Issues         = $issues
  ElapsedSeconds = $ElapsedSeconds
}

# Output (FULL by default, JSON only if -AsJson)
Write-AVOutput -Result $result -AsJson:$AsJson -DebugMode:$DebugMode

# Exit codes: 0 OK, 1 Warning, 2 Critical
switch ($result.Severity) {
  'OK'       { exit 0 }
  'Warning'  { exit 1 }
  'Critical' { exit 2 }
  default    { exit 0 }
}

#endregion Main Logic
