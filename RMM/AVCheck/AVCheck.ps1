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

.PARAMETER AsJson
  Emit structured JSON output instead of human-readable multi-line text.

.PARAMETER DebugMode
  Include timestamped debug trace in output.

.PARAMETER SigAgeThresholdHours
  Maximum acceptable Defender signature age in hours before raising DEF_SIG_OLD. Default: 48.

.PARAMETER QuickScanThresholdDays
  Maximum acceptable quick scan age in days before raising DEF_QUICKSCAN_STALE. Default: 7.

.PARAMETER FullScanThresholdDays
  Maximum acceptable full scan age in days before raising DEF_FULLSCAN_STALE. Default: 30.
  Set to 0 to disable full-scan age alerting.

.NOTES
    Name:       AVCheck.ps1
    Author:     Stu Villanti (s.villanti@kenstra.com.au)
    Version:    6.0

#>

#region Globals / Parameters

[CmdletBinding()]
param(
  [switch]$AsJson,
  [switch]$DebugMode,
  # FIX #6: Tunable thresholds exposed as parameters instead of hardcoded values.
  [int]$SigAgeThresholdHours   = 48,
  [int]$QuickScanThresholdDays = 7,
  [int]$FullScanThresholdDays  = 30
)

$ErrorActionPreference = 'Stop'
$script:DebugBuffer = New-Object System.Collections.Generic.List[string]

# Record script start time for runtime telemetry (useful for RMM timeouts / slow endpoints).
$ScriptStart = Get-Date

# -----------------------------------------------------------------------------
# Allowed AV list
# -----------------------------------------------------------------------------

$AllowedAVNamePatterns = @(
  '(?i)^Managed Antivirus Antimalware$'
  '(?i)^Microsoft Defender Antivirus$'
  '(?i)^Windows Defender$'
  '(?i)Defender'
  '(?i)^BitDefender \(N-able managed\)$'
  '(?i)^BitDefender\b'
  '(?i)Bitdefender'
)

# -----------------------------------------------------------------------------
# Managed AV (Bitdefender) detection patterns
# -----------------------------------------------------------------------------
# Used to short-circuit Defender health checks when Bitdefender is the intended
# primary AV for the client. Defender being "off" and signatures "out of date"
# can be expected when a third-party AV is controlling protection.
$ManagedAVNamePatterns = @(
  '(?i)^Managed Antivirus Antimalware$'
  '(?i)Bitdefender'
  '(?i)Managed Antivirus'
  '(?i)Managed AV'
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

# FIX #8: Renamed from Decode-WscProductState to use an approved PowerShell verb.
function ConvertFrom-WscProductState {

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

function Test-NameMatchesAnyPattern {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string[]]$Patterns
  )

  foreach ($pat in $Patterns) {
    if ($Name -match $pat) { return $true }
  }
  return $false
}

#endregion Helper Functions

#region Data Collectors

function Get-WSCAVProducts {
  Add-Debug 'Get-WSCAVProducts: querying root/SecurityCenter2 AntiVirusProduct.'

  # FIX #7: Use a Generic List instead of += array concatenation to avoid repeated
  # array allocation on each iteration.
  $out = New-Object System.Collections.Generic.List[object]

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
      # FIX #8: Updated call site to use renamed function.
      $decoded = ConvertFrom-WscProductState -ProductState $raw

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

    [void]$out.Add([pscustomobject]@{
      DisplayName             = $p.displayName
      PathToSignedProductExe  = $p.pathToSignedProductExe
      ProductStateRaw         = $raw
      ProductStateHex         = $(if ($decoded) { $decoded.Hex } else { $null })
      ProductStateRealtime    = $(if ($decoded) { $decoded.RealtimeStatus } else { $null })
      ProductStateDefinitions = $(if ($decoded) { $decoded.DefinitionStatus } else { $null })
      RealTimeEnabled         = $rtEnabled
      SignaturesUpToDate      = $sigUpToDate
    })
  }

  return $out.ToArray()
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

    # FIX #3: Guard against the default DateTime (year 1/1/0001) returned by Defender
    # when signatures have never been updated, which would produce a misleadingly
    # enormous age value with no issue raised.
    if ($mp.AntivirusSignatureLastUpdated -and $mp.AntivirusSignatureLastUpdated.Year -gt 2000) {
      $age = New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)
      $def.SigAgeHours = [math]::Round($age.TotalHours, 2)
      $def.SigUpToDate = ($def.SigAgeHours -le $SigAgeThresholdHours)
    } else {
      # Timestamp is absent or epoch default — treat as unknown/never updated.
      $def.SigAgeHours = $null
      $def.SigUpToDate = $false
      Add-Debug 'Get-DefenderStatus: AntivirusSignatureLastUpdated is absent or default epoch; treating signatures as not up to date.'
    }

    $def.AMProduct = $mp.AMProductVersion
    $def.AMEngine  = $mp.AMEngineVersion

    # FIX #3: Guard QuickScanEndTime against default DateTime before calculating age.
    if ($mp.QuickScanEndTime -and $mp.QuickScanEndTime.Year -gt 2000) {
      $qsAge = New-TimeSpan -Start $mp.QuickScanEndTime -End (Get-Date)
      $def.QuickScanAgeDays = [math]::Round($qsAge.TotalDays, 2)
    } else {
      $def.QuickScanAgeDays = $null
      Add-Debug 'Get-DefenderStatus: QuickScanEndTime is absent or default epoch; quick scan age unavailable.'
    }

    # FIX #3: Guard FullScanEndTime against default DateTime before calculating age.
    if ($mp.FullScanEndTime -and $mp.FullScanEndTime.Year -gt 2000) {
      $fsAge = New-TimeSpan -Start $mp.FullScanEndTime -End (Get-Date)
      $def.FullScanAgeDays = [math]::Round($fsAge.TotalDays, 2)
    } else {
      $def.FullScanAgeDays = $null
      Add-Debug 'Get-DefenderStatus: FullScanEndTime is absent or default epoch; full scan age unavailable.'
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
    # FIX #9: Notes field is now populated with a meaningful hint instead of left as dead $null.
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
    } else {
      # FIX #9: Populate Notes when onboarding state key is present but value is null.
      $mde.Notes = 'Registry key present but OnboardingState value is null; onboarding state indeterminate.'
    }
  } catch {
    $mde.Onboarded = $null
    # FIX #9: Populate Notes when registry path is absent (common on non-MDE endpoints).
    $mde.Notes = 'MDE registry path not found; endpoint is likely not onboarded to Defender for Endpoint.'
  }

  return $mde
}

#endregion Data Collectors

#region Output

function Write-AVOutput {
  param(
    [Parameter(Mandatory = $true)][pscustomobject]$Result
    # FIX #11: Removed redundant [switch]$AsJson and [switch]$DebugMode parameters.
    # $AsJson and $DebugMode are script-scoped and accessed directly below,
    # and $script:DebugBuffer is already script-scoped. Passing them as params
    # was redundant and created a confusing shadow of the outer variables.
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
    if ($Result.MDE.Notes) {
      Write-Output ("MDE Notes: {0}" -f $Result.MDE.Notes)
    }
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

# FIX #5: Wrap entire main logic in a top-level try/catch so that any unexpected
# exception (WMI provider crash, permission failure, etc.) still produces structured
# output and a non-zero exit code rather than a bare terminating error with no result.
try {

  # Collect data
  $products = Get-WSCAVProducts
  $def      = Get-DefenderStatus
  $mde      = Get-MDEStatus

  # ---------------------------------------------------------------------------
  # Determine "primary" AV for evaluation purposes
  # ---------------------------------------------------------------------------
  # If managed AV (Bitdefender / N-able Managed AV) is present in WSC inventory, we
  # treat it as authoritative and skip Defender posture checks. This avoids false
  # Critical states when Defender is intentionally disabled by third-party AV.
  $managedProducts = @()
  if ($products -and $products.Count -gt 0) {
    $managedProducts = @($products | Where-Object { Test-NameMatchesAnyPattern -Name $_.DisplayName -Patterns $ManagedAVNamePatterns })
  }

  $IsManagedAVPresent = (@($managedProducts).Count -gt 0)
  Add-Debug ("Main: IsManagedAVPresent={0}; ManagedProducts={1}" -f $IsManagedAVPresent, ($managedProducts.DisplayName -join ', '))

  # Determine "active" AV (best effort)
  $activeAV = 'Unknown'
  $realTime = 'Unknown'

  if ($IsManagedAVPresent) {
    # Prefer managed AV as active when present
    $primary = $managedProducts | Select-Object -First 1
    $activeAV = $primary.DisplayName
    # FIX #2: Report 'Off/Unknown' (not 'On/Unknown') when managed AV RT state is false,
    # so that a genuinely disabled RT protection is not silently reported as on.
    $realTime = $(if ($primary.RealTimeEnabled) { 'On' } else { 'Off/Unknown' })
  }
  elseif ($def.Present -and $def.ServiceStatus -eq 'Running') {
    $activeAV = 'Microsoft Defender Antivirus'
    $realTime = $(if ($def.RTEnabled) { 'On' } else { 'Off' })
  }
  elseif ($products -and $products.Count -gt 0) {
    # Prefer the first WSC product as "active" (best effort only)
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
    # FIX #10: Replaced -like array operator with Test-NameMatchesAnyPattern for
    # consistency with the rest of the script and correct regex-based matching.
    if (-not ($installedAVNames | Where-Object { Test-NameMatchesAnyPattern -Name $_ -Patterns @('(?i)Defender') })) {
      $installedAVNames += 'Microsoft Defender Antivirus'
    }
  }

  $installedAV = $(if ($installedAVNames.Count -gt 0) { ($installedAVNames -join ', ') } else { 'None detected' })

  # Issues evaluation
  $issues   = New-Object System.Collections.Generic.List[object]
  $severity = 'OK'

  # FIX #1: Raise Critical when no AV is detected at all (WSC empty + Defender absent).
  # Previously the script exited OK with "Active AV: Unknown" in this scenario.
  if (($null -eq $products -or $products.Count -eq 0) -and (-not $def.Present)) {
    [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'NO_AV_DETECTED' `
      -Details 'No AV products detected via Windows Security Center and Microsoft Defender is not present or responding.' `
      -Recommendation 'Install and configure an approved AV product immediately. Verify the Windows Security Center service (wscsvc) is running.'))
    $severity = 'Critical'
  }

  # When managed AV (Bitdefender/N-able) is present, we expect BOTH it and Windows
  # Defender to be enrolled in WSC. If WSC only shows 1 product, one of them has
  # dropped out of the registry — flag it. This check does NOT apply to Defender-only
  # endpoints, where a single WSC entry is the correct and expected state.
  $wscCount = if ($products) { @($products).Count } else { 0 }
  if ($IsManagedAVPresent -and $wscCount -lt 2) {
    [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'BELOW_AV_THRESHOLD' `
      -Details "Only $wscCount AV product(s) registered in Windows Security Center (minimum expected: 2 when managed AV is deployed). WSC registered: $($products.DisplayName -join ', ')." `
      -Recommendation 'Verify that both the managed AV (Bitdefender/N-able) and Windows Defender are correctly enrolled in WSC. Re-register or reinstall the missing product if needed.'))
    if ($severity -ne 'Critical') { $severity = 'Warning' }
  }

  # Detect unexpected third-party AV products (WSC inventory)
  # We allow Defender + BitDefender (N-able managed). Anything else is flagged.
  $unexpectedAV = @()
  if ($products -and $products.Count -gt 0) {
    foreach ($name in ($products.DisplayName | Where-Object { $_ } | Sort-Object -Unique)) {
      $isAllowed = Test-NameMatchesAnyPattern -Name $name -Patterns $AllowedAVNamePatterns
      if (-not $isAllowed) { $unexpectedAV += $name }
    }
  }

  if ($unexpectedAV.Count -gt 0) {
    $msg = "Unexpected AV product(s) detected via WSC: {0}" -f ($unexpectedAV -join ', ')
    [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'UNEXPECTED_AV_INSTALLED' -Details $msg -Recommendation 'Confirm the product is approved. If not, remove/uninstall the unexpected AV to avoid conflicts and false alerts.'))
    if ($severity -ne 'Critical') { $severity = 'Warning' }
  }

  # ---------------------------------------------------------------------------
  # Managed AV guardrail
  # ---------------------------------------------------------------------------
  # If managed AV is present, skip Defender RT/signature checks (those being off/stale
  # is expected when a third-party AV owns protection). However, scan age checks and
  # the managed AV's own RT state are still evaluated — a 180-day-old scan is a real
  # problem regardless of which product is managing protection.
  if ($IsManagedAVPresent) {
    [void]$issues.Add((New-Issue -Severity 'Info' -Code 'MANAGED_AV_PRESENT' `
      -Details ("Managed AV detected via WSC: {0}. Skipping Defender RT/signature checks by design." -f ($managedProducts.DisplayName -join ', ')) `
      -Recommendation 'No action required. Ensure Bitdefender policies are applied and up to date.'))

    # Validate the managed AV product itself has real-time protection on.
    # If the managed AV's own RT is off, that is a genuine gap — nothing is protecting the endpoint.
    $managedRTOff = @($managedProducts | Where-Object { -not $_.RealTimeEnabled })
    if ($managedRTOff.Count -gt 0) {
      $names = ($managedRTOff.DisplayName -join ', ')
      [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'MANAGED_AV_REALTIME_OFF' `
        -Details "Managed AV real-time protection is reported as OFF for: $names. No AV product has active real-time protection." `
        -Recommendation 'Check Bitdefender/N-able policy assignment and agent health. Re-push policy or reinstall the agent if needed.'))
      $severity = 'Critical'
    }

    # Defender scan age is still meaningful even in passive mode — Windows schedules
    # periodic scans for Defender regardless of which AV owns real-time protection.
    # A severely stale scan timestamp indicates scheduled tasks may have broken.
    if ($def.Present) {
      if ($null -ne $def.QuickScanAgeDays -and $def.QuickScanAgeDays -gt $QuickScanThresholdDays) {
        [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_QUICKSCAN_STALE' `
          -Details "Last Defender quick scan was $($def.QuickScanAgeDays) days ago (threshold: $QuickScanThresholdDays days). Defender is present and should still run periodic scans even in passive mode." `
          -Recommendation 'Trigger a Defender quick scan manually or verify that Windows scheduled scan tasks are enabled and not broken.'))
        if ($severity -ne 'Critical') { $severity = 'Warning' }
      } elseif ($null -eq $def.QuickScanAgeDays) {
        [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_QUICKSCAN_NEVER' `
          -Details 'No Defender quick scan timestamp found; Defender may never have scanned this endpoint.' `
          -Recommendation 'Trigger a Defender quick scan and confirm scheduled scan tasks are enabled.'))
        if ($severity -ne 'Critical') { $severity = 'Warning' }
      }
    }
  }
  else {
    # Defender checks (only if Defender present)
    if ($def.Present) {

      if ($def.ServiceStatus -ne 'Running') {
        [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'DEF_SERVICE_STOPPED' `
          -Details "WinDefend service status: $($def.ServiceStatus)" `
          -Recommendation 'Start the WinDefend service and ensure it is not disabled by policy.'))
        $severity = 'Critical'
      }

      if ($def.RTEnabled -eq $false) {
        [void]$issues.Add((New-Issue -Severity 'Critical' -Code 'DEF_REALTIME_OFF' `
          -Details 'Microsoft Defender real-time protection is disabled.' `
          -Recommendation 'Enable real-time protection via policy or local settings; confirm no third-party AV is disabling it.'))
        $severity = 'Critical'
      }

      if ($null -ne $def.SigUpToDate -and $def.SigUpToDate -eq $false) {
        $sigDetail = if ($null -ne $def.SigAgeHours) {
          "Defender signatures are $($def.SigAgeHours) hours old (threshold: $SigAgeThresholdHours hours)."
        } else {
          "Defender signature last-updated timestamp is absent or invalid; signatures may never have been updated."
        }
        [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_SIG_OLD' `
          -Details $sigDetail `
          -Recommendation 'Trigger a signature update and confirm endpoint connectivity to update sources.'))
        if ($severity -ne 'Critical') { $severity = 'Warning' }
      }

      # FIX #4: Evaluate quick scan age against threshold and raise an issue if stale.
      # Previously this value was collected but never checked.
      if ($null -ne $def.QuickScanAgeDays -and $def.QuickScanAgeDays -gt $QuickScanThresholdDays) {
        [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_QUICKSCAN_STALE' `
          -Details "Last Defender quick scan was $($def.QuickScanAgeDays) days ago (threshold: $QuickScanThresholdDays days)." `
          -Recommendation 'Trigger a Defender quick scan manually or verify scheduled scan tasks are enabled and running.'))
        if ($severity -ne 'Critical') { $severity = 'Warning' }
      } elseif ($null -eq $def.QuickScanAgeDays) {
        [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_QUICKSCAN_NEVER' `
          -Details 'No Defender quick scan timestamp found; endpoint may never have been scanned.' `
          -Recommendation 'Trigger a Defender quick scan and confirm scheduled scan tasks are enabled.'))
        if ($severity -ne 'Critical') { $severity = 'Warning' }
      }

      # FIX #4: Evaluate full scan age against threshold when configured (FullScanThresholdDays > 0).
      if ($FullScanThresholdDays -gt 0) {
        if ($null -ne $def.FullScanAgeDays -and $def.FullScanAgeDays -gt $FullScanThresholdDays) {
          [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'DEF_FULLSCAN_STALE' `
            -Details "Last Defender full scan was $($def.FullScanAgeDays) days ago (threshold: $FullScanThresholdDays days)." `
            -Recommendation 'Schedule or trigger a full scan. Consider enabling periodic full scans via Defender policy.'))
          if ($severity -ne 'Critical') { $severity = 'Warning' }
        }
        # Note: null FullScanAgeDays is not alerted — full scans have never run on many
        # managed endpoints where quick scans and cloud protection are the primary posture.
        # Raise a full-scan-never alert only if your environment mandates full scans.
      }
    }
  }

  # MDE hints (non-fatal by default)
  if ($mde -and $mde.SensePresent) {
    if ($mde.SenseStatus -ne 'Running') {
      [void]$issues.Add((New-Issue -Severity 'Warning' -Code 'MDE_SENSE_NOT_RUNNING' `
        -Details 'Sense service present but not running.' `
        -Recommendation 'Check onboarding status, service startup type, and tenant connectivity.'))
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

  # FIX #11: Removed -AsJson and -DebugMode pass-through params from Write-AVOutput call
  # as the function now reads those values from script scope directly.
  Write-AVOutput -Result $result

  # Exit codes: 0 OK, 1 Warning, 2 Critical
  switch ($result.Severity) {
    'OK'       { exit 0 }
    'Warning'  { exit 1 }
    'Critical' { exit 2 }
    default    { exit 0 }
  }

} catch {
  # FIX #5: Top-level catch ensures any unhandled exception produces structured output
  # and a Critical exit code rather than a bare terminating error with no RMM-parseable result.
  $errMsg = $_.Exception.Message
  Write-Output "Status: Critical"
  Write-Output "Active AV: Unknown"
  Write-Output "Installed AV: Unknown"
  Write-Output "Real-time AV: Unknown"
  Write-Output ""
  Write-Output "Issues:"
  Write-Output "  - [Critical] SCRIPT_ERROR: Unhandled exception during AV check: $errMsg"
  Write-Output "      Recommendation: Review script execution context, permissions, and WMI/CIM provider health on this endpoint."
  if ($DebugMode) {
    Write-Output ""
    Write-Output "Debug:"
    Write-Output ("  Exception: {0}" -f $errMsg)
    Write-Output ("  StackTrace: {0}" -f $_.ScriptStackTrace)
    foreach ($d in $script:DebugBuffer) {
      Write-Output ("  {0}" -f $d)
    }
  }
  exit 2
}

#endregion Main Logic
