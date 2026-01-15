<#
.SYNOPSIS
  AVCheck.ps1 — Endpoint antivirus and Microsoft Defender / MDE posture check (PowerShell 5.1+).

.DESCRIPTION
  This script is intended for RMM execution. It gathers signals from:
    1) Windows Security Center (WSC) for installed AV products and real-time status
    2) Microsoft Defender (Get-MpComputerStatus) for service/RT/signature/scan health
    3) Microsoft Defender for Endpoint (Sense service) for basic onboarding visibility
    4) Related security services for vendor/EDR footprint (best-effort)

  It then evaluates those signals against configurable thresholds and emits a
  single-line result suitable for monitoring/alerting, plus optional verbose/debug output.

  IMPORTANT NOTES
    - WSC can lag behind reality immediately after AV install/uninstall.
    - Some third-party AV products do not expose granular state via WSC.
    - MDE onboarding is represented here as “Sense service present + running”
      (this is a practical heuristic, not a full compliance attestation).

.PARAMETER MaxSigAgeHours
  Maximum allowed age (hours) of Defender AV signatures before warning/critical.

.PARAMETER MaxQuickScanAgeDays
  Maximum allowed age (days) of last quick scan before warning.

.PARAMETER MaxFullScanAgeDays
  Maximum allowed age (days) of last full scan before warning.

.PARAMETER RequireRealTime
  If set, the script will raise severity when no real-time AV is enabled.

.PARAMETER RequireMDE
  If set, the script will raise severity when MDE (Sense) is not onboarded.

.PARAMETER DebugMode
  If set, emits additional debug lines (useful for troubleshooting templates / parsing).

.OUTPUTS
  Default: One line intended for RMM parsers, including key-value pairs.
  With -Full: Additional detail objects can be included (depending on your RMM needs).

.EXIT CODES
  0 = Secure / OK
  1 = Warning (stale signatures/scans, soft posture issues)
  2 = Critical (no real-time AV, multiple real-time AV engines, required control missing)
  4 = Script error (unhandled / environment issue)


#>

[CmdletBinding()]
param(
  # Defender signatures are considered "fresh" within this many hours
  [int]$SigFreshHours = 48,

  # Quick scan should have occurred within this many days
  [int]$MaxQuickScanAgeDays = 14,

  # Full scan should have occurred within this many days
  [int]$MaxFullScanAgeDays = 30,

  # If true, flag Critical if no AV engine is real-time enabled
  [switch]$RequireRealTime,

  # If true, flag Warning/Critical when MDE is not onboarded
  [switch]$RequireMDE,

  # If true, emit additional debug log lines
  [switch]$DebugMode,

  # If true, emit a more verbose, multi-line output
  [switch]$Full,

  # If true, emit JSON output (structured, for ingestion)
  [switch]$AsJson
)

# ---------------------------------------------------------------------------
# ----------------------------- Globals / helpers -----------------------------
# ---------------------------------------------------------------------------

# Debug log buffer (only printed if -DebugMode)
$script:DebugLog = New-Object System.Collections.Generic.List[string]

# Issues list used to build final severity/summary
$script:Issues = New-Object System.Collections.Generic.List[pscustomobject]

function Add-Debug {
  param([string]$Message)
  if ($DebugMode) {
    $ts = (Get-Date).ToString('s')
    $script:DebugLog.Add(("{0} {1}" -f $ts, $Message)) | Out-Null
  }
}

function Add-Issue {
  param(
    [Parameter(Mandatory = $true)][ValidateSet('Warning','Critical')][string]$Severity,
    [Parameter(Mandatory = $true)][string]$Short,
    [string]$Details,
    [string]$Recommendation
  )

  $script:Issues.Add([pscustomobject]@{
    Severity       = $Severity
    Short          = $Short
    Details        = $Details
    Recommendation = $Recommendation
  }) | Out-Null
}

# ---------------------------------------------------------------------------
# ----------------------------- Core info functions -----------------------------
# ---------------------------------------------------------------------------

function Get-DefenderInfo {
  Add-Debug 'Get-DefenderInfo: querying Get-MpComputerStatus.'

  $mp = $null
  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
  } catch {
    Add-Debug ("Get-DefenderInfo: Get-MpComputerStatus failed: {0}" -f $_.Exception.Message)
  }

  # Determine service status (Defender AV service)
  $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue

  # Signature age (hours) calculation (if we have a valid timestamp)
  $sigAgeH = $null
  if ($mp -and $mp.AntivirusSignatureLastUpdated) {
    $sigAgeH = [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalHours, 1)
  }

  # Return a stable, structured object (do not rely on raw $mp in later code)
  return [pscustomobject]@{
    Present                   = [bool]$mp
    ServiceStatus             = if ($svc) { $svc.Status.ToString() } else { 'NotPresent' }
    RealTimeProtectionEnabled = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
    SigAgeHours               = $sigAgeH
    AVSignatureVersion        = if ($mp) { $mp.AntivirusSignatureVersion } else { $null }
    LastQuickScan             = if ($mp) { $mp.QuickScanEndTime } else { $null }
    LastFullScan              = if ($mp) { $mp.FullScanEndTime } else { $null }

    # Added for platform/engine validation
    AMProductVersion          = if ($mp) { $mp.AMProductVersion } else { $null }
    AMEngineVersion           = if ($mp) { $mp.AMEngineVersion } else { $null }
    AMServiceEnabled          = if ($mp) { $mp.AMServiceEnabled } else { $null }
  }
}

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
    $rtEnabled   = $false
    $sigUpToDate = $false

    if ($null -ne $raw) {
      # WSC productState bits (best-effort decode)
      # 0x10     => real-time protection on
      # 0x100000 => signatures up to date
      $rtEnabled   = [bool]($raw -band 0x10)
      $sigUpToDate = [bool]($raw -band 0x100000)
    }

    Add-Debug ("Get-WSCAVProducts: {0} state={1} RT={2} Sig...UpToDate={3}" -f $p.displayName, $raw, $rtEnabled, $sigUpToDate)

    $out += [pscustomobject]@{
      DisplayName        = $p.displayName
      ProductStateRaw    = $raw
      RealTime           = $rtEnabled
      SignaturesUpToDate = $sigUpToDate
      ProductExe         = $p.pathToSignedProductExe
      ReportingExe       = $p.pathToSignedReportingExe
      Timestamp          = $p.timestamp
    }
  }

  return $out
}

function Get-MDEInfo {
  # MDE uses the "Sense" service. Presence + running is used as onboarding proxy.
  Add-Debug 'Get-MDEInfo: checking Sense service.'

  $svc       = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
  $present   = [bool]$svc
  $status    = if ($svc) { $svc.Status.ToString() } else { 'NotPresent' }
  $onboarded = ($svc -and $svc.Status -eq 'Running')

  Add-Debug ("Get-MDEInfo: SensePresent={0} Status={1} Onboarded={2}" -f $present, $status, $onboarded)

  [pscustomobject]@{
    SensePresent = $present
    SenseStatus  = $status
    Onboarded    = $onboarded
  }
}

function Get-RelatedSecurityServices {
  Add-Debug 'Get-RelatedSecurityServices: scanning for AV/EDR-related services.'
  $patterns = @(
    'defender','bitdefender','managed antivirus','sophos','trend','mcafee','norton','symantec',
    'kaspersky','eset','avast','avg','sentinel','crowdstrike','falcon','carbon black','cbdefense',
    'panda','webroot','web root','malwarebytes','forti','f-secure','fsecure','vipre','secureanywhere'
  )

  $all  = @()
  try {
    $all = Get-Service -ErrorAction SilentlyContinue
  } catch {
    Add-Debug ("Get-RelatedSecurityServices: Get-Service failed: {0}" -f $_.Exception.Message)
    return @()
  }

  $hits = @()
  foreach ($p in $patterns) {
    $hits += $all | Where-Object {
      $_.Name -match $p -or $_.DisplayName -match $p
    }
  }

  $hits = $hits | Sort-Object Name -Unique

  # Return service hits for visibility only (not used to drive severity directly)
  return $hits | Select-Object Name, DisplayName, Status, StartType
}

# ---------------------------------------------------------------------------
# ----------------------------- Main logic with catch-all -----------------------------
# STEP 0 — Initialise runtime state
#   - $startTime is used for duration / telemetry.
#   - $severity is the running classification that will map to the script exit code.
#   - $result will hold the final structured output object.
# ---------------------------------------------------------------------------

$startTime = Get-Date
$severity  = 'OK'
$result    = $null

try {
  Add-Debug ('Script start on {0} as user {1}' -f $env:COMPUTERNAME, (whoami))

  # STEP 1 — Collect raw signals
  #   Gather the raw facts first (do not classify yet):
  #     - Defender health (Get-MpComputerStatus)
  #     - WSC AV products (installed + RT status, best-effort decode)
  #     - MDE onboarding proxy (Sense service)
  #     - Related security services for vendor visibility
  $def      = Get-DefenderInfo
  $products = Get-WSCAVProducts
  $mde      = Get-MDEInfo
  $svcHits  = Get-RelatedSecurityServices

  # ----------------------------- AV analysis -----------------------------
  # STEP 2 — Normalise and interpret AV posture
  #   Convert raw WSC + Defender signals into:
  #     - Installed AV list (human-readable)
  #     - Real-time enabled AV engines (Defender + 3rd party)
  #     - Primary/Active AV selection (for dashboard reporting)
  $installedAVs = $products

  # Real-time info for 3rd-party AV from WSC
  $rtAVs_WSC = $products | Where-Object { $_.RealTime -eq $true -and $_.DisplayName -notmatch 'Defender' }
  Add-Debug ("AV analysis: rtAVs_WSC count={0}" -f $rtAVs_WSC.Count)

  # Trust Defender RT first
  $defRT = ($def.Present -and $def.RealTimeProtectionEnabled -eq $true -and $def.ServiceStatus -eq 'Running')

  # Determine how many real-time engines are enabled (Defender + 3rd party)
  $rtEngines = @()
  if ($defRT) { $rtEngines += 'Microsoft Defender Antivirus' }
  if ($rtAVs_WSC.Count -gt 0) { $rtEngines += ($rtAVs_WSC.DisplayName | Sort-Object -Unique) }

  $rtEngines = $rtEngines | Sort-Object -Unique

  # Detect multiple RT engines (common cause of instability / conflicts)
  if ($rtEngines.Count -gt 1) {
    Add-Issue -Severity 'Critical' `
      -Short ("Multiple real-time AV engines: {0}" -f ($rtEngines -join ', ')) `
      -Details 'More than one AV engine reports real-time protection enabled.' `
      -Recommendation 'Ensure only one real-time AV product is enabled. Remove/disable the others and re-check.'
  }

  # If RequireRealTime is set, enforce at least one RT engine
  if ($RequireRealTime -and $rtEngines.Count -eq 0) {
    Add-Issue -Severity 'Critical' `
      -Short 'No real-time AV enabled' `
      -Details 'Neither Defender nor any third-party AV reports real-time protection enabled.' `
      -Recommendation 'Enable real-time protection for the installed AV or deploy a supported AV solution.'
  }

  # Defender-specific checks (only if present)
  if ($def.Present) {

    # Defender service must be running for Defender to meaningfully protect
    if ($def.ServiceStatus -ne 'Running') {
      Add-Issue -Severity 'Critical' `
        -Short ("Defender service not running ({0})" -f $def.ServiceStatus) `
        -Details 'WinDefend service is not running.' `
        -Recommendation 'Start WinDefend service and confirm Defender is not disabled by policy or third-party AV.'
    }

    # Signature freshness check (soft posture issue unless extremely stale)
    if ($null -ne $def.SigAgeHours -and $def.SigAgeHours -gt $SigFreshHours) {
      Add-Issue -Severity 'Warning' `
        -Short ("Defender signatures stale ({0}h)" -f $def.SigAgeHours) `
        -Details ("Signature age exceeds configured threshold ({0}h)." -f $SigFreshHours) `
        -Recommendation 'Trigger signature update, validate Windows Update connectivity, and ensure Defender updates are not blocked.'
    }

    # Quick scan age check (warning posture)
    if ($def.LastQuickScan) {
      $qDays = [math]::Floor(((Get-Date) - $def.LastQuickScan).TotalDays)
      if ($qDays -gt $MaxQuickScanAgeDays) {
        Add-Issue -Severity 'Warning' `
          -Short ("Quick scan old ({0}d)" -f $qDays) `
          -Details ("Quick scan last completed {0} days ago." -f $qDays) `
          -Recommendation 'Schedule or trigger a quick scan via Defender.'
      }
    }

    # Full scan age check (warning posture)
    if ($def.LastFullScan) {
      $fDays = [math]::Floor(((Get-Date) - $def.LastFullScan).TotalDays)
      if ($fDays -gt $MaxFullScanAgeDays) {
        Add-Issue -Severity 'Warning' `
          -Short ("Full scan old ({0}d)" -f $fDays) `
          -Details ("Full scan last completed {0} days ago." -f $fDays) `
          -Recommendation 'Schedule or trigger a full scan via Defender.'
      }
    }
  }

  # MDE check (only if RequireMDE requested)
  if ($RequireMDE) {
    if (-not $mde.SensePresent) {
      Add-Issue -Severity 'Critical' `
        -Short 'MDE Sense service not present' `
        -Details 'Sense service missing; MDE agent not installed.' `
        -Recommendation 'Install/repair MDE onboarding package and confirm service exists.'
    } elseif (-not $mde.Onboarded) {
      Add-Issue -Severity 'Warning' `
        -Short ("MDE not onboarded (Sense: {0})" -f $mde.SenseStatus) `
        -Details 'Sense service present but not running.' `
        -Recommendation 'Check onboarding status, service startup type, and tenant connectivity.'
    }
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

  $installedAVNames = $installedAVNames | Sort-Object -Unique

  # Primary AV (ActiveAV) = primary AV engine, even if RT is OFF.
  # Priority:
  #   1) Any WSC AV with RT ON
  #   2) Defender if present & running
  #   3) First installed AV from WSC
  #   4) None
  $primaryAVName = 'None'
  if ($rtAVs_WSC.Count -gt 0) {
    $primaryAVName = ($rtAVs_WSC.DisplayName | Sort-Object -Unique)[0]
  }
  elseif ($def.Present -and $def.ServiceStatus -eq 'Running') {
    $primaryAVName = 'Microsoft Defender Antivirus'
  }
  elseif ($installedAVNames.Count -gt 0) {
    $primaryAVName = $installedAVNames[0]
  }

  $installedSummary = if ($installedAVNames.Count -gt 0) {
    $installedAVNames -join '; '
  } else {
    'None'
  }

  $rtSummary = if ($rtEngines.Count -gt 0) { $rtEngines -join '; ' } else { 'None' }

  # STEP 3 — Classify posture into severity
  #   Issues are accumulated in $script:Issues (Critical/Warning) during analysis.
  #   Here we collapse those issues into a single overall $severity value for RMM.
  # Overall severity
  if ($script:Issues.Count -gt 0) {
    if ($script:Issues | Where-Object { $_.Severity -eq 'Critical' }) {
      $severity = 'Critical'
    }
    elseif ($script:Issues | Where-Object { $_.Severity -eq 'Warning' }) {
      $severity = 'Warning'
    }
  }

  $elapsed = ((Get-Date) - $startTime).TotalSeconds

  # STEP 4 — Build the output payload
  #   $result is the single source of truth for output formatting.
  #   Keep it stable so your RMM parser/template does not break on changes.
  $result = [pscustomobject]@{
    Timestamp      = (Get-Date).ToString('s')
    Hostname       = $env:COMPUTERNAME
    Severity       = $severity

    # Primary/Active AV name for dashboards
    ActiveAV       = $primaryAVName

    # Human-readable summaries
    InstalledAV    = $installedSummary
    RealTimeAV     = $rtSummary

    # Defender details
    Defender       = $def

    # MDE details
    MDE            = $mde

    # Issues list (drives summary + tickets)
    Issues         = $script:Issues

    # Service visibility only
    RelatedServices= $svcHits

    ElapsedSeconds = $elapsed
    DebugLog       = $script:DebugLog
    Parameters     = [pscustomobject]@{
      SigFreshHours       = $SigFreshHours
      MaxQuickScanAgeDays = $MaxQuickScanAgeDays
      MaxFullScanAgeDays  = $MaxFullScanAgeDays
      RequireRealTime     = [bool]$RequireRealTime
      RequireMDE          = [bool]$RequireMDE
      DebugMode           = [bool]$DebugMode
    }
  }
}
catch {
  # Catch-all: produce a stable error result so the RMM parser still gets output
  $msg = $_.Exception.Message
  Add-Debug ("MAIN: unhandled exception: {0}" -f $msg)

  $elapsed = ((Get-Date) - $startTime).TotalSeconds

  $result = [pscustomobject]@{
    Timestamp      = (Get-Date).ToString('s')
    Hostname       = $env:COMPUTERNAME
    Severity       = 'Error'
    ActiveAV       = 'Unknown'
    InstalledAV    = 'Unknown'
    RealTimeAV     = 'Unknown'
    Defender       = $null
    MDE            = $null
    Issues         = @(
      [pscustomobject]@{
        Severity       = 'Critical'
        Short          = "Script error: $msg"
        Details        = $msg
        Recommendation = 'Check PowerShell execution policy, required modules, and permissions.'
      }
    )
    RelatedServices= @()
    ElapsedSeconds = $elapsed
    DebugLog       = $script:DebugLog
    Parameters     = [pscustomobject]@{
      SigFreshHours       = $SigFreshHours
      MaxQuickScanAgeDays = $MaxQuickScanAgeDays
      MaxFullScanAgeDays  = $MaxFullScanAgeDays
      RequireRealTime     = [bool]$RequireRealTime
      RequireMDE          = [bool]$RequireMDE
      DebugMode           = [bool]$DebugMode
    }
  }

  $severity = 'Error'
}

# ----------------------------- Output -----------------------------
function Write-AVOutput {
  param(
    [Parameter(Mandatory = $true)][pscustomobject]$Result,
    [switch]$Full,
    [switch]$AsJson,
    [switch]$DebugMode
  )

  # If JSON requested, emit structured object for ingestion
  if ($AsJson) {
    $Result | ConvertTo-Json -Depth 6
    return
  }

  # Issues summary (flatten issues into a short, single-line string)
  $issuesSummary = 'None'
  if ($Result.Issues -and $Result.Issues.Count -gt 0) {
    $shorts = $Result.Issues | ForEach-Object { $_.Short } | Where-Object { $_ } | Select-Object -Unique
    $issuesSummary = ($shorts -join '; ')
  }

  # Debug summary (only included when DebugMode true)
  $debugSummary = 'None'
  if ($DebugMode -and $Result.DebugLog -and $Result.DebugLog.Count -gt 0) {
    $debugSummary = ('{0} lines' -f $Result.DebugLog.Count)
  }

  if (-not $Full) {
    # Default: single-line RMM-friendly output
    # Keep key names stable for monitors/templates.
    Write-Output ("Status:{0} | ActiveAV:{1} | InstalledAV:{2} | RealTimeAV:{3} | Issues:{4} | SigAgeHours:{5} | MDE:{6}" -f `
      $Result.Severity,
      $Result.ActiveAV,
      $Result.InstalledAV,
      $Result.RealTimeAV,
      $issuesSummary,
      $Result.Defender.SigAgeHours,
      $(if ($Result.MDE) {
    "SensePresent=$($Result.MDE.SensePresent);Onboarded=$($Result.MDE.Onboarded);Status=$($Result.MDE.SenseStatus)"
} else {
    'Unknown'
})    )

    if ($DebugMode) {
      Write-Output ("Debug:{0}" -f $debugSummary)
    }

    return
  }

  # Full mode: multi-line output suitable for tickets / human review
  Write-Output ("Status: {0}" -f $Result.Severity)
  Write-Output ("ActiveAV: {0}" -f $Result.ActiveAV)
  Write-Output ("InstalledAV: {0}" -f $Result.InstalledAV)
  Write-Output ("RealTimeAV: {0}" -f $Result.RealTimeAV)
  Write-Output ("ElapsedSeconds: {0}" -f $Result.ElapsedSeconds)

  Write-Output ''
  Write-Output 'Defender'
  if ($Result.Defender) {
    $Result.Defender | Format-List | Out-String | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ } | ForEach-Object { Write-Output $_ }
  } else {
    Write-Output '  Not available'
  }

  Write-Output ''
  Write-Output 'MDE'
  if ($Result.MDE) {
    $Result.MDE | Format-List | Out-String | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ } | ForEach-Object { Write-Output $_ }
  } else {
    Write-Output '  Not available'
  }

  Write-Output ''
  Write-Output 'Issues'
  if (-not $Result.Issues -or $Result.Issues.Count -eq 0) {
    Write-Output '  None'
  } else {
    $i = 1
    foreach ($issue in $Result.Issues) {
      Write-Output ("  {0}. [{1}] {2}" -f $i, $issue.Severity, $issue.Short)
      if ($issue.Details) {
        Write-Output ("       {0}" -f $issue.Details)
      }
      if ($issue.Recommendation) {
        Write-Output ("       Recommendation: {0}" -f $issue.Recommendation)
      }
      $i++
    }
  }

  if ($DebugMode) {
    Write-Output ''
    Write-Output 'Debug log'
    if ($Result.DebugLog -and $Result.DebugLog.Count -gt 0) {
      foreach ($d in $Result.DebugLog) {
        Write-Output ("  {0}" -f $d)
      }
    } else {
      Write-Output '  None'
    }
  }

  Write-Output ''
  Write-Output 'Related security services'
  if ($Result.RelatedServices -and $Result.RelatedServices.Count -gt 0) {
    $Result.RelatedServices | Format-Table -AutoSize | Out-String | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ } | ForEach-Object { Write-Output $_ }
  } else {
    Write-Output '  None found'
  }
}

# STEP 5 — Emit output in the required format
#   - Default: single-line key=value output for RMM parsing
#   - -Full: human-friendly multi-line output (useful for tickets / troubleshooting)
#   - -AsJson: structured output for downstream ingestion (if your tooling supports it)
Write-AVOutput -Result $result -Full:$Full -AsJson:$AsJson -DebugMode:$DebugMode

# ----------------------------- Exit code -----------------------------
# STEP 6 — Exit with an RMM-friendly code
#   RMM platforms typically map exit codes to OK/Warn/Critical states.
#   Keep this mapping stable to avoid alerting regressions.
switch ($severity) {
  'Critical' { exit 2 }
  'Warning'  { exit 1 }
  'Error'    { exit 4 }
  default    { exit 0 }
}
