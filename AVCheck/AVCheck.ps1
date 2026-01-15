<# 
.SYNOPSIS
  AVCheck.ps1 — Endpoint Antivirus and MDE security posture check (PowerShell 5.1+).

.DESCRIPTION
  Detects and reports:

    • What antivirus products are installed (via Windows Security Center).
    • Which AV(s) have real-time protection enabled.
    • Whether multiple AVs are running with real-time protection (conflict).
    • Microsoft Defender health (service status, real-time, signature age, scan age).
    • Microsoft Defender for Endpoint (MDE / Sense) onboarding status.
    • Related AV / EDR services for vendor visibility.

  Output:
    • Default: single line suitable for RMM parsing.
    • -Full   : multi-line human readable summary for ticket notes.
    • -AsJson : JSON object for advanced parsing.

.EXIT CODES
  0 = Secure
  1 = Warning (old scans, stale signatures, soft issues)
  2 = Critical (no RT AV, multiple RT AV, core control missing)
  4 = Script error (unhandled / environment issue)
#>


[CmdletBinding()]
param(
  [switch]$Full,
  [switch]$AsJson,

  [int]$SigFreshHours       = 48,
  [int]$MaxQuickScanAgeDays = 14,
  [int]$MaxFullScanAgeDays  = 30,

  [switch]$RequireRealTime,
  [switch]$RequireMDE,

  [switch]$DebugMode
)


# --- TEMP: Execution Policy bypass for this PowerShell process (testing only) ---
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
} catch {
    # Non-fatal: some environments may block even Process scope changes
}
# ---------------------------------------------------------------------------



# ----------------------------- Globals / helpers -----------------------------
$script:Issues    = @()
$script:DebugLog  = @()

function Add-Issue {
  param(
    [Parameter(Mandatory = $true)][string]$Short,
    [ValidateSet('OK','Warning','Critical')][string]$Severity = 'Warning',
    [string]$Details,
    [string]$Recommendation
  )
  $script:Issues += [pscustomobject]@{
    Short          = $Short
    Severity       = $Severity
    Details        = $Details
    Recommendation = $Recommendation
  }
}

function Add-Debug {
  param(
    [Parameter(Mandatory = $true)][string]$Message
  )
  $entry = '[{0}] {1}' -f (Get-Date).ToString('s'), $Message
  $script:DebugLog += $entry
}

# ----------------------------- Core info functions -----------------------------
function Get-DefenderInfo {
  Add-Debug 'Get-DefenderInfo: starting query for WinDefend + Get-MpComputerStatus.'
  $svc = $null
  $mp  = $null

  try {
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
  } catch {
    Add-Debug ("Get-DefenderInfo: Get-Service WinDefend failed: {0}" -f $_.Exception.Message)
  }

  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-Debug 'Get-DefenderInfo: Get-MpComputerStatus succeeded.'
  } catch {
    Add-Debug ("Get-DefenderInfo: Get-MpComputerStatus failed: {0}" -f $_.Exception.Message)
  }

  # Real-time protection: TRUST Defender API first
  $rtEnabled = $false
  if ($mp) {
    $rtEnabled = [bool]$mp.RealTimeProtectionEnabled
    Add-Debug ("Get-DefenderInfo: RealTimeProtectionEnabled from API = {0}" -f $rtEnabled)
  } elseif ($svc -and $svc.Status -eq 'Running') {
    # Fallback heuristic if cmdlet fails
    $rtEnabled = $true
    Add-Debug 'Get-DefenderInfo: MpComputerStatus missing; inferring RT=ON because WinDefend is Running.'
  } else {
    Add-Debug 'Get-DefenderInfo: No Defender service or MpComputerStatus; treating Defender as not present.'
  }

  $sigLast = $null
  $sigAgeH = $null
  if ($mp -and $mp.AntivirusSignatureLastUpdated) {
    $sigLast = [datetime]$mp.AntivirusSignatureLastUpdated
    $sigAgeH = ((Get-Date) - $sigLast).TotalHours
    Add-Debug ("Get-DefenderInfo: Signature last updated {0}, age {1:N1}h." -f $sigLast, $sigAgeH)
  }

  [pscustomobject]@{
    Present                   = [bool]$svc
    ServiceStatus             = if ($svc) { $svc.Status.ToString() } else { 'NotPresent' }
    RealTimeProtectionEnabled = $rtEnabled
    SigLastUpdated            = $sigLast
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
  $list = @()

  try {
    $list = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    Add-Debug ("Get-WSCAVProducts: retrieved {0} AV product(s) from SecurityCenter2." -f $list.Count)
  } catch {
    Add-Debug ("Get-WSCAVProducts: failed to query SecurityCenter2: {0}" -f $_.Exception.Message)
    Add-Issue 'Failed to query Windows Security Center (SecurityCenter2).' -Severity 'Warning' -Details $_.Exception.Message
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

    Add-Debug ("Get-WSCAVProducts: {0} state={1} RT={2} SigUpToDate={3}" -f $p.displayName, $raw, $rtEnabled, $sigUpToDate)

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
  Add-Debug 'Get-MDEInfo: querying Sense service.'
  $svc = $null
  try {
    $svc = Get-Service -Name Sense -ErrorAction SilentlyContinue
  } catch {
    Add-Debug ("Get-MDEInfo: Get-Service Sense failed: {0}" -f $_.Exception.Message)
  }

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
  Add-Debug ("Get-RelatedSecurityServices: found {0} matching service(s)." -f $hits.Count)

  if ($hits) {
    $hits | Select-Object Name, DisplayName, Status, StartType
  } else {
    @()
  }
}

# ----------------------------- Main logic with catch-all -----------------------------
$startTime = Get-Date
$severity  = 'OK'
$result    = $null

try {
  Add-Debug ('Script start on {0} as user {1}' -f $env:COMPUTERNAME, (whoami))

  $def      = Get-DefenderInfo
  $products = Get-WSCAVProducts
  $mde      = Get-MDEInfo
  $svcHits  = Get-RelatedSecurityServices

  # ----------------------------- AV analysis -----------------------------
  $installedAVs = $products

  # Real-time info for 3rd-party AV from WSC
  $rtAVs_WSC = $products | Where-Object { $_.RealTime -eq $true -and $_.DisplayName -notmatch 'Defender' }
  Add-Debug ("AV analysis: rtAVs_WSC count={0}" -f $rtAVs_WSC.Count)

  # Trust Defender RT first
  $rtFromDef = ($def.RealTimeProtectionEnabled -eq $true)
  Add-Debug ("AV analysis: Defender RT from API={0}" -f $rtFromDef)

  # Multi-AV detection (3rd-party via WSC)
  $rtMulti = ($rtAVs_WSC.Count -gt 1)
  if ($rtMulti) { Add-Debug 'AV analysis: multiple AVs with RT detected.' }

  # Classification
  $classification = $null

  if ($rtMulti) {
    $names = ($rtAVs_WSC.DisplayName | Sort-Object -Unique) -join ', '
    $classification = 'Multiple AV with real-time enabled'
    Add-Issue "Multiple antivirus products have real-time protection enabled: $names" -Severity 'Critical'
  }
  elseif ($rtAVs_WSC.Count -eq 1) {
    $activeThird = $rtAVs_WSC[0]
    if ($activeThird.DisplayName -match 'Bitdefender|Managed Antivirus') {
      $classification = 'Managed Antivirus / Bitdefender (real-time ON)'
    } else {
      $classification = "3rd-party AV: $($activeThird.DisplayName) (real-time ON)"
    }
  }
  elseif ($rtFromDef -and $def.Present -and $def.ServiceStatus -eq 'Running') {
    $classification = 'Defender (real-time ON)'
  }
  else {
    # No AV with realtime enabled anywhere
    if ($installedAVs.Count -gt 0 -or $def.Present) {
      $classification = 'AV installed but real-time protection is OFF'
      Add-Issue 'Real-time antivirus protection is OFF' -Severity 'Critical'
    } else {
      $classification = 'No antivirus installed'
      Add-Issue 'No antivirus installed or registered in Windows Security Center' -Severity 'Critical'
    }
  }

  # Defender-specific checks
  if ($def.Present) {
    if ($def.ServiceStatus -ne 'Running') {
      Add-Issue "Defender service not running (Status=$($def.ServiceStatus))" -Severity 'Critical'
    }

    if ($RequireRealTime -and -not $def.RealTimeProtectionEnabled) {
      Add-Issue 'Defender real-time protection is OFF while required' -Severity 'Critical'
    }

    if ($def.SigAgeHours -ne $null) {
      if ($def.SigAgeHours -gt [double]$SigFreshHours) {
        Add-Issue ("Defender signatures older than {0} hours" -f $SigFreshHours) -Severity 'Warning'
      }
    }

    if ($MaxQuickScanAgeDays -gt 0 -and $def.LastQuickScan) {
      $qsAge = ((Get-Date) - [datetime]$def.LastQuickScan).TotalDays
      if ($qsAge -gt $MaxQuickScanAgeDays) {
        Add-Issue ("Last Quick Scan older than {0} days" -f $MaxQuickScanAgeDays) -Severity 'Warning'
      }
    }

    if ($MaxFullScanAgeDays -gt 0 -and $def.LastFullScan) {
      $fsAge = ((Get-Date) - [datetime]$def.LastFullScan).TotalDays
      if ($fsAge -gt $MaxFullScanAgeDays) {
        Add-Issue ("Last Full Scan older than {0} days" -f $MaxFullScanAgeDays) -Severity 'Warning'
      }
    }
  }

  # MDE requirement
  if ($RequireMDE -and -not $mde.Onboarded) {
    Add-Issue 'MDE is required but this endpoint is not onboarded' -Severity 'Critical'
  }

  # Overall severity
  if ($script:Issues.Count -gt 0) {
    if ($script:Issues | Where-Object { $_.Severity -eq 'Critical' }) {
      $severity = 'Critical'
    }
    elseif ($script:Issues | Where-Object { $_.Severity -eq 'Warning' }) {
      $severity = 'Warning'
    }
  }

  # ----------------------------- Active vs Installed AV -----------------------------
  $installedAVNames = @()
  if ($installedAVs.Count -gt 0) {
    $installedAVNames = $installedAVs.DisplayName | Sort-Object -Unique
  }

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

  # Real-time state for summary
  $hasRT = $rtFromDef -or ($rtAVs_WSC.Count -gt 0)

  $rtState = if ($rtMulti) {
    'Multi'
  }
  elseif ($hasRT) {
    'On'
  }
  else {
    'Off'
  }

  # Signature state (Defender only – best effort)
  $sigState = 'Unknown'
  if ($def.SigAgeHours -ne $null) {
    if ($def.SigAgeHours -le [double]$SigFreshHours) {
      $sigState = 'Up to date'
    } else {
      $sigState = 'Out of date'
    }
  }

  $elapsed = ((Get-Date) - $startTime).TotalSeconds

  $result = [pscustomobject]@{
    Timestamp      = (Get-Date).ToString('s')
    ComputerName   = $env:COMPUTERNAME
    Status         = $severity
    Classification = $classification
    PrimaryAV      = $primaryAVName
    InstalledAV    = $installedSummary
    RealTimeState  = $rtState
    SignatureState = $sigState
    Issues         = $script:Issues
    Defender       = $def
    MDE            = $mde
    AVProducts     = $products
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

} catch {
  # Catch-all for unexpected runtime failures
  $msg = $_.Exception.Message
  Add-Debug ("MAIN: unhandled exception: {0}" -f $msg)
  Add-Issue 'Script runtime error (unhandled exception).' -Severity 'Critical' -Details $msg

  $elapsed = ((Get-Date) - $startTime).TotalSeconds

  $result = [pscustomobject]@{
    Timestamp      = (Get-Date).ToString('s')
    ComputerName   = $env:COMPUTERNAME
    Status         = 'Error'
    Classification = 'Script error'
    PrimaryAV      = 'Unknown'
    InstalledAV    = 'Unknown'
    RealTimeState  = 'Unknown'
    SignatureState = 'Unknown'
    Issues         = $script:Issues
    Defender       = $null
    MDE            = $null
    AVProducts     = @()
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

  if ($AsJson) {
    $Result | ConvertTo-Json -Depth 6
    return
  }

  # Issues summary
  $issuesSummary = 'None'
  if ($Result.Issues -and $Result.Issues.Count -gt 0) {
    $shorts = $Result.Issues | ForEach-Object { $_.Short } | Where-Object { $_ } | Select-Object -Unique
    $issuesSummary = ($shorts -join '; ')
  }

  # Debug summary
  $debugSummary = 'None'
  if ($DebugMode -and $Result.DebugLog -and $Result.DebugLog.Count -gt 0) {
    # First log line only to keep one-liner reasonable
    $debugSummary = $Result.DebugLog[0]
  }

  if (-not $Full) {
    # One-liner for RMM (enhanced with Defender platform/engine/service)
    $amProduct = if ($Result.Defender -and $Result.Defender.AMProductVersion) { $Result.Defender.AMProductVersion } else { 'N/A' }
    $amEngine  = if ($Result.Defender -and $Result.Defender.AMEngineVersion)  { $Result.Defender.AMEngineVersion }  else { 'N/A' }
    $amService = if ($null -ne $Result.Defender.AMServiceEnabled) { $Result.Defender.AMServiceEnabled } else { 'N/A' }

    $line = '[{0}] {1} | Status:{2} | ActiveAV:{3} | InstalledAV:{4} | Classification:{5} | RT:{6} | Sig:{7} | AMProduct:{8} | AMEngine:{9} | AMService:{10} | MDE:{11} | Issues:{12}' -f `
      $Result.Timestamp,
      $Result.ComputerName,
      $Result.Status,
      $Result.PrimaryAV,
      $Result.InstalledAV,
      $Result.Classification,
      $Result.RealTimeState,
      $Result.SignatureState,
      $amProduct,
      $amEngine,
      $amService,
      ('Sense=' + ($Result.MDE.SenseStatus)),
      $issuesSummary

    if ($DebugMode) {
      $line = $line + (" | Debug:{0}" -f $debugSummary)
    }

    Write-Output $line
    return
  }

  # Full output
  Write-Output ('===== AV / MDE Security Check (Elapsed: {0:N1}s) =====' -f $Result.ElapsedSeconds)
  Write-Output ('Computer      : {0}' -f $Result.ComputerName)
  Write-Output ('Overall Status: {0}' -f $Result.Status)
  Write-Output ('Classification: {0}' -f $Result.Classification)
  Write-Output ('Checked At    : {0}' -f $Result.Timestamp)
  Write-Output ''

  Write-Output 'Antivirus'
  Write-Output ('  Active AV   : {0}' -f $Result.PrimaryAV)
  Write-Output ('  Installed   : {0}' -f $Result.InstalledAV)
  Write-Output ('  RT State    : {0}' -f $Result.RealTimeState)
  Write-Output ('  Sig State   : {0}' -f $Result.SignatureState)

  if ($Result.Defender) {
    Write-Output ''
    Write-Output 'Defender details'
    Write-Output ('  Present     : {0}' -f $Result.Defender.Present)
    Write-Output ('  Service     : {0}' -f $Result.Defender.ServiceStatus)
    Write-Output ('  RT Enabled  : {0}' -f $Result.Defender.RealTimeProtectionEnabled)
    Write-Output ('  AM Product  : {0}' -f $Result.Defender.AMProductVersion)
    Write-Output ('  AM Engine   : {0}' -f $Result.Defender.AMEngineVersion)
    Write-Output ('  AM Service  : {0}' -f $Result.Defender.AMServiceEnabled)
    Write-Output ('  Sig Age (h) : {0}' -f $Result.Defender.SigAgeHours)
    Write-Output ('  Last QScan  : {0}' -f $Result.Defender.LastQuickScan)
    Write-Output ('  Last FScan  : {0}' -f $Result.Defender.LastFullScan)
  }

  Write-Output ''
  Write-Output 'All AV products (WSC)'
  if ($Result.AVProducts.Count -gt 0) {
    foreach ($p in $Result.AVProducts) {
      Write-Output ("  - {0} | RT:{1} | SigUpToDate:{2} | State:{3}" -f `
        $p.DisplayName, $p.RealTime, $p.SignaturesUpToDate, $p.ProductStateRaw)
    }
  } else {
    Write-Output '  (None registered in Windows Security Center or query failed)'
  }

  Write-Output ''
  Write-Output 'Related security services'
  if ($Result.RelatedServices -and $Result.RelatedServices.Count -gt 0) {
    foreach ($s in $Result.RelatedServices) {
      Write-Output ("  - {0} | {1} | {2} | {3}" -f $s.Name, $s.DisplayName, $s.Status, $s.StartType)
    }
  } else {
    Write-Output '  (No obvious 3rd-party AV/EDR services found or query failed)'
  }

  Write-Output ''
  Write-Output 'Issues'
  if ($Result.Issues.Count -eq 0) {
    Write-Output '  None detected.'
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
      Write-Output '  (No debug entries)'
    }
  }

  Write-Output ''
  Write-Output 'Parameters'
  Write-Output ("  SigFreshHours       : {0}" -f $Result.Parameters.SigFreshHours)
  Write-Output ("  MaxQuickScanAgeDays : {0}" -f $Result.Parameters.MaxQuickScanAgeDays)
  Write-Output ("  MaxFullScanAgeDays  : {0}" -f $Result.Parameters.MaxFullScanAgeDays)
  Write-Output ("  RequireRealTime     : {0}" -f $Result.Parameters.RequireRealTime)
  Write-Output ("  RequireMDE          : {0}" -f $Result.Parameters.RequireMDE)
  Write-Output ("  DebugMode           : {0}" -f $Result.Parameters.DebugMode)
}

Write-AVOutput -Result $result -Full:$Full -AsJson:$AsJson -DebugMode:$DebugMode

# ----------------------------- Exit code -----------------------------
switch ($severity) {
  'Critical' { exit 2 }
  'Warning'  { exit 1 }
  'Error'    { exit 4 }
  default    { exit 0 }
}
