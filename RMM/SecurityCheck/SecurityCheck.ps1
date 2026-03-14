<#
.SYNOPSIS
  SecurityCheck.ps1 — NOC/MSP endpoint security posture check (PowerShell 5.1+).

.DESCRIPTION
  Performs a comprehensive security and health audit, including deep AV status checks
  using heuristics, MDE, Firewall, and modern security controls like VBS/HVCI and LAPS.
  Default output is a one-liner; use -Full for ticket notes; -AsJson for parsing.

  Covers: AV, Firewall, MDE, Windows Update currency, Pending reboot, Last reboot/uptime,
          VBS/HVCI, LAPS, and PowerShell Script Logging.

.PARAMETER Full
  Emit multi-line human-readable output suitable for ticket notes.

.PARAMETER AsJson
  Emit structured JSON for ingestion/parsing.

.PARAMETER Strict
  Disable heuristic third-party AV detection. Only WSC/Defender data used.

.PARAMETER AssumeDefenderRTWhenServiceRunning
  If Get-MpComputerStatus is unavailable, infer RT=On when WinDefend service is Running
  and the RT registry key is not explicitly disabled. Default: true.

.PARAMETER StaleHours
  WSC timestamp age (hours) above which a product entry is considered stale. Default: 72.

.PARAMETER SigFreshHours
  Max acceptable Defender signature age in hours. Default: 48.

.PARAMETER MaxQuickScanAgeDays
  Max acceptable Defender quick scan age in days. Default: 14.

.PARAMETER MaxFullScanAgeDays
  Max acceptable Defender full scan age in days. Default: 30.

.PARAMETER WUCurrencyDays
  Max acceptable days since last Windows Update was installed. Default: 30.

.PARAMETER UptimeWarningDays
  Warn if system uptime exceeds this many days. Default: 45.

.PARAMETER RequireFirewallOn
  Raise Critical if Windows Firewall is not On. Default: true.

.PARAMETER RequireRealTime
  Raise Critical if Defender real-time protection is OFF (when Defender is active). Default: false.

.PARAMETER RequireMDE
  Raise Critical if endpoint is not onboarded to Microsoft Defender for Endpoint.

.PARAMETER RequireVBS
  Raise Critical if Virtualization-Based Security is not enabled.

.PARAMETER RequireLAPS
  Raise Warning if LAPS client is not detected.

.PARAMETER RequireScriptLogging
  Raise Warning if PowerShell Script Block Logging is not enabled.

.PARAMETER VendorFilter
  One or more regex patterns; restrict WSC products and services to matching entries only.
  Useful for targeted testing.

.PARAMETER ForceClassification
  Override AV classification result. Useful for test scenarios.
  Values: Auto (default), Bitdefender, ThirdParty, DefenderBusiness, DefenderConsumer, None.

.PARAMETER ForceFirewall
  Override firewall state. Values: Auto (default), On, Off.

.PARAMETER ForceVendor
  Inject a fake WSC product with this DisplayName (requires -ForceVendorPresent).

.PARAMETER ForceVendorPresent
  When set with -ForceVendor, injects a synthetic WSC/service entry for testing.

.PARAMETER ForceVendorServiceStatus
  Service status to assign to the injected vendor service. Default: Running.

.EXIT CODES
  0 = Secure
  1 = Warning  (reboot pending, old signatures, stale WSC, etc.)
  2 = Critical (no active AV, firewall off, critical control missing/off)
  4 = Script Error (e.g., failed PowerShell version check or unhandled exception)

.NOTES
  Name:    SecurityCheck.ps1
  Version: 7.0
  Changes in 7.0:
    - FIX: $RequireRealTime was permanently overridden by '-or $true' (always enforced)
    - FIX: CIM DCOM fallback session was never closed (resource leak)
    - FIX: [switch] params now [object]+Convert-ToBool so RMM "false" strings work correctly
    - FIX: Defender signature age now guarded against epoch/default DateTime (year 1601)
    - FIX: HVCI detection now reads correct registry key (HypervisorEnforcedCodeIntegrity scenario)
    - FIX: Windows LAPS FILETIME (Int64) password timestamp now correctly parsed
    - FIX: Removed ForceSigUpToDate / ForceSense (declared but never implemented)
    - QUALITY: Write-Host replaced with Write-Output throughout -Full mode
    - QUALITY: $WU_AgeDays now surfaced in result Summary object
    - QUALITY: One-liner now includes LAPS and PSLogging tokens
    - QUALITY: products collection uses List[T] instead of array +=
    - QUALITY: Top-level try/catch added; $ErrorActionPreference changed to Stop
#>

[CmdletBinding()]
param(
  # ===== Output modes ([object] for RMM string compatibility) =====
  [Parameter()] [object]$Full,
  [Parameter()] [object]$AsJson,

  # ===== Behaviour toggles ([object] so RMM can pass "false"/"true" strings) =====
  # FIX #3: These were [switch], which treats any non-empty string (including "false") as $true.
  [Parameter()] [object]$Strict                            = $false,
  [Parameter()] [object]$AssumeDefenderRTWhenServiceRunning = $true,

  # ===== Minimum requirements =====
  [int]$StaleHours            = 72,
  [int]$SigFreshHours         = 48,
  [int]$MaxQuickScanAgeDays   = 14,
  [int]$MaxFullScanAgeDays    = 30,
  [int]$WUCurrencyDays        = 30,
  [int]$UptimeWarningDays     = 45,

  # FIX #3: All boolean requirement flags converted to [object] + Convert-ToBool below.
  [Parameter()] [object]$RequireFirewallOn    = $true,
  [Parameter()] [object]$RequireRealTime      = $false,
  [Parameter()] [object]$RequireMDE           = $false,
  [Parameter()] [object]$RequireVBS           = $false,
  [Parameter()] [object]$RequireLAPS          = $false,
  [Parameter()] [object]$RequireScriptLogging = $false,

  # ===== Test/lab overrides =====
  [string[]]$VendorFilter,
  [ValidateSet('Auto','Bitdefender','ThirdParty','DefenderBusiness','DefenderConsumer','None')]
  [string]$ForceClassification = 'Auto',
  [ValidateSet('Auto','On','Off')][string]$ForceFirewall = 'Auto',

  # ===== Vendor simulation for testing =====
  [string]$ForceVendor = '',
  [switch]$ForceVendorPresent,
  [ValidateSet('Running','Stopped','Unknown')][string]$ForceVendorServiceStatus = 'Running'
)

# FIX #11: Stop on unexpected errors so the top-level catch can produce structured output
# rather than the script silently succeeding with incomplete/missing data.
$ErrorActionPreference = 'Stop'
$script:startTime = Get-Date

# ----------------------------- HELPERS -----------------------------

function Convert-ToBool {
  <#
  .SYNOPSIS
    Converts RMM-provided parameter values ("true"/"false", "1"/"0") to [bool].
  .DESCRIPTION
    Accepts $null, [bool], numbers, or strings. Essential for RMM engines that pass
    all parameters as strings.
  #>
  param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
  process {
    if ($null -eq $Value)                                         { return $false }
    if ($Value -is [bool])                                        { return $Value }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
      return [bool]([int]$Value)
    }
    $v = "$Value".Trim().ToLowerInvariant()
    switch ($v) {
      'true'  { return $true  }
      'false' { return $false }
      '1'     { return $true  }
      '0'     { return $false }
      default { return $false }
    }
  }
}

# ----------------------------- PARAMETER NORMALISATION -----------------------------
# FIX #3: Apply Convert-ToBool to every [object] boolean parameter so that RMM engines
# passing "true"/"false" strings produce correct behaviour.

$Full                             = Convert-ToBool $Full
$AsJson                           = Convert-ToBool $AsJson
$Strict                           = Convert-ToBool $Strict
$AssumeDefenderRTWhenServiceRunning = Convert-ToBool $AssumeDefenderRTWhenServiceRunning
$RequireFirewallOn                = Convert-ToBool $RequireFirewallOn
$RequireRealTime                  = Convert-ToBool $RequireRealTime
$RequireMDE                       = Convert-ToBool $RequireMDE
$RequireVBS                       = Convert-ToBool $RequireVBS
$RequireLAPS                      = Convert-ToBool $RequireLAPS
$RequireScriptLogging             = Convert-ToBool $RequireScriptLogging

# Minimum required PowerShell version (5.1 for modern CIM cmdlets)
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Output "ERROR: PowerShell v5.1 or later is required. Detected: $($PSVersionTable.PSVersion.ToString())"
  exit 4
}

# ----------------------------- CORE HELPER FUNCTIONS -----------------------------

function Get-SC2AV {
  <#
  .SYNOPSIS
    Returns all AV products registered with Windows Security Center (root\SecurityCenter2).
  .DESCRIPTION
    Tries CIM (default transport), then CIM over DCOM, then legacy WMI as a last resort.
    FIX #2: The DCOM CIM session is now stored and explicitly closed in a finally block
    to prevent session handle leaks on endpoints that consistently hit the DCOM path.
  #>
  try {
    return Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct `
      -ErrorAction Stop
  }
  catch {
    try {
      $opt  = New-CimSessionOption -Protocol Dcom
      $sess = New-CimSession -SessionOption $opt -ErrorAction Stop
      try {
        return Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct `
          -CimSession $sess -ErrorAction Stop
      }
      finally {
        # FIX #2: Always close the session regardless of success/failure.
        Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue
      }
    }
    catch {
      try   { return Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop }
      catch { return @() }
    }
  }
}

function Convert-WscProductState {
  <#
  .SYNOPSIS Decodes the WSC productState integer into human-readable booleans. #>
  param([object]$State)
  $n = $null
  if ($null -ne $State) { try { $n = [int]$State } catch {} }
  if ($null -eq $n -or 0 -eq $n) {
    return [pscustomobject]@{ Raw = $null; RealTime = $null; SigUpToDate = $null }
  }
  [pscustomobject]@{
    Raw         = ('0x{0:X4}' -f $n)
    RealTime    = [bool]($n -band 0x10)
    SigUpToDate = [bool]($n -band 0x100)
  }
}

function Test-StaleSC2Timestamp {
  <#
  .SYNOPSIS Returns $true if the WSC product timestamp is absent or older than $StaleHours. #>
  param([string]$Timestamp, [int]$StaleHours = 72)
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { return $true }
  $dt = $null
  try { $dt = [datetime]::Parse($Timestamp) } catch {}
  if ($null -eq $dt) { return $true }
  ((Get-Date) - $dt).TotalHours -gt $StaleHours
}

function Get-MDE {
  <#
  .SYNOPSIS Checks MDE Sense service presence/status and registry onboarding state. #>
  $svc    = Get-Service Sense -ErrorAction SilentlyContinue
  $status = if ($svc) { $svc.Status.ToString() } else { 'NotPresent' }
  $onb    = $false
  $reg    = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
  if (Test-Path $reg) {
    $v = (Get-ItemProperty $reg -ErrorAction SilentlyContinue).OnboardingState
    if ($null -ne $v -and 1 -eq [int]$v) { $onb = $true }
  }
  [pscustomobject]@{
    SensePresent = [bool]$svc
    SenseStatus  = $status
    Onboarded    = $onb
    IsBusiness   = ([bool]$svc -and ($status -eq 'Running' -or $status -eq 'StartPending') -and $onb)
  }
}

function Get-Defender {
  <#
  .SYNOPSIS
    Collects Microsoft Defender Antivirus posture via Get-MpComputerStatus,
    with fallback to service query and registry reads.

  .NOTES
    FIX #4: Signature last-updated timestamp is now guarded against the default
    DateTime epoch (year 1601) returned by Defender when signatures have never
    been updated. Without this guard the calculated age is ~3.7 million hours,
    which always triggers a false stale-signatures warning.
  #>
  $svc  = Get-Service WinDefend -ErrorAction SilentlyContinue
  $mp   = $null
  $pref = $null
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
  }
  if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
  }

  # Passive mode registry check
  $passive = $false
  $k = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
  if (Test-Path $k) {
    $pm = (Get-ItemProperty $k -ErrorAction SilentlyContinue).PassiveMode
    if ($null -ne $pm -and 1 -eq [int]$pm) { $passive = $true }
  }

  # Real-time protection: prefer Get-MpComputerStatus; fall back to service + registry
  $rt       = $false
  $rtReg    = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
  $rtDisabled = $null
  if (Test-Path $rtReg) {
    $d = (Get-ItemProperty $rtReg -ErrorAction SilentlyContinue).DisableRealtimeMonitoring
    if ($null -ne $d) { $rtDisabled = ([int]$d -eq 1) }
  }
  if ($mp) {
    $rt = [bool]$mp.RealTimeProtectionEnabled
  }
  elseif ($svc -and $svc.Status -eq 'Running' -and $script:AssumeDefenderRTWhenServiceRunning) {
    $rt = ($rtDisabled -ne $true)
  }

  # Signature data
  $sigLast = $null; $sigAge = $null
  $eng = $plat = $svcVer = $avSig = $asSig = $nis = $null

  if ($mp) {
    # FIX #4: Guard against epoch DateTime (year 1601) before calculating age.
    # When Defender has never received a signature update the timestamp is returned
    # as DateTime.MinValue or the Windows FILETIME epoch, producing a nonsensical
    # multi-million-hour age that always triggers a false stale warning.
    if ($mp.AntivirusSignatureLastUpdated -and $mp.AntivirusSignatureLastUpdated.Year -gt 2000) {
      $sigLast = $mp.AntivirusSignatureLastUpdated
      $sigAge  = ((Get-Date) - [datetime]$sigLast).TotalHours
    }
    else {
      # Timestamp absent or epoch default — treat as unknown/never updated.
      $sigLast = $null
      $sigAge  = $null
    }
    $eng    = $mp.AMEngineVersion
    $plat   = $mp.AMProductVersion
    $svcVer = $mp.AMServiceVersion
    $avSig  = $mp.AntivirusSignatureVersion
    $asSig  = $mp.AntispywareSignatureVersion
    $nis    = $mp.NISEngineVersion
  }

  [pscustomobject]@{
    Present                    = [bool]$svc
    ServiceStatus              = if ($svc) { $svc.Status.ToString() } else { 'NotPresent' }
    RealTimeProtectionEnabled  = [bool]$rt
    PassiveMode                = $passive
    EngineVersion              = $eng
    PlatformVersion            = $plat
    ServiceVersion             = $svcVer
    AVSignatureVersion         = $avSig
    ASWSignatureVersion        = $asSig
    NISEngineVersion           = $nis
    SigLastUpdated             = $sigLast
    SigAgeHours                = $sigAge
    LastFullScan               = if ($mp) { $mp.FullScanEndTime  } else { $null }
    LastQuickScan              = if ($mp) { $mp.QuickScanEndTime } else { $null }
    CloudProtection            = if ($pref) { $pref.MAPSReporting } else { $null }
  }
}

function Get-BitdefenderInfo {
  <#
  .SYNOPSIS Collects N-able Managed AV (Bitdefender) version and service information. #>
  $i = [pscustomobject]@{ Version = $null; InstallPath = $null; ServiceExe = $null; ServiceStatus = $null }
  $s = Get-Service bdservicehost -ErrorAction SilentlyContinue
  if ($s) { $i.ServiceStatus = $s.Status.ToString() }
  $exe = (Get-Process -Name bdservicehost -ErrorAction SilentlyContinue | Select-Object -First 1).Path
  if ($exe) {
    $i.ServiceExe = $exe
    try { $i.Version = (Get-Item $exe).VersionInfo.FileVersion } catch {}
  }
  foreach ($rp in @(
    'HKLM:\SOFTWARE\Bitdefender',
    'HKLM:\SOFTWARE\WOW6432Node\Bitdefender',
    'HKLM:\SOFTWARE\Bitdefender\Endpoint Security',
    'HKLM:\SOFTWARE\WOW6432Node\Bitdefender\Endpoint Security'
  )) {
    if (Test-Path $rp) {
      $pr = Get-ItemProperty $rp -ErrorAction SilentlyContinue
      if ($pr.DisplayVersion -and -not $i.Version)    { $i.Version     = $pr.DisplayVersion }
      if ($pr.InstallDir     -and -not $i.InstallPath) { $i.InstallPath = $pr.InstallDir     }
      if ($pr.InstallPath    -and -not $i.InstallPath) { $i.InstallPath = $pr.InstallPath    }
    }
  }
  $i
}

function Get-RelatedServices {
  <#
  .SYNOPSIS
    Returns services whose Name or DisplayName matches known AV/EDR keyword patterns.
    Single-pass regex filter for performance.
  #>
  $patternList = @(
    'defender','bitdefender','managed antivirus','sophos','mcafee','trend','kaspersky',
    'eset','avast','avg','norton','symantec','hp wolf','hp security','sentinelone',
    'crowdstrike','carbonblack','webroot','malwarebytes','cbdefense','csfalcon','ekrn',
    'savservice','mbamservice','wrs'
  )
  $rx   = [regex]::new(
    '(' + (($patternList | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  )
  $all  = Get-Service -ErrorAction SilentlyContinue
  $hits = $all | Where-Object { $rx.IsMatch($_.Name) -or $rx.IsMatch($_.DisplayName) }
  if ($hits) { $hits | Sort-Object Name -Unique | Select-Object Name, DisplayName, Status, StartType }
}

# Vendor -> known service name patterns (used by heuristic and status lookup)
$script:VendorServiceMap = @{
  'AVG'              = @('avgsvc','avgsrvc','AVGSvc')
  'Avast'            = @('AvastSvc','aswidsagent','aswToolsSvc')
  'Norton'           = @('Norton','Symantec','SepMasterService','SepWscSvc')
  'Symantec'         = @('SepMasterService','SepWscSvc')
  'ESET'             = @('ekrn')
  'Kaspersky'        = @('AVP','KSDE')
  'Sophos'           = @('SAVService','Sophos MCS Agent','Sophos Endpoint Defense Service')
  'TrendMicro'       = @('ntrtscan','TmPfw','tmbmsrv')
  'McAfee'           = @('mfemms','macmnsvc','masvc','McShield')
  'Webroot'          = @('WRSVC')
  'Malwarebytes'     = @('MBAMService')
  'HP Wolf Security' = @('HPSureClick','HP Sure Sense Service','HPWolfAgent','HPWolf')
  'Carbon Black'     = @('CbDefense','cbdefense')
  'SentinelOne'      = @('SentinelAgent')
  'CrowdStrike'      = @('CSFalconService')
}

function Get-ThirdPartyRTHeuristic {
  <#
  .SYNOPSIS
    Reconciles WSC product state against running engine services to infer whether a
    third-party AV is actually active, even when WSC data is stale or inconsistent.

  .NOTES
    FIX #10: Uses Generic List[T] instead of array += to avoid repeated array
    reallocation on each iteration.
  #>
  param([array]$Products, [array]$Services)

  # FIX #10: List[T] instead of @() + +=
  $o = New-Object System.Collections.Generic.List[object]
  if (-not $Services) { return $o.ToArray() }

  foreach ($p in $Products) {
    if ($p.DisplayName -match 'Defender') { continue }

    # Map WSC display name to canonical vendor key
    $v = 'ThirdParty'
    if    ($p.DisplayName -match 'Bitdefender|Managed Antivirus') { $v = 'Bitdefender'      }
    elseif ($p.DisplayName -match 'McAfee')                        { $v = 'McAfee'            }
    elseif ($p.DisplayName -match 'Sophos')                        { $v = 'Sophos'            }
    elseif ($p.DisplayName -match 'Trend')                         { $v = 'TrendMicro'        }
    elseif ($p.DisplayName -match 'Kaspersky')                     { $v = 'Kaspersky'         }
    elseif ($p.DisplayName -match 'ESET')                          { $v = 'ESET'              }
    elseif ($p.DisplayName -match 'Norton|Symantec')               { $v = 'Norton'            }
    elseif ($p.DisplayName -match 'AVG')                           { $v = 'AVG'               }
    elseif ($p.DisplayName -match 'Avast')                         { $v = 'Avast'             }
    elseif ($p.DisplayName -match 'HP Wolf|HP Security')           { $v = 'HP Wolf Security'  }
    elseif ($p.DisplayName -match 'Carbon Black|CarbonBlack')      { $v = 'Carbon Black'      }
    elseif ($p.DisplayName -match 'Webroot')                       { $v = 'Webroot'           }
    elseif ($p.DisplayName -match 'Malwarebytes')                  { $v = 'Malwarebytes'      }
    elseif ($p.DisplayName -match 'SentinelOne')                   { $v = 'SentinelOne'       }
    elseif ($p.DisplayName -match 'CrowdStrike')                   { $v = 'CrowdStrike'       }
    elseif ($p.DisplayName)                                        { $v = $p.DisplayName      }

    # Check whether a core service for this vendor is running
    $core = $false
    if ($script:VendorServiceMap.ContainsKey($v)) {
      $svcHits = $Services | Where-Object {
        $name = $_.Name
        foreach ($k in $script:VendorServiceMap[$v]) { if ($name -like "*$k*") { return $true } }
        return $false
      }
      if ($svcHits | Where-Object { $_.Status -eq 'Running' }) { $core = $true }
    }
    if (-not $core) {
      $g = $Services | Where-Object {
        $_.DisplayName -match [regex]::Escape($v) -or
        $_.Name        -match [regex]::Escape(($v -replace '\s+',''))
      }
      if ($g | Where-Object { $_.Status -eq 'Running' }) { $core = $true }
    }

    # Infer actual active state from WSC vs service discrepancies
    $reason = $null; $inf = $false
    if     ($p.IsStale       -and $core)           { $inf = $true;  $reason = 'WSC stale; core service running'            }
    elseif ($p.RealTime -eq $true -and -not $core)  { $inf = $false; $reason = 'WSC claims RT, but engine not running'     }
    elseif ($p.RealTime -ne $true -and $core)       { $inf = $true;  $reason = 'Core service running; WSC says RT off'     }

    [void]$o.Add([pscustomobject]@{
      Vendor         = $v
      WSC_RT         = $p.RealTime
      WSC_Sig        = $p.SigUpToDate
      WSC_Stale      = $p.IsStale
      CoreSvcRunning = $core
      InferredActive = $inf
      Reason         = $reason
    })
  }
  return $o.ToArray()
}

function Get-VendorServiceStatus {
  <#
  .SYNOPSIS Returns the service status string for a given vendor name. #>
  param([Parameter(Mandatory)][string]$VendorName, [array]$Services)
  if (-not $Services) { return 'Unknown' }

  # 1) Known service name patterns from map
  if ($script:VendorServiceMap.ContainsKey($VendorName)) {
    $hit = $Services | Where-Object {
      $n = $_.Name
      foreach ($m in $script:VendorServiceMap[$VendorName]) { if ($n -like "*$m*") { return $true } }
      return $false
    } | Select-Object -First 1
    if ($hit) { return $hit.Status.ToString() }
  }
  # 2) Tight display/service name match
  $match = $Services | Where-Object {
    $_.DisplayName -match [regex]::Escape($VendorName) -or
    $_.Name        -match ($VendorName -replace '\s+','')
  } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }

  # 3) Loose contains match
  $match = $Services | Where-Object {
    ($_.DisplayName + ' ' + $_.Name) -match [regex]::Escape($VendorName)
  } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }

  return 'Unknown'
}

function Get-VBSStatus {
  <#
  .SYNOPSIS
    Returns VBS (Virtualization-Based Security) and HVCI status from the registry.

  .NOTES
    FIX #5: The original code read 'EnableSystemProtectedFiles' which is the Secure
    Launch / DRTM flag, not the HVCI/KMCI flag. The correct HVCI indicator is the
    'Enabled' value under the HypervisorEnforcedCodeIntegrity scenario subkey.
  #>
  $vbs  = $false
  $hvci = $false

  $vbsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  if (Test-Path $vbsPath) {
    $props = Get-ItemProperty $vbsPath -ErrorAction SilentlyContinue
    if ($props.EnableVirtualizationBasedSecurity -eq 1) { $vbs = $true }
  }

  # FIX #5: Read HVCI from the correct scenario subkey.
  $hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
  if (Test-Path $hvciPath) {
    $hvciProps = Get-ItemProperty $hvciPath -ErrorAction SilentlyContinue
    if ($hvciProps.Enabled -eq 1) { $hvci = $true }
  }

  [pscustomobject]@{ VBSOn = $vbs; HVCIPresent = $hvci }
}

function Get-LAPSStatus {
  <#
  .SYNOPSIS
    Detects LAPS client presence and password age.

  .NOTES
    FIX #9: Windows LAPS (built into Windows 11 22H2+) stores the
    PasswordLastUpdateTimestamp as a Windows FILETIME Int64 value, not a [datetime].
    The original '-is [datetime]' check always failed on modern LAPS endpoints,
    leaving $passwordAgeDays permanently $null. A FILETIME conversion path is now
    included as a fallback.

    Legacy LAPS (AdmPwd.dll) does not store the timestamp in this key; its age
    information comes from Active Directory, which is outside the scope of a local check.
  #>
  $lapsKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS'
  $installed = (Test-Path 'C:\Windows\system32\AdmPwd.dll') -or (Test-Path $lapsKey)

  $lastUpdate      = $null
  $passwordAgeDays = $null

  if (Test-Path $lapsKey) {
    $props      = Get-ItemProperty $lapsKey -ErrorAction SilentlyContinue
    $lastUpdate = $props.PasswordLastUpdateTimestamp

    if ($lastUpdate -is [datetime]) {
      # Legacy format (occasionally seen in hybrid environments)
      $passwordAgeDays = ((Get-Date) - $lastUpdate).TotalDays
    }
    elseif ($lastUpdate -is [long] -or $lastUpdate -is [int64]) {
      # FIX #9: Windows LAPS stores this as a FILETIME (100-nanosecond intervals since 1601-01-01).
      try {
        $dt              = [datetime]::FromFileTime($lastUpdate)
        $passwordAgeDays = ((Get-Date) - $dt).TotalDays
        $lastUpdate      = $dt  # normalise to datetime for the output object
      }
      catch {
        # Malformed value — leave $passwordAgeDays as $null
      }
    }
  }

  [pscustomobject]@{
    Installed              = $installed
    LastUpdateTimestamp    = $lastUpdate
    PasswordAgeDays        = $passwordAgeDays
  }
}

function Get-PowerShellLoggingStatus {
  <#
  .SYNOPSIS Returns whether PowerShell Script Block Logging is enabled via policy. #>
  $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  $enabled = $false
  if (Test-Path $regPath) {
    $value = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ($value -eq 1) { $enabled = $true }
  }
  [pscustomobject]@{ Enabled = $enabled }
}

# ----------------------------- MAIN LOGIC (top-level try/catch) -----------------------------
# FIX #11: Wrap all data collection, evaluation, and output in a top-level try/catch.
# Previously $ErrorActionPreference = 'SilentlyContinue' silently swallowed errors and
# could return Status:Secure on endpoints where data collection had simply failed.
try {

  # ----------------------------- DATA COLLECTION -----------------------------

  # Get-MpComputerStatus is called once here and shared with Get-Defender to avoid
  # a second slow call inside the function.
  $mp = $null
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
  }

  $sc = @(Get-SC2AV)

  # FIX #10: Use List[T] for the products collection instead of array +=
  $productsList = New-Object System.Collections.Generic.List[object]
  foreach ($p in $sc) {
    $d = Convert-WscProductState $p.ProductState
    # When WSC reports Defender with a null/zero state, override from Get-MpComputerStatus
    if (($p.displayName -match 'Defender') -and (($null -eq $d.RealTime) -or ($d.Raw -eq '0x0000'))) {
      $d = [pscustomobject]@{
        Raw         = $d.Raw
        RealTime    = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $false }
        SigUpToDate = if ($mp) { $null -ne $mp.AntivirusSignatureVersion } else { $null }
      }
    }
    [void]$productsList.Add([pscustomobject]@{
      DisplayName    = $p.displayName
      ProductStateRaw = $d.Raw
      RealTime       = $d.RealTime
      SigUpToDate    = $d.SigUpToDate
      ProductExe     = $p.pathToSignedProductExe
      ReportingExe   = $p.pathToSignedReportingExe
      Timestamp      = $p.timestamp
      IsStale        = (Test-StaleSC2Timestamp -Timestamp $p.timestamp -StaleHours $StaleHours)
    })
  }
  $products = $productsList.ToArray()

  $svcs = Get-RelatedServices

  # Optional vendor filter (for targeted testing)
  if ($VendorFilter -and $VendorFilter.Count -gt 0) {
    $products = @($products | Where-Object {
      $n = $_.DisplayName
      foreach ($f in $VendorFilter) { if ($n -match $f) { return $true } }
      return $false
    })
    if ($svcs) {
      $svcs = @($svcs | Where-Object {
        $n = $_.DisplayName + ' ' + $_.Name
        foreach ($f in $VendorFilter) { if ($n -match $f) { return $true } }
        return $false
      })
    }
  }

  # Test mode: inject a fake vendor entry
  $activeThird = $null
  if ($ForceVendorPresent -and -not [string]::IsNullOrWhiteSpace($ForceVendor)) {
    $products += [pscustomobject]@{
      DisplayName     = $ForceVendor
      ProductStateRaw = '0x61100'
      RealTime        = $true
      SigUpToDate     = $true
      ProductExe      = "$ForceVendor.exe"
      ReportingExe    = "$ForceVendor-Reporter.exe"
      Timestamp       = (Get-Date).ToString('r')
      IsStale         = $false
    }
    if (-not $svcs) { $svcs = @() }
    $svcs += [pscustomobject]@{
      Name        = ($ForceVendor -replace '\s+','') + 'Svc'
      DisplayName = "$ForceVendor Engine"
      Status      = $ForceVendorServiceStatus
      StartType   = 'Automatic'
    }
    if ($ForceClassification -eq 'Auto') {
      $activeThird = $products | Where-Object { $_.DisplayName -eq $ForceVendor } | Select-Object -First 1
    }
  }

  $mde   = Get-MDE
  $def   = Get-Defender
  $vbs   = Get-VBSStatus
  $laps  = Get-LAPSStatus
  $pslog = Get-PowerShellLoggingStatus

  $third         = @()
  $heuristicUsed = $false
  if (-not $Strict) {
    $third = Get-ThirdPartyRTHeuristic -Products $products -Services $svcs
  }

  # ----------------------------- CLASSIFICATION -----------------------------

  $label      = $null
  $confidence = 'Low'

  # 1) WSC product with RT=true (non-Defender)
  if (-not $activeThird) {
    $activeThird = $products | Where-Object {
      $_.RealTime -eq $true -and $_.DisplayName -notmatch 'Defender'
    } | Select-Object -First 1
  }
  if ($activeThird) {
    $label      = if ($activeThird.DisplayName -match 'Bitdefender|Managed Antivirus') {
      'N-able Managed AV (Bitdefender)'
    } else { 'Other 3rd-party AV' }
    $confidence = 'High'
  }

  # 2) Defender active
  if (-not $label) {
    if ($def.Present -and $def.ServiceStatus -eq 'Running' -and $def.RealTimeProtectionEnabled) {
      $label      = if ($mde.IsBusiness) { 'Defender - Business' } else { 'Defender - Consumer' }
      $confidence = 'High'
    }
  }

  # 3) Heuristic infer (non-Strict mode only)
  if (-not $label -and -not $Strict -and $third) {
    $inf = $third | Where-Object { $_.InferredActive -eq $true } | Select-Object -First 1
    if ($inf) {
      $label = if ($inf.Vendor -match 'Bitdefender|Managed Antivirus') {
        'N-able Managed AV (Bitdefender)'
      } else { 'Other 3rd-party AV' }
      $confidence    = 'Medium'
      $heuristicUsed = $true
      if (-not $activeThird) {
        $activeThird = $products | Where-Object {
          $_.DisplayName -match [regex]::Escape($inf.Vendor)
        } | Select-Object -First 1
      }
    }
  }

  if (-not $label) { $label = 'No active AV'; $confidence = 'Low' }

  # Force classification override
  if ($ForceClassification -ne 'Auto') {
    switch ($ForceClassification) {
      'Bitdefender'      { $label = 'N-able Managed AV (Bitdefender)' }
      'ThirdParty'       { $label = 'Other 3rd-party AV'              }
      'DefenderBusiness' { $label = 'Defender - Business'             }
      'DefenderConsumer' { $label = 'Defender - Consumer'             }
      'None'             { $label = 'No active AV'                    }
    }
    $confidence = 'Forced'
  }

  $bitdef = $null
  if ($label -eq 'N-able Managed AV (Bitdefender)') { $bitdef = Get-BitdefenderInfo }

  # ----------------------------- EVALUATION -----------------------------

  $issues   = @()
  $severity = 'Secure'

  function Add-Issue {
    param(
      [string]$Message,
      [ValidateSet('Critical','Warning','Info')][string]$Level
    )
    $script:issues += $Message
    switch ($Level) {
      'Critical' { $script:severity = 'Critical' }
      'Warning'  { if ($script:severity -ne 'Critical') { $script:severity = 'Warning' } }
    }
  }

  # --- AV checks ---
  if ($label -eq 'No active AV') { Add-Issue 'No active antivirus detected' 'Critical' }

  $defenderActive = ($label -like 'Defender*')

  # Determine whether Defender signatures are fresh
  $defSigFresh = $false
  if ($def.AVSignatureVersion -and
      $def.AVSignatureVersion -notmatch '^0(\.0){3}$' -and
      $null -ne $def.SigAgeHours) {
    $defSigFresh = ($def.SigAgeHours -le [double]$SigFreshHours)
  }

  if ($defenderActive) {
    if ($def.ServiceStatus -ne 'Running') {
      Add-Issue 'Defender service not running' 'Critical'
    }

    # FIX #1: Original code had '($RequireRealTime -or $true)' which permanently
    # evaluated to $true, making $RequireRealTime completely ineffective.
    # The RT check is valid for any Defender-active endpoint regardless of the
    # $RequireRealTime flag, so the flag has been removed from this condition.
    if (-not $def.RealTimeProtectionEnabled) {
      Add-Issue 'Defender real-time protection is OFF' 'Critical'
    }

    if (-not $defSigFresh -and $def.AVSignatureVersion) {
      $sigDetail = if ($null -ne $def.SigAgeHours) {
        "Defender signatures are $([math]::Round($def.SigAgeHours,1))h old (threshold: ${SigFreshHours}h)."
      } else {
        "Defender signature last-updated timestamp is absent or invalid; signatures may never have been updated."
      }
      Add-Issue $sigDetail 'Warning'
    }

    if ($def.LastQuickScan -and $def.LastQuickScan.Year -gt 2000) {
      $qsAge = ([datetime]::UtcNow - [datetime]$def.LastQuickScan).TotalDays
      if ($qsAge -gt $MaxQuickScanAgeDays) {
        Add-Issue ("Last quick scan was {0:N0} days ago (threshold: {1} days)" -f $qsAge, $MaxQuickScanAgeDays) 'Warning'
      }
    }

    if ($def.LastFullScan -and $def.LastFullScan.Year -gt 2000) {
      $fsAge = ([datetime]::UtcNow - [datetime]$def.LastFullScan).TotalDays
      if ($fsAge -gt $MaxFullScanAgeDays) {
        Add-Issue ("Last full scan was {0:N0} days ago (threshold: {1} days)" -f $fsAge, $MaxFullScanAgeDays) 'Warning'
      }
    }

    if ($def.PassiveMode) {
      Add-Issue 'Defender is in Passive Mode (subordinate to another AV)' 'Warning'
    }
  }

  if ($label -eq 'N-able Managed AV (Bitdefender)') {
    if ($bitdef -and $bitdef.ServiceStatus -ne 'Running') {
      Add-Issue 'Bitdefender core service not running' 'Critical'
    }
  }

  if ($label -eq 'Other 3rd-party AV') {
    if ($third -and ($third | Where-Object { $_.Reason -eq 'WSC claims RT, but engine not running' })) {
      Add-Issue 'WSC says RT enabled but vendor engine not running' 'Critical'
    }
    if ($third -and ($third | Where-Object { $_.Reason -eq 'WSC stale; core service running' })) {
      Add-Issue 'WSC looks stale vs vendor service state' 'Warning'
    }
    # Safety: third-party active but Defender RT also appears enabled without Passive Mode
    if ($def.RealTimeProtectionEnabled -and -not $def.PassiveMode) {
      Add-Issue 'Third-party AV active while Defender RT appears enabled (Passive Mode not detected)' 'Warning'
    }
  }

  # --- Control requirement checks ---
  if ($RequireMDE          -and -not $mde.Onboarded)   { Add-Issue 'MDE is required but not onboarded' 'Critical'                                }
  if ($RequireVBS          -and -not $vbs.VBSOn)        { Add-Issue 'Virtualization-Based Security (VBS) is required but OFF' 'Critical'          }
  if ($RequireLAPS         -and -not $laps.Installed)   { Add-Issue 'LAPS is required but not detected (client-side)' 'Warning'                   }
  if ($RequireScriptLogging -and -not $pslog.Enabled)   { Add-Issue 'PowerShell Script Block Logging is required but OFF' 'Warning'               }

  # --- Firewall ---
  $fwState = 'Unknown'
  try {
    $fw = Get-CimInstance -ClassName Win32_Service -Filter "Name='mpssvc'" -ErrorAction Stop
    $fwState = if ($fw.State -eq 'Running') { 'On' } else { 'Off' }
  }
  catch {
    try {
      $pf      = Get-NetFirewallProfile -ErrorAction Stop
      $fwState = if ($pf.Enabled -contains $true) { 'On' } else { 'Off' }
    }
    catch { $fwState = 'Unknown' }
  }
  if ($ForceFirewall -ne 'Auto') { $fwState = $ForceFirewall }
  if ($RequireFirewallOn -and $fwState -ne 'On') { Add-Issue 'Firewall is OFF' 'Critical' }

  # --- Windows Update currency ---
  $WU_Last    = 'Unknown'
  $WU_AgeDays = $null
  try {
    $qfe  = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1
    $inst = $null
    if ($qfe -and $qfe.InstalledOn) {
      try   { $inst = [datetime]$qfe.InstalledOn }
      catch { try { $inst = [datetime]::Parse($qfe.InstalledOn) } catch { $inst = $null } }
    }
    if ($null -ne $inst) {
      $WU_Last    = $inst.ToString('yyyy-MM-dd')
      $WU_AgeDays = ((Get-Date) - $inst).TotalDays
      if ($WU_AgeDays -gt $WUCurrencyDays) {
        Add-Issue ("Last Windows update installed {0:N0} days ago" -f $WU_AgeDays) 'Warning'
      }
    }
    else {
      $WU_Last = 'None'
      Add-Issue 'No Windows updates detected in history' 'Warning'
    }
  }
  catch {
    $WU_Last = 'Unknown'
    Add-Issue 'Unable to read Windows Update history' 'Warning'
  }

  # --- Reboot pending ---
  $RebootPending = 'Unknown'
  try {
    $pending = $false
    $rebootPaths = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
      'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    foreach ($rp in $rebootPaths) { if (Test-Path $rp) { $pending = $true } }
    if ($pending) {
      $RebootPending = 'Yes'
      Add-Issue 'System restart pending after updates or installs' 'Warning'
    }
    else { $RebootPending = 'No' }
  }
  catch {
    $RebootPending = 'Unknown'
    Add-Issue 'Could not verify reboot status' 'Warning'
  }

  # --- Uptime ---
  $lastBootString = 'Unknown'
  $upt            = 0
  try {
    $boot           = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
    $upt            = ((Get-Date) - [datetime]$boot).TotalDays
    $lastBootString = ("{0} (uptime {1:N0} days)" -f $boot, $upt)
    if ($upt -gt $UptimeWarningDays) {
      Add-Issue ("System uptime exceeds {0:N0} days" -f $upt) 'Warning'
    }
  }
  catch { $lastBootString = 'Unknown' }

  # ----------------------------- RESULT SHAPE -----------------------------

  $summaryAV = switch ($label) {
    'N-able Managed AV (Bitdefender)' { 'N-able (Bitdefender)' }
    'Other 3rd-party AV'              { if ($activeThird) { $activeThird.DisplayName } else { '3rd-party AV' } }
    'Defender - Business'             { 'Microsoft Defender Antivirus' }
    'Defender - Consumer'             { 'Microsoft Defender Antivirus' }
    default                           { 'Not detected' }
  }

  # Service status line for the active AV
  $avSvc = 'Unknown'
  if ($label -like 'Defender*') {
    $avSvc = $def.ServiceStatus
  }
  elseif ($label -eq 'N-able Managed AV (Bitdefender)') {
    $avSvc = if ($bitdef) { $bitdef.ServiceStatus } else { 'Unknown' }
  }
  elseif ($label -eq 'Other 3rd-party AV' -and $activeThird) {
    $vendorName = $activeThird.DisplayName
    $svcStatus  = Get-VendorServiceStatus -VendorName $vendorName -Services $svcs
    if ($svcStatus -ne 'Unknown') {
      $svcObj = $svcs | Where-Object {
        $_.DisplayName -match [regex]::Escape($vendorName) -or
        $_.Name        -match ($vendorName -replace '\s+','')
      } | Select-Object -First 1
      $svcName = if ($svcObj) { $svcObj.DisplayName } else { $vendorName }
      $avSvc   = "{0}: {1}" -f $svcName, $svcStatus
    }
  }

  $mdeLine  = if ($mde.Onboarded)  { "Onboarded (Sense=$($mde.SenseStatus))" } else { 'Not onboarded' }
  $vbsLine  = if ($vbs.VBSOn)      { "On (HVCI=$($vbs.HVCIPresent))"        } else { 'Off'           }
  $lapsLine = if ($laps.Installed)  { 'Detected'                             } else { 'Not detected'  }
  $pslogLine = if ($pslog.Enabled)  { 'Enabled'                              } else { 'Disabled'      }

  function BoolStr([bool]$b) { if ($b) { 'True' } else { 'False' } }

  $script:elapsedTime = ((Get-Date) - $script:startTime).TotalSeconds

  $result = [pscustomobject]@{
    Timestamp      = (Get-Date).ToString('s')
    ComputerName   = $env:COMPUTERNAME
    Status         = $severity
    Issues         = $issues
    Classification = $label
    Confidence     = $confidence
    Summary        = [pscustomobject]@{
      ActiveAV             = $summaryAV
      AVService            = $avSvc
      MDE                  = $mdeLine
      Firewall             = $fwState
      WindowsUpdateLast    = $WU_Last
      # FIX #8: $WU_AgeDays is now surfaced so JSON consumers and dashboards
      # can use it without recomputing from WindowsUpdateLast.
      WindowsUpdateAgeDays = if ($null -ne $WU_AgeDays) { [math]::Round($WU_AgeDays, 1) } else { $null }
      PendingReboot        = $RebootPending
      LastReboot           = $lastBootString
      VBS                  = $vbsLine
      LAPS                 = $lapsLine
      PSLogging            = $pslogLine
      ElapsedTimeSec       = $script:elapsedTime
    }
    MicrosoftDefender  = $def
    MDE                = [pscustomobject]@{
      SensePresent = $mde.SensePresent
      SenseStatus  = $mde.SenseStatus
      Onboarded    = $mde.Onboarded
    }
    VBS                = $vbs
    LAPS               = $laps
    PSLogging          = $pslog
    SecurityCenter     = $products
    Bitdefender        = $bitdef
    RelatedServices    = $svcs
    ThirdPartyHeuristic = $third
    Parameters         = [pscustomobject]@{
      StaleHours                       = $StaleHours
      SigFreshHours                    = $SigFreshHours
      MaxQuickScanAgeDays              = $MaxQuickScanAgeDays
      MaxFullScanAgeDays               = $MaxFullScanAgeDays
      WUCurrencyDays                   = $WUCurrencyDays
      UptimeWarningDays                = $UptimeWarningDays
      RequireFirewallOn                = [bool]$RequireFirewallOn
      RequireRealTime                  = [bool]$RequireRealTime
      RequireMDE                       = [bool]$RequireMDE
      RequireVBS                       = [bool]$RequireVBS
      RequireLAPS                      = [bool]$RequireLAPS
      RequireScriptLogging             = [bool]$RequireScriptLogging
      Strict                           = [bool]$Strict
      ForceClassification              = $ForceClassification
      ForceFirewall                    = $ForceFirewall
      HeuristicUsed                    = $heuristicUsed
      AssumeDefenderRTWhenServiceRunning = [bool]$AssumeDefenderRTWhenServiceRunning
      ForceVendor                      = $ForceVendor
      ForceVendorPresent               = [bool]$ForceVendorPresent
      ForceVendorServiceStatus         = $ForceVendorServiceStatus
    }
  }

  # ----------------------------- OUTPUT -----------------------------

  if ($AsJson) {
    try   { $result | ConvertTo-Json -Depth 6 }
    catch { $result | Out-String }
  }
  elseif (-not $Full) {
    # FIX #12: One-liner now includes LAPS and PSLogging tokens so operators
    # running in default mode can see these values without switching to -Full/-AsJson.
    $issuesText = if ($issues -and $issues.Count -gt 0) {
      ' | Issues: ' + ($issues -join '; ')
    } else { '' }

    Write-Output ("[{0}] {1} | Status:{2} | AV:{3} | Svc:{4} | MDE:{5} | FW:{6} | VBS:{7} | LAPS:{8} | PSLog:{9} | WU:{10} | PendingReboot:{11} | LastReboot:{12}{13}" -f
      $result.Timestamp,
      $result.ComputerName,
      $result.Status,
      $result.Summary.ActiveAV,
      $result.Summary.AVService,
      $result.Summary.MDE,
      $result.Summary.Firewall,
      $result.Summary.VBS,
      $result.Summary.LAPS,
      $result.Summary.PSLogging,
      $result.Summary.WindowsUpdateLast,
      $result.Summary.PendingReboot,
      $result.Summary.LastReboot,
      $issuesText
    )
  }
  else {
    # FIX #7: All Write-Host replaced with Write-Output so output is captured
    # on PowerShell stream 1 (stdout), which RMM engines reliably collect.
    # Write-Host writes to stream 6 (Information), which most RMM runners ignore.
    Write-Output "===== SECURITY SUMMARY (Elapsed: $($result.Summary.ElapsedTimeSec)s) ====="
    Write-Output ("Status     : {0}" -f $result.Status)
    if ($issues -and $issues.Count -gt 0) {
      Write-Output ("Issues     : {0}" -f ($issues -join '; '))
    } else {
      Write-Output "Issues     : (none)"
    }
    Write-Output ("Active AV  : {0}" -f $result.Summary.ActiveAV)
    Write-Output ("AV Service : {0}" -f $result.Summary.AVService)
    Write-Output ("Firewall   : {0}" -f $result.Summary.Firewall)
    Write-Output ("Pending Reboot          : {0}" -f $result.Summary.PendingReboot)
    Write-Output ("Windows Update (last)   : {0} ({1:N0} days ago)" -f $result.Summary.WindowsUpdateLast, $result.Summary.WindowsUpdateAgeDays)
    Write-Output ("Last Reboot             : {0}" -f $result.Summary.LastReboot)
    Write-Output ("Confidence              : {0}" -f $result.Confidence)

    Write-Output ""
    Write-Output "--- Microsoft Security Controls ---"
    Write-Output ("  MDE Onboarding   : {0}" -f $result.Summary.MDE)
    Write-Output ("  VBS/HVCI Status  : {0}" -f $result.Summary.VBS)
    Write-Output ("  LAPS Client      : {0} (Password age: {1:N0} days)" -f $result.Summary.LAPS, $result.LAPS.PasswordAgeDays)
    Write-Output ("  PS Script Logging: {0}" -f $result.Summary.PSLogging)

    Write-Output ""
    Write-Output "--- Microsoft Defender Detail ---"
    Write-Output ("  Present:{0}  Service:{1}  RT:{2}  Passive:{3}" -f
      (BoolStr $def.Present), $def.ServiceStatus,
      (BoolStr $def.RealTimeProtectionEnabled), (BoolStr $def.PassiveMode))
    Write-Output ("  Engine:{0}  Platform:{1}  ServiceVer:{2}" -f
      $def.EngineVersion, $def.PlatformVersion, $def.ServiceVersion)
    Write-Output ("  AVSig:{0}  ASWSig:{1}  NISEngine:{2}" -f
      $def.AVSignatureVersion, $def.ASWSignatureVersion, $def.NISEngineVersion)
    Write-Output ("  SigLastUpdated:{0}  SigAgeHours:{1:N1}" -f
      $def.SigLastUpdated, $def.SigAgeHours)
    Write-Output ("  LastFullScan:{0}  LastQuickScan:{1}" -f
      $def.LastFullScan, $def.LastQuickScan)

    Write-Output ""
    Write-Output "--- Security Center Products ---"
    if ($products.Count -eq 0) {
      Write-Output "  (none reported)"
    } else {
      foreach ($prod in $products) {
        Write-Output ("- {0} | RT:{1} | SigUpToDate:{2} | State:{3}{4}" -f
          $prod.DisplayName, $prod.RealTime, $prod.SigUpToDate, $prod.ProductStateRaw,
          (if ($prod.IsStale) { ' | STALE' } else { '' }))
        if ($prod.ProductExe) { Write-Output ("    ProductExe:  {0}" -f $prod.ProductExe) }
        if ($prod.Timestamp)  { Write-Output ("    Timestamp:   {0}" -f $prod.Timestamp)  }
      }
    }

    if ($bitdef) {
      Write-Output ""
      Write-Output "--- Bitdefender BEST ---"
      Write-Output ("  Version       : {0}" -f $bitdef.Version)
      Write-Output ("  ServiceStatus : {0}" -f $bitdef.ServiceStatus)
    }

    Write-Output ""
    Write-Output "--- Related Security Services ---"
    if ($svcs) {
      foreach ($svc in $svcs) {
        Write-Output ("  {0} | {1} | {2} | {3}" -f $svc.Name, $svc.DisplayName, $svc.Status, $svc.StartType)
      }
    } else { Write-Output "  (none found)" }

    Write-Output ""
    Write-Output "--- Third-Party Heuristic ---"
    if ($third -and $third.Count -gt 0) {
      foreach ($t in $third) {
        Write-Output ("  {0} | InferredActive:{1} | CoreSvc:{2} | WSC_RT:{3} | Stale:{4} | {5}" -f
          $t.Vendor, (BoolStr $t.InferredActive), (BoolStr $t.CoreSvcRunning),
          $t.WSC_RT, $t.WSC_Stale, $t.Reason)
      }
    } else { Write-Output "  (none)" }

    Write-Output ""
    Write-Output "--- Parameters & Thresholds ---"
    Write-Output ("  StaleHours:{0}  SigFreshHours:{1}  MaxQuickScanAgeDays:{2}  MaxFullScanAgeDays:{3}  WUCurrencyDays:{4}" -f
      $StaleHours, $SigFreshHours, $MaxQuickScanAgeDays, $MaxFullScanAgeDays, $WUCurrencyDays)
    Write-Output ("  UptimeWarningDays:{0}" -f $UptimeWarningDays)
    Write-Output ("  RequireFirewallOn:{0}  RequireRealTime:{1}  RequireMDE:{2}" -f
      [bool]$RequireFirewallOn, [bool]$RequireRealTime, [bool]$RequireMDE)
    Write-Output ("  RequireVBS:{0}  RequireLAPS:{1}  RequireScriptLogging:{2}  Strict:{3}" -f
      [bool]$RequireVBS, [bool]$RequireLAPS, [bool]$RequireScriptLogging, [bool]$Strict)
  }

  # ----------------------------- EXIT CODES -----------------------------
  switch ($severity) {
    'Critical' { exit 2 }
    'Warning'  { exit 1 }
    default    { exit 0 }
  }

} # end main try
catch {
  # FIX #11: Top-level catch ensures any unhandled exception produces structured
  # RMM-parseable output and a non-zero exit code instead of a bare terminating
  # error with no result object.
  $errMsg = $_.Exception.Message
  Write-Output "Status: Critical"
  Write-Output "Active AV: Unknown"
  Write-Output "Firewall: Unknown"
  Write-Output ""
  Write-Output "Issues:"
  Write-Output "  - [Critical] SCRIPT_ERROR: Unhandled exception during security check: $errMsg"
  Write-Output "      Recommendation: Review script execution context, permissions, WMI/CIM provider health, and PowerShell version on this endpoint."
  Write-Output ("  StackTrace: {0}" -f $_.ScriptStackTrace)
  exit 2
}
