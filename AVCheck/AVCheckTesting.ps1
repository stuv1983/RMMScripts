<# 
.SYNOPSIS
  AVCheck.ps1 — Endpoint Antivirus and MDE security posture check (PowerShell 5.1+).

.DESCRIPTION
  Performs a comprehensive audit of Antivirus (Defender/3rd-party) status and MDE 
  onboarding using advanced heuristics to avoid stale Windows Security Center (WSC) false-negatives.
  
.EXIT CODES
  0 = Secure (Active AV and MDE status OK)
  1 = Warning (Signatures stale, Defender in Passive Mode, or WSC issue)
  2 = Critical (No active AV, core service stopped, or Real-Time Protection is OFF)
  4 = Script Error (e.g., failed PowerShell version check)
#>

[CmdletBinding()]
param(
  # ===== Output modes - Use [object] for RMM string compatibility (UPDATED FOR RMM) =====
  [Parameter()] [object]$Full, 
  [Parameter()] [object]$AsJson,

  # ===== Behaviour toggles =====
  [Parameter()] [object]$Strict, # Converted to object for RMM compatibility
  [Parameter()] [object]$AssumeDefenderRTWhenServiceRunning = $true, # Converted to object for RMM compatibility

  # ===== Thresholds & Requirements =====
  [int]$StaleHours = 72, 
  [int]$SigFreshHours = 48,
  [int]$MaxQuickScanAgeDays = 14, 
  [int]$MaxFullScanAgeDays = 30,
  [Parameter()] [object]$RequireRealTime = $false, # Converted to object for RMM compatibility
  [Parameter()] [object]$RequireMDE,               # Converted to object for RMM compatibility

  # ===== Test/lab overrides (retained for testing complex AV states) =====
  [string[]]$VendorFilter,
  [ValidateSet('Auto','Bitdefender','ThirdParty','DefenderBusiness','DefenderConsumer','None')]
  [string]$ForceClassification = 'Auto',
  [ValidateSet('Auto','True','False')][string]$ForceSigUpToDate = 'Auto',
  [ValidateSet('Auto','True','False')][string]$ForceSense = 'Auto',
  [string]$ForceVendor = '', 
  [Parameter()] [object]$ForceVendorPresent, # Converted to object for RMM compatibility
  [ValidateSet('Running','Stopped','Unknown')][string]$ForceVendorServiceStatus = 'Running',
  
  # === NEW PARAMETERS FOR THRESHOLD SPOOFING ===
  [ValidateSet('Auto','True','False')][string]$ForceSigFresh = 'Auto', # Force Signature Freshness Check Result
  [ValidateSet('Auto','True','False')][string]$ForceScansCurrent = 'Auto', # Force Scan Age Check Result
  # =============================================
  
  # === NEW PARAMETER TO FORCE 3RD PARTY AV VENDOR NAME ===
  [string]$ForceActiveAVVendor = '', # New string parameter to specify a 3rd party vendor name
  # =======================================================
  
  # ===== NEW TEST MODE SWITCH for MDE Call Checks (UPDATED FOR RMM) =====
  [Parameter()] [object]$TestMDE,                  # Forces MDE to report as Onboarded and Sense as Running.
  [ValidateSet('Auto','True','False')][string]$ForceOnboarded = 'Auto' # Specific MDE onboarding override.
)

$ErrorActionPreference = 'SilentlyContinue'
$script:startTime = Get-Date

# ----------------------------- HELPERS -----------------------------

function Convert-ToBool {
    <#
    .SYNOPSIS
        Converts RMM-provided parameter values ("true"/"false", "1"/"0") to [bool].
    #>
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }
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

function BoolStr([bool]$b){ if($b){'True'}else{'False'} }

# --- RMM Parameter Conversion (UPDATED) ---
$Full   = Convert-ToBool $Full
$AsJson = Convert-ToBool $AsJson
# Convert previously switch/boolean parameters to handle RMM string inputs
$Strict = Convert-ToBool $Strict
$AssumeDefenderRTWhenServiceRunning = Convert-ToBool $AssumeDefenderRTWhenServiceRunning
$RequireRealTime = Convert-ToBool $RequireRealTime
$RequireMDE = Convert-ToBool $RequireMDE
$ForceVendorPresent = Convert-ToBool $ForceVendorPresent
$TestMDE = Convert-ToBool $TestMDE

# --- Process TestMDE and set overrides ---
if ($TestMDE) {
  # If TestMDE is used, force Sense to running and Onboarded to true, 
  # unless a specific Force* parameter has already been set.
  if ($ForceSense -eq 'Auto') { $ForceSense = 'True' }
  if ($ForceOnboarded -eq 'Auto') { $ForceOnboarded = 'True' }
}


# Check for minimum required PowerShell version (5.1 or later)
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Host "ERROR: PowerShell v5.1 or later is required. Detected: $($PSVersionTable.PSVersion.ToString())"
  exit 4
}


# ----------------------------- CORE AV CHECK FUNCTIONS -----------------------------

function Get-SC2AV { # Windows Security Center (all registered AV)
  try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop }
  catch { try { Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct } catch { @() } }
}

function Convert-WscProductState { param([object]$State) # Decode hex state to booleans
  $n=$null; if ($null -ne $State) { try{$n=[int]$State}catch{} }
  if ($null -eq $n -or 0 -eq $n) { return [pscustomobject]@{ Raw=$null; RealTime=$null; SigUpToDate=$null } }
  [pscustomobject]@{ Raw=('0x{0:X4}' -f $n); RealTime=[bool]($n -band 0x10); SigUpToDate=[bool]($n -band 0x100) }
}

function Test-StaleSC2Timestamp { param([string]$Timestamp,[int]$StaleHours=72) # WSC staleness
  if ([string]::IsNullOrWhiteSpace($Timestamp)) { return $true }
  $dt=$null; try{$dt=[datetime]::Parse($Timestamp)}catch{}; if ($null -eq $dt) { return $true }
  ((Get-Date)-$dt).TotalHours -gt $StaleHours
}

function Get-MDE { # MDE Sense + registry onboarding
  $svc=Get-Service Sense -ErrorAction SilentlyContinue
  $status= if($svc){$svc.Status.ToString()}else{'NotPresent'}
  $onb=$false; $reg='HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
  if (Test-Path $reg){ $v=(Get-ItemProperty $reg -ErrorAction SilentlyContinue).OnboardingState; if($null -ne $v -and 1 -eq [int]$v){$onb=$true} }
  
  # --- MDE TEST OVERRIDE LOGIC ---
  $isSensePresent = [bool]$svc
  $isSenseRunning = ($status -eq 'Running' -or $status -eq 'StartPending')
  $isOnboarded    = $onb

  if ($script:ForceSense -ne 'Auto') {
    if ($script:ForceSense -eq 'True') { 
      $isSensePresent = $true; $status = 'Running' 
    } else { 
      $isSensePresent = $false; $status = 'Stopped' 
    }
  }

  if ($script:ForceOnboarded -ne 'Auto') {
    $isOnboarded = (Convert-ToBool $script:ForceOnboarded)
  }
  # --- END MDE TEST OVERRIDE LOGIC ---

  [pscustomobject]@{ SensePresent=$isSensePresent; SenseStatus=$status; Onboarded=$isOnboarded;
    IsBusiness=($isSensePresent -and ($status -eq 'Running' -or $status -eq 'StartPending') -and $isOnboarded) }
}

function Get-Defender { # Defender cmdlets -> fallback to service/registry
  $svc=Get-Service WinDefend -ErrorAction SilentlyContinue
  $mp=$null; if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){$mp=Get-MpComputerStatus -ErrorAction SilentlyContinue}
  $pref=$null; if(Get-Command Get-MpPreference -ErrorAction SilentlyContinue){$pref=Get-MpPreference -ErrorAction SilentlyContinue}
  $passive=$false; $k='HKLM:\SOFTWARE\Microsoft\Windows Defender'
  if(Test-Path $k){ $pm=(Get-ItemProperty $k -ErrorAction SilentlyContinue).PassiveMode; if($null -ne $pm -and 1 -eq [int]$pm){$passive=$true} }
  $rt=$false; $rtReg='HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'; $rtDisabled=$null
  if (Test-Path $rtReg){ $d=(Get-ItemProperty $rtReg -ErrorAction SilentlyContinue).DisableRealtimeMonitoring; if($null -ne $d){$rtDisabled=([int]$d -eq 1)} }
  if($mp){ $rt=[bool]$mp.RealTimeProtectionEnabled }
  elseif ($svc -and $svc.Status -eq 'Running' -and $script:AssumeDefenderRTWhenServiceRunning){ $rt = ($rtDisabled -ne $true) }
  $sigLast=$null;$sigAge=$null;$eng=$plat=$svcVer=$avSig=$asSig=$nis=$null
  if($mp){ $sigLast=$mp.AntivirusSignatureLastUpdated; if($sigLast){$sigAge=((Get-Date)-[datetime]$sigLast).TotalHours}
           $eng=$mp.AMEngineVersion;$plat=$mp.AMProductVersion;$svcVer=$mp.AMServiceVersion
           $avSig=$mp.AntivirusSignatureVersion;$asSig=$mp.AntispywareSignatureVersion;$nis=$mp.NISEngineVersion }
  [pscustomobject]@{ Present=[bool]$svc; ServiceStatus=if($svc){$svc.Status.ToString()}else{'NotPresent'}
    RealTimeProtectionEnabled=[bool]$rt; PassiveMode=$passive; EngineVersion=$eng; PlatformVersion=$plat; ServiceVersion=$svcVer
    AVSignatureVersion=$avSig; ASWSignatureVersion=$asSig; NISEngineVersion=$nis; SigLastUpdated=$sigLast; SigAgeHours=$sigAge
    LastFullScan=if($mp){$mp.FullScanEndTime}else{$null}; LastQuickScan=if($mp){$mp.QuickScanEndTime}else{$null}
    CloudProtection=if($pref){$pref.MAPSReporting}else{$null} }
}

function Get-BitdefenderInfo { # N‑able Managed AV
  $i=[pscustomobject]@{ Version=$null; InstallPath=$null; ServiceExe=$null; ServiceStatus=$null }
  $s=Get-Service bdservicehost -ErrorAction SilentlyContinue; if($s){$i.ServiceStatus=$s.Status.ToString()}
  $exe=(Get-Process -Name bdservicehost -ErrorAction SilentlyContinue | Select-Object -First 1).Path
  if($exe){ $i.ServiceExe=$exe; try{$i.Version=(Get-Item $exe).VersionInfo.FileVersion}catch{} }
  foreach($rp in 'HKLM:\SOFTWARE\Bitdefender','HKLM:\SOFTWARE\WOW6432Node\Bitdefender','HKLM:\SOFTWARE\Bitdefender\Endpoint Security','HKLM:\SOFTWARE\WOW6432Node\Bitdefender\Endpoint Security'){
    if(Test-Path $rp){ $pr=Get-ItemProperty $rp -ErrorAction SilentlyContinue
      if($pr.DisplayVersion -and -not $i.Version){$i.Version=$pr.DisplayVersion}
      if($pr.InstallDir -and -not $i.InstallPath){$i.InstallPath=$pr.InstallDir}
      if($pr.InstallPath -and -not $i.InstallPath){$i.InstallPath=$pr.InstallPath} } }
  $i
}

function Get-RelatedServices { # Spot 3rd‑party engines/EDR by services
  $patterns='defender','bitdefender','managed antivirus','sophos','mcafee','trend','kaspersky','eset','avast','avg','norton','symantec','hp wolf','hp security','sentinelone','crowdstrike','carbonblack','webroot','malwarebytes','cbdefense','csfalcon','ekrn','savservice','mbamservice','wrs' 
  $all=Get-Service -ErrorAction SilentlyContinue; $hits=@()
  foreach($p in $patterns){ $hits += ($all | Where-Object { $_.Name -match $p -or $_.DisplayName -match $p }) }
  if($hits){ $hits | Sort-Object Name -Unique | Select-Object Name,DisplayName,Status,StartType }
}

$script:VendorServiceMap = @{
  'AVG'                = @('avgsvc','avgsrvc','AVGSvc')
  'Avast'              = @('AvastSvc','aswidsagent','aswToolsSvc')
  'Norton'             = @('Norton','Symantec','SepMasterService','SepWscSvc')
  'Symantec'           = @('SepMasterService','SepWscSvc')
  'ESET'               = @('ekrn')
  'Kaspersky'          = @('AVP','KSDE')
  'Sophos'             = @('SAVService','Sophos MCS Agent','Sophos Endpoint Defense Service')
  'TrendMicro'         = @('ntrtscan','TmPfw','tmbmsrv')
  'McAfee'             = @('mfemms','macmnsvc','masvc','McShield')
  'Webroot'            = @('WRSVC')
  'Malwarebytes'       = @('MBAMService')
  'HP Wolf Security'   = @('HPSureClick','HP Sure Sense Service','HPWolfAgent','HPWolf')
  'Carbon Black'       = @('CbDefense','cbdefense')
  'SentinelOne'        = @('SentinelAgent')
  'CrowdStrike'        = @('CSFalconService')
}

function Get-ThirdPartyRTHeuristic { param([array]$Products,[array]$Services) # Reconcile WSC vs engine
  $o=@(); if(-not $Services){return $o}
  foreach($p in $Products){
    if($p.DisplayName -match 'Defender'){continue}
    $v='ThirdParty'
    if($p.DisplayName -match 'Bitdefender|Managed Antivirus'){$v='Bitdefender'}
    elseif($p.DisplayName -match 'McAfee'){$v='McAfee'}
    elseif($p.DisplayName -match 'Sophos'){$v='Sophos'}
    elseif($p.DisplayName -match 'Trend'){$v='TrendMicro'}
    elseif($p.DisplayName -match 'Kaspersky'){$v='Kaspersky'}
    elseif($p.DisplayName -match 'ESET'){$v='ESET'}
    elseif($p.DisplayName -match 'Norton|Symantec'){$v='Norton'}
    elseif($p.DisplayName -match 'AVG'){$v='AVG'}
    elseif($p.DisplayName -match 'Avast'){$v='Avast'}
    elseif($p.DisplayName -match 'HP Wolf|HP Security'){$v='HP Wolf Security'}
    elseif($p.DisplayName -match 'Carbon Black|CarbonBlack'){$v='Carbon Black'}
    elseif($p.DisplayName -match 'Webroot'){$v='Webroot'}
    elseif($p.DisplayName -match 'Malwarebytes'){$v='Malwarebytes'}
    elseif($p.DisplayName -match 'SentinelOne'){$v='SentinelOne'}
    elseif($p.DisplayName -match 'CrowdStrike'){$v='CrowdStrike'}
    elseif($p.DisplayName){$v=$p.DisplayName}

    $core=$false
    $svcHits=$null
    if($script:VendorServiceMap.ContainsKey($v)){
      $svcHits = $Services | Where-Object { $name=$_.Name; foreach($k in $script:VendorServiceMap[$v]){ if($name -like "*$k*"){ return $true } }; return $false }
      if($svcHits | Where-Object { $_.Status -eq 'Running' }) { $core=$true }
    }
    if(-not $core){
      $g=$Services | Where-Object { $_.DisplayName -match [regex]::Escape($v) -or $_.Name -match [regex]::Escape(($v -replace '\s+','')) }
      if($g | Where-Object { $_.Status -eq 'Running' }){$core=$true}
    }

    $reason=$null; $inf=$false
    if($p.IsStale -and $core){$inf=$true;$reason='WSC stale; core service running'}
    elseif($p.RealTime -eq $true -and -not $core){$inf=$false;$reason='WSC claims RT, but engine not running'}
    elseif($p.RealTime -ne $true -and $core){$inf=$true;$reason='Core service running; WSC says RT off'}

    $o += [pscustomobject]@{ Vendor=$v; WSC_RT=$p.RealTime; WSC_Sig=$p.SigUpToDate; WSC_Stale=$p.IsStale; CoreSvcRunning=$core; InferredActive=$inf; Reason=$reason }
  }
  $o
}

function Get-VendorServiceStatus { # Report 3rd‑party service state for summary
  param([Parameter(Mandatory=$true)][string]$VendorName,[array]$Services)
  if (-not $Services) { return 'Unknown' }
  if ($script:VendorServiceMap.ContainsKey($VendorName)){
    $hit = $Services | Where-Object { $n=$_.Name; foreach($m in $script:VendorServiceMap[$VendorName]){ if($n -like "*$m*"){ return $true } }; return $false } | Select-Object -First 1
    if ($hit) { return "{0}" -f $hit.Status }
  }
  $match = $Services | Where-Object {
    $_.DisplayName -match [regex]::Escape($VendorName) -or $_.Name -match ($VendorName -replace '\s+','')
  } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }
  $match = $Services | Where-Object { ($_.DisplayName + ' ' + $_.Name) -match [regex]::Escape($VendorName) } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }
  'Unknown'
}

# ----------------------------- TELEMETRY & CLASSIFICATION -----------------------------

$mp=$null; if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){$mp=Get-MpComputerStatus -ErrorAction SilentlyContinue}
$sc=@(Get-SC2AV)
$products=@()
foreach($p in $sc){
  $d=Convert-WscProductState $p.ProductState
  if(($p.displayName -match 'Defender') -and (($null -eq $d.RealTime) -or ($d.Raw -eq '0x0000'))){
    $d=[pscustomobject]@{ Raw=$d.Raw; RealTime=(if($mp){[bool]$mp.RealTimeProtectionEnabled}else{$false}); SigUpToDate=(if($mp){$mp.AntivirusSignatureVersion -ne $null}else{$null}) }
  }
  $products += [pscustomobject]@{
    DisplayName=$p.displayName; ProductStateRaw=$d.Raw; RealTime=$d.RealTime; SigUpToDate=$d.SigUpToDate
    ProductExe=$p.pathToSignedProductExe; ReportingExe=$p.pathToSignedReportingExe; Timestamp=$p.timestamp
    IsStale=(Test-StaleSC2Timestamp -Timestamp $p.timestamp -StaleHours $StaleHours)
  }
}
$svcs=Get-RelatedServices

if($VendorFilter -and $VendorFilter.Count -gt 0){
  $products=@($products | Where-Object { $n=$_.DisplayName; foreach($f in $VendorFilter){ if($n -match $f){ return $true } } ; return $false })
  if($svcs){ $svcs=@($svcs | Where-Object { $n=$_.DisplayName + ' ' + $_.Name; foreach($f in $VendorFilter){ if($n -match $f){ return $true } } ; return $false }) }
}

# Test mode: inject fake vendor
if ($ForceVendorPresent -and -not [string]::IsNullOrWhiteSpace($ForceVendor)) {
  $products += [pscustomobject]@{ DisplayName=$ForceVendor; ProductStateRaw='0x61100'; RealTime=$true; SigUpToDate=$true; ProductExe="$ForceVendor.exe"; Timestamp=(Get-Date).ToString('r'); IsStale=$false }
  if (-not $svcs) { $svcs=@() }
  $svcs += [pscustomobject]@{ Name=($ForceVendor -replace '\s+','') + 'Svc'; DisplayName="$ForceVendor Engine"; Status=$ForceVendorServiceStatus; StartType='Automatic' }
  if ($ForceClassification -eq 'Auto') { $activeThird = $products | Where-Object { $_.DisplayName -eq $ForceVendor } | Select-Object -First 1 }
}

$mde=Get-MDE; 
$def=Get-Defender
$third=@(); $heuristicUsed=$false
if(-not $Strict){ $third=Get-ThirdPartyRTHeuristic -Products $products -Services $svcs }

# --- New Force Active AV Vendor Logic ---
if (-not [string]::IsNullOrWhiteSpace($ForceActiveAVVendor)) {
    Write-Host "⚠️ [TEST MODE] Forcing classification to 3rd-party AV: '$ForceActiveAVVendor'"
    
    # 1. Force the classification type
    $ForceClassification = 'ThirdParty' 
    
    # 2. Spoof a placeholder product object for the evaluation logic to use
    $activeThird = [pscustomobject]@{
        DisplayName = $ForceActiveAVVendor; 
        RealTime = $true; 
        ProductStateRaw = '0x0000'
    }
    $confidence='Forced'
    $label='Other 3rd-party AV'
    
    # 3. SPOOF DEFENDER OFF/PASSIVE
    $def.PassiveMode = $true
    $def.RealTimeProtectionEnabled = $false
    Write-Host "⚠️ [TEST MODE] Forced Defender to PassiveMode=True and RealTimeProtectionEnabled=False."
}
# --- End New Force Active AV Vendor Logic ---

# --- Classification Logic ---
$label=$null; $confidence='Low'
if(-not $activeThird){ $activeThird = $products | Where-Object { $_.RealTime -eq $true -and $_.DisplayName -notmatch 'Defender' } | Select-Object -First 1 }
if($activeThird){ if($activeThird.DisplayName -match 'Bitdefender|Managed Antivirus'){$label='N-able Managed AV (Bitdefender)'}else{$label='Other 3rd-party AV'}; $confidence='High' }
if(-not $label){
  if($def.Present -and $def.ServiceStatus -eq 'Running' -and $def.RealTimeProtectionEnabled){
    if($mde.IsBusiness){$label='Defender - Business'}else{$label='Defender - Consumer'}; $confidence='High'
  }
}
if(-not $label -and -not $Strict -and $third){
  $inf=$third | Where-Object { $_.InferredActive -eq $true } | Select-Object -First 1
  if($inf){ if($inf.Vendor -match 'Bitdefender|Managed Antivirus'){$label='N-able Managed AV (Bitdefender)'}else{$label='Other 3rd-party AV'}
    $confidence='Medium'; $heuristicUsed=$true; if(-not $activeThird){ $activeThird = $products | Where-Object { $_.DisplayName -match [regex]::Escape($inf.Vendor) } | Select-Object -First 1 } }
}
if(-not $label){ $label='No active AV'; $confidence='Low' }
if($ForceClassification -ne 'Auto'){ switch($ForceClassification){'Bitdefender'{$label='N-able Managed AV (Bitdefender)'}'ThirdParty'{$label='Other 3rd-party AV'}'DefenderBusiness'{$label='Defender - Business'}'DefenderConsumer'{$label='Defender - Consumer'}'None'{$label='No active AV'}}; $confidence='Forced' }
$bitdef=$null; if($label -eq 'N-able Managed AV (Bitdefender)'){ $bitdef=Get-BitdefenderInfo }

# ----------------------------- EVALUATION -----------------------------

$issues=@(); $severity='Secure'
function Add-Issue { param([string]$Message,[ValidateSet('Critical','Warning','Info')][string]$Level)
  $script:issues += $Message
  switch($Level){'Critical'{$script:severity='Critical'}'Warning'{if($script:severity -ne 'Critical'){$script:severity='Warning'}}default{}}
}

# --- AV Checks ---
if($label -eq 'No active AV'){ Add-Issue 'No active antivirus detected' 'Critical' }
$defenderActive = ($label -like 'Defender*')
$defSigFresh=$false
if($def.AVSignatureVersion -and $def.AVSignatureVersion -notmatch '^0(\.0){3}$' -and $null -ne $def.SigAgeHours){ $defSigFresh = ($def.SigAgeHours -le [double]$SigFreshHours) }

# >>> NEW LOGIC: Override Signature Freshness <<<
if ($ForceSigFresh -ne 'Auto') {
    $defSigFresh = (Convert-ToBool $ForceSigFresh)
    Write-Host "⚠️ [TEST MODE] Forced \$defSigFresh to: $defSigFresh"
}
# >>> END NEW LOGIC <<<

# >>> NEW LOGIC: Override Scan Checks and Inject Dates if needed (FIXED) <<<
$scansCurrent = $true
if ($ForceScansCurrent -ne 'Auto') {
    $scansCurrent = (Convert-ToBool $ForceScansCurrent)
    Write-Host "⚠️ [TEST MODE] Forced scan checks to: $scansCurrent"

    if ($scansCurrent -eq $false) {
        # If the user forces a failure AND the scan dates are null, inject old dates 
        # that are guaranteed to fail the threshold checks.
        if (-not $def.LastQuickScan) {
            $def.LastQuickScan = (Get-Date).AddDays(-100)
            Write-Host "⚠️ [TEST MODE] Injected old LastQuickScan date."
        }
        if (-not $def.LastFullScan) {
            $def.LastFullScan = (Get-Date).AddDays(-100)
            Write-Host "⚠️ [TEST MODE] Injected old LastFullScan date."
        }
    }
}
# >>> END NEW LOGIC <<<

if($defenderActive){
  if($def.ServiceStatus -ne 'Running'){ Add-Issue 'Defender service not running' 'Critical' }
  if(($RequireRealTime -or $true) -and -not $def.RealTimeProtectionEnabled){ Add-Issue 'Defender real-time protection is OFF' 'Critical' }
  
  # Check 1: Signature Freshness (Uses $defSigFresh variable which can be forced)
  if(-not $defSigFresh -and $def.AVSignatureVersion){ Add-Issue ("Defender signatures are stale (> {0}h)" -f $SigFreshHours) 'Warning' }
  
  # Check 2 & 3: Scan Age (Only perform/report if not forcefully successful)
  if ($scansCurrent -eq $false) {
    # If forced false, these inner checks will now run against the injected (old) dates
    if($def.LastQuickScan){ $qsAge=([datetime]::UtcNow - [datetime]$def.LastQuickScan).TotalDays; if($qsAge -gt $MaxQuickScanAgeDays){ Add-Issue ("Last quick scan older than {0} days" -f $MaxQuickScanAgeDays) 'Warning' } }
    if($def.LastFullScan){  $fsAge=([datetime]::UtcNow - [datetime]$def.LastFullScan).TotalDays; if($fsAge -gt $MaxFullScanAgeDays){ Add-Issue ("Last full scan older than {0} days" -f $MaxFullScanAgeDays) 'Warning' } }
  } else {
    # Normal logic path: Check against actual thresholds if not being forced to fail
    if($def.LastQuickScan){ $qsAge=([datetime]::UtcNow - [datetime]$def.LastQuickScan).TotalDays; if($qsAge -gt $MaxQuickScanAgeDays){ Add-Issue ("Last quick scan older than {0} days" -f $MaxQuickScanAgeDays) 'Warning' } }
    if($def.LastFullScan){  $fsAge=([datetime]::UtcNow - [datetime]$def.LastFullScan).TotalDays; if($fsAge -gt $MaxFullScanAgeDays){ Add-Issue ("Last full scan older than {0} days" -f $MaxFullScanAgeDays) 'Warning' } }
  }

  if($def.PassiveMode){ Add-Issue 'Defender is in Passive Mode (subordinate to another AV)' 'Warning' }
}

if($label -eq 'N-able Managed AV (Bitdefender)'){
  if($bitdef -and $bitdef.ServiceStatus -ne 'Running'){ Add-Issue 'Bitdefender core service not running' 'Critical' }
}

if($label -eq 'Other 3rd-party AV'){
  if($third -and ($third | Where-Object { $_.Reason -eq 'WSC claims RT, but engine not running' })){
    Add-Issue 'WSC says RT enabled but vendor engine not running' 'Critical'
  }
  if($third -and ($third | Where-Object { $_.Reason -eq 'WSC stale; core service running' })){
    Add-Issue 'WSC looks stale vs vendor service state' 'Warning'
  }
  # Optional safety: third-party RT + Defender RT (not Passive) -> warn
  if ($def.RealTimeProtectionEnabled -and -not $def.PassiveMode) {
    Add-Issue 'Third-party AV active while Defender RT appears enabled (Passive Mode not detected)' 'Warning'
  }
}

# --- MDE Enforcement ---
if ($RequireMDE -and -not $mde.Onboarded){ Add-Issue 'MDE is required but not onboarded' 'Critical' }

# ----------------------------- RESULT OBJECT -----------------------------

$summaryAV= switch($label){
  'N-able Managed AV (Bitdefender)'{'N-able (Bitdefender)'}
  'Other 3rd-party AV' { if($activeThird){$activeThird.DisplayName}else{'3rd-party AV'} }
  'Defender - Business'{'Microsoft Defender Antivirus'}
  'Defender - Consumer'{'Microsoft Defender Antivirus'}
  default{'Not detected'}
}

# AV Service status in summary
$avSvc='Unknown'
if ($label -like 'Defender*') {
  $avSvc = $def.ServiceStatus
}
elseif ($label -eq 'N-able Managed AV (Bitdefender)') {
  $avSvc = if ($bitdef) { $bitdef.ServiceStatus } else { 'Unknown' }
}
elseif ($label -eq 'Other 3rd-party AV' -and $activeThird) {
  $vendorName = $activeThird.DisplayName
  $svcStatus  = Get-VendorServiceStatus -VendorName $vendorName -Services $svcs
  # If we forced the AV vendor, assume a running status for simplicity in call checks
  if ($ForceActiveAVVendor) {
      $svcName = $ForceActiveAVVendor
      $svcStatus = 'Running (Spoofed)'
      $avSvc = "{0}: {1}" -f $svcName, $svcStatus
  } 
  elseif ($svcStatus -ne 'Unknown') {
    $svcObj = $svcs | Where-Object { $_.DisplayName -match [regex]::Escape($vendorName) -or $_.Name -match ($vendorName -replace '\s+','') } | Select-Object -First 1
    $svcName = if ($svcObj) { $svcObj.DisplayName } else { $vendorName }
    $avSvc   = "{0}: {1}" -f $svcName, $svcStatus  
  }
}

# Add TestMode Note to MDE line if testing is active
$mdeNote = if ($TestMDE) { ' (TEST MODE)' } else { '' }
$mdeLine = if($mde.Onboarded){ "Onboarded (Sense=$($mde.SenseStatus))$mdeNote" } else { "Not onboarded$mdeNote" }

$script:elapsedTime = ((Get-Date) - $script:startTime).TotalSeconds
$result=[pscustomobject]@{
  Timestamp=(Get-Date).ToString('s'); ComputerName=$env:COMPUTERNAME
  Status=$severity; Issues=$issues; Classification=$label; Confidence=$confidence
  Summary=[pscustomobject]@{ ActiveAV=$summaryAV; AVService=$avSvc; MDE=$mdeLine; ElapsedTimeSec=$script:elapsedTime }
  MicrosoftDefender=$def
  MDE=[pscustomobject]@{SensePresent=$mde.SensePresent;SenseStatus=$mde.SenseStatus;Onboarded=$mde.Onboarded}
  SecurityCenter=$products; Bitdefender=$bitdef; RelatedServices=$svcs; ThirdPartyHeuristic=$third
  Parameters=[pscustomobject]@{ 
    StaleHours=$StaleHours; SigFreshHours=$SigFreshHours; MaxQuickScanAgeDays=$MaxQuickScanAgeDays; MaxFullScanAgeDays=$MaxFullScanAgeDays;
    RequireRealTime=[bool]$RequireRealTime; RequireMDE=[bool]$RequireMDE; Strict=[bool]$Strict
    ForceClassification=$ForceClassification; ForceSigUpToDate=$ForceSigUpToDate; ForceSense=$ForceSense; HeuristicUsed=$heuristicUsed; AssumeDefenderRTWhenServiceRunning=[bool]$AssumeDefenderRTWhenServiceRunning
    ForceVendor=$ForceVendor; ForceVendorPresent=[bool]$ForceVendorPresent; ForceVendorServiceStatus=$ForceVendorServiceStatus;
    ForceActiveAVVendor=$ForceActiveAVVendor;
    ForceSigFresh=$ForceSigFresh;
    ForceScansCurrent=$ForceScansCurrent;
    TestMDE=[bool]$TestMDE; ForceOnboarded=$ForceOnboarded 
  }
}

# ----------------------------- OUTPUT -----------------------------
if($AsJson){
  try{ $result | ConvertTo-Json -Depth 6 }catch{ $result | Out-String }
}elseif(-not $Full){
  $issuesText = if($issues -and $issues.Count -gt 0){ ' | Issues: ' + ($issues -join '; ') } else { '' }
  Write-Output ("[{0}] {1} | Status:{2} | AV:{3} | Svc:{4} | MDE:{5}{6}" -f `
    $result.Timestamp,$result.ComputerName,$result.Status,$result.Summary.ActiveAV,$result.Summary.AVService,$result.Summary.MDE,$issuesText)
}else{
  Write-Host "===== AV SECURITY SUMMARY (Elapsed: $($result.Summary.ElapsedTimeSec)s) ====="
  Write-Host ("Status: {0}" -f $result.Status)
  if($issues -and $issues.Count -gt 0){ Write-Host ("Issues: {0}" -f ($issues -join '; ')) } else { Write-Host "Issues: (none)" }
  Write-Host ("Active AV: {0}" -f $result.Summary.ActiveAV)
  Write-Host ("AV Service: {0}" -f $result.Summary.AVService)
  Write-Host ("MDE Onboarding: {0}" -f $result.Summary.MDE)
  Write-Host ("Confidence: {0}" -f $result.Confidence)

  Write-Host "`n--- Microsoft Defender Detail ---"
  Write-Host ("  Present:{0} Service:{1} RT:{2} Passive:{3}" -f (BoolStr $def.Present), $def.ServiceStatus, (BoolStr $def.RealTimeProtectionEnabled), (BoolStr $def.PassiveMode))
  Write-Host ("  AVSig:{0} SigAgeHours:{1:N1}" -f $def.AVSignatureVersion, $def.SigAgeHours)
  Write-Host ("  LastFullScan:{0} LastQuickScan:{1}" -f $def.LastFullScan, $def.LastQuickScan)

  Write-Host "`n--- Security Center Products ---"
  if($products.Count -eq 0){ Write-Host "  (none reported)" } else {
    $products | ForEach-Object {
      Write-Host ("- {0} | RT:{1} | SigUpToDate:{2} | State:{3}{4}" -f $_.DisplayName, $_.RealTime, $_.SigUpToDate, $_.ProductStateRaw, ($(if ($_.IsStale) { ' | STALE' } else { '' })))
      if ($_.ProductExe)   { Write-Host ("    ProductExe:   {0}" -f $_.ProductExe) }
      if ($_.Timestamp)    { Write-Host ("    Timestamp:    {0}" -f $_.Timestamp) }
    }
  }

  Write-Host "`n--- Related Security Services ---"
  if($svcs){ $svcs | ForEach-Object { Write-Host ("  {0} | {1} | {2} | {3}" -f $_.Name, $_.DisplayName, $_.Status, $_.StartType) } } else { Write-Host "  (none found)" }
  
  Write-Host "`n--- Parameters & Thresholds ---"
  Write-Host ("  SigFreshHours:{0} MaxQuickScanAgeDays:{1} MaxFullScanAgeDays:{2}" -f $SigFreshHours, $MaxQuickScanAgeDays, $MaxFullScanAgeDays)
  Write-Host ("  RequireRealTime:{0} RequireMDE:{1} Strict:{2}" -f ([bool]$RequireRealTime), ([bool]$RequireMDE), ([bool]$Strict))
  if ($TestMDE) { 
      Write-Host "  !!! MDE Testing Active: TestMDE=True !!!" 
      Write-Host "  ForceSense: {0} ForceOnboarded: {1}" -f $ForceSense, $ForceOnboarded
  }
  if (-not [string]::IsNullOrWhiteSpace($ForceActiveAVVendor)) {
      Write-Host "  !!! AV Testing Active: ForceActiveAVVendor='{0}' !!!" -f $ForceActiveAVVendor
  }
  if ($ForceSigFresh -ne 'Auto' -or $ForceScansCurrent -ne 'Auto') {
      Write-Host "  !!! THRESHOLD Testing Active: SigFresh='{0}' ScansCurrent='{1}' !!!" -f $ForceSigFresh, $ForceScansCurrent
  }
}

# ----------------------------- Exit codes -----------------------------
switch ($severity) { 'Critical'{exit 2} 'Warning'{exit 1} default{exit 0} }