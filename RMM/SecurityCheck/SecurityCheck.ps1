<# 
.SYNOPSIS
  SecurityCheck.ps1 — NOC/MSP endpoint security posture check (PowerShell 5.1+).

.DESCRIPTION
  Performs a comprehensive security and health audit, including deep AV status checks
  using heuristics, MDE, Firewall, and modern security controls like VBS/HVCI and LAPS.
  Default output is a one-liner; use -Full for ticket notes; -AsJson for parsing.
  
  Covers: AV, Firewall, MDE, Windows Update currency, Pending reboot, Last reboot/uptime,
          VBS/HVCI, LAPS, and PowerShell Script Logging.
  
.EXIT CODES
  0 = Secure
  1 = Warning (reboot pending, old signatures, stale WSC, etc.)
  2 = Critical (no active AV, firewall off, critical control missing/off)
  4 = Script Error (e.g., failed PowerShell version check)
#>

[CmdletBinding()]
param(
  # ===== Output modes - CHANGED TO [object] FOR RMM STRING COMPATIBILITY =====
  [Parameter()] [object]$Full, 
  [Parameter()] [object]$AsJson,

  # ===== Behaviour toggles =====
  [switch]$Strict,
  [switch]$AssumeDefenderRTWhenServiceRunning = $true,

  # ===== Minimum requirements (set these to trigger Critical/Warning issues) =====
  [int]$StaleHours = 72, 
  [int]$SigFreshHours = 48,
  [int]$MaxQuickScanAgeDays = 14, 
  [int]$MaxFullScanAgeDays = 30,
  [int]$WUCurrencyDays = 30,
  [int]$UptimeWarningDays = 45, # Days since last reboot to warn
  [switch]$RequireFirewallOn = $true, 
  [switch]$RequireRealTime = $false, 
  [switch]$RequireMDE,
  [switch]$RequireVBS,
  [switch]$RequireLAPS,
  [switch]$RequireScriptLogging,

  # ===== Test/lab overrides =====
  [string[]]$VendorFilter,
  [ValidateSet('Auto','Bitdefender','ThirdParty','DefenderBusiness','DefenderConsumer','None')]
  [string]$ForceClassification = 'Auto',
  [ValidateSet('Auto','On','Off')][string]$ForceFirewall = 'Auto',
  [ValidateSet('Auto','True','False')][string]$ForceSigUpToDate = 'Auto',
  [ValidateSet('Auto','True','False')][string]$ForceSense = 'Auto',

  # ===== Vendor simulation for testing =====
  [string]$ForceVendor = '', 
  [switch]$ForceVendorPresent,
  [ValidateSet('Running','Stopped','Unknown')][string]$ForceVendorServiceStatus = 'Running'
)

$ErrorActionPreference = 'SilentlyContinue'
$script:startTime = Get-Date

# ----------------------------- HELPERS -----------------------------

function Convert-ToBool {
    <#
    .SYNOPSIS
        Converts RMM-provided parameter values ("true"/"false", "1"/"0") to [bool].
    .DESCRIPTION
        Accepts $null, [bool], numbers, or strings. This is essential for RMM engines.
    #>
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
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

# --- RMM Parameter Conversion ---
# Convert RMM string inputs for the output modes to proper Booleans
$Full   = Convert-ToBool $Full
$AsJson = Convert-ToBool $AsJson

# Check for minimum required PowerShell version (5.1 or later for modern cmdlets)
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Host "ERROR: PowerShell v5.1 or later is required. Detected: $($PSVersionTable.PSVersion.ToString())"
  exit 4
}


# ----------------------------- CORE HELPER FUNCTIONS (UNCHANGED) -----------------------------

function Get-SC2AV { # Windows Security Center (all registered AV)
  # Prefer CIM. If the default transport fails (often due to WinRM configuration), retry CIM via DCOM.
  # Only fall back to legacy WMI as a last resort.
  try {
    return Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
  }
  catch {
    try {
      $opt = New-CimSessionOption -Protocol Dcom
      return Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -CimSession (New-CimSession -SessionOption $opt) -ErrorAction Stop
    }
    catch {
      try { return Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop }
      catch { return @() }
    }
  }
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
  [pscustomobject]@{ SensePresent=[bool]$svc; SenseStatus=$status; Onboarded=$onb;
    IsBusiness=([bool]$svc -and ($status -eq 'Running' -or $status -eq 'StartPending') -and $onb) }
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
  # PERF: single-pass filter rather than N * Where-Object scans.
  # Note: escape/quote carefully because some patterns contain spaces.
  $patternList = @(
    'defender','bitdefender','managed antivirus','sophos','mcafee','trend','kaspersky','eset','avast','avg','norton','symantec',
    'hp wolf','hp security','sentinelone','crowdstrike','carbonblack','webroot','malwarebytes','cbdefense','csfalcon','ekrn','savservice','mbamservice','wrs'
  )
  $rx = [regex]::new('(' + (($patternList | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

  $all = Get-Service -ErrorAction SilentlyContinue
  $hits = $all | Where-Object { $rx.IsMatch($_.Name) -or $rx.IsMatch($_.DisplayName) }
  if ($hits) { $hits | Sort-Object Name -Unique | Select-Object Name, DisplayName, Status, StartType }
}

# Map common vendor -> service name patterns to improve detection
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
  # 1) Specific name patterns from map
  if ($script:VendorServiceMap.ContainsKey($VendorName)){
    $hit = $Services | Where-Object { $n=$_.Name; foreach($m in $script:VendorServiceMap[$VendorName]){ if($n -like "*$m*"){ return $true } }; return $false } | Select-Object -First 1
    if ($hit) { return "{0}" -f $hit.Status }
  }
  # 2) Tight vendor name match
  $match = $Services | Where-Object {
    $_.DisplayName -match [regex]::Escape($VendorName) -or $_.Name -match ($VendorName -replace '\s+','')
  } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }
  # 3) Loose contains match
  $match = $Services | Where-Object { ($_.DisplayName + ' ' + $_.Name) -match [regex]::Escape($VendorName) } | Select-Object -First 1
  if ($match) { return $match.Status.ToString() }
  'Unknown'
}

function Get-VBSStatus { # Virtualization Based Security / HVCI check
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $vbs = $false; $hvci = $false
    if (Test-Path $regPath) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        # 1 means VBS is enabled
        if ($props.EnableVirtualizationBasedSecurity -eq 1) { $vbs = $true }
        # 1 means HVCI (Code Integrity) is enabled
        if ($props.EnableSystemProtectedFiles -eq 1) { $hvci = $true }
    }
    [pscustomobject]@{ VBSOn=$vbs; HVCIPresent=$hvci }
}

function Get-LAPSStatus { # Client-side LAPS status
    $lapsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS'
    $installed = (Test-Path 'C:\Windows\system32\AdmPwd.dll') -or (Test-Path $lapsKey) # Basic file/key check
    $passwordAgeDays = $null
    if (Test-Path $lapsKey) {
        $props = Get-ItemProperty $lapsKey -ErrorAction SilentlyContinue
        $lastUpdate = $props.PasswordLastUpdateTimestamp
        if ($lastUpdate -is [datetime]) {
            $passwordAgeDays = ((Get-Date) - $lastUpdate).TotalDays
        }
    }
    [pscustomobject]@{ Installed=$installed; LastUpdateTimestamp=$lastUpdate; PasswordAgeDays=$passwordAgeDays }
}

function Get-PowerShellLoggingStatus { # PowerShell Script Block Logging status
    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $enabled = $false
    if (Test-Path $regPath) {
        $value = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        # 1 means Script Block Logging is enabled
        if ($value -eq 1) { $enabled = $true }
    }
    [pscustomobject]@{ Enabled=$enabled }
}

# ----------------------------- Telemetry -----------------------------

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
  $products += [pscustomobject]@{
    DisplayName=$ForceVendor; ProductStateRaw='0x61100'; RealTime=$true; SigUpToDate=$true
    ProductExe="$ForceVendor.exe"; ReportingExe="$ForceVendor-Reporter.exe"; Timestamp=(Get-Date).ToString('r'); IsStale=$false
  }
  if (-not $svcs) { $svcs=@() }
  $svcs += [pscustomobject]@{ Name=($ForceVendor -replace '\s+','') + 'Svc'; DisplayName="$ForceVendor Engine"; Status=$ForceVendorServiceStatus; StartType='Automatic' }
  if ($ForceClassification -eq 'Auto') { $activeThird = $products | Where-Object { $_.DisplayName -eq $ForceVendor } | Select-Object -First 1 }
}

$mde=Get-MDE; 
$def=Get-Defender
$vbs=Get-VBSStatus            
$laps=Get-LAPSStatus          
$pslog=Get-PowerShellLoggingStatus 

$third=@(); $heuristicUsed=$false
if(-not $Strict){ $third=Get-ThirdPartyRTHeuristic -Products $products -Services $svcs }

# ----------------------------- Classification -----------------------------
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

# ----------------------------- Evaluation -----------------------------
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

if($defenderActive){
  if($def.ServiceStatus -ne 'Running'){ Add-Issue 'Defender service not running' 'Critical' }
  if(($RequireRealTime -or $true) -and -not $def.RealTimeProtectionEnabled){ Add-Issue 'Defender real-time protection is OFF' 'Critical' }
  if(-not $defSigFresh -and $def.AVSignatureVersion){ Add-Issue ("Defender signatures are stale (> {0}h)" -f $SigFreshHours) 'Warning' }
  if($def.LastQuickScan){ $qsAge=([datetime]::UtcNow - [datetime]$def.LastQuickScan).TotalDays; if($qsAge -gt $MaxQuickScanAgeDays){ Add-Issue ("Last quick scan older than {0} days" -f $MaxQuickScanAgeDays) 'Warning' } }
  if($def.LastFullScan){  $fsAge=([datetime]::UtcNow - [datetime]$def.LastFullScan).TotalDays; if($fsAge -gt $MaxFullScanAgeDays){ Add-Issue ("Last full scan older than {0} days" -f $MaxFullScanAgeDays) 'Warning' } }
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

# --- VBS (Credential Guard / HVCI) Check ---
if ($RequireVBS -and -not $vbs.VBSOn){ Add-Issue 'Virtualization-Based Security (VBS) is required but OFF' 'Critical' }

# --- LAPS Check ---
if ($RequireLAPS -and -not $laps.Installed){ Add-Issue 'LAPS is required but not detected (client-side)' 'Warning' }

# --- PowerShell Logging Check ---
if ($RequireScriptLogging -and -not $pslog.Enabled){ Add-Issue 'PowerShell Script Block Logging is required but OFF' 'Warning' }


# ----------------------------- System health -----------------------------
$fwState='Unknown'
try{ $fw=Get-CimInstance -ClassName Win32_Service -Filter "Name='mpssvc'" -ErrorAction Stop; $fwState= if($fw.State -eq 'Running'){'On'}else{'Off'} }
catch{ try{ $pf=Get-NetFirewallProfile -ErrorAction Stop; $fwState= if($pf.Enabled -contains $true){'On'}else{'Off'} } catch{ $fwState='Unknown' } }
if($ForceFirewall -ne 'Auto'){$fwState=$ForceFirewall}
if($RequireFirewallOn){ if($fwState -ne 'On'){ Add-Issue 'Firewall is OFF' 'Critical' } }

$WU_Last='Unknown'; $WU_AgeDays=$null
try{
  $qfe=Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1
  $inst=$null; if($qfe -and $qfe.InstalledOn){ try{$inst=[datetime]$qfe.InstalledOn}catch{try{$inst=[datetime]::Parse($qfe.InstalledOn)}catch{$inst=$null}} }
  if($null -ne $inst){ $WU_Last=$inst.ToString('yyyy-MM-dd'); $WU_AgeDays=((Get-Date)-$inst).TotalDays; if($WU_AgeDays -gt $WUCurrencyDays){ Add-Issue ("Last Windows update installed {0:N0} days ago" -f $WU_AgeDays) 'Warning' } }
  else { $WU_Last='None'; Add-Issue 'No Windows updates detected in history' 'Warning' }
}catch{ $WU_Last='Unknown'; Add-Issue 'Unable to read Windows Update history' 'Warning' }

$RebootPending='Unknown'
try{
  $pending=$false; $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations')
  foreach($p in $paths){ if(Test-Path $p){ $pending=$true } }
  if($pending){ $RebootPending='Yes'; Add-Issue 'System restart pending after updates or installs' 'Warning' } else { $RebootPending='No' }
}catch{ $RebootPending='Unknown'; Add-Issue 'Could not verify reboot status' 'Warning' }

$lastBootString='Unknown'
$upt=0
try{ $boot=(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime; $upt=((Get-Date)-[datetime]$boot).TotalDays; $lastBootString=("{0} (uptime {1:N0} days)" -f $boot,$upt); if($upt -gt $UptimeWarningDays){ Add-Issue ("System uptime exceeds {0:N0} days" -f $upt) 'Warning' } }catch{ $lastBootString='Unknown' }

# ----------------------------- Result shape -----------------------------
$summaryAV= switch($label){
  'N-able Managed AV (Bitdefender)'{'N-able (Bitdefender)'}
  'Other 3rd-party AV' { if($activeThird){$activeThird.DisplayName}else{'3rd-party AV'} }
  'Defender - Business'{'Microsoft Defender Antivirus'}
  'Defender - Consumer'{'Microsoft Defender Antivirus'}
  default{'Not detected'}
}

# Third‑party service status in summary (e.g., AVG Anti-Virus Service: Running)
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
  if ($svcStatus -ne 'Unknown') {
    # Use DisplayName for cleaner output (e.g. 'AVG Anti-Virus Service: Running')
    $svcObj = $svcs | Where-Object { $_.DisplayName -match [regex]::Escape($vendorName) -or $_.Name -match ($vendorName -replace '\s+','') } | Select-Object -First 1
    $svcName = if ($svcObj) { $svcObj.DisplayName } else { $vendorName }
    $avSvc   = "{0}: {1}" -f $svcName, $svcStatus  
  }
}

$mdeLine = if($mde.Onboarded){ "Onboarded (Sense=$($mde.SenseStatus))" } else { "Not onboarded" }
$vbsLine = if($vbs.VBSOn){ "On (HVCI=$($vbs.HVCIPresent))" } else { "Off" }
$lapsLine = if($laps.Installed){ "Detected" } else { "Not detected" }
$pslogLine = if($pslog.Enabled){ "Enabled" } else { "Disabled" }

function BoolStr([bool]$b){ if($b){'True'}else{'False'} }

$script:elapsedTime = ((Get-Date) - $script:startTime).TotalSeconds
$result=[pscustomobject]@{
  Timestamp=(Get-Date).ToString('s'); ComputerName=$env:COMPUTERNAME
  Status=$severity; Issues=$issues; Classification=$label; Confidence=$confidence
  Summary=[pscustomobject]@{ ActiveAV=$summaryAV; AVService=$avSvc; MDE=$mdeLine; Firewall=$fwState; WindowsUpdateLast=$WU_Last; PendingReboot=$RebootPending; LastReboot=$lastBootString; VBS=$vbsLine; LAPS=$lapsLine; PSLogging=$pslogLine; ElapsedTimeSec=$script:elapsedTime }
  MicrosoftDefender=$def
  MDE=[pscustomobject]@{SensePresent=$mde.SensePresent;SenseStatus=$mde.SenseStatus;Onboarded=$mde.Onboarded}
  VBS=$vbs 
  LAPS=$laps 
  PSLogging=$pslog 
  SecurityCenter=$products; Bitdefender=$bitdef; RelatedServices=$svcs; ThirdPartyHeuristic=$third
  Parameters=[pscustomobject]@{ 
    StaleHours=$StaleHours; SigFreshHours=$SigFreshHours; MaxQuickScanAgeDays=$MaxQuickScanAgeDays; MaxFullScanAgeDays=$MaxFullScanAgeDays; WUCurrencyDays=$WUCurrencyDays
    UptimeWarningDays=$UptimeWarningDays;
    RequireFirewallOn=[bool]$RequireFirewallOn; RequireRealTime=[bool]$RequireRealTime; RequireMDE=[bool]$RequireMDE; RequireVBS=[bool]$RequireVBS; RequireLAPS=[bool]$RequireLAPS; RequireScriptLogging=[bool]$RequireScriptLogging; Strict=[bool]$Strict
    ForceClassification=$ForceClassification; ForceFirewall=$ForceFirewall; ForceSigUpToDate=$ForceSigUpToDate; ForceSense=$ForceSense; HeuristicUsed=$heuristicUsed; AssumeDefenderRTWhenServiceRunning=[bool]$AssumeDefenderRTWhenServiceRunning
    ForceVendor=$ForceVendor; ForceVendorPresent=[bool]$ForceVendorPresent; ForceVendorServiceStatus=$ForceVendorServiceStatus }
}

# ----------------------------- Output -----------------------------
if($AsJson){
  try{ $result | ConvertTo-Json -Depth 6 }catch{ $result | Out-String }
}elseif(-not $Full){
  $issuesText = if($issues -and $issues.Count -gt 0){ ' | Issues: ' + ($issues -join '; ') } else { '' }
  Write-Output ("[{0}] {1} | Status:{2} | AV:{3} | Svc:{4} | MDE:{5} | FW:{6} | VBS:{7} | WU:{8} | PendingReboot:{9} | LastReboot:{10}{11}" -f `
    $result.Timestamp,$result.ComputerName,$result.Status,$result.Summary.ActiveAV,$result.Summary.AVService,$result.Summary.MDE,$result.Summary.Firewall,$result.Summary.VBS,$result.Summary.WindowsUpdateLast,$result.Summary.PendingReboot,$result.Summary.LastReboot,$issuesText)
}else{
  Write-Host "===== SECURITY SUMMARY (Elapsed: $($result.Summary.ElapsedTimeSec)s) ====="
  Write-Host ("Status: {0}" -f $result.Status)
  if($issues -and $issues.Count -gt 0){ Write-Host ("Issues: {0}" -f ($issues -join '; ')) } else { Write-Host "Issues: (none)" }
  Write-Host ("Active AV: {0}" -f $result.Summary.ActiveAV)
  Write-Host ("AV Service: {0}" -f $result.Summary.AVService)
  Write-Host ("Firewall: {0}" -f $result.Summary.Firewall)
  Write-Host ("Pending Reboot: {0}" -f $result.Summary.PendingReboot)
  Write-Host ("Windows Update (last installed): {0}" -f $result.Summary.WindowsUpdateLast)
  Write-Host ("Last Reboot: {0}" -f $result.Summary.LastReboot)
  Write-Host ("Confidence: {0}" -f $result.Confidence)

  Write-Host "`n--- Microsoft Security Controls ---"
  Write-Host ("  MDE Onboarding: {0}" -f $result.Summary.MDE)
  Write-Host ("  VBS/HVCI Status: {0}" -f $result.Summary.VBS)
  Write-Host ("  LAPS Client: {0} (Age: {1:N0} days)" -f $result.Summary.LAPS, $result.LAPS.PasswordAgeDays)
  Write-Host ("  PS Script Logging: {0}" -f $result.Summary.PSLogging)


  Write-Host "`n--- Microsoft Defender Detail ---"
  Write-Host ("  Present:{0} Service:{1} RT:{2} Passive:{3}" -f (BoolStr $def.Present), $def.ServiceStatus, (BoolStr $def.RealTimeProtectionEnabled), (BoolStr $def.PassiveMode))
  Write-Host ("  Engine:{0} Platform:{1} ServiceVer:{2}" -f $def.EngineVersion, $def.PlatformVersion, $def.ServiceVersion)
  Write-Host ("  AVSig:{0} ASWSig:{1} NISEngine:{2}" -f $def.AVSignatureVersion, $def.ASWSignatureVersion)
  Write-Host ("  SigLastUpdated:{0} SigAgeHours:{1:N1}" -f $def.SigLastUpdated, $def.SigAgeHours)
  Write-Host ("  LastFullScan:{0} LastQuickScan:{1}" -f $def.LastFullScan, $def.LastQuickScan)

  Write-Host "`n--- Security Center Products ---"
  if($products.Count -eq 0){ Write-Host "  (none reported)" } else {
    $products | ForEach-Object {
      Write-Host ("- {0} | RT:{1} | SigUpToDate:{2} | State:{3}{4}" -f $_.DisplayName, $_.RealTime, $_.SigUpToDate, $_.ProductStateRaw, ($(if ($_.IsStale) { ' | STALE' } else { '' })))
      if ($_.ProductExe)   { Write-Host ("    ProductExe:   {0}" -f $_.ProductExe) }
      if ($_.Timestamp)    { Write-Host ("    Timestamp:    {0}" -f $_.Timestamp) }
    }
  }

  if($bitdef){
    Write-Host "`n--- Bitdefender BEST ---"
    Write-Host ("  Version:{0}" -f $bitdef.Version)
    Write-Host ("  ServiceStatus:{0}" -f $bitdef.ServiceStatus)
  }

  Write-Host "`n--- Related Security Services ---"
  if($svcs){ $svcs | ForEach-Object { Write-Host ("  {0} | {1} | {2} | {3}" -f $_.Name, $_.DisplayName, $_.Status, $_.StartType) } } else { Write-Host "  (none found)" }

  Write-Host "`n--- Third-Party Heuristic ---"
  if($third -and $third.Count -gt 0){
    $third | ForEach-Object { Write-Host ("  {0} | InferredActive:{1} | CoreSvc:{2} | WSC_RT:{3} | Stale:{4} | {5}" -f $_.Vendor, (BoolStr $_.InferredActive), (BoolStr $_.CoreSvcRunning), $_.WSC_RT, $_.WSC_Stale, $_.Reason) }
  } else { Write-Host "  (none)" }
  
  Write-Host "`n--- Parameters & Thresholds ---"
  Write-Host ("  StaleHours:{0} SigFreshHours:{1} MaxQuickScanAgeDays:{2} MaxFullScanAgeDays:{3} WUCurrencyDays:{4}" -f $StaleHours, $SigFreshHours, $MaxQuickScanAgeDays, $MaxFullScanAgeDays, $WUCurrencyDays)
  Write-Host ("  UptimeWarningDays:{0}" -f $UptimeWarningDays)
  Write-Host ("  RequireFirewallOn:{0} RequireRealTime:{1} RequireMDE:{2}" -f ([bool]$RequireFirewallOn), ([bool]$RequireRealTime), ([bool]$RequireMDE))
  Write-Host ("  RequireVBS:{0} RequireLAPS:{1} RequireScriptLogging:{2} Strict:{3}" -f ([bool]$RequireVBS), ([bool]$RequireLAPS), ([bool]$RequireScriptLogging), ([bool]$Strict))
}

# ----------------------------- Exit codes -----------------------------
switch ($severity) { 'Critical'{exit 2} 'Warning'{exit 1} default{exit 0} }