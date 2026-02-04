<#
.SYNOPSIS
  Update-only maintenance script for:
    - Mozilla Firefox (dynamic or pinned)
    - Google Chrome (dynamic or pinned, Enterprise MSI)
    - Microsoft Office Click-to-Run (trigger update)
    - Adobe Reader/Acrobat (REPORT-ONLY; no update action)

  This version focuses on RMM-friendly output and “no surprises” behaviour.

.DESCRIPTION
  This script is intended for RMM automation (e.g. N-able) where you want a single run to:
    1) Detect installed versions of common apps
    2) Update Firefox/Chrome/Office when below target (or when target is “latest”)
    3) Report Adobe Reader/Acrobat status (without installing/updating Adobe)

  Output format is “Key : Value” per line to support basic RMM custom field parsing.

  IMPORTANT NOTES
  - Requires elevation (Admin) to install/update Firefox/Chrome and to trigger Office updates reliably.
  - If Office apps are open, Click-to-Run will typically stage updates and apply on app close/restart.
    If forceappshutdown is set to $true, Office may close apps to apply updates.

.NOTES
  Author: Stu
  Version: 1.9.1 (Commented Standard + safer version parsing + Adobe target-parse handling)
#>

# =============================================================================
# CONFIGURATION
# =============================================================================
# NOTE:
# - Keep configuration simple: edit the values below.
# - “Dynamic” mode pulls the latest stable version from vendor endpoints.
# - “Pinned” mode uses the versions you define here (useful for change control).

$ScriptVersion        = "1.9.1"

# -------------------------
# FIREFOX CONFIG
# -------------------------
# UseDynamicFirefox:
#   $true  -> pull latest stable version from Mozilla product-details API
#   $false -> use $PinnedFirefoxVersion
$UseDynamicFirefox    = $true
$PinnedFirefoxVersion = "147.0.2"

# FirefoxLocale:
#   Used for the Mozilla release download URL.
#   Examples: "en-US", "en-GB", "en-AU"
$FirefoxLocale        = "en-US"

# -------------------------
# CHROME CONFIG
# -------------------------
# UseDynamicChrome:
#   $true  -> pull latest stable version from Chromium Dash API
#   $false -> use $PinnedChromeVersion
$UseDynamicChrome     = $true
$PinnedChromeVersion  = "121.0.6167.161"

# ChromeForceClose:
#   When installing via MSI, FORCECLOSE=1 can force-close Chrome if it is running.
#   Keep $false by default to avoid disrupting users.
$ChromeForceClose     = $false

# -------------------------
# ADOBE CONFIG (REPORT-ONLY)
# -------------------------
# TargetAdobeVersion:
#   Used ONLY for reporting “Compliant vs Outdated” status.
#   Recommended to match the same version field your vulnerability scanner uses.
#   Example (Continuous track style): 23.008.20555
$TargetAdobeVersion   = "23.008.20555"

# -------------------------
# OFFICE CONFIG
# -------------------------
# OfficeForceShutdown:
#   Passed to OfficeC2RClient.exe as forceappshutdown=<true|false>
#   - $false (default): stage updates; apply after Office apps close/restart
#   - $true: may close Office apps to apply updates
$OfficeForceShutdown  = $false

# =============================================================================
# SAFETY: ADMIN CHECK
# =============================================================================
# WHY:
# - Firefox/Chrome installs typically require admin.
# - OfficeC2RClient generally runs fine elevated and avoids UAC prompts.
# - RMM tasks usually run as SYSTEM/admin; local testing in VS Code often does not.

$IsAdmin = $false
try {
  $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
  $IsAdmin = $false
}

Write-Output "Mode                     : UpdateOnly"
Write-Output ("Script_Version           : {0}" -f $ScriptVersion)
Write-Output ("Elevation_Status         : {0}" -f ($(if ($IsAdmin) { 'Elevated' } else { 'NotElevated' })))

if (-not $IsAdmin) {
  Write-Output "Result                   : Blocked (Not Elevated)"
  exit 1
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Download-File {
  <#
    PURPOSE
      Download a file over HTTPS to a local path.

    WHY
      RMM tasks often run in restricted environments; WebClient is simple and reliable for this use case.

    BEHAVIOUR
      - Forces TLS 1.2
      - Returns $true on success, $false on failure (no terminating errors)
  #>
  param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$OutFile
  )
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    (New-Object System.Net.WebClient).DownloadFile($Url, $OutFile)
    return $true
  } catch {
    return $false
  }
}

function Get-FileProductVersion {
  <#
    PURPOSE
      Read the ProductVersion from a Windows executable.

    WHY
      Simple, consistent method to check installed app versions when an EXE exists.
  #>
  param([string]$Path)
  try {
    return (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.ProductVersion
  } catch {
    return $null
  }
}

function Try-ParseVersion {
  <#
    PURPOSE
      Safely parse a version string into a [version] object.

    WHY
      - Vendors (especially Adobe) present versions in multiple formats.
      - Strings may include commas or extra text (e.g. “(64-bit)”).
      - Direct [version] casting fails easily and creates false “Compliant” results.

    BEHAVIOUR
      - Extracts the first version-like token (2–4 numeric components)
      - Normalises commas to dots
      - Returns $null if parsing is not possible
  #>
  param([string]$V)

  if ([string]::IsNullOrWhiteSpace($V)) { return $null }

  # Extract a token like: 23.008.20470 OR 24.0.0.312 (supports '.' or ',' separators)
  $m = [regex]::Match($V, '\d+(?:[.,]\d+){1,3}')
  if (-not $m.Success) { return $null }

  $tok = $m.Value -replace ',', '.'
  try { return [version]$tok } catch { return $null }
}

function Get-MozillaLatest {
  <#
    PURPOSE
      Get latest stable Firefox version (non-ESR) from Mozilla.

    NOTE
      If you manage ESR fleets, do not use this API field; use ESR fields instead.
  #>
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $content = (New-Object System.Net.WebClient).DownloadString("https://product-details.mozilla.org/1.0/firefox_versions.json") | ConvertFrom-Json
    return $content.LATEST_FIREFOX_VERSION
  } catch {
    return $null
  }
}

function Get-ChromeLatest {
  <#
    PURPOSE
      Get latest stable Chrome version for Windows from Chromium Dash.
  #>
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $content = (New-Object System.Net.WebClient).DownloadString("https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1") | ConvertFrom-Json
    return $content[0].version
  } catch {
    return $null
  }
}

function Get-UninstallEntries {
  <#
    PURPOSE
      Read installed program entries from Uninstall registry keys.

    WHY
      Many vulnerability scanners match software using:
        - DisplayName
        - DisplayVersion
        - Publisher

    BEHAVIOUR
      Reads both:
        - Native Uninstall key
        - WOW6432Node Uninstall key (32-bit apps on 64-bit OS)
  #>
  param([string]$HiveRoot)

  $paths = @(
    "$HiveRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "$HiveRoot\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $results = @()
  foreach ($p in $paths) {
    $results += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and ($_.Publisher -match '^Adobe' -or $_.DisplayName -match '^Adobe') } |
      Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, PSChildName
  }

  return $results
}

# =============================================================================
# FIREFOX (UPDATE-ACTIVE)
# =============================================================================
$TargetFirefox = $PinnedFirefoxVersion
$SrcFirefox    = "Pinned"

if ($UseDynamicFirefox) {
  $d = Get-MozillaLatest
  if ($d) { $TargetFirefox = $d; $SrcFirefox = "MozillaAPI" }
}

Write-Output "----------------------------------------"
Write-Output ("Firefox_Target           : {0} ({1})" -f $TargetFirefox, $SrcFirefox)

# Detect both possible install locations (x64 / x86)
$FirefoxPaths = @()
if (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") { $FirefoxPaths += "C:\Program Files\Mozilla Firefox\firefox.exe" }
if (Test-Path "C:\Program Files (x86)\Mozilla Firefox\firefox.exe") { $FirefoxPaths += "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" }

$FirefoxGlobalSuccess   = $true
$FirefoxUpdateAttempted = $false

foreach ($FirefoxExe in $FirefoxPaths) {
  $before       = Get-FileProductVersion -Path $FirefoxExe
  $beforeParsed = Try-ParseVersion -V $before
  $targetParsed = Try-ParseVersion -V $TargetFirefox

  # If we cannot parse either side, assume update is needed (safer than a false compliant state)
  $needsUpdate = $true
  if ($beforeParsed -and $targetParsed -and ($beforeParsed -ge $targetParsed)) { $needsUpdate = $false }

  if ($needsUpdate) {
    $FirefoxUpdateAttempted = $true

    # Decide download architecture based on install path
    $isX64  = ($FirefoxExe -like "C:\Program Files\*") -and ($FirefoxExe -notlike "C:\Program Files (x86)\*")
    $mozArch = $(if ($isX64) { "win64" } else { "win32" })

    $url       = "https://ftp.mozilla.org/pub/firefox/releases/$TargetFirefox/$mozArch/$FirefoxLocale/Firefox Setup $TargetFirefox.exe"
    $installer = Join-Path $env:TEMP "FirefoxSetup.exe"

    if (Download-File -Url $url -OutFile $installer) {
      # -ms = silent install for Firefox Setup EXE
      $proc = Start-Process -FilePath $installer -ArgumentList "-ms" -Wait -PassThru -WindowStyle Hidden
      if ($proc.ExitCode -ne 0) { $FirefoxGlobalSuccess = $false }
      try { Remove-Item $installer -Force -ErrorAction SilentlyContinue } catch {}
    } else {
      $FirefoxGlobalSuccess = $false
    }
  }
}

Write-Output ("Firefox_Status           : {0}" -f $(
  if ($FirefoxUpdateAttempted) { if ($FirefoxGlobalSuccess) { "Updated" } else { "Failed" } }
  else { "Compliant" }
))

# =============================================================================
# CHROME (UPDATE-ACTIVE)
# =============================================================================
$TargetChrome = $PinnedChromeVersion
$SrcChrome    = "Pinned"

if ($UseDynamicChrome) {
  $c = Get-ChromeLatest
  if ($c) { $TargetChrome = $c; $SrcChrome = "ChromiumAPI" }
}

Write-Output "----------------------------------------"
Write-Output ("Chrome_Target            : {0} ({1})" -f $TargetChrome, $SrcChrome)

# Detect both possible install locations (x64 / x86)
$ChromePaths = @()
if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") { $ChromePaths += "C:\Program Files\Google\Chrome\Application\chrome.exe" }
if (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") { $ChromePaths += "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" }

$ChromeGlobalSuccess   = $true
$ChromeUpdateAttempted = $false
$ChromeNeedsUpdate     = $false

foreach ($path in $ChromePaths) {
  $vp = Try-ParseVersion -V (Get-FileProductVersion -Path $path)
  $tp = Try-ParseVersion -V $TargetChrome
  if ($vp -and $tp -and ($vp -lt $tp)) { $ChromeNeedsUpdate = $true }
}

if ($ChromeNeedsUpdate) {
  $ChromeUpdateAttempted = $true

  # NOTE:
  # - This uses the Enterprise 64-bit MSI. In most cases it upgrades existing installs cleanly.
  # - If you encounter fleets with 32-bit Chrome only, you may need logic to pull the 32-bit MSI.
  $url       = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
  $installer = Join-Path $env:TEMP "ChromeEnt64.msi"

  if (Download-File -Url $url -OutFile $installer) {
    $args = "/i `"$installer`" /qn /norestart"
    if ($ChromeForceClose) { $args += " FORCECLOSE=1" }

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden

    # ExitCode 3010 = success, reboot required
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { $ChromeGlobalSuccess = $false }
    try { Remove-Item $installer -Force -ErrorAction SilentlyContinue } catch {}
  } else {
    $ChromeGlobalSuccess = $false
  }
}

Write-Output ("Chrome_Status            : {0}" -f $(
  if ($ChromeUpdateAttempted) { if ($ChromeGlobalSuccess) { "Updated" } else { "Failed" } }
  else { "Compliant" }
))

# =============================================================================
# ADOBE (REPORT-ONLY) – Reader + Acrobat, Registry-first
# =============================================================================

Write-Output "----------------------------------------"
Write-Output ("Adobe_TargetVersion      : {0}" -f $TargetAdobeVersion)

# Registry discovery (scanner-aligned)
$un = @()
$un += Get-UninstallEntries -HiveRoot "HKLM:"
$un += Get-UninstallEntries -HiveRoot "HKCU:"

# Limit scope to Reader/Acrobat only (avoid Creative Cloud noise)
$targets = $un |
  Where-Object { $_.DisplayName -match 'Acrobat' -or $_.DisplayName -match 'Reader' } |
  Sort-Object DisplayName -Unique

# EXE discovery (sanity/fallback)
$exeCandidates = @(
  @{ Product="Acrobat"; Arch="x64"; Path="C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{ Product="Acrobat"; Arch="x86"; Path="C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{ Product="Reader";  Arch="x64"; Path="C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" },
  @{ Product="Reader";  Arch="x86"; Path="C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" },
  # Older/common alternate folder names
  @{ Product="Reader";  Arch="x64"; Path="C:\Program Files\Adobe\Acrobat Reader\Reader\AcroRd32.exe" },
  @{ Product="Reader";  Arch="x86"; Path="C:\Program Files (x86)\Adobe\Acrobat Reader\Reader\AcroRd32.exe" }
)

$foundExe = @()
foreach ($c in $exeCandidates) {
  if (Test-Path -LiteralPath $c.Path) {
    $foundExe += [pscustomobject]@{
      Product = $c.Product
      Arch    = $c.Arch
      Path    = $c.Path
      ExeVer  = (Get-FileProductVersion -Path $c.Path)
    }
  }
}

if (-not $targets -and -not $foundExe) {
  Write-Output "Adobe_Status             : NotInstalled"
} else {

  # Report registry entries (best alignment to scanners)
  if ($targets) {
    $i = 0
    foreach ($t in $targets) {
      $i++
      Write-Output ("Adobe_{0}_Name           : {1}" -f $i, $t.DisplayName)
      Write-Output ("Adobe_{0}_DisplayVer     : {1}" -f $i, $t.DisplayVersion)
    }
  }

  # Report EXE versions (diagnostic / reconciliation when registry is stale)
  if ($foundExe) {
    $j = 0
    foreach ($e in ($foundExe | Sort-Object Product, Arch)) {
      $j++
      Write-Output ("AdobeExe_{0}_Product     : {1} ({2})" -f $j, $e.Product, $e.Arch)
      Write-Output ("AdobeExe_{0}_ExeVer      : {1}" -f $j, $e.ExeVer)
      Write-Output ("AdobeExe_{0}_Path        : {1}" -f $j, $e.Path)
    }
  }

  # Compliance decision (report-only)
  $targParsed = Try-ParseVersion -V $TargetAdobeVersion
  if (-not $targParsed) {
    Write-Output "Adobe_Status             : Unknown (Target parse failed)"
  } else {
    $installedVersions = @()

    # Prefer DisplayVersion (scanner-aligned)
    foreach ($t in $targets) {
      if ($t.DisplayVersion) {
        $installedVersions += (Try-ParseVersion -V $t.DisplayVersion)
      }
    }

    # Fallback to EXE versions only if we got nothing usable from registry
    if ((($installedVersions | Where-Object { $_ -ne $null }).Count -eq 0) -and $foundExe) {
      foreach ($e in $foundExe) {
        $installedVersions += (Try-ParseVersion -V $e.ExeVer)
      }
    }

    $validVersions = $installedVersions | Where-Object { $_ -ne $null }

    if ($validVersions.Count -eq 0) {
      Write-Output "Adobe_Status             : Unknown (Parse Failed)"
    } else {
      # “Lowest version wins” approach: if ANY installed Reader/Acrobat is below target, treat as outdated.
      $minVer = ($validVersions | Measure-Object -Minimum).Minimum
      if ($minVer -lt $targParsed) {
        Write-Output "Adobe_Status             : Outdated (Update Disabled)"
      } else {
        Write-Output "Adobe_Status             : Compliant"
      }
    }
  }
}

# =============================================================================
# OFFICE (UPDATE-ACTIVE) – Click-to-Run
# =============================================================================
Write-Output "----------------------------------------"

$OfficeExe       = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
$OfficeAttempted = $false
$OfficeSuccess   = $true

if (Test-Path -LiteralPath $OfficeExe) {

  $OfficeAttempted = $true

  # NOTE:
  # - “/update user” uses the current user context semantics for Click-to-Run updating.
  # - displaylevel=false attempts to suppress UI prompts.
  # - forceappshutdown controls whether Office apps may be closed to apply updates.
  $args = "/update user displaylevel=false forceappshutdown=$OfficeForceShutdown"

  $proc = Start-Process -FilePath $OfficeExe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
  if ($proc.ExitCode -ne 0) { $OfficeSuccess = $false }

  Write-Output ("Office_Result            : {0}" -f $(if ($OfficeSuccess) { "Success" } else { "Failed" }))

} else {
  Write-Output "Office_Status            : NotInstalled"
}

# =============================================================================
# EXIT MAPPING (RMM)
# =============================================================================
Write-Output "----------------------------------------"

# IMPORTANT:
# - Adobe is report-only and MUST NOT change the exit code.
# - Exit code indicates whether any active update action failed (Firefox/Chrome/Office).

$AnyFailure = ($FirefoxUpdateAttempted -and -not $FirefoxGlobalSuccess) -or `
              ($ChromeUpdateAttempted  -and -not $ChromeGlobalSuccess)  -or `
              ($OfficeAttempted        -and -not $OfficeSuccess)

if ($AnyFailure) {
  Write-Output "Global_Result            : Failure"
  exit 2
}

Write-Output "Global_Result            : Success"
exit 0
