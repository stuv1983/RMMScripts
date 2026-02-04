<#
.SYNOPSIS
  Firefox Update Only (Dynamic or Pinned)
#>

# CONFIGURATION
$UseDynamicFirefox    = $true
$PinnedFirefoxVersion = "147.0.2"
$FirefoxLocale        = "en-US"

# ADMIN CHECK
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Output "Blocked: Not Elevated"; exit 1 }

# HELPERS
function Download-File {
  param($Url, $OutFile)
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile($Url, $OutFile); return $true } catch { return $false }
}
function Get-FileProductVersion { param($Path); try { return (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.ProductVersion } catch { return $null } }
function Try-ParseVersion {
  param($V)
  if ([string]::IsNullOrWhiteSpace($V)) { return $null }
  $m = [regex]::Match($V, '\d+(?:[.,]\d+){1,3}'); if (-not $m.Success) { return $null }
  try { return [version]($m.Value -replace ',', '.') } catch { return $null }
}
function Get-MozillaLatest {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; return ((New-Object System.Net.WebClient).DownloadString("https://product-details.mozilla.org/1.0/firefox_versions.json") | ConvertFrom-Json).LATEST_FIREFOX_VERSION } catch { return $null }
}

# LOGIC
$Target = $PinnedFirefoxVersion
if ($UseDynamicFirefox) { $d = Get-MozillaLatest; if ($d) { $Target = $d } }
Write-Output "Firefox_Target: $Target"

$Paths = @()
if (Test-Path "C:\Program Files\Mozilla Firefox\firefox.exe") { $Paths += "C:\Program Files\Mozilla Firefox\firefox.exe" }
if (Test-Path "C:\Program Files (x86)\Mozilla Firefox\firefox.exe") { $Paths += "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" }

$GlobalSuccess = $true
$Attempted = $false

foreach ($exe in $Paths) {
    $curr = Try-ParseVersion (Get-FileProductVersion $exe)
    $targ = Try-ParseVersion $Target
    
    if ($curr -and $targ -and $curr -lt $targ) {
        $Attempted = $true
        # Detect Arch
        $isX64 = ($exe -like "C:\Program Files\*") -and ($exe -notlike "C:\Program Files (x86)\*")
        $arch = $(if ($isX64) { "win64" } else { "win32" })
        
        $url = "https://ftp.mozilla.org/pub/firefox/releases/$Target/$arch/$FirefoxLocale/Firefox Setup $Target.exe"
        $file = "$env:TEMP\FirefoxSetup.exe"
        
        if (Download-File $url $file) {
            $p = Start-Process $file -ArgumentList "-ms" -Wait -PassThru -WindowStyle Hidden
            if ($p.ExitCode -ne 0) { $GlobalSuccess = $false }
            Remove-Item $file -ErrorAction SilentlyContinue
        } else { $GlobalSuccess = $false }
    }
}

if ($Attempted -and -not $GlobalSuccess) { Write-Output "Result: Failed"; exit 2 }
Write-Output "Result: Success"; exit 0