<#
.SYNOPSIS
  Chrome Update Only (Dynamic or Pinned)
#>

# CONFIGURATION
$UseDynamicChrome    = $true
$PinnedChromeVersion = "121.0.6167.161"
$ChromeForceClose    = $false

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
function Get-ChromeLatest {
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; return ((New-Object System.Net.WebClient).DownloadString("https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1") | ConvertFrom-Json)[0].version } catch { return $null }
}

# LOGIC
$Target = $PinnedChromeVersion
if ($UseDynamicChrome) { $c = Get-ChromeLatest; if ($c) { $Target = $c } }

Write-Output "Chrome_Target: $Target"

$Paths = @()
if (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") { $Paths += "C:\Program Files\Google\Chrome\Application\chrome.exe" }
if (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe") { $Paths += "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" }

$UpdateNeeded = $false
foreach ($p in $Paths) {
    $curr = Try-ParseVersion (Get-FileProductVersion $p)
    $targ = Try-ParseVersion $Target
    if ($curr -and $targ -and $curr -lt $targ) { $UpdateNeeded = $true }
}

if ($UpdateNeeded) {
    Write-Output "Status: Update Required. Downloading MSI..."
    $installer = "$env:TEMP\ChromeEnt64.msi"
    if (Download-File "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi" $installer) {
        $args = "/i `"$installer`" /qn /norestart"
        if ($ChromeForceClose) { $args += " FORCECLOSE=1" }
        $p = Start-Process "msiexec.exe" -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        
        # 0 = Success, 3010 = Reboot Required (Success)
        if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) { 
            Write-Output "Result: Success"
            exit 0 
        } else { 
            Write-Output "Result: Failed (Exit $($p.ExitCode))"
            exit 2 
        }
    } else {
        Write-Output "Result: Failed (Download Error)"
        exit 2
    }
} else {
    Write-Output "Status: Compliant"
    exit 0
}