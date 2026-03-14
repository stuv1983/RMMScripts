<#
.SYNOPSIS
  Adobe Reader/Acrobat Report Only
#>

# CONFIGURATION
$TargetAdobeVersion = "23.008.20555"

# HELPERS
function Get-FileProductVersion { param($Path); try { return (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.ProductVersion } catch { return $null } }
function Try-ParseVersion {
  param($V)
  if ([string]::IsNullOrWhiteSpace($V)) { return $null }
  $m = [regex]::Match($V, '\d+(?:[.,]\d+){1,3}'); if (-not $m.Success) { return $null }
  try { return [version]($m.Value -replace ',', '.') } catch { return $null }
}
function Get-UninstallEntries {
  $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
  $res = @(); foreach ($p in $paths) { $res += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Acrobat|Reader' } }
  return $res
}

# LOGIC
Write-Output "Adobe_Target: $TargetAdobeVersion"

# 1. Registry Scan
$targets = Get-UninstallEntries | Sort-Object DisplayName -Unique
if ($targets) { foreach ($t in $targets) { Write-Output "Found_Reg: $($t.DisplayName) ($($t.DisplayVersion))" } }

# 2. EXE Scan
$exes = @("C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe", "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe", "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
$foundExes = @(); foreach ($e in $exes) { if (Test-Path $e) { $foundExes += $e; Write-Output "Found_Exe: $e ($(Get-FileProductVersion $e))" } }

# 3. Compliance Check
$targVer = Try-ParseVersion $TargetAdobeVersion
if (-not $targets -and -not $foundExes) { Write-Output "Status: Not Installed"; exit 0 }

$installed = @()
foreach ($t in $targets) { if ($t.DisplayVersion) { $installed += Try-ParseVersion $t.DisplayVersion } }
if (-not $installed -and $foundExes) { foreach ($e in $foundExes) { $installed += Try-ParseVersion (Get-FileProductVersion $e) } }

$valid = $installed | Where-Object { $_ }
if (-not $valid) { Write-Output "Status: Unknown (Parse Failed)"; exit 0 }

$min = ($valid | Measure-Object -Minimum).Minimum
if ($min -lt $targVer) {
    Write-Output "Status: Outdated (Update Disabled)"
    # Exit 0 because we intentionally aren't updating it
    exit 0 
} else {
    Write-Output "Status: Compliant"
    exit 0
}