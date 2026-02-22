<#
.SYNOPSIS
  Strict Version Detection for Google Chrome.
  Checks System x64, System x86, and Per-User AppData installs.
#>
$TargetVersion = "145.0.7632.110"

$ErrorActionPreference = "SilentlyContinue"
$Target = [version]$TargetVersion

$FoundAny = $false
$NeedsUpdate = $false

function Test-ChromeVersion($Path) {
    if (Test-Path $Path) {
        $script:FoundAny = $true
        $LocalVer = (Get-Item $Path).VersionInfo.ProductVersion
        $CleanLocal = [version]($LocalVer -split '\s+')[0]
        
        if ($CleanLocal -lt $Target) {
            Write-Output "Found old version ($CleanLocal) at: $Path"
            $script:NeedsUpdate = $true
        }
    }
}

# 1. Check System Installs
Test-ChromeVersion "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
Test-ChromeVersion "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"

# 2. Check AppData (Per-User) Installs
if (Test-Path "C:\Users") {
    $Profiles = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($profile in $Profiles) {
        Test-ChromeVersion "$($profile.FullName)\AppData\Local\Google\Chrome\Application\chrome.exe"
    }
}

# 3. Evaluate Compliance
if (-not $FoundAny) {
    Write-Output "Chrome not installed anywhere. Compliant (Update-Only)."
    exit 0
}

if ($NeedsUpdate) {
    Write-Output "One or more instances require an update. Non-Compliant."
    exit 1
}

Write-Output "All detected instances meet or exceed $TargetVersion. Compliant."
exit 0