param(
    [string]$TargetVersion = '145.0.7632.75'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-ToVersion {
    param([string]$v)
    try { [version]$v } catch { [version]'0.0.0.0' }
}

function Get-ChromeMachineExe {
    $paths = @()
    if ($env:ProgramFiles) {
        $paths += Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
    }
    $pf86 = ${env:ProgramFiles(x86)}
    if ($pf86) {
        $paths += Join-Path $pf86 'Google\Chrome\Application\chrome.exe'
    }
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-ChromeVersion {
    param([string]$ExePath)
    $vi = (Get-Item $ExePath).VersionInfo
    $v  = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($v)) { $v = $vi.FileVersion }
    Convert-ToVersion $v
}

$target = Convert-ToVersion $TargetVersion
$chromeExe = Get-ChromeMachineExe

if (-not $chromeExe) {
    # For "Update Only" Win32 apps, we report compliant if not installed to avoid forced installs
    Write-Output "Installed=No; Compliant=Yes (UpdateOnly)"
    exit 0
}

$current = Get-ChromeVersion -ExePath $chromeExe
$appFolder = Split-Path $chromeExe -Parent
$targetFolder = Join-Path $appFolder $TargetVersion

# COMPLIANCE LOGIC: 
# Compliant if the running version is >= target OR if the target version folder is staged on disk
$isStaged = Test-Path $targetFolder
$compliant = ($current -ge $target) -or $isStaged

$compText = if ($compliant) { 'Yes' } else { 'No' }
Write-Output ("Installed=Yes; Version={0}; Staged={1}; Target={2}; Compliant={3}" -f $current, $isStaged, $target, $compText)

if ($compliant) { exit 0 } else { exit 1 }