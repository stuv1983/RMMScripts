<#
.SYNOPSIS
    Detect-Chrome.ps1
    Intune Win32 detection script (Strict MSI Option B)
#>

$TargetVersion = [version]"145.0.7632.110"
$isNonCompliant = $false
$anyChromeFound = $false

# 1) AppData Check
$skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")
$users = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name }

foreach ($u in $users) {
    $appDataChrome = Join-Path -Path $u.FullName -ChildPath "AppData\Local\Google\Chrome\Application\chrome.exe"
    if (Test-Path -LiteralPath $appDataChrome) {
        Write-Output "Detected rogue per-user Chrome: $appDataChrome"
        $anyChromeFound = $true
        $isNonCompliant = $true
    }
}

# 2) Strict MSI Registry Check (This catches the EXE fake-out!)
$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$chromeExes = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -match "^Google Chrome$" -and $_.WindowsInstaller -ne 1 }

$chromeMsi = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -match "^Google Chrome$" -and $_.WindowsInstaller -eq 1 }

if ($chromeExes) {
    Write-Output "NON-COMPLIANT: System Chrome EXE detected. Requires MSI migration."
    $anyChromeFound = $true
    $isNonCompliant = $true
}

# 3) Physical Files & Version Check
$sysPaths = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
)

foreach ($p in $sysPaths) {
    if (Test-Path -LiteralPath $p) {
        $anyChromeFound = $true
        if ($p -match "x86") {
            Write-Output "NON-COMPLIANT: 32-bit Chrome detected."
            $isNonCompliant = $true
        } else {
            $v = (Get-Item -LiteralPath $p).VersionInfo.ProductVersion
            if ([version]$v -lt $TargetVersion) {
                Write-Output "NON-COMPLIANT: Chrome outdated ($v < $TargetVersion)."
                $isNonCompliant = $true
            }
        }
    }
}

# 4) Final evaluation
if ($anyChromeFound -and -not $chromeMsi -and -not $chromeExes) {
    Write-Output "NON-COMPLIANT: Chrome files exist, but valid MSI registration is missing."
    $isNonCompliant = $true
}

if (-not $anyChromeFound) {
    Write-Output "Chrome not installed. No action required."
    exit 0
} elseif ($isNonCompliant) {
    Write-Output "NON-COMPLIANT: Device failed Strict MSI standard."
    exit 1
} else {
    Write-Output "COMPLIANT: Meets Strict Enterprise MSI Chrome standard."
    exit 0
}