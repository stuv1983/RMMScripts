<#
.SYNOPSIS
  Detect-Firefox.ps1 
  Detection method for Intune Win32 App (UPDATE ONLY MODE)
#>

$TargetVersion = [version]"147.0.4"
$isNonCompliant = $false
$anyFirefoxFound = $false

# ==============================================================================
# PHASE 1: Scan for rogue per-user consumer installations
# ==============================================================================
$skip = @("All Users","Default","Default User","Public","WDAGUtilityAccount")
$users = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue | 
    Where-Object { $skip -notcontains $_.Name }

foreach ($u in $users) {
    # FIXED: Added all 3 known AppData variations (Space, Nested, and No-Mozilla)
    $targets = @(
        (Join-Path -Path $u.FullName -ChildPath "AppData\Local\Mozilla Firefox\firefox.exe"),
        (Join-Path -Path $u.FullName -ChildPath "AppData\Local\Mozilla\Firefox\firefox.exe"),
        (Join-Path -Path $u.FullName -ChildPath "AppData\Local\Firefox\firefox.exe")
    )
    
    foreach ($t in $targets) {
        if (Test-Path -LiteralPath $t) {
            Write-Output "Found rogue per-user install: $t"
            $anyFirefoxFound = $true
            $isNonCompliant = $true
        }
    }
}

# ==============================================================================
# PHASE 2: Verify Enterprise System Installation
# ==============================================================================
# FIXED: Hardcoded SystemDrive bypasses the Intune 32-bit PowerShell variable trap
$sysPaths = @(
    "$env:SystemDrive\Program Files\Mozilla Firefox\firefox.exe",
    "$env:SystemDrive\Program Files (x86)\Mozilla Firefox\firefox.exe"
)

foreach ($p in $sysPaths) {
    if (Test-Path -LiteralPath $p) {
        $anyFirefoxFound = $true
        try {
            $v = [version]((Get-Item -LiteralPath $p).VersionInfo.ProductVersion)
            if ($v -lt $TargetVersion) {
                Write-Output "Outdated System Firefox found at $p ($v < $TargetVersion)."
                $isNonCompliant = $true
            } else {
                Write-Output "Valid System Firefox found at $p."
            }
        } catch {}
    }
}

# ==============================================================================
# PHASE 3: Final Intune Evaluation
# ==============================================================================
if (-not $anyFirefoxFound) {
    Write-Output "Firefox is not installed on this device. No upgrade required."
    exit 0
} elseif ($isNonCompliant) {
    Write-Output "Non-compliant: Rogue or Outdated Firefox detected. Requires Remediation."
    exit 1
} else {
    Write-Output "Compliant: Device meets Enterprise Firefox standards."
    exit 0
}