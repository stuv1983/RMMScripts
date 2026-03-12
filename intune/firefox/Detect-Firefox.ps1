<#
.SYNOPSIS
    Mozilla Firefox Lean Detection
.NOTES
    IMPORTANT: $MinimumVersion, $Firefox64Exe, $Firefox86Dir, and $RoguePaths
    are intentionally duplicated from Install-Firefox.ps1. This is NOT a bug.
    Intune evaluates this detection script independently in a separate process
    and cannot share state with the install script. Update both files if values change.
#>

# --- Constants ---
# NOTE: Duplicated in Install-Firefox.ps1 by design. See .NOTES above.
$Firefox64Exe   = "C:\Program Files\Mozilla Firefox\firefox.exe"
$Firefox86Dir   = "C:\Program Files (x86)\Mozilla Firefox"
$MinimumVersion = [version]"148.0"

$RoguePaths = @(
    "AppData\Local\Mozilla Firefox",
    "AppData\Local\Programs\Mozilla Firefox"
)


# 1. TRAP SHADOW IT & x86
if (Test-Path $Firefox86Dir) {
    Write-Output "Non-Compliant (Exit 1): 32-bit Firefox directory detected."
    exit 1
}

$UserProfiles = Get-ChildItem "C:\Users" -Directory |
                Where-Object { Test-Path (Join-Path $_.FullName "NTUSER.DAT") }

foreach ($Profile in $UserProfiles) {
    foreach ($RelativePath in $RoguePaths) {
        if (Test-Path (Join-Path $Profile.FullName $RelativePath)) {
            Write-Output "Non-Compliant (Exit 1): Rogue AppData installation detected in $($Profile.Name)."
            exit 1
        }
    }
}


# 2. VALIDATE 64-BIT PRESENCE & VERSION
# Exit 0 here means Firefox is simply absent — no rogue installs were found
# above, so the environment is clean. The install script will deploy Firefox.
# If your policy requires Firefox to already be present, change this to exit 1.
if (-not (Test-Path $Firefox64Exe)) {
    Write-Output "Compliant (Exit 0): Firefox is not installed (no rogue installs detected)."
    exit 0
}

try {
    $CurrentVersion = [version]((Get-Item $Firefox64Exe).VersionInfo.ProductVersion)
    if ($CurrentVersion -lt $MinimumVersion) {
        Write-Output "Non-Compliant (Exit 1): Firefox version $CurrentVersion is below floor $MinimumVersion."
        exit 1
    }
} catch {
    Write-Output "Non-Compliant (Exit 1): Unable to parse 64-bit version string."
    exit 1
}


# All checks passed
Write-Output "Compliant (Exit 0): Environment is clean and up to date."
exit 0
