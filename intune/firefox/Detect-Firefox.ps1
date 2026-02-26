<#
.SYNOPSIS
    Detect-Firefox.ps1
    Intune Custom Detection Script for Firefox Enterprise (Strict 64-Bit MSI).
    
.DESCRIPTION
    STRICT WATERFALL LOGIC:
    1. FAIL if any per-user AppData installation exists (forces remediation).
    2. FAIL if Legacy 32-bit Firefox exists (forces remediation to 64-bit).
    3. PASS only if 64-bit System-level binary exists AND meets/exceeds target version.
    4. FAIL if missing, outdated, or ghosted.
#>

$ErrorActionPreference = "SilentlyContinue"

$TargetVersion = [version]"147.0.4"

# ==============================================================================
# PHASE 1: ROGUE / PER-USER INSTALLATION CHECK (IMMEDIATE FAIL)
# ==============================================================================
$users = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force

foreach ($u in $users) {
    # Skip default and system profiles
    if ($u.Name -match "^(All Users|Default|Default User|Public|WDAGUtilityAccount|Administrator)$") { continue }

    $roguePaths = @(
        "$($u.FullName)\AppData\Local\Mozilla Firefox\firefox.exe",
        "$($u.FullName)\AppData\Local\Mozilla\Firefox\firefox.exe",
        "$($u.FullName)\AppData\Local\Firefox\firefox.exe"
    )

    foreach ($exe in $roguePaths) {
        if (Test-Path -LiteralPath $exe) {
            # Intune Detection: Exit non-zero with NO output to signal "Not Compliant"
            Write-Warning "Non-compliant: Rogue per-user Firefox found at $exe. Requires remediation."
            exit 1 
        }
    }
}

# ==============================================================================
# PHASE 2: LEGACY 32-BIT CHECK (IMMEDIATE FAIL)
# ==============================================================================
# If 32-bit exists, force a failure so the Install script can rip it out
$legacy32BitPath = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"

if (Test-Path -LiteralPath $legacy32BitPath) {
    Write-Warning "Non-compliant: Legacy 32-bit Firefox found at $legacy32BitPath. Requires remediation."
    exit 1
}

# ==============================================================================
# PHASE 3: 64-BIT SYSTEM-LEVEL COMPLIANCE CHECK (PASS CONDITION)
# ==============================================================================
$system64BitPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"

if (Test-Path -LiteralPath $system64BitPath) {
    $fileVersionString = (Get-Item -LiteralPath $system64BitPath).VersionInfo.ProductVersion
    
    if (-not [string]::IsNullOrWhiteSpace($fileVersionString)) {
        # Strip out any Mozilla beta/release channel tags (e.g., "147.0.4b1" -> "147.0.4")
        $cleanVersion = $fileVersionString -replace '[a-zA-Z\-].*',''
        $installedVersion = [version]$cleanVersion

        if ($installedVersion -ge $TargetVersion) {
            # Intune Detection: STDOUT output + Exit 0 = "Compliant / Installed"
            Write-Output "Compliant: 64-bit System Firefox found at $system64BitPath (Version: $installedVersion)"
            exit 0
        } else {
            Write-Warning "Non-compliant: 64-bit System Firefox is outdated ($installedVersion < $TargetVersion)."
            exit 1
        }
    }
}

# ==============================================================================
# PHASE 4: GHOST FOOTPRINT / MISSING (CATCH-ALL FAIL)
# ==============================================================================
# If the script reaches this point, no valid 64-bit system binary was found.
Write-Warning "Non-compliant: 64-bit System Firefox binary missing or broken."
exit 1