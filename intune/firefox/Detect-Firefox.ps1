<#
.SYNOPSIS
    Detect-Firefox.ps1
    Intune Custom Detection Script for Firefox Enterprise.
    
.DESCRIPTION
    STRICT WATERFALL LOGIC:
    1. FAIL if any per-user AppData installation exists (forces remediation).
    2. PASS only if System-level binary exists AND meets/exceeds target version.
    3. FAIL if missing, outdated, or ghosted.
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
            # We use Write-Warning just for local testing visibility.
            Write-Warning "Non-compliant: Rogue per-user Firefox found at $exe. Requires remediation."
            exit 1 
        }
    }
}

# ==============================================================================
# PHASE 2: SYSTEM-LEVEL COMPLIANCE CHECK (PASS CONDITION)
# ==============================================================================
$systemPaths = @(
    "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
    "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
)

foreach ($exe in $systemPaths) {
    if (Test-Path -LiteralPath $exe) {
        $fileVersionString = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
        
        if (-not [string]::IsNullOrWhiteSpace($fileVersionString)) {
            # Strip out any Mozilla beta/release channel tags (e.g., "147.0.4b1" -> "147.0.4")
            $cleanVersion = $fileVersionString -replace '[a-zA-Z\-].*',''
            $installedVersion = [version]$cleanVersion

            if ($installedVersion -ge $TargetVersion) {
                # Intune Detection: STDOUT output + Exit 0 = "Compliant / Installed"
                Write-Output "Compliant: System Firefox found at $exe (Version: $installedVersion)"
                exit 0
            } else {
                Write-Warning "Non-compliant: System Firefox is outdated ($installedVersion < $TargetVersion)."
                exit 1
            }
        }
    }
}

# ==============================================================================
# PHASE 3: GHOST FOOTPRINT / MISSING (CATCH-ALL FAIL)
# ==============================================================================
# If the script reaches this point, no valid system binary was found.
Write-Warning "Non-compliant: System Firefox binary missing or broken."
exit 1