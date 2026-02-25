<#
.SYNOPSIS
    Hardened Detection for TeamViewer Eradication.
.DESCRIPTION
    Returns Exit 0 if TeamViewer is found (triggering the Uninstall script).
    Returns Exit 1 if the device is clean or if it's an excluded server.

.NOTES
    NAME: Detect-TeamViewer
    AUTHOR: Stu    
#>
#>

# --- CONFIGURATION TOGGLES ---
$AllowOnServers = $false    # Set to $true to allow detection on Servers and Domain Controllers

# --- STEP 1: WORKSTATION GUARDRAIL ---
# ProductType 1 = Workstation. We skip Servers (3) and DCs (2) by default to prevent 
# accidental removal from critical support infrastructure.
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

if ((-not $os -or $os.ProductType -ne 1) -and -not $AllowOnServers) { 
    Write-Output "Not a workstation. Skipping detection."
    exit 1 
} elseif ($os -and $os.ProductType -ne 1 -and $AllowOnServers) {
    Write-Output "Target is a server, but `$AllowOnServers is enabled. Proceeding with detection..."
}

$targetFound = $false

# --- STEP 2: REGISTRY DETECTION (HKLM) ---
# Anchored Regex: We use '^TeamViewer\b' to ensure we match "TeamViewer" 
# or "TeamViewer Host" while avoiding false positives like "TeamViewerMeeting".
$pattern = "^TeamViewer\b" 
$registryPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$installedApps = Get-ItemProperty -Path $registryPaths -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName -split ' ' | Select-Object -First 1 -match $pattern }

if ($installedApps) {
    Write-Output "NON-COMPLIANT: Found TeamViewer registry entry: $($installedApps.DisplayName)"
    $targetFound = $true
}

# --- STEP 3: SERVICE DETECTION ---
# Catch "Ghost" installs where the files/registry are gone but the service remains.
if (Get-Service -Name "*TeamViewer*" -ErrorAction SilentlyContinue) {
    Write-Output "NON-COMPLIANT: TeamViewer background service detected."
    $targetFound = $true
}

# --- STEP 4: PER-USER APPDATA DETECTION ---
# We scan user profiles because TeamViewer "Consumer" installs often bypass HKLM.
$skipList = @("All Users","Default","Default User","Public","WDAGUtilityAccount","DefaultAppPool","Administrator")
$userProfiles = Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $skipList -notcontains $_.Name }

foreach ($u in $userProfiles) {
    $checkPaths = @(
        (Join-Path $u.FullName "AppData\Local\TeamViewer\TeamViewer.exe"),
        (Join-Path $u.FullName "AppData\Roaming\TeamViewer\TeamViewer.exe")
    )
    foreach ($cp in $checkPaths) {
        if (Test-Path -LiteralPath $cp) { 
            Write-Output "NON-COMPLIANT: Per-user binary found in $($u.Name)'s AppData."
            $targetFound = $true; break 
        }
    }
    if ($targetFound) { break }
}

# --- STEP 5: EXIT LOGIC ---
if ($targetFound) { exit 0 } else { exit 1 }