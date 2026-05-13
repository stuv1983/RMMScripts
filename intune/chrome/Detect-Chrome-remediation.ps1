<#
.SYNOPSIS
    Intune Win32 Detection Script - Google Chrome Governance Remediation

.DESCRIPTION
    Use this as the custom detection script for the dedicated Chrome Governance Remediation Win32 app.

    The app is detected/installed only when:
      - Chrome x64 system install exists under C:\Program Files
      - 32-bit Chrome application footprint is absent
      - Per-user AppData Chrome application binaries are absent
      - Google Update policy allows auto-update every 24 hours
      - Google Update services/tasks/updater executable are present and not disabled

    Intune Win32 detection behaviour:
      - Exit 0 + STDOUT = detected/installed
      - Exit 1 = not detected, causing the Win32 install command to run again

.NOTES
    This is intentionally health/governance-based detection, not latest-version detection.
    Google staged Stable rollout can make strict latest-version checks noisy.
#>

$ChromeSystem64 = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$ChromeX86Exe   = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
$ChromeX86Dir   = 'C:\Program Files (x86)\Google\Chrome'
$ChromeGUID     = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
$PolicyPath     = 'HKLM:\SOFTWARE\Policies\Google\Update'
$RequiredUpdateCheckMinutes = 1440

$ExcludedProfiles = @(
    'Public',
    'Default',
    'Default User',
    'All Users',
    'defaultuser0'
)

function Fail-Detection {
    param([string]$Reason)
    Write-Output "Not detected: $Reason"
    exit 1
}

function Get-UserProfiles {
    return @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin $ExcludedProfiles })
}

# ------------------------------------------------------------------------
# 1. Required x64 Chrome system install
# ------------------------------------------------------------------------
if (-not (Test-Path $ChromeSystem64)) {
    Fail-Detection 'Chrome x64 system install not found under C:\Program Files.'
}

try {
    $ChromeVersion = (Get-Item $ChromeSystem64).VersionInfo.ProductVersion
} catch {
    Fail-Detection "Unable to read Chrome x64 version: $($_.Exception.Message)"
}

# ------------------------------------------------------------------------
# 2. Unsupported 32-bit Chrome footprint must be absent
# ------------------------------------------------------------------------
if (Test-Path $ChromeX86Exe) {
    Fail-Detection "Unsupported 32-bit Chrome executable found: $ChromeX86Exe"
}

if (Test-Path $ChromeX86Dir) {
    $X86AppContent = Get-ChildItem -Path $ChromeX86Dir -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\Application\\' } |
        Select-Object -First 1

    if ($X86AppContent) {
        Fail-Detection "Unsupported 32-bit Chrome application footprint found: $ChromeX86Dir"
    }
}

# ------------------------------------------------------------------------
# 3. Unsupported per-user AppData Chrome application binaries must be absent
# ------------------------------------------------------------------------
foreach ($Profile in (Get-UserProfiles)) {
    $UserChromeExe = Join-Path $Profile.FullName 'AppData\Local\Google\Chrome\Application\chrome.exe'
    if (Test-Path $UserChromeExe) {
        Fail-Detection "Unsupported per-user Chrome binary found for profile '$($Profile.Name)': $UserChromeExe"
    }
}

# ------------------------------------------------------------------------
# 4. Google Update policy validation
# ------------------------------------------------------------------------
if (-not (Test-Path $PolicyPath)) {
    Fail-Detection 'Google Update policy key is missing.'
}

$Policy = Get-ItemProperty -Path $PolicyPath -ErrorAction SilentlyContinue
$ChromeUpdatePolicyName = "Update$ChromeGUID"

if ($Policy.UpdateDefault -ne 1) {
    Fail-Detection "UpdateDefault is not enabled. Current value: $($Policy.UpdateDefault)"
}

if ($Policy.$ChromeUpdatePolicyName -ne 1) {
    Fail-Detection "$ChromeUpdatePolicyName is not enabled. Current value: $($Policy.$ChromeUpdatePolicyName)"
}

if ($Policy.AutoUpdateCheckPeriodMinutes -ne $RequiredUpdateCheckMinutes) {
    Fail-Detection "AutoUpdateCheckPeriodMinutes is not $RequiredUpdateCheckMinutes. Current value: $($Policy.AutoUpdateCheckPeriodMinutes)"
}

# ------------------------------------------------------------------------
# 5. Google Update service health
# ------------------------------------------------------------------------
$UpdateServices = @(Get-Service -Name 'gupdate','gupdatem','GoogleUpdater*' -ErrorAction SilentlyContinue)
if ($UpdateServices.Count -eq 0) {
    Fail-Detection 'No Google Update services found.'
}

$EnabledServices = @($UpdateServices | Where-Object { $_.StartType -ne 'Disabled' })
if ($EnabledServices.Count -eq 0) {
    Fail-Detection 'Google Update services exist but are all disabled.'
}

# ------------------------------------------------------------------------
# 6. Google Update scheduled task health
# ------------------------------------------------------------------------
$Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -match '^GoogleUpdateTaskMachine' -or
    $_.TaskName -match '^GoogleUpdaterTaskSystem'
})

if ($Tasks.Count -eq 0) {
    Fail-Detection 'No Google Update scheduled tasks found.'
}

$EnabledTasks = @($Tasks | Where-Object { $_.State -ne 'Disabled' })
if ($EnabledTasks.Count -eq 0) {
    Fail-Detection 'Google Update scheduled tasks exist but are all disabled.'
}

# ------------------------------------------------------------------------
# 7. Google Update executable presence
# ------------------------------------------------------------------------
$UpdaterExecutables = @(
    "$env:ProgramData\Google\GoogleUpdater\*\GoogleUpdater.exe",
    "$env:ProgramFiles\Google\GoogleUpdater\*\GoogleUpdater.exe",
    "$env:ProgramFiles\Google\Update\GoogleUpdate.exe",
    "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
)

$UpdaterFound = $false
foreach ($Pattern in $UpdaterExecutables) {
    if (Get-ChildItem -Path $Pattern -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $UpdaterFound = $true
        break
    }
}

if (-not $UpdaterFound) {
    Fail-Detection 'No Google Update executable found.'
}

Write-Output "Detected: Chrome $ChromeVersion is governed. x64 system install only, AppData Chrome removed, Google Update policy/services/tasks healthy."
exit 0
