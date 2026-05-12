<#
.SYNOPSIS
    Intune Win32 Detection Script - Google Chrome Governance Remediation v2

.DESCRIPTION
    Detection script for a dedicated Chrome Governance Remediation Win32 app.

    Compliant only when:
      - Chrome x64 system install exists under C:\Program Files
      - 32-bit Chrome application footprint is absent
      - Per-user AppData Chrome application binaries are absent
      - Per-user Chrome ARP/uninstall entries are absent where visible
      - Google Update policy allows auto-update every 24 hours
      - Google Update services/tasks/updater executable are present and not disabled

    This version collects and reports all failures instead of exiting on the first issue.

.INTUNE DETECTION BEHAVIOUR
    - Exit 0 + STDOUT = detected/installed/compliant
    - Exit 1 = not detected/non-compliant, causing the Win32 install command to run
#>

$ChromeSystem64 = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$ChromeX86Exe   = 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
$ChromeX86Dir   = 'C:\Program Files (x86)\Google\Chrome'
$ChromeGUID     = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
$PolicyPath     = 'HKLM:\SOFTWARE\Policies\Google\Update'
$RequiredUpdateCheckMinutes = 1440
$RequiredTargetChannel = 'stable'
$ChromeUpdatePolicyName = "Update$ChromeGUID"
$ChromeTargetChannelPolicyName = "TargetChannel$ChromeGUID"
$ChromeTargetVersionPolicyName = "TargetVersionPrefix$ChromeGUID"
$ChromeRollbackPolicyName = "RollbackToTargetVersion$ChromeGUID"

$ExcludedProfiles = @(
    'Public',
    'Default',
    'Default User',
    'All Users',
    'defaultuser0'
)

$Findings = New-Object System.Collections.Generic.List[string]

function Add-Finding {
    param([string]$Reason)
    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        [void]$Findings.Add($Reason)
    }
}

function Get-UserProfiles {
    return @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin $ExcludedProfiles })
}

function Get-VisibleChromeUninstallEntries {
    $Entries = @()

    $RegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($Path in $RegistryPaths) {
        $Entries += @(Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq 'Google Chrome' } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, PSPath)
    }

    return @($Entries)
}

# ------------------------------------------------------------------------
# 1. Required x64 Chrome system install
# ------------------------------------------------------------------------
$ChromeVersion = $null
if (-not (Test-Path $ChromeSystem64)) {
    Add-Finding "Chrome x64 system install not found: $ChromeSystem64"
} else {
    try {
        $ChromeVersion = (Get-Item $ChromeSystem64).VersionInfo.ProductVersion
    } catch {
        Add-Finding "Unable to read Chrome x64 version: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------------
# 2. Unsupported 32-bit Chrome footprint must be absent
# ------------------------------------------------------------------------
if (Test-Path $ChromeX86Exe) {
    Add-Finding "Unsupported 32-bit Chrome executable found: $ChromeX86Exe"
}

if (Test-Path $ChromeX86Dir) {
    $X86AppContent = Get-ChildItem -Path $ChromeX86Dir -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\Application\\' } |
        Select-Object -First 1

    if ($X86AppContent) {
        Add-Finding "Unsupported 32-bit Chrome application footprint found: $ChromeX86Dir"
    }
}

# ------------------------------------------------------------------------
# 3. Unsupported per-user AppData Chrome application binaries must be absent
# ------------------------------------------------------------------------
foreach ($Profile in (Get-UserProfiles)) {
    $UserChromeExe = Join-Path $Profile.FullName 'AppData\Local\Google\Chrome\Application\chrome.exe'
    if (Test-Path $UserChromeExe) {
        Add-Finding "Unsupported per-user Chrome binary found for profile '$($Profile.Name)': $UserChromeExe"
    }
}

# ------------------------------------------------------------------------
# 4. Visible Add/Remove Programs Chrome entries
# ------------------------------------------------------------------------
$ChromeUninstallEntries = @(Get-VisibleChromeUninstallEntries)

foreach ($Entry in $ChromeUninstallEntries) {
    $InstallLocation = [string]$Entry.InstallLocation
    $UninstallString = [string]$Entry.UninstallString
    $PSPath          = [string]$Entry.PSPath

    if ($InstallLocation -match '\\AppData\\Local\\Google\\Chrome' -or
        $UninstallString -match '\\AppData\\Local\\Google\\Chrome' -or
        $PSPath -match 'HKEY_USERS') {
        Add-Finding "Unsupported per-user Chrome uninstall entry found. Version: $($Entry.DisplayVersion); InstallLocation: $InstallLocation"
    }

    if ($InstallLocation -match '\\Program Files \(x86\)\\Google\\Chrome' -or
        $UninstallString -match '\\Program Files \(x86\)\\Google\\Chrome') {
        Add-Finding "Unsupported 32-bit Chrome uninstall entry found. Version: $($Entry.DisplayVersion); InstallLocation: $InstallLocation"
    }
}

# This is informational only. We do not fail just because there are two entries,
# unless one is per-user or x86 as checked above.
$ChromeEntryCount = $ChromeUninstallEntries.Count

# ------------------------------------------------------------------------
# 5. Google Update policy validation
# ------------------------------------------------------------------------
if (-not (Test-Path $PolicyPath)) {
    Add-Finding 'Google Update policy key is missing.'
} else {
    $Policy = Get-ItemProperty -Path $PolicyPath -ErrorAction SilentlyContinue

    if ($Policy.UpdateDefault -ne 1) {
        Add-Finding "UpdateDefault is not enabled. Current value: $($Policy.UpdateDefault)"
    }

    if ($Policy.$ChromeUpdatePolicyName -ne 1) {
        Add-Finding "$ChromeUpdatePolicyName is not enabled. Current value: $($Policy.$ChromeUpdatePolicyName)"
    }

    if ($Policy.AutoUpdateCheckPeriodMinutes -ne $RequiredUpdateCheckMinutes) {
        Add-Finding "AutoUpdateCheckPeriodMinutes is not $RequiredUpdateCheckMinutes. Current value: $($Policy.AutoUpdateCheckPeriodMinutes)"
    }

    if ([string]$Policy.$ChromeTargetChannelPolicyName -ne $RequiredTargetChannel) {
        Add-Finding "$ChromeTargetChannelPolicyName is not '$RequiredTargetChannel'. Current value: $($Policy.$ChromeTargetChannelPolicyName)"
    }

    if ($null -ne $Policy.$ChromeTargetVersionPolicyName -and [string]$Policy.$ChromeTargetVersionPolicyName -ne '') {
        Add-Finding "$ChromeTargetVersionPolicyName is set, which may pin Chrome. Current value: $($Policy.$ChromeTargetVersionPolicyName)"
    }

    if ($null -ne $Policy.$ChromeRollbackPolicyName -and [string]$Policy.$ChromeRollbackPolicyName -ne '') {
        Add-Finding "$ChromeRollbackPolicyName is set, which may force rollback. Current value: $($Policy.$ChromeRollbackPolicyName)"
    }
}

# ------------------------------------------------------------------------
# 6. Google Update service health
# ------------------------------------------------------------------------
$UpdateServices = @(Get-Service -Name 'gupdate','gupdatem','GoogleUpdater*' -ErrorAction SilentlyContinue)
if ($UpdateServices.Count -eq 0) {
    Add-Finding 'No Google Update services found.'
} else {
    $EnabledServices = @($UpdateServices | Where-Object { $_.StartType -ne 'Disabled' })
    if ($EnabledServices.Count -eq 0) {
        Add-Finding 'Google Update services exist but are all disabled.'
    }
}

# ------------------------------------------------------------------------
# 7. Google Update scheduled task health
# ------------------------------------------------------------------------
$Tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -match '^GoogleUpdateTaskMachine' -or
    $_.TaskName -match '^GoogleUpdaterTaskSystem'
})

if ($Tasks.Count -eq 0) {
    Add-Finding 'No Google Update scheduled tasks found.'
} else {
    $EnabledTasks = @($Tasks | Where-Object { $_.State -ne 'Disabled' })
    if ($EnabledTasks.Count -eq 0) {
        Add-Finding 'Google Update scheduled tasks exist but are all disabled.'
    }
}

# ------------------------------------------------------------------------
# 8. Google Update executable presence
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
    Add-Finding 'No Google Update executable found.'
}

# ------------------------------------------------------------------------
# Final Intune result
# ------------------------------------------------------------------------
if ($Findings.Count -gt 0) {
    Write-Output "Not detected: Chrome governance remediation required. Chrome ARP entries visible: $ChromeEntryCount"
    foreach ($Finding in $Findings) {
        Write-Output " - $Finding"
    }
    exit 1
}

Write-Output "Detected: Chrome $ChromeVersion is governed. Chrome ARP entries visible: $ChromeEntryCount. x64 system install only, AppData Chrome removed, Google Update policy/services/tasks healthy. UpdateDetail: Updates: Enabled | Channel: $RequiredTargetChannel | CheckPeriodMinutes: $RequiredUpdateCheckMinutes"
exit 0
