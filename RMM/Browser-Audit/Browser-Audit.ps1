# ============================================================
#  Browser Audit + Chrome Update Health
#  Audits Firefox, Chrome, and Edge installations
#  Detects why Chrome may not be auto-updating
# ============================================================

# ── Configuration ────────────────────────────────────────────────────────────
$ChromeMinVersion = "147.0.7727.117"   # Minimum safe Chrome version - update per CVE
$MaxUpdateLagDays = 7                  # Flag updater task if not run within N days

$Results = @()


# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════

function Get-ExeVersion {
    param([string]$Path)
    if (Test-Path $Path) { return (Get-Item $Path).VersionInfo.ProductVersion }
    return $null
}

function Get-ServiceStatus {
    param([string[]]$ServiceNames)
    $parts = @()
    foreach ($name in $ServiceNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            $startType = (Get-WmiObject Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue).StartMode
            $parts += "$name`: $startType ($($svc.Status))"
        } else {
            $parts += "$name`: Not Found"
        }
    }
    return ($parts -join " | ")
}

function Get-ScheduledTaskStatus {
    param([string[]]$TaskNames)
    $parts = @()
    foreach ($name in $TaskNames) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task) {
            $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction SilentlyContinue
            $lastResult = if ($info.LastTaskResult -eq 0) { "OK" } else { "0x{0:X}" -f $info.LastTaskResult }
            $parts += "$name`: $($task.State) (last: $lastResult)"
        } else {
            $parts += "$name`: Not Found"
        }
    }
    return ($parts -join " | ")
}

function Get-UninstallInfo {
    param([string]$DisplayNamePattern)
    $hives = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($hive in $hives) {
        if (-not (Test-Path $hive)) { continue }
        $match = Get-ChildItem $hive -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like $DisplayNamePattern } |
            Select-Object -First 1
        if ($match) {
            return [PSCustomObject]@{
                InstallMethod = if ($match.WindowsInstaller -eq 1) { "MSI" } else { "EXE" }
                Publisher     = if ($match.Publisher) { $match.Publisher } else { "Unknown" }
                InstallSource = if ($match.InstallSource) { $match.InstallSource } else { "Unknown" }
            }
        }
    }
    return [PSCustomObject]@{ InstallMethod = "Not in Registry"; Publisher = "N/A"; InstallSource = "N/A" }
}

function Get-PolicyState {
    param([string]$PolicyPath)
    if (Test-Path $PolicyPath) {
        $vals = (Get-Item $PolicyPath -ErrorAction SilentlyContinue).Property
        if ($vals -and $vals.Count -gt 0) { return "Managed ($($vals.Count) policies)" }
        return "Key exists (no values)"
    }
    return "Not Managed"
}

function Get-ChromeUpdateDetail {
    $guid  = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
    $hive  = 'HKLM:\SOFTWARE\Policies\Google\Update'
    if (-not (Test-Path $hive)) { return 'Not Managed' }
    $props = Get-ItemProperty $hive -ErrorAction SilentlyContinue
    if (-not $props) { return 'Key exists (no values)' }

    $updateVal = if ($null -ne $props."Update$guid") { [int]$props."Update$guid" }
                 elseif ($null -ne $props.UpdateDefault) { [int]$props.UpdateDefault }
                 else { $null }
    $updateMap = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'Manual only'; 3 = 'Auto-silent only' }
    $updateStr = if ($null -ne $updateVal -and $updateMap.ContainsKey($updateVal)) { $updateMap[$updateVal] } else { 'Unknown' }

    $installVal = if ($null -ne $props."Install$guid") { [int]$props."Install$guid" }
                  elseif ($null -ne $props.InstallDefault) { [int]$props.InstallDefault }
                  else { $null }
    $installStr = if ($installVal -eq 5) { 'Blocked' }
                  elseif ($installVal -eq 0 -or $installVal -eq 1) { 'Allowed' }
                  elseif ($null -eq $installVal) { 'Default' }
                  else { "Policy=$installVal" }

    $channel    = $props."TargetChannel$guid"
    $channelStr = if ($channel) { $channel } else { 'default' }

    $period    = $props.AutoUpdateCheckPeriodMinutes
    $periodStr = if ($period -eq 0) { 'Check: DISABLED' }
                 elseif ($null -ne $period) { "Check: every $period min" }
                 else { $null }

    $parts = @("Updates: $updateStr", "Install: $installStr", "Channel: $channelStr")
    if ($periodStr) { $parts += $periodStr }
    return $parts -join '  |  '
}

function Get-UserPaths {
    param([string]$RelativePath)
    $paths = @()
    $profileRoot = "$env:SystemDrive\Users"
    if (Test-Path $profileRoot) {
        Get-ChildItem $profileRoot -Directory | ForEach-Object {
            $full = Join-Path $_.FullName $RelativePath
            if (Test-Path $full) { $paths += $full }
        }
    }
    return $paths
}

# ── Chrome update health / stuck-update detection ────────────────────────────
function Get-ChromeUpdateHealth {
    param(
        [string]$InstalledVersion,
        [string]$MinVersion,
        [int]$MaxLagDays
    )

    $guid = '{8A69D345-D564-463C-AFF1-A69D9E530F96}'

    $h = [ordered]@{
        VersionCompliant     = $false
        PolicyAllowsUpdates  = $false
        UpdateDefault        = $null
        ChromeUpdatePolicy   = $null
        CheckMinutes         = $null
        TargetChannel        = $null
        NewUpdaterPresent    = $false
        LegacyUpdaterPresent = $false
        SvcNewUpdater        = "Not Found"
        SvcNewUpdaterInt     = "Not Found"
        SvcElevation         = "Not Found"
        SvcLegacy            = "Not Found"
        SvcLegacyM           = "Not Found"
        TasksFound           = $false
        TaskLastRun          = $null
        TaskLastResult       = $null
        TaskAgeOk            = $false
        PendingRelaunch      = $false
        ChromeRunning        = $false
        Status               = "Unknown"
        Reasons              = @()
    }

    # Version compliance
    try {
        $h.VersionCompliant = ([version]$InstalledVersion -ge [version]$MinVersion)
    } catch {
        $h.Reasons += "Unable to parse Chrome version for comparison."
    }

    # Policy
    $policyPath = "HKLM:\SOFTWARE\Policies\Google\Update"
    if (Test-Path $policyPath) {
        $policy = Get-ItemProperty $policyPath -ErrorAction SilentlyContinue
        $h.UpdateDefault      = $policy.UpdateDefault
        $h.ChromeUpdatePolicy = $policy."Update$guid"
        $h.CheckMinutes       = $policy.AutoUpdateCheckPeriodMinutes
        $h.TargetChannel      = $policy."TargetChannel$guid"

        if (
            ($h.UpdateDefault -eq 1 -or $null -eq $h.UpdateDefault) -and
            ($h.ChromeUpdatePolicy -eq 1 -or $null -eq $h.ChromeUpdatePolicy) -and
            ($h.CheckMinutes -ne 0)
        ) {
            $h.PolicyAllowsUpdates = $true
        } else {
            $h.Reasons += "Chrome update policy may be blocking updates."
        }
    } else {
        $h.PolicyAllowsUpdates = $true   # no policy = default (allow)
        $h.Reasons += "No Google Update policy found - relying on defaults."
    }

    # Services
    $svcChecks = @{
        'GoogleUpdaterService'         = 'SvcNewUpdater'
        'GoogleUpdaterInternalService' = 'SvcNewUpdaterInt'
        'GoogleChromeElevationService' = 'SvcElevation'
        'gupdate'                      = 'SvcLegacy'
        'gupdatem'                     = 'SvcLegacyM'
    }
    foreach ($svcName in $svcChecks.Keys) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        $h[$svcChecks[$svcName]] = if ($svc) { "$($svc.StartType) / $($svc.Status)" } else { "Not Found" }
    }

    $h.NewUpdaterPresent    = ($h.SvcNewUpdater -ne "Not Found" -or $h.SvcNewUpdaterInt -ne "Not Found")
    $h.LegacyUpdaterPresent = ($h.SvcLegacy -ne "Not Found" -or $h.SvcLegacyM -ne "Not Found")

    if (-not $h.NewUpdaterPresent -and -not $h.LegacyUpdaterPresent) {
        $h.Reasons += "No Google updater services found."
    }

    # Scheduled tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                $_.TaskName -like "*GoogleUpdater*" -or
                $_.TaskName -like "GoogleUpdateTaskMachine*" -or
                $_.TaskPath -like "\GoogleSystem*"
            }

        if ($tasks) {
            $h.TasksFound = $true
            $taskInfo = $tasks | ForEach-Object {
                try { Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath } catch {}
            } | Sort-Object LastRunTime -Descending | Select-Object -First 1

            if ($taskInfo) {
                $h.TaskLastRun    = $taskInfo.LastRunTime
                $h.TaskLastResult = "0x{0:X}" -f $taskInfo.LastTaskResult

                if ($taskInfo.LastTaskResult -eq 0) {
                    $h.TaskAgeOk = $true
                    if ($taskInfo.LastRunTime -and $taskInfo.LastRunTime -lt (Get-Date).AddDays(-$MaxLagDays)) {
                        $h.TaskAgeOk = $false
                        $h.Reasons += "Updater task has not run in over $MaxLagDays days."
                    }
                } else {
                    $h.Reasons += "Updater task last result was not successful: $($h.TaskLastResult)"
                }
            }
        } else {
            $h.Reasons += "No Google updater scheduled tasks found."
        }
    } catch {
        $h.Reasons += "Unable to query Google scheduled tasks."
    }

    # Pending relaunch (update downloaded, waiting for restart)
    foreach ($path in @(
        "HKLM:\SOFTWARE\Google\Update\Clients\$guid",
        "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\$guid"
    )) {
        if (Test-Path $path) {
            $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
            if ($props.ap -match "update|relaunch") { $h.PendingRelaunch = $true }
        }
    }

    # Chrome process running
    $h.ChromeRunning = [bool](Get-Process chrome -ErrorAction SilentlyContinue)

    # Final status
    if ($h.VersionCompliant) {
        $h.Status = if ($h.PendingRelaunch) { "Compliant - Relaunch Pending" } else { "Compliant" }
    } elseif (-not $h.PolicyAllowsUpdates) {
        $h.Status = "Non-Compliant - Policy Issue"
    } elseif (-not $h.NewUpdaterPresent -and -not $h.LegacyUpdaterPresent) {
        $h.Status = "Non-Compliant - Updater Missing"
    } elseif (-not $h.TasksFound) {
        $h.Status = "Non-Compliant - Update Task Missing"
    } elseif ($h.PendingRelaunch -or $h.ChromeRunning) {
        $h.Status = "Non-Compliant - Likely Pending Relaunch"
        $h.Reasons += "Chrome is behind baseline and may require browser restart to finalise update."
    } elseif (-not $h.TaskAgeOk) {
        $h.Status = "Non-Compliant - Updater Task Error"
    } else {
        $h.Status = "Non-Compliant - Stuck or Waiting"
        $h.Reasons += "Policy and updater appear healthy, but Chrome remains below baseline."
    }

    return $h
}


# ════════════════════════════════════════════════════════════
#  FIREFOX
# ════════════════════════════════════════════════════════════
$firefoxExePaths  = @(
    "$env:SystemDrive\Program Files\Mozilla Firefox\firefox.exe",
    "$env:SystemDrive\Program Files (x86)\Mozilla Firefox\firefox.exe"
)
$firefoxExePaths += Get-UserPaths "AppData\Local\Mozilla Firefox\firefox.exe"

$firefoxFound     = $false
$firefoxUpdateSvc = Get-ServiceStatus @("MozillaMaintenance")
$firefoxUninstall = Get-UninstallInfo "*Firefox*"
$firefoxPolicy    = Get-PolicyState "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"

foreach ($path in $firefoxExePaths) {
    $ver = Get-ExeVersion $path
    if ($ver) {
        $firefoxFound = $true
        $Results += [PSCustomObject]@{
            Browser       = "Firefox"
            Location      = $path
            Version       = $ver
            InstallType   = if ($path -like "*Users*") { "Per-User (AppData)" } else { "System-Wide" }
            InstallMethod = $firefoxUninstall.InstallMethod
            Publisher     = $firefoxUninstall.Publisher
            InstallSource = $firefoxUninstall.InstallSource
            PolicyManaged = $firefoxPolicy
            UpdateDetail  = "N/A"
            UpdateService = $firefoxUpdateSvc
            UpdateTasks   = "N/A"
        }
    }
}

if (-not $firefoxFound) {
    $Results += [PSCustomObject]@{
        Browser       = "Firefox"
        Location      = "Not Found"
        Version       = "N/A"
        InstallType   = "N/A"
        InstallMethod = $firefoxUninstall.InstallMethod
        Publisher     = $firefoxUninstall.Publisher
        InstallSource = $firefoxUninstall.InstallSource
        PolicyManaged = $firefoxPolicy
        UpdateDetail  = "N/A"
        UpdateService = $firefoxUpdateSvc
        UpdateTasks   = "N/A"
    }
}


# ════════════════════════════════════════════════════════════
#  GOOGLE CHROME
# ════════════════════════════════════════════════════════════
$chromeExePaths  = @(
    "$env:SystemDrive\Program Files\Google\Chrome\Application\chrome.exe",
    "$env:SystemDrive\Program Files (x86)\Google\Chrome\Application\chrome.exe"
)
$chromeExePaths += Get-UserPaths "AppData\Local\Google\Chrome\Application\chrome.exe"

$chromeFound        = $false
$chromeUpdateSvc    = Get-ServiceStatus @("gupdate", "gupdatem", "GoogleChromeElevationService", "GoogleUpdaterInternalService", "GoogleUpdaterService")
$chromeUninstall    = Get-UninstallInfo "*Google Chrome*"
$chromePolicy       = Get-PolicyState "HKLM:\SOFTWARE\Policies\Google\Chrome"
$chromeUpdateDetail = Get-ChromeUpdateDetail
$chromeUpdateTasks  = Get-ScheduledTaskStatus @("GoogleUpdateTaskMachineUA", "GoogleUpdateTaskMachineCore")

foreach ($path in $chromeExePaths) {
    $ver = Get-ExeVersion $path
    if ($ver) {
        $chromeFound = $true
        $Results += [PSCustomObject]@{
            Browser       = "Chrome"
            Location      = $path
            Version       = $ver
            InstallType   = if ($path -like "*Users*") { "Per-User (AppData)" } else { "System-Wide" }
            InstallMethod = $chromeUninstall.InstallMethod
            Publisher     = $chromeUninstall.Publisher
            InstallSource = $chromeUninstall.InstallSource
            PolicyManaged = $chromePolicy
            UpdateDetail  = $chromeUpdateDetail
            UpdateService = $chromeUpdateSvc
            UpdateTasks   = $chromeUpdateTasks
        }
    }
}

if (-not $chromeFound) {
    $Results += [PSCustomObject]@{
        Browser       = "Chrome"
        Location      = "Not Found"
        Version       = "N/A"
        InstallType   = "N/A"
        InstallMethod = $chromeUninstall.InstallMethod
        Publisher     = $chromeUninstall.Publisher
        InstallSource = $chromeUninstall.InstallSource
        PolicyManaged = $chromePolicy
        UpdateDetail  = $chromeUpdateDetail
        UpdateService = $chromeUpdateSvc
        UpdateTasks   = $chromeUpdateTasks
    }
}

# Run Chrome update health check
$chromeHealth      = $null
$chromeAuditEntry  = $Results | Where-Object { $_.Browser -eq "Chrome" -and $_.Location -ne "Not Found" } | Select-Object -First 1

if ($chromeAuditEntry) {
    $chromeHealth = Get-ChromeUpdateHealth `
        -InstalledVersion $chromeAuditEntry.Version `
        -MinVersion       $ChromeMinVersion `
        -MaxLagDays       $MaxUpdateLagDays
}


# ════════════════════════════════════════════════════════════
#  MICROSOFT EDGE
# ════════════════════════════════════════════════════════════
$edgeExePaths  = @(
    "$env:SystemDrive\Program Files\Microsoft\Edge\Application\msedge.exe",
    "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
)
$edgeExePaths += Get-UserPaths "AppData\Local\Microsoft\Edge\Application\msedge.exe"

$edgeFound       = $false
$edgeUpdateSvc   = Get-ServiceStatus @("edgeupdate", "edgeupdatem")
$edgeUninstall   = Get-UninstallInfo "*Microsoft Edge*"
$edgePolicy      = Get-PolicyState "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$edgeUpdateTasks = Get-ScheduledTaskStatus @("MicrosoftEdgeUpdateTaskMachineUA", "MicrosoftEdgeUpdateTaskMachineCore")

foreach ($path in $edgeExePaths) {
    $ver = Get-ExeVersion $path
    if ($ver) {
        $edgeFound = $true
        $Results += [PSCustomObject]@{
            Browser       = "Edge"
            Location      = $path
            Version       = $ver
            InstallType   = if ($path -like "*Users*") { "Per-User (AppData)" } else { "System-Wide" }
            InstallMethod = $edgeUninstall.InstallMethod
            Publisher     = $edgeUninstall.Publisher
            InstallSource = $edgeUninstall.InstallSource
            PolicyManaged = $edgePolicy
            UpdateDetail  = "N/A"
            UpdateService = $edgeUpdateSvc
            UpdateTasks   = $edgeUpdateTasks
        }
    }
}

if (-not $edgeFound) {
    $Results += [PSCustomObject]@{
        Browser       = "Edge"
        Location      = "Not Found"
        Version       = "N/A"
        InstallType   = "N/A"
        InstallMethod = $edgeUninstall.InstallMethod
        Publisher     = $edgeUninstall.Publisher
        InstallSource = $edgeUninstall.InstallSource
        PolicyManaged = $edgePolicy
        UpdateDetail  = "N/A"
        UpdateService = $edgeUpdateSvc
        UpdateTasks   = $edgeUpdateTasks
    }
}


# ════════════════════════════════════════════════════════════
#  OUTPUT
# ════════════════════════════════════════════════════════════
$div = '-' * 55

Write-Output ""
Write-Output "======================================================="
Write-Output "  BROWSER AUDIT  --  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "  Device: $env:COMPUTERNAME"
Write-Output "======================================================="

# ── Per-browser audit blocks ─────────────────────────────────────────────────
foreach ($r in $Results) {
    Write-Output ""
    Write-Output $div

    if ($r.Location -ne "Not Found") {
        Write-Output "  [$($r.Browser.ToUpper())]  INSTALLED"
        Write-Output "  Version      : $($r.Version)"
        Write-Output "  Install Type : $($r.InstallType)  |  $($r.InstallMethod)  |  $($r.Publisher)"
        Write-Output "  Policy       : $($r.PolicyManaged)"
        if ($r.UpdateDetail -ne "N/A") {
            Write-Output "  Auto-Update  : $($r.UpdateDetail)"
        }
        Write-Output "  Update Svc   : $($r.UpdateService)"
        if ($r.UpdateTasks -ne "N/A") {
            Write-Output "  Update Tasks : $($r.UpdateTasks)"
        }
        Write-Output "  Path         : $($r.Location)"
    } else {
        Write-Output "  [$($r.Browser.ToUpper())]  NOT INSTALLED"
        Write-Output "  Policy       : $($r.PolicyManaged)"
        if ($r.UpdateDetail -ne "N/A") {
            Write-Output "  Auto-Update  : $($r.UpdateDetail)"
        }
        Write-Output "  Update Svc   : $($r.UpdateService)"
        if ($r.UpdateTasks -ne "N/A") {
            Write-Output "  Update Tasks : $($r.UpdateTasks)"
        }
    }
}

# ── Chrome update health block ───────────────────────────────────────────────
if ($chromeHealth) {
    Write-Output ""
    Write-Output $div
    Write-Output "  [CHROME UPDATE HEALTH]"
    Write-Output "  Status       : $($chromeHealth.Status)"
    Write-Output "  Version      : $($chromeAuditEntry.Version)  (required >= $ChromeMinVersion)"

    $policyLine = if ($chromeHealth.PolicyAllowsUpdates) { "Updates allowed" } else { "Updates BLOCKED" }
    if ($chromeHealth.TargetChannel) { $policyLine += "  |  Channel: $($chromeHealth.TargetChannel)" }
    if ($null -ne $chromeHealth.CheckMinutes) {
        $policyLine += if ($chromeHealth.CheckMinutes -eq 0) { "  |  Check: DISABLED" } else { "  |  Check: every $($chromeHealth.CheckMinutes) min" }
    }
    Write-Output "  Policy       : $policyLine"

    $newSvcs = @()
    if ($chromeHealth.SvcNewUpdater    -ne "Not Found") { $newSvcs += "GoogleUpdaterService: $($chromeHealth.SvcNewUpdater)" }
    if ($chromeHealth.SvcNewUpdaterInt -ne "Not Found") { $newSvcs += "GoogleUpdaterInternalService: $($chromeHealth.SvcNewUpdaterInt)" }
    if ($chromeHealth.SvcElevation     -ne "Not Found") { $newSvcs += "GoogleChromeElevationService: $($chromeHealth.SvcElevation)" }
    Write-Output "  New Updater  : $(if ($newSvcs) { $newSvcs -join '  |  ' } else { 'Not Found' })"

    $legSvcs = @()
    if ($chromeHealth.SvcLegacy  -ne "Not Found") { $legSvcs += "gupdate: $($chromeHealth.SvcLegacy)" }
    if ($chromeHealth.SvcLegacyM -ne "Not Found") { $legSvcs += "gupdatem: $($chromeHealth.SvcLegacyM)" }
    Write-Output "  Legacy Svc   : $(if ($legSvcs) { $legSvcs -join '  |  ' } else { 'Not Found' })"

    if ($chromeHealth.TasksFound) {
        $taskAge = if ($chromeHealth.TaskLastRun) {
            $days = [int]((Get-Date) - $chromeHealth.TaskLastRun).TotalDays
            "$days day(s) ago"
        } else { "never" }
        Write-Output "  Update Task  : Last run $taskAge  |  Result: $($chromeHealth.TaskLastResult)  |  $(if ($chromeHealth.TaskAgeOk) { 'Age: OK' } else { 'Age: STALE' })"
    } else {
        Write-Output "  Update Task  : Not Found"
    }

    Write-Output "  Chrome Live  : $(if ($chromeHealth.ChromeRunning) { 'Yes (running)' } else { 'No' })  |  Relaunch Pending: $(if ($chromeHealth.PendingRelaunch) { 'Yes' } else { 'No' })"

    if ($chromeHealth.Reasons.Count -gt 0) {
        Write-Output "  Reasons      :"
        $chromeHealth.Reasons | ForEach-Object { Write-Output "    - $_" }
    }
} elseif (-not $chromeFound) {
    Write-Output ""
    Write-Output $div
    Write-Output "  [CHROME UPDATE HEALTH]  Chrome not installed - skipped."
}

Write-Output ""
Write-Output $div
Write-Output ""

# ── N-able single-line summary (machine-parseable) ───────────────────────────
Write-Output "--- Summary ---"
foreach ($r in $Results) {
    $healthStr = if ($r.Browser -eq "Chrome" -and $chromeHealth) { " | UpdateHealth: $($chromeHealth.Status)" } else { "" }
    if ($r.Location -ne "Not Found") {
        Write-Output "$($r.Browser) INSTALLED | Type: $($r.InstallType) | Method: $($r.InstallMethod) | Publisher: $($r.Publisher) | Version: $($r.Version) | Policy: $($r.PolicyManaged) | UpdateDetail: $($r.UpdateDetail) | UpdateSvc: $($r.UpdateService) | UpdateTasks: $($r.UpdateTasks) | Path: $($r.Location)$healthStr"
    } else {
        Write-Output "$($r.Browser) NOT INSTALLED | Policy: $($r.PolicyManaged) | UpdateDetail: $($r.UpdateDetail) | UpdateSvc: $($r.UpdateService)$healthStr"
    }
}

# ── Exit: 1 if Chrome is installed but non-compliant ─────────────────────────
if ($chromeHealth -and $chromeHealth.Status -notlike "Compliant*") {
    exit 1
}
exit 0
