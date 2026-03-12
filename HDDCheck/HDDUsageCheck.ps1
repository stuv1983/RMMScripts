<#
.SYNOPSIS
    Hard drive usage + per-user profile sizing + large folder/file reporting (RMM-ready).
    Includes specific alerting for User Downloads folders > 5GB, accurate cloud-file sizing,
    and read-only SharePoint sync detection.

.NOTES
    Name:       HDDUsageCheck_v5.5.ps1
    Author:     Stu Villanti
    Modified:   v5.5 - Hardened error handling, List[T] collections, expanded profile skip
                list, console profile/recycle bin output, Downloads always reported in JSON,
                object parameter comments, Downloads/general threshold mutual exclusion doc.
    Version:    5.5

.DESCRIPTION
    - Reports used/free space for all fixed drives.
    - Reports per-drive Recycle Bin usage.
    - Lists each user profile under C:\Users with total size (ignoring cloud-only files).
    - Checks User "Downloads" folder specifically against a separate threshold.
    - Identifies synced SharePoint locations via HKEY_USERS (Read-Only).
    - Console output pushes alerts to the top for quick technician review.
    - Returns structured exit codes for N-able task condition matching.

.EXIT CODES
    0 = OK            (no issues)
    1 = Low space     (drive free space below threshold)
    2 = Large items   (Downloads > threshold OR other large folders/files found)
    3 = Both issues   (low space AND large items detected)
    4 = Script error  (unexpected failure during data collection)

.PARAMETER LowSpaceThreshold
    Percentage of free space below which a drive is considered low. Default: 10

.PARAMETER UserRoot
    Root path containing user profile folders. Default: C:\Users

.PARAMETER LargeThresholdGB
    Size in GB above which a top-level profile folder or file triggers a large-item alert.
    NOTE: The Downloads folder is excluded from this check - it has its own dedicated
    threshold ($DownloadsThresholdGB). This mutual exclusion is intentional so the two
    thresholds can be tuned independently without double-alerting. Default: 5

.PARAMETER DownloadsThresholdGB
    Size in GB above which a user's Downloads folder triggers an alert.
    Evaluated independently from $LargeThresholdGB. Default: 5

.PARAMETER IncludeHidden
    [object] type to accept N-able string inputs ("true"/"false"/"1"/"0") as well as
    native PowerShell booleans. Converted internally via Convert-ToBool. Default: true

.PARAMETER AsJson
    When set, outputs a single compressed JSON line (ideal for N-able custom field
    ingestion). All Write-Host colour output is suppressed.
    [object] type - same N-able string compatibility reason as IncludeHidden. Default: false

.PARAMETER IncludeRecycleBin
    Whether to scan and report Recycle Bin sizes per drive.
    [object] type - same N-able string compatibility reason as IncludeHidden. Default: true

.PARAMETER RecycleBinThresholdGB
    Size in GB above which a Recycle Bin triggers a large-item alert. Default: 5

.PARAMETER IncludeLargeFiles
    Whether to scan for and report individual large files within profiles.
    [object] type - same N-able string compatibility reason as IncludeHidden. Default: true
#>

[CmdletBinding()]
param(
    [Parameter()] [int]$LowSpaceThreshold      = 10,
    [Parameter()] [string]$UserRoot            = 'C:\Users',
    [Parameter()] [int]$LargeThresholdGB       = 5,
    [Parameter()] [int]$DownloadsThresholdGB   = 5,
    # [object] used (not [bool]) so N-able can pass "true"/"false" strings via task params.
    # Convert-ToBool normalises all inputs to a proper PowerShell bool before use.
    [Parameter()] [object]$IncludeHidden       = $true,
    [Parameter()] [object]$AsJson,
    [Parameter()] [object]$IncludeRecycleBin   = $true,
    [Parameter()] [int]$RecycleBinThresholdGB  = 5,
    [Parameter()] [object]$IncludeLargeFiles   = $true
)

function Convert-ToBool {
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return [bool]([int]$Value) }
        switch ("$Value".Trim().ToLowerInvariant()) {
            'true'  { return $true }
            '1'     { return $true }
            default { return $false }
        }
    }
}

$IncludeHidden      = Convert-ToBool $IncludeHidden
$AsJson             = Convert-ToBool $AsJson
$IncludeRecycleBin  = Convert-ToBool $IncludeRecycleBin
$IncludeLargeFiles  = Convert-ToBool $IncludeLargeFiles

# ---------------- STATE & RESULTS COLLECTIONS ----------------
$LowSpaceFound   = $false
$LargeItemsFound = $false

# Using Generic List[T] throughout to avoid the O(n) array copy that += causes
# on plain @() arrays - matters when profileResults/largeItemsResults grow large.
$Alerts            = New-Object System.Collections.Generic.List[string]
$driveResults      = New-Object System.Collections.Generic.List[object]
$recycleBinResults = New-Object System.Collections.Generic.List[object]
$profileResults    = New-Object System.Collections.Generic.List[object]
$largeItemsResults = New-Object System.Collections.Generic.List[object]
$downloadsResults  = New-Object System.Collections.Generic.List[object]
$sharePointResults = New-Object System.Collections.Generic.List[string]

# ---------------- HELPERS ----------------
function To-GB {
    param([long]$Bytes, [int]$Round = 2)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, $Round)
}

function Get-FolderSizeBytes {
    param([Parameter(Mandatory)][string]$Path)
    try {
        return (Get-ChildItem -Path $Path -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                Where-Object { -not ($_.Attributes -match 'RecallOnDataAccess' -or $_.Attributes -match 'Offline') } |
                Measure-Object -Property Length -Sum).Sum
    } catch {
        Write-Verbose "Get-FolderSizeBytes failed for '$Path': $($_.Exception.Message)"
        return 0
    }
}

function Get-TopLevelNameFromProfilePath {
    param([Parameter(Mandatory)][string]$ProfilePath, [Parameter(Mandatory)][string]$FileFullPath)
    try {
        $rel = $FileFullPath.Substring($ProfilePath.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { return '(root)' }
        $parts = $rel.Split('\')
        if ($parts.Count -ge 2) { return $parts[0] }
        return '(root)'
    } catch { return '(unknown)' }
}

function Get-SharePointSyncFolders {
    $syncPaths = New-Object System.Collections.Generic.List[string]
    try {
        $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'S-1-5-21-[\d\-]+$' }

        foreach ($sid in $userSIDs) {
            $regPath = "$($sid.PSPath)\Software\SyncEngines\Providers\OneDrive"
            if (Test-Path $regPath) {
                $syncKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                foreach ($key in $syncKeys) {
                    $mountPoint = (Get-ItemProperty -Path $key.PSPath -Name "MountPoint" -ErrorAction SilentlyContinue).MountPoint
                    if ($mountPoint -and ($mountPoint -notmatch "\\OneDrive$") -and ($mountPoint -notmatch "\\OneDrive - ")) {
                        if (-not $syncPaths.Contains($mountPoint)) { $syncPaths.Add($mountPoint) }
                    }
                }
            }
        }
    } catch {
        # Non-fatal: registry access may fail on locked-down endpoints.
        # Surface via Verbose so a tech running with -Verbose can see why sync data is absent.
        Write-Verbose "Get-SharePointSyncFolders failed: $($_.Exception.Message)"
    }
    return $syncPaths
}

function Get-ProfileStatsSinglePass {
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][int64]$ThresholdBytes
    )
    $total      = [int64]0
    $bytesByTop = @{}
    $largeFiles = New-Object System.Collections.Generic.List[object]

    try {
        Get-ChildItem -Path $ProfilePath -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object {
            $f           = $_
            $isCloudOnly = ($f.Attributes -match 'RecallOnDataAccess') -or ($f.Attributes -match 'Offline')

            if (-not $isCloudOnly) {
                $len    = [int64]$f.Length
                $total += $len

                $top = Get-TopLevelNameFromProfilePath -ProfilePath $ProfilePath -FileFullPath $f.FullName
                if (-not $bytesByTop.ContainsKey($top)) { $bytesByTop[$top] = [int64]0 }
                $bytesByTop[$top] += $len

                if ($IncludeLargeFiles -and ($len -ge $ThresholdBytes)) {
                    $largeFiles.Add([pscustomobject]@{
                        ItemType = 'File'; User = $User; Name = $f.Name
                        SizeGB   = To-GB $len; Path = $f.FullName
                    }) | Out-Null
                }
            }
        }
    } catch {
        # Profile may be inaccessible (locked, permission-denied, deleted-but-present folder).
        # Return whatever was accumulated so far - partial data is better than none.
        # A 0-byte result in profileResults may indicate access failure, not an empty profile.
        Write-Verbose "Get-ProfileStatsSinglePass partial failure for user '$User': $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        User             = $User
        Path             = $ProfilePath
        TotalBytes       = $total
        BytesByTopFolder = $bytesByTop
        LargeFiles       = $largeFiles.ToArray()
    }
}

# ==============================================================================
# DATA COLLECTION PHASE
# ==============================================================================

try {
    # --- DRIVE USAGE ---
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
    foreach ($d in $drives) {
        $totalGB = To-GB $d.Size
        $freeGB  = To-GB $d.FreeSpace
        $usedGB  = [math]::Round($totalGB - $freeGB, 2)
        $pctFree = if ($d.Size) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }

        $driveResults.Add([pscustomobject]@{
            Drive       = $d.DeviceID; TotalGB = $totalGB
            UsedGB      = $usedGB;     FreeGB  = $freeGB
            PercentFree = $pctFree
        })

        if ($pctFree -lt $LowSpaceThreshold) {
            $LowSpaceFound = $true
            $Alerts.Add("Drive $($d.DeviceID) is low on space ($pctFree% free. Limit: $LowSpaceThreshold%)")
        }

        # --- RECYCLE BIN ---
        if ($IncludeRecycleBin) {
            # Join-Path "C:" '$Recycle.Bin' produces "C:$Recycle.Bin" (missing slash).
            # Appending '\' to DeviceID before Join-Path is the correct workaround for
            # this known PowerShell quirk with drive-root paths.
            $rbPath = Join-Path ($d.DeviceID + '\') '$Recycle.Bin'
            if (Test-Path $rbPath) {
                $rbBytes = Get-FolderSizeBytes -Path $rbPath
                $rbGB    = To-GB $rbBytes
                if ($rbGB -ge $RecycleBinThresholdGB) {
                    $LargeItemsFound = $true
                    $Alerts.Add("Drive $($d.DeviceID) Recycle Bin is $rbGB GB (Limit: $RecycleBinThresholdGB GB)")
                }
                $recycleBinResults.Add([pscustomobject]@{
                    Drive          = $d.DeviceID
                    RecycleBinGB   = $rbGB
                    RecycleBinPath = $rbPath
                })
            }
        }
    }

    # --- SHAREPOINT SYNC ---
    $spFolders = Get-SharePointSyncFolders
    foreach ($sp in $spFolders) { $sharePointResults.Add($sp) }

    # --- USER PROFILES ---
    if (Test-Path $UserRoot) {
        # Skip list covers system/built-in profiles that should never be scanned.
        # Includes WDAGUtilityAccount (Windows Defender Application Guard) and
        # DefaultAppPool (IIS) which appear on managed endpoints.
        $skip = @('Default', 'Default User', 'Public', 'All Users', 'WDAGUtilityAccount', 'DefaultAppPool')
        $profiles = Get-ChildItem -Path $UserRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skip -notcontains $_.Name }

        $generalThresholdBytes   = [int64]($LargeThresholdGB * 1GB)
        $downloadsThresholdBytes = [int64]($DownloadsThresholdGB * 1GB)

        foreach ($p in $profiles) {
            $stats = Get-ProfileStatsSinglePass -User $p.Name -ProfilePath $p.FullName -ThresholdBytes $generalThresholdBytes

            $profileResults.Add([pscustomobject]@{
                User   = $p.Name
                Path   = $p.FullName
                SizeGB = To-GB $stats.TotalBytes
            })

            # --- DOWNLOADS CHECK ---
            # Downloads is evaluated against $DownloadsThresholdGB independently.
            # It is intentionally excluded from the general large-folder check below
            # to allow the two thresholds to be tuned separately without double-alerting.
            # Always recorded in $downloadsResults (with Alerted flag) so JSON consumers
            # can see the actual size even when below the alert threshold.
            $dlGB      = 0
            $dlAlerted = $false
            if ($stats.BytesByTopFolder.ContainsKey('Downloads')) {
                $dlGB = To-GB $stats.BytesByTopFolder['Downloads']
                if ($dlGB -ge $DownloadsThresholdGB) {
                    $LargeItemsFound = $true
                    $dlAlerted       = $true
                    $Alerts.Add("User '$($stats.User)' Downloads folder is $dlGB GB (Limit: $DownloadsThresholdGB GB)")
                }
            }
            # Record Downloads entry for every user so JSON consumers have full context,
            # not just those that breached the threshold.
            $downloadsResults.Add([pscustomobject]@{
                User    = $stats.User
                SizeGB  = $dlGB
                Alerted = $dlAlerted
            })

            # --- GENERAL LARGE FOLDERS ---
            # Downloads is explicitly excluded here - see note above.
            foreach ($k in $stats.BytesByTopFolder.Keys) {
                $b = [int64]$stats.BytesByTopFolder[$k]
                if ($b -ge $generalThresholdBytes -and $k -ne 'Downloads') {
                    $LargeItemsFound = $true
                    $largeItemsResults.Add([pscustomobject]@{
                        ItemType = 'Folder'
                        User     = $stats.User
                        Name     = $k
                        SizeGB   = To-GB $b
                        Path     = if ($k -eq '(root)') { $stats.Path } else { Join-Path $stats.Path $k }
                    })
                }
            }

            # --- LARGE FILES ---
            if ($stats.LargeFiles.Count -gt 0) {
                $LargeItemsFound = $true
                foreach ($lf in $stats.LargeFiles) { $largeItemsResults.Add($lf) }
            }
        }
    }

} catch {
    # Use Write-Output (not Write-Host) so N-able captures the error in task output.
    # Write-Host writes to the Information stream which N-able does not collect.
    Write-Output "CRITICAL SCRIPT ERROR: $($_.Exception.Message)"
    exit 4
}

# ==============================================================================
# OUTPUT PHASE
# ==============================================================================

if ($AsJson) {
    # Single compressed JSON line - ideal for N-able custom field ingestion.
    [pscustomobject]@{
        Version         = '5.5'
        LowSpaceFound   = $LowSpaceFound
        LargeItemsFound = $LargeItemsFound
        Alerts          = $Alerts
        Drives          = $driveResults
        RecycleBins     = $recycleBinResults
        Downloads       = $downloadsResults
        LargeItems      = $largeItemsResults
        Profiles        = $profileResults
        SharePointPaths = $sharePointResults
    } | ConvertTo-Json -Depth 6 -Compress | Write-Output
}
else {
    # --- ALERTS BANNER ---
    if ($Alerts.Count -gt 0) {
        Write-Host "=== ACTION REQUIRED ===" -ForegroundColor Yellow
        foreach ($alert in $Alerts) { Write-Host "[WARN] $alert" -ForegroundColor Yellow }
        Write-Host ""
    } else {
        Write-Host "[ OK ] No storage thresholds exceeded.`n" -ForegroundColor Green
    }

    # --- DRIVE STATUS ---
    Write-Host "=== DRIVE STATUS ===" -ForegroundColor Cyan
    foreach ($d in $driveResults) {
        Write-Host ("{0,-5} | {1,6}% Free | {2,7} GB Used / {3,7} GB Total" -f $d.Drive, $d.PercentFree, $d.UsedGB, $d.TotalGB)
    }
    Write-Host ""

    # --- RECYCLE BIN STATUS ---
    if ($IncludeRecycleBin -and $recycleBinResults.Count -gt 0) {
        Write-Host "=== RECYCLE BIN ===" -ForegroundColor Cyan
        foreach ($rb in $recycleBinResults) {
            $marker = if ($rb.RecycleBinGB -ge $RecycleBinThresholdGB) { "[WARN]" } else { "[ OK ]" }
            Write-Host ("{0} {1,-5} | {2,7} GB" -f $marker, $rb.Drive, $rb.RecycleBinGB)
        }
        Write-Host ""
    }

    # --- USER PROFILES ---
    if ($profileResults.Count -gt 0) {
        Write-Host "=== USER PROFILES ===" -ForegroundColor Cyan
        $profileResults | Sort-Object SizeGB -Descending | ForEach-Object {
            Write-Host ("{0,-20} | {1,7} GB | {2}" -f $_.User, $_.SizeGB, $_.Path)
        }
        Write-Host ""
    }

    # --- DOWNLOADS SUMMARY ---
    $downloadsWithData = $downloadsResults | Where-Object { $_.SizeGB -gt 0 }
    if ($downloadsWithData) {
        Write-Host ("=== DOWNLOADS (Alert threshold: {0} GB) ===" -f $DownloadsThresholdGB) -ForegroundColor Cyan
        $downloadsWithData | Sort-Object SizeGB -Descending | ForEach-Object {
            $marker = if ($_.Alerted) { "[WARN]" } else { "[ OK ]" }
            Write-Host ("{0} {1,-20} | {2,7} GB" -f $marker, $_.User, $_.SizeGB)
        }
        Write-Host ""
    }

    # --- LARGE ITEMS ---
    if ($largeItemsResults.Count -gt 0) {
        Write-Host ("=== LARGE ITEMS FOUND (> {0} GB) ===" -f $LargeThresholdGB) -ForegroundColor Cyan
        $largeItemsResults | Sort-Object SizeGB -Descending | ForEach-Object {
            Write-Host ("{0,-15} | {1,-6} | {2,7} GB | {3}" -f $_.User, $_.ItemType, $_.SizeGB, $_.Name)
        }
        Write-Host ""
    }

    # --- SHAREPOINT SYNCS ---
    if ($sharePointResults.Count -gt 0) {
        Write-Host "=== ACTIVE SHAREPOINT SYNCS ===" -ForegroundColor Cyan
        foreach ($sp in $sharePointResults) { Write-Host $sp }
        Write-Host ""
    }
}

# ---------------- EXIT CODES ----------------
if ($LowSpaceFound -and $LargeItemsFound) { exit 3 }
elseif ($LowSpaceFound)                   { exit 1 }
elseif ($LargeItemsFound)                 { exit 2 }
else                                      { exit 0 }
