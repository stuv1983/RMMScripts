<#
.SYNOPSIS
    Hard drive usage + per-user profile sizing + large folder/file reporting (RMM-ready), with per-drive Recycle Bin sizing.

.DESCRIPTION
    - Reports used/free space for all fixed drives.
    - Reports per-drive Recycle Bin usage (X:\$Recycle.Bin).
    - Lists each user profile under C:\Users with total size.
    - For each user, reports top-level folders whose *aggregated* size >= threshold (single traversal).
    - Optionally reports individual files >= threshold (found during the same traversal).
    - Console-only output (no disk writes). ASCII-only to avoid encoding issues.
    - Returns exit codes suitable for RMM alerting.

.ARCHITECTURE NOTE
    Single traversal per profile:
      The script enumerates files under each profile once and simultaneously computes:
        - Profile total bytes
        - Aggregated bytes per top-level folder
        - Large files list (optional)
      This removes redundant recursive scans and reduces disk I/O significantly.

.EXIT CODES
    0 = OK            (no low space, no large items)
    1 = Low space     (one or more drives below threshold)
    2 = Large items   (one or more folders/files >= threshold, incl. Recycle Bin threshold)
    3 = Both issues   (low space AND large items detected)
    4 = Script error  (unexpected failure)

.NOTES
    Author: Stu (Kenstra IT Support), EN-AU
    Version: 1.7 (single-pass profile traversal + per-drive Recycle Bin sizing)
#>

[CmdletBinding()]
param(
    [Parameter()] [int]$LowSpaceThreshold = 10,              # Warn if drive free % < this
    [Parameter()] [string]$UserRoot = 'C:\Users',            # Root for user profiles
    [Parameter()] [int]$LargeThresholdGB = 5,                # Flag any folder/file >= this size (GB)
    [Parameter()] [object]$IncludeHidden = $true,            # Include hidden/system items during enumeration
    [Parameter()] [object]$AsJson,

    # Recycle Bin sizing
    [Parameter()] [object]$IncludeRecycleBin = $true,
    [Parameter()] [int]$RecycleBinThresholdGB = 5,           # Flag Recycle Bin if >= this size (GB)

    # Large-file reporting (kept for backward compatibility; still single-pass)
    [Parameter()] [object]$IncludeLargeFiles = $true
)

function Convert-ToBool {
    param([Parameter(ValueFromPipeline)][AllowNull()][object]$Value)
    process {
        if ($null -eq $Value) { return $false }
        if ($Value -is [bool]) { return $Value }
        if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
            return [bool]([int]$Value)
        }
        $v = "$Value".Trim().ToLowerInvariant()
        switch ($v) {
            'true'  { return $true }
            'false' { return $false }
            '1'     { return $true }
            '0'     { return $false }
            default { return $false }
        }
    }
}

$IncludeHidden      = Convert-ToBool $IncludeHidden
$AsJson             = Convert-ToBool $AsJson
$IncludeRecycleBin  = Convert-ToBool $IncludeRecycleBin
$IncludeLargeFiles  = Convert-ToBool $IncludeLargeFiles

function Write-Report {
    param([string]$Message, [ConsoleColor]$ForegroundColor)
    if (-not $AsJson) {
        if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
            Write-Host $Message -ForegroundColor $ForegroundColor
        } else {
            Write-Host $Message
        }
    }
}

# ---------------- STATE FLAGS FOR EXIT CODES ----------------
$LowSpaceFound    = $false
$LargeItemsFound  = $false

$driveResults       = @()
$recycleBinResults  = @()
$profileResults     = @()
$largeItemsResults  = @()

# ---------------- HELPERS ----------------
function To-GB {
    param([long]$Bytes, [int]$Round=2)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, $Round)
}

function Get-FolderSizeBytes {
    <#
        Returns recursive size of a folder in bytes.
        Uses -Force to include hidden/system (optional) and SilentlyContinue to ignore access issues.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        return (Get-ChildItem -Path $Path -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
    } catch {
        return 0
    }
}

function Get-TopLevelNameFromProfilePath {
    <#
        Given a file full path and the profile root path (C:\Users\<user>),
        returns the top-level folder name under the profile, or '(root)' if file is directly under the profile root.
    #>
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$FileFullPath
    )

    try {
        $rel = $FileFullPath.Substring($ProfilePath.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { return '(root)' }
        $parts = $rel.Split('\')
        if ($parts.Count -ge 2) { return $parts[0] }  # inside a top-level folder
        return '(root)'
    } catch {
        return '(unknown)'
    }
}

function Get-ProfileStatsSinglePass {
    <#
        Enumerates files under a profile ONCE and computes:
          - TotalBytes
          - BytesByTopFolder (Hashtable)
          - LargeFiles (Array, optional)

        Implementation note:
          - Uses streaming pipeline enumeration (no $files array) to keep memory usage flat on very large profiles.
          - This is NOT ForEach-Object -Parallel, so variable updates (e.g. $total += ...) are safe.
    #>
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][int64]$ThresholdBytes
    )

    $total = [int64]0
    $bytesByTop = @{}
    $largeFiles = New-Object System.Collections.Generic.List[object]

    try {
        Get-ChildItem -Path $ProfilePath -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
        ForEach-Object {
            $f = $_
            $len = [int64]$f.Length

            $total += $len

            $top = Get-TopLevelNameFromProfilePath -ProfilePath $ProfilePath -FileFullPath $f.FullName
            if (-not $bytesByTop.ContainsKey($top)) { $bytesByTop[$top] = [int64]0 }
            $bytesByTop[$top] += $len

            if ($IncludeLargeFiles -and ($len -ge $ThresholdBytes)) {
                $largeFiles.Add([pscustomobject]@{
                    ItemType = 'File'
                    User     = $User
                    Name     = $f.Name
                    SizeGB   = To-GB $len
                    Path     = $f.FullName
                    Modified = $f.LastWriteTime
                }) | Out-Null
            }
        }
    } catch {
        # Best-effort: return what we have, don't hard-fail for one profile
    }

    return [pscustomobject]@{
        User             = $User
        Path             = $ProfilePath
        TotalBytes       = $total
        BytesByTopFolder = $bytesByTop
        LargeFiles       = $largeFiles.ToArray()
    }
}

# ---------------- DRIVE USAGE ----------------
Write-Report "=== Hard Drive Usage Report ===`n"

try {
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
} catch {
    Write-Report "ERROR: Unable to query logical disks: $($_.Exception.Message)"
    exit 4
}

foreach ($d in $drives) {
    $totalGB = To-GB $d.Size
    $freeGB  = To-GB $d.FreeSpace
    $usedGB  = [math]::Round($totalGB - $freeGB, 2)
    $pctFree = if ($d.Size) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }

    $driveObj = [pscustomobject]@{
        Drive       = $d.DeviceID
        TotalGB     = $totalGB
        UsedGB      = $usedGB
        FreeGB      = $freeGB
        PercentFree = $pctFree
        LowSpace    = ($pctFree -lt $LowSpaceThreshold)
    }
    $driveResults += $driveObj

    Write-Report ("Drive {0}: Total={1} GB | Used={2} GB | Free={3} GB ({4}% free)" -f $d.DeviceID, $totalGB, $usedGB, $freeGB, $pctFree)

    if ($pctFree -lt $LowSpaceThreshold) {
        $LowSpaceFound = $true
        Write-Report ("WARNING: {0} low on space (< {1}% free)" -f $d.DeviceID, $LowSpaceThreshold) -ForegroundColor Yellow
    }
}

# ---------------- RECYCLE BIN (PER DRIVE) ----------------
if ($IncludeRecycleBin) {
    $rbThresholdBytes = [int64]($RecycleBinThresholdGB * 1GB)

    Write-Report "`n=== Recycle Bin Usage (per drive) ===`n"

    foreach ($d in $drives) {
        $root = $d.DeviceID.TrimEnd('\') + '\'
        $rbPath = Join-Path $root '$Recycle.Bin'

        $rbBytes = 0
        $rbLarge = $false

        if (Test-Path $rbPath) {
            $rbBytes = Get-FolderSizeBytes -Path $rbPath
            if ($rbBytes -ge $rbThresholdBytes) {
                $rbLarge = $true
                $LargeItemsFound = $true
            }
        }

        $rbObj = [pscustomobject]@{
            Drive            = $d.DeviceID
            RecycleBinGB     = To-GB $rbBytes
            RecycleBinPath   = $rbPath
            RecycleBinLarge  = $rbLarge
            ThresholdGB      = $RecycleBinThresholdGB
        }
        $recycleBinResults += $rbObj

        Write-Report ("Drive {0}: Recycle Bin={1} GB (threshold {2} GB)" -f $d.DeviceID, (To-GB $rbBytes), $RecycleBinThresholdGB)

        if ($rbLarge) {
            Write-Report ("WARNING: {0} Recycle Bin >= {1} GB" -f $d.DeviceID, $RecycleBinThresholdGB) -ForegroundColor Yellow
        }
    }

    if (-not $AsJson -and $recycleBinResults.Count -gt 0) {
        Write-Report ""
        $recycleBinResults | Format-Table -AutoSize
        Write-Report ""
    }
}

# ---------------- USER PROFILE SIZES + LARGE ITEMS (SINGLE PASS PER PROFILE) ----------------
if (-not (Test-Path $UserRoot)) {
    Write-Report "`nUser root not found: $UserRoot"
} else {
    Write-Report "`n=== User Profile Space Usage ($UserRoot) ===`n"

    $skip = @('Default','Default User','Public','All Users')

    try {
        $profiles = Get-ChildItem -Path $UserRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skip -notcontains $_.Name }
    } catch {
        Write-Report "ERROR: Unable to enumerate profiles: $($_.Exception.Message)"
        exit 4
    }

    $thresholdBytes = [int64]($LargeThresholdGB * 1GB)

    # First: compute stats per profile (single pass each), store in memory for later printing
    $profileStats = @()

    foreach ($p in $profiles) {
        $stats = Get-ProfileStatsSinglePass -User $p.Name -ProfilePath $p.FullName -ThresholdBytes $thresholdBytes

        $row = [pscustomobject]@{
            User   = $p.Name
            Path   = $p.FullName
            SizeGB = To-GB $stats.TotalBytes
        }

        $profileStats += $stats
        $profileResults += $row
    }

    if ($profileResults.Count -gt 0) {
        if (-not $AsJson) {
            $profileResults | Sort-Object SizeGB -Descending | Format-Table -AutoSize
        }
    } else {
        Write-Report "No user profiles found."
    }

    # Then: per-user large items derived from the same single traversal
    foreach ($stats in $profileStats) {
        Write-Report ""
        Write-Report ("--- {0} ({1}) ---" -f $stats.User, $stats.Path)

        $bigFolders = @()

        foreach ($k in $stats.BytesByTopFolder.Keys) {
            $b = [int64]$stats.BytesByTopFolder[$k]

            if ($b -ge $thresholdBytes) {
                $LargeItemsFound = $true

                $folderPath = if ($k -eq '(root)') { $stats.Path } else { Join-Path $stats.Path $k }
                $modified = $null
                try {
                    $modified = (Get-Item -LiteralPath $folderPath -Force:$IncludeHidden -ErrorAction SilentlyContinue).LastWriteTime
                } catch { $modified = $null }

                $item = [pscustomobject]@{
                    ItemType = if ($k -eq '(root)') { 'Root' } else { 'Folder' }
                    User     = $stats.User
                    Name     = if ($k -eq '(root)') { '(profile root files)' } else { $k }
                    SizeGB   = To-GB $b
                    Path     = $folderPath
                    Modified = $modified
                }

                $bigFolders += $item
                $largeItemsResults += $item
            }
        }

        $bigFiles = @()
        if ($IncludeLargeFiles -and $stats.LargeFiles) {
            $bigFiles = $stats.LargeFiles
            foreach ($bf in $bigFiles) { $largeItemsResults += $bf }
        }

        if (($bigFolders.Count + $bigFiles.Count) -gt 0) {
            Write-Report ("Large items (>= {0} GB) for user {1}:" -f $LargeThresholdGB, $stats.User)
            if (-not $AsJson) {
                ($bigFolders + $bigFiles) | Sort-Object SizeGB -Descending | Format-Table -AutoSize
            }
        } else {
            Write-Report ("No folders/files >= {0} GB under this profile." -f $LargeThresholdGB)
        }
    }
}

# ---------------- SUMMARY / EXIT CODE ----------------
Write-Report "`n=== Check complete ==="

if ($AsJson) {
    [pscustomobject]@{
        Version              = '1.7'
        LowSpaceThreshold    = $LowSpaceThreshold
        LargeThresholdGB     = $LargeThresholdGB
        UserRoot             = $UserRoot
        IncludeHidden        = $IncludeHidden
        IncludeRecycleBin    = $IncludeRecycleBin
        RecycleBinThresholdGB = $RecycleBinThresholdGB
        IncludeLargeFiles    = $IncludeLargeFiles
        LowSpaceFound        = $LowSpaceFound
        LargeItemsFound      = $LargeItemsFound
        Drives               = $driveResults
        RecycleBins          = $recycleBinResults
        Profiles             = $profileResults
        LargeItems           = $largeItemsResults
    } | ConvertTo-Json -Depth 6
}

try {
    if ($LowSpaceFound -and $LargeItemsFound) { exit 3 }
    elseif ($LowSpaceFound)                   { exit 1 }
    elseif ($LargeItemsFound)                 { exit 2 }
    else                                      { exit 0 }
} catch {
    Write-Report "ERROR: Unexpected failure when setting exit code: $($_.Exception.Message)"
    exit 4
}
