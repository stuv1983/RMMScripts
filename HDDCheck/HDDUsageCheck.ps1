<#
.SYNOPSIS
    Hard drive usage + per-user profile sizing + large folder/file reporting (RMM-ready).
    Includes specific alerting for User Downloads folders > 5GB, accurate cloud-file sizing, 
    and read-only SharePoint sync detection.

.NOTES
    Name:       HDDUsageCheck_v5.3.ps1
    Author:     Stu Villanti
    Modified:   Patched regex to properly exclude personal OneDrive from SharePoint syncs.
    Version:    5.3

.DESCRIPTION
    - Reports used/free space for all fixed drives.
    - Reports per-drive Recycle Bin usage.
    - Lists each user profile under C:\Users with total size (ignoring cloud-only files).
    - Checks User "Downloads" folder specifically against a threshold.
    - Identifies synced SharePoint locations via HKEY_USERS (Read-Only).
    - Console-only output. Returns exit codes for RMM alerting.

.EXIT CODES
    0 = OK            (no issues)
    1 = Low space     (drive free space < threshold)
    2 = Large items   (Downloads > 5GB OR other large folders/files found)
    3 = Both issues   (low space AND large items detected)
    4 = Script error  (unexpected failure)
#>

[CmdletBinding()]
param(
    [Parameter()] [int]$LowSpaceThreshold = 10,
    [Parameter()] [string]$UserRoot = 'C:\Users',
    [Parameter()] [int]$LargeThresholdGB = 5,
    [Parameter()] [int]$DownloadsThresholdGB = 5,
    [Parameter()] [object]$IncludeHidden = $true,
    [Parameter()] [object]$AsJson,
    [Parameter()] [object]$IncludeRecycleBin = $true,
    [Parameter()] [int]$RecycleBinThresholdGB = 5,
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
$downloadsResults   = @()
$sharePointResults  = @()

# ---------------- HELPERS ----------------
function To-GB {
    param([long]$Bytes, [int]$Round=2)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, $Round)
}

function Get-FolderSizeBytes {
    param([Parameter(Mandatory)][string]$Path)
    try {
        # Filter out cloud-only files to get actual disk usage
        return (Get-ChildItem -Path $Path -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                Where-Object { -not ($_.Attributes -match 'RecallOnDataAccess' -or $_.Attributes -match 'Offline') } |
                Measure-Object -Property Length -Sum).Sum
    } catch {
        return 0
    }
}

function Get-TopLevelNameFromProfilePath {
    param(
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$FileFullPath
    )
    try {
        $rel = $FileFullPath.Substring($ProfilePath.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($rel)) { return '(root)' }
        $parts = $rel.Split('\')
        if ($parts.Count -ge 2) { return $parts[0] }
        return '(root)'
    } catch {
        return '(unknown)'
    }
}

function Get-SharePointSyncFolders {
    $syncPaths = @()
    try {
        # Safe, read-only iteration of loaded user profiles
        $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -match 'S-1-5-21-[\d\-]+$' }
        
        foreach ($sid in $userSIDs) {
            $regPath = "$($sid.PSPath)\Software\SyncEngines\Providers\OneDrive"
            if (Test-Path $regPath) {
                $syncKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                foreach ($key in $syncKeys) {
                    $mountPoint = (Get-ItemProperty -Path $key.PSPath -Name "MountPoint" -ErrorAction SilentlyContinue).MountPoint
                    # Filter out standard personal AND business OneDrive roots to isolate SharePoint
                    if ($mountPoint -and ($mountPoint -notmatch "\\OneDrive$") -and ($mountPoint -notmatch "\\OneDrive - ")) {
                        if ($syncPaths -notcontains $mountPoint) {
                            $syncPaths += $mountPoint
                        }
                    }
                }
            }
        }
    } catch { }
    return $syncPaths
}

function Get-ProfileStatsSinglePass {
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
            
            # Skip cloud-only placeholders so they don't skew the physical size
            $isCloudOnly = ($f.Attributes -match 'RecallOnDataAccess') -or ($f.Attributes -match 'Offline')
            
            if (-not $isCloudOnly) {
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
        }
    } catch { }

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

# ---------------- SHAREPOINT SYNC DETECTION ----------------
Write-Report "`n=== Synced SharePoint Locations ===`n"
$sharePointResults = Get-SharePointSyncFolders
if ($sharePointResults.Count -gt 0) {
    foreach ($sp in $sharePointResults) {
        Write-Report "Found Sync: $sp"
    }
} else {
    Write-Report "No active SharePoint syncs detected."
}

# ---------------- RECYCLE BIN ----------------
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
        }
        $recycleBinResults += $rbObj

        Write-Report ("Drive {0}: Recycle Bin={1} GB" -f $d.DeviceID, (To-GB $rbBytes))
        if ($rbLarge) {
            Write-Report ("WARNING: {0} Recycle Bin >= {1} GB" -f $d.DeviceID, $RecycleBinThresholdGB) -ForegroundColor Yellow
        }
    }
}

# ---------------- USER PROFILES & DOWNLOADS CHECK ----------------
if (-not (Test-Path $UserRoot)) {
    Write-Report "`nUser root not found: $UserRoot"
} else {
    Write-Report "`n=== User Profile Space Usage ($UserRoot) ===`n"

    $skip = @('Default','Default User','Public','All Users')
    try {
        $profiles = Get-ChildItem -Path $UserRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skip -notcontains $_.Name }
    } catch {
        Write-Report "ERROR: Unable to enumerate profiles"
        exit 4
    }

    $generalThresholdBytes = [int64]($LargeThresholdGB * 1GB)
    $downloadsThresholdBytes = [int64]($DownloadsThresholdGB * 1GB)
    $profileStats = @()

    foreach ($p in $profiles) {
        $stats = Get-ProfileStatsSinglePass -User $p.Name -ProfilePath $p.FullName -ThresholdBytes $generalThresholdBytes
        
        $profileStats += $stats
        $profileResults += [pscustomobject]@{
            User   = $p.Name
            Path   = $p.FullName
            SizeGB = To-GB $stats.TotalBytes
        }
    }

    if ($profileResults.Count -gt 0 -and -not $AsJson) {
        $profileResults | Sort-Object SizeGB -Descending | Format-Table -AutoSize
    }

    foreach ($stats in $profileStats) {
        Write-Report ""
        Write-Report ("--- {0} ({1}) ---" -f $stats.User, $stats.Path)

        if ($stats.BytesByTopFolder.ContainsKey('Downloads')) {
            $dlBytes = [int64]$stats.BytesByTopFolder['Downloads']
            $dlGB = To-GB $dlBytes
            
            if ($dlBytes -ge $downloadsThresholdBytes) {
                $LargeItemsFound = $true
                Write-Report ("WARNING: Downloads folder is {0} GB (Limit {1} GB)" -f $dlGB, $DownloadsThresholdGB) -ForegroundColor Yellow
                
                $downloadsResults += [pscustomobject]@{
                    User = $stats.User
                    SizeGB = $dlGB
                }
            } else {
                Write-Report ("Downloads folder: {0} GB (OK)" -f $dlGB)
            }
        } else {
            Write-Report "Downloads folder: 0 GB (OK)"
        }

        $bigFolders = @()
        foreach ($k in $stats.BytesByTopFolder.Keys) {
            $b = [int64]$stats.BytesByTopFolder[$k]
            
            if ($b -ge $generalThresholdBytes) {
                $LargeItemsFound = $true
                $folderPath = if ($k -eq '(root)') { $stats.Path } else { Join-Path $stats.Path $k }
                
                $bigFolders += [pscustomobject]@{
                    ItemType = 'Folder'
                    User     = $stats.User
                    Name     = $k
                    SizeGB   = To-GB $b
                    Path     = $folderPath
                }
            }
        }

        if (($bigFolders.Count + $stats.LargeFiles.Count) -gt 0) {
            Write-Report ("Top folders/files >= {0} GB:" -f $LargeThresholdGB)
            if (-not $AsJson) {
                ($bigFolders + $stats.LargeFiles) | Sort-Object SizeGB -Descending | Format-Table -AutoSize
            }
            $largeItemsResults += ($bigFolders + $stats.LargeFiles)
        }
    }
}

# ---------------- SUMMARY / EXIT CODE ----------------
Write-Report "`n=== Check complete ==="

if ($AsJson) {
    [pscustomobject]@{
        Version              = '5.3'
        LowSpaceFound        = $LowSpaceFound
        LargeItemsFound      = $LargeItemsFound
        DownloadsAlerts      = $downloadsResults
        SharePointPaths      = $sharePointResults
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
    exit 4
}