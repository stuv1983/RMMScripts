<#
.SYNOPSIS
    Hard drive usage + per-user profile sizes + large folder/file reporting (RMM-ready).

.DESCRIPTION
    - Reports used/free space for all fixed drives.
    - Lists each user profile under C:\Users with total size.
    - For each user, shows top-level subfolders >= threshold (recursive size) and any files >= threshold (incl. OST).
    - Console-only output (no disk writes). ASCII-only to avoid encoding issues.
    - Returns exit codes suitable for RMM alerting.

.EXIT CODES
    0 = OK            (no low space, no large items)
    1 = Low space     (one or more drives below threshold)
    2 = Large items   (one or more folders/files >= threshold)
    3 = Both issues   (low space AND large items detected)
    4 = Script error  (unexpected failure)

.NOTES
    Author: Stu (Kenstra IT Support), EN-AU
    Version: 1.5 (adds exit codes for RMM)
#>

# ---------------- SETTINGS ----------------
$LowSpaceThreshold = 10          # Warn if drive free % < this
$UserRoot          = 'C:\Users'  # Root for user profiles
$LargeThresholdGB  = 5           # Flag any folder/file >= this size
$IncludeHidden     = $true       # Include hidden/system items during sizing

# ---------------- STATE FLAGS FOR EXIT CODES ----------------
$LowSpaceFound    = $false       # Set true if any drive is below threshold
$LargeItemsFound  = $false       # Set true if any large folder/file found

# ---------------- HELPERS ----------------
function To-GB {
    param([long]$Bytes, [int]$Round=2)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, $Round)
}

function Get-FolderSizeBytes {
    <#
        Returns recursive size of a folder in bytes.
        Uses -Force to include hidden/system, and SilentlyContinue to ignore access issues.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        return (Get-ChildItem -Path $Path -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
    } catch {
        return 0
    }
}

# ---------------- DRIVE USAGE ----------------
Write-Host "=== Hard Drive Usage Report ===`n"

try {
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
} catch {
    Write-Host "ERROR: Unable to query logical disks: $($_.Exception.Message)"
    exit 4
}

foreach ($d in $drives) {
    $totalGB = To-GB $d.Size
    $freeGB  = To-GB $d.FreeSpace
    $usedGB  = [math]::Round($totalGB - $freeGB, 2)
    $pctFree = if ($d.Size) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }

    Write-Host ("Drive {0}: Total={1} GB | Used={2} GB | Free={3} GB ({4}% free)" -f $d.DeviceID, $totalGB, $usedGB, $freeGB, $pctFree)

    if ($pctFree -lt $LowSpaceThreshold) {
        $LowSpaceFound = $true
        Write-Host ("WARNING: {0} low on space (< {1}% free)" -f $d.DeviceID, $LowSpaceThreshold) -ForegroundColor Yellow
    }
}

# ---------------- USER PROFILE SIZES ----------------
if (-not (Test-Path $UserRoot)) {
    Write-Host "`nUser root not found: $UserRoot"
    # continue; still return low-space status if it was detected
} else {
    Write-Host "`n=== User Profile Space Usage ($UserRoot) ===`n"

    $skip = @('Default','Default User','Public','All Users')

    try {
        $profiles = Get-ChildItem -Path $UserRoot -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skip -notcontains $_.Name }
    } catch {
        Write-Host "ERROR: Unable to enumerate profiles: $($_.Exception.Message)"
        exit 4
    }

    $profileRows = @()
    foreach ($p in $profiles) {
        $bytes = (Get-ChildItem -Path $p.FullName -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
        $profileRows += [pscustomobject]@{
            User   = $p.Name
            Path   = $p.FullName
            SizeGB = To-GB $bytes
        }
    }

    if ($profileRows) {
        $profileRows | Sort-Object SizeGB -Descending | Format-Table -AutoSize
    } else {
        Write-Host "No user profiles found."
    }

    # ---------------- PER-USER LARGE PATHS (FOLDERS AND FILES) ----------------
    $thresholdBytes = [int64]($LargeThresholdGB * 1GB)

    foreach ($p in $profiles) {
        Write-Host ""
        Write-Host ("--- {0} ({1}) ---" -f $p.Name, $p.FullName)

        # Top-level subfolders sized recursively; report those >= threshold
        $childDirs = Get-ChildItem -Path $p.FullName -Directory -Force:$IncludeHidden -ErrorAction SilentlyContinue
        $bigFolders = @()

        foreach ($dir in $childDirs) {
            $sizeB = Get-FolderSizeBytes -Path $dir.FullName
            if ($sizeB -ge $thresholdBytes) {
                $LargeItemsFound = $true
                $bigFolders += [pscustomobject]@{
                    ItemType = 'Folder'
                    Name     = $dir.Name
                    SizeGB   = To-GB $sizeB
                    Path     = $dir.FullName
                    Modified = $dir.LastWriteTime
                }
            }
        }

        # Any individual files >= threshold anywhere under this profile (includes OST)
        $bigFiles = Get-ChildItem -Path $p.FullName -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge $thresholdBytes } |
                    ForEach-Object {
                        $LargeItemsFound = $true
                        [pscustomobject]@{
                            ItemType = 'File'
                            Name     = $_.Name
                            SizeGB   = To-GB $_.Length
                            Path     = $_.FullName
                            Modified = $_.LastWriteTime
                        }
                    }

        if (($bigFolders.Count + $bigFiles.Count) -gt 0) {
            Write-Host ("Large items (>= {0} GB) for user {1}:" -f $LargeThresholdGB, $p.Name)
            ($bigFolders + $bigFiles) | Sort-Object SizeGB -Descending | Format-Table -AutoSize
        } else {
            Write-Host ("No folders/files >= {0} GB under this profile." -f $LargeThresholdGB)
        }
    }
}

# ---------------- SUMMARY / EXIT CODE ----------------
Write-Host "`n=== Check complete ==="

try {
    if ($LowSpaceFound -and $LargeItemsFound) { exit 3 }
    elseif ($LowSpaceFound)                 { exit 1 }
    elseif ($LargeItemsFound)               { exit 2 }
    else                                    { exit 0 }
} catch {
    Write-Host "ERROR: Unexpected failure when setting exit code: $($_.Exception.Message)"
    exit 4
}
