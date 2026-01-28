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
    Version: 1.6 (adds per-drive Recycle Bin sizing + faster folder sizing)
#>

[CmdletBinding()]
param(
    [Parameter()] [int]$LowSpaceThreshold = 10,          # Warn if drive free % < this
    [Parameter()] [string]$UserRoot = 'C:\Users',         # Root for user profiles
    [Parameter()] [int]$LargeThresholdGB = 5,             # Flag any folder/file >= this size
    [Parameter()] [object]$IncludeHidden = $true,         # Include hidden/system items during sizing
    [Parameter()] [object]$IncludeRecycleBin = $true,    # Include $Recycle.Bin size per drive
    [Parameter()] [int]$RecycleBinThresholdGB = 5,          # Flag Recycle Bin >= this size (counts as Large items)
    [Parameter()] [object]$AsJson
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

$IncludeHidden = Convert-ToBool $IncludeHidden
$IncludeRecycleBin = Convert-ToBool $IncludeRecycleBin
$AsJson = Convert-ToBool $AsJson

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
$LowSpaceFound    = $false       # Set true if any drive is below threshold
$LargeItemsFound  = $false       # Set true if any large folder/file found

$driveResults = @()
$recycleBinResults = @()
$profileResults = @()
$largeItemsResults = @()

# ---------------- HELPERS ----------------
function To-GB {
    param([long]$Bytes, [int]$Round=2)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, $Round)
}

function Get-FolderSizeBytes {
    <#
        Returns recursive size of a folder in bytes.
        Uses .NET enumeration for better performance than Get-ChildItem -Recurse.
        Suppresses access denied and other IO errors.
    #>
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return 0 }
        $total = 0L
        $stack = New-Object System.Collections.Generic.Stack[string]
        $stack.Push($Path)

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            try {
                $dirs = [System.IO.Directory]::EnumerateDirectories($current)
                foreach ($d in $dirs) { $stack.Push($d) }

                $files = [System.IO.Directory]::EnumerateFiles($current)
                foreach ($f in $files) {
                    try {
                        $fi = New-Object System.IO.FileInfo($f)
                        if (-not $IncludeHidden) {
                            $attr = $fi.Attributes
                            if (($attr -band [System.IO.FileAttributes]::Hidden) -ne 0) { continue }
                            if (($attr -band [System.IO.FileAttributes]::System) -ne 0) { continue }
                        }
                        $total += $fi.Length
                    } catch { }
                }
            } catch { }
        }

        return $total
    } catch {
        return 0
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

    $driveResults += [pscustomobject]@{
        Drive      = $d.DeviceID
        TotalGB    = $totalGB
        UsedGB     = $usedGB
        FreeGB     = $freeGB
        PercentFree = $pctFree
        LowSpace   = ($pctFree -lt $LowSpaceThreshold)
    }

    Write-Report ("Drive {0}: Total={1} GB | Used={2} GB | Free={3} GB ({4}% free)" -f $d.DeviceID, $totalGB, $usedGB, $freeGB, $pctFree)

    if ($pctFree -lt $LowSpaceThreshold) {
        $LowSpaceFound = $true
        Write-Report ("WARNING: {0} low on space (< {1}% free)" -f $d.DeviceID, $LowSpaceThreshold) -ForegroundColor Yellow
    }
}


# ---------------- RECYCLE BIN (PER DRIVE) ----------------
if ($IncludeRecycleBin) {
    Write-Report "`n=== Recycle Bin Usage (per drive) ===`n"

    $rbThresholdBytes = [int64]($RecycleBinThresholdGB * 1GB)

    foreach ($d in $drives) {
        $root = ($d.DeviceID + "\")
        $rbPath = Join-Path -Path $root -ChildPath '$Recycle.Bin'

        $rbBytes = 0L
        if (Test-Path -LiteralPath $rbPath) {
            $rbBytes = Get-FolderSizeBytes -Path $rbPath
        }

        $rbGB = To-GB $rbBytes
        $isLarge = ($rbBytes -ge $rbThresholdBytes)

        if ($isLarge) { $LargeItemsFound = $true }

        $row = [pscustomobject]@{
            Drive              = $d.DeviceID
            RecycleBinGB       = $rbGB
            RecycleBinPath     = $rbPath
            RecycleBinLarge    = $isLarge
            ThresholdGB        = $RecycleBinThresholdGB
        }

        $recycleBinResults += $row

        Write-Report ("Drive {0}: Recycle Bin={1} GB (threshold {2} GB)" -f $d.DeviceID, $rbGB, $RecycleBinThresholdGB)
        if ($isLarge) {
            Write-Report ("WARNING: {0} Recycle Bin >= {1} GB" -f $d.DeviceID, $RecycleBinThresholdGB) -ForegroundColor Yellow
        }
    }

    if (-not $AsJson) {
        if ($recycleBinResults) {
            $recycleBinResults | Sort-Object RecycleBinGB -Descending | Format-Table -AutoSize
        }
    }
}

# ---------------- USER PROFILE SIZES ----------------
if (-not (Test-Path $UserRoot)) {
    Write-Report "`nUser root not found: $UserRoot"
    # continue; still return low-space status if it was detected
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

    $profileRows = @()
    foreach ($p in $profiles) {
        $bytes = Get-FolderSizeBytes -Path $p.FullName
        $row = [pscustomobject]@{
            User   = $p.Name
            Path   = $p.FullName
            SizeGB = To-GB $bytes
        }
        $profileRows += $row
        $profileResults += $row
    }

    if ($profileRows) {
        if (-not $AsJson) {
            $profileRows | Sort-Object SizeGB -Descending | Format-Table -AutoSize
        }
    } else {
        Write-Report "No user profiles found."
    }

    # ---------------- PER-USER LARGE PATHS (FOLDERS AND FILES) ----------------
    $thresholdBytes = [int64]($LargeThresholdGB * 1GB)

    foreach ($p in $profiles) {
        Write-Report ""
        Write-Report ("--- {0} ({1}) ---" -f $p.Name, $p.FullName)

        # Top-level subfolders sized recursively; report those >= threshold
        $childDirs = Get-ChildItem -Path $p.FullName -Directory -Force:$IncludeHidden -ErrorAction SilentlyContinue
        $bigFolders = @()

        foreach ($dir in $childDirs) {
            $sizeB = Get-FolderSizeBytes -Path $dir.FullName
            if ($sizeB -ge $thresholdBytes) {
                $LargeItemsFound = $true
                $item = [pscustomobject]@{
                    ItemType = 'Folder'
                    User     = $p.Name
                    Name     = $dir.Name
                    SizeGB   = To-GB $sizeB
                    Path     = $dir.FullName
                    Modified = $dir.LastWriteTime
                }
                $bigFolders += $item
                $largeItemsResults += $item
            }
        }

        # Any individual files >= threshold anywhere under this profile (includes OST)
        $bigFiles = Get-ChildItem -Path $p.FullName -Recurse -File -Force:$IncludeHidden -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge $thresholdBytes } |
                    ForEach-Object {
                        $LargeItemsFound = $true
                        $item = [pscustomobject]@{
                            ItemType = 'File'
                            User     = $p.Name
                            Name     = $_.Name
                            SizeGB   = To-GB $_.Length
                            Path     = $_.FullName
                            Modified = $_.LastWriteTime
                        }
                        $largeItemsResults += $item
                        $item
                    }

        if (($bigFolders.Count + $bigFiles.Count) -gt 0) {
            Write-Report ("Large items (>= {0} GB) for user {1}:" -f $LargeThresholdGB, $p.Name)
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
        LowSpaceThreshold = $LowSpaceThreshold
        LargeThresholdGB = $LargeThresholdGB
        UserRoot          = $UserRoot
        IncludeRecycleBin = $IncludeRecycleBin
        RecycleBinThresholdGB = $RecycleBinThresholdGB
        LowSpaceFound     = $LowSpaceFound
        LargeItemsFound   = $LargeItemsFound
        Drives            = $driveResults
        RecycleBins       = $recycleBinResults
        Profiles          = $profileResults
        LargeItems        = $largeItemsResults
    } | ConvertTo-Json -Depth 5
}

try {
    if ($LowSpaceFound -and $LargeItemsFound) { exit 3 }
    elseif ($LowSpaceFound)                 { exit 1 }
    elseif ($LargeItemsFound)               { exit 2 }
    else                                    { exit 0 }
} catch {
    Write-Report "ERROR: Unexpected failure when setting exit code: $($_.Exception.Message)"
    exit 4
}
