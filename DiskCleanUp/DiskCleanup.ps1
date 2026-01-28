<#
.SYNOPSIS
  Runs Windows Disk Cleanup silently and reports before/after free space via stdout.

.DESCRIPTION
  - Captures drive free space before and after cleanmgr.
  - Runs cleanmgr.exe /sagerun:<id> with hidden window.
  - Emits results to stdout (or JSON) for RMM logging.
  - Writes NOTHING to disk.

.REQUIREMENTS
  - Run as SYSTEM (RMM / Scheduled Task).
  - cleanmgr.exe /sageset:<id> must be configured once per device.

.EXIT CODES
  0 = Completed successfully
  1 = cleanmgr.exe missing
  2 = Drive not found
  3 = Cleanup failed
#>

[CmdletBinding()]
param(
    [Parameter()] [ValidatePattern('^[A-Z]:$')] [string]$DriveLetter = 'C:',
    [Parameter()] [int]$SageId = 1,
    [Parameter()] [switch]$AsJson
)

function Get-DriveStats {
    param([string]$Drive)
    $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction Stop
    $total = [int64]$d.Size
    $free  = [int64]$d.FreeSpace
    $used  = $total - $free
    $pctFree = if ($total -gt 0) { [math]::Round(($free / $total) * 100, 1) } else { 0 }

    [pscustomobject]@{
        Drive       = $Drive
        TotalGB     = [math]::Round($total / 1GB, 2)
        UsedGB      = [math]::Round($used  / 1GB, 2)
        FreeGB      = [math]::Round($free  / 1GB, 2)
        PercentFree = $pctFree
        FreeBytes   = $free
    }
}

$cleanmgr = Join-Path $env:SystemRoot 'System32\cleanmgr.exe'
if (-not (Test-Path $cleanmgr)) {
    Write-Output "ERROR: cleanmgr.exe not found"
    exit 1
}

try {
    $before = Get-DriveStats -Drive $DriveLetter
} catch {
    Write-Output "ERROR: Drive $DriveLetter not found or not queryable"
    exit 2
}

try {
    Start-Process -FilePath $cleanmgr `
        -ArgumentList ("/sagerun:{0}" -f $SageId) `
        -WindowStyle Hidden `
        -Wait `
        -ErrorAction Stop
} catch {
    Write-Output "ERROR: Failed to start cleanmgr: $($_.Exception.Message)"
    exit 3
}

try {
    $after = Get-DriveStats -Drive $DriveLetter
} catch {
    Write-Output "ERROR: Failed to query drive after cleanup"
    exit 3
}

$deltaGB = [math]::Round((($after.FreeBytes - $before.FreeBytes) / 1GB), 2)

$result = [pscustomobject]@{
    Drive       = $DriveLetter
    SageId      = $SageId
    BeforeFreeGB= $before.FreeGB
    AfterFreeGB = $after.FreeGB
    ReclaimedGB = $deltaGB
    BeforePct   = $before.PercentFree
    AfterPct    = $after.PercentFree
}

if ($AsJson) {
    $result | ConvertTo-Json -Depth 4
} else {
    Write-Output (
        "Disk Cleanup complete | Drive {0} | Free: {1}GB → {2}GB | Reclaimed {3}GB" -f
        $DriveLetter, $before.FreeGB, $after.FreeGB, $deltaGB
    )
}

exit 0