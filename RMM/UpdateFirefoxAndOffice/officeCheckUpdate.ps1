<#
.SYNOPSIS
  Office 365 / C2R Update Trigger
#>

# CONFIGURATION
$OfficeForceShutdown = $false # $true will kill open apps

# ADMIN CHECK
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Output "Blocked: Not Elevated"; exit 1 }

# LOGIC
$OfficeExe = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"

if (Test-Path -LiteralPath $OfficeExe) {
    Write-Output "Office: Detected. Triggering Update..."
    $args = "/update user displaylevel=false forceappshutdown=$OfficeForceShutdown"
    $p = Start-Process -FilePath $OfficeExe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    
    if ($p.ExitCode -eq 0) {
        Write-Output "Result: Success"
        exit 0
    } else {
        Write-Output "Result: Failed (Exit $($p.ExitCode))"
        exit 2
    }
} else {
    Write-Output "Office: Not Installed"
    exit 0
}