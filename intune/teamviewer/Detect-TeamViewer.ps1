<#
.SYNOPSIS
    Detects TeamViewer presence on Windows workstations for Intune Uninstall Assignment.
.DESCRIPTION
    Exit 0 = TeamViewer detected (Tells Intune: "Target found, run the Uninstall script")
    Exit 1 = Not detected / Not a workstation (Tells Intune: "Already clean, do nothing")
#>

[CmdletBinding()]
param()

# --- Workstation Guardrail ---
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if (-not $os -or $os.ProductType -ne 1) { 
    Write-Output "Not a workstation. Compliant by default."
    exit 1 
}

# --- Installed Detection (Registry) ---
$UninstallPaths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$installed = foreach ($p in $UninstallPaths) {
  Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'TeamViewer' } |
    Select-Object DisplayName, DisplayVersion
}

if ($installed) {
    Write-Output "TeamViewer detected. Remediation required."
    $installed | ForEach-Object { Write-Output (" - {0} (v{1})" -f $_.DisplayName, $_.DisplayVersion) }
    exit 0
} else {
    Write-Output "TeamViewer not found. Device is clean."
    exit 1
}