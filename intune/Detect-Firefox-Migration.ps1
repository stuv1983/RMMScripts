$ErrorActionPreference = "SilentlyContinue"

$System64 = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
$System32 = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"

$HasSystem = (Test-Path $System64) -or (Test-Path $System32)

# If system Firefox not present, not migrated
if (-not $HasSystem) {
  Write-Output "Non-compliant: Enterprise/system Firefox not detected."
  exit 1
}

# If any per-user AppData firefox.exe exists, migration not complete
$PerUser = Get-ChildItem "C:\Users\*\AppData\Local\Mozilla Firefox\firefox.exe" -ErrorAction SilentlyContinue
if ($PerUser) {
  Write-Output "Non-compliant: Per-user consumer Firefox binaries still present."
  exit 1
}

Write-Output "Compliant: Enterprise/system Firefox present and no per-user binaries."
exit 0